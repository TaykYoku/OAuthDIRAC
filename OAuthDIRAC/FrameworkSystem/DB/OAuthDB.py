""" OAuth class is a front-end to the OAuth Database
"""

import re
import json
import pprint

from ast import literal_eval
from datetime import datetime

from DIRAC import gConfig, S_OK, S_ERROR, gLogger
from DIRAC.Core.Base.DB import DB
from DIRAC.ConfigurationSystem.Client.CSAPI import CSAPI
from DIRAC.ConfigurationSystem.Client.Helpers import Registry
from DIRAC.ConfigurationSystem.Client.Utilities import getAuthAPI
from DIRAC.Resources.IdProvider.IdProviderFactory import IdProviderFactory
from DIRAC.Resources.ProxyProvider.ProxyProviderFactory import ProxyProviderFactory
from DIRAC.FrameworkSystem.Client.NotificationClient import NotificationClient

from OAuthDIRAC.FrameworkSystem.Client.OAuthManagerClient import OAuthManagerClient

__RCSID__ = "$Id$"

gCSAPI = CSAPI()


class OAuthDB(DB):
  """ OAuthDB class is a front-end to the OAuth Database
  """
  tableDict = {'Sessions': {'Fields': {'ID': 'VARCHAR(128)',
                                       'Status': 'VARCHAR(32) DEFAULT "prepared"',
                                       'Session': 'VARCHAR(64) NOT NULL',
                                       'Comment': 'MEDIUMBLOB',
                                       'Provider': 'VARCHAR(255) NOT NULL',
                                       'TokenType': 'VARCHAR(32) DEFAULT "bearer"',
                                       'ExpiresIn': 'DATETIME',
                                       'AccessToken': 'VARCHAR(1000)',
                                       'RefreshToken': 'VARCHAR(1000)',
                                       'LastAccess': 'DATETIME'},
                            'PrimaryKey': 'Session',
                            'Engine': 'InnoDB'}}

  def __init__(self):
    """ Constructor
    """
    self.__permValues = ['USER', 'GROUP', 'VO', 'ALL']
    self.__permAttrs = ['ReadAccess', 'PublishAccess']
    DB.__init__(self, 'OAuthDB', 'Framework/OAuthDB')
    retVal = self.__initializeDB()
    if not retVal['OK']:
      raise Exception("Can't create tables: %s" % retVal['Message'])

  def _checkTable(self):
    """ Make sure the tables are created
    """
    return self.__initializeDB()

  def __initializeDB(self):
    """ Create the tables
    """
    retVal = self._query("show tables")
    if not retVal['OK']:
      return retVal

    tablesInDB = [t[0] for t in retVal['Value']]
    tablesD = {}

    if 'Sessions' not in tablesInDB:
      tablesD['Sessions'] = self.tableDict['Sessions']

    return self._createTables(tablesD)

  def cleanZombieSessions(self):
    """ Kill sessions with old states
    
        :return: S_OK(int)/S_ERROR()
    """
    result = self.__getFields(['Session'], conn='TIMESTAMPDIFF(SECOND,LastAccess,UTC_TIMESTAMP()) > 43200')
    if not result['OK']:
      return result
    sessions = result['Value']
    self.log.info('Found %s old sessions for cleaning' % len(sessions))
    for i in range(0, len(sessions)):
      if sessions[i].get('Session'):
        result = self.logOutSession(sessions[i]['Session'])
        self.log.debug(result['Message'] or result['Value'])
    return S_OK(len(sessions))
  
  def updateIdPSessionsInfoCache(self, idPs=None, IDs=None):
    """ Update cache with information about active session with identity provider

        :param list idPs: list of identity providers that sessions need to update, if None - update all
        :param list IDs: list of IDs that need to update, if None - update all

        :return: S_OK()/S_ERROR()
    """
    IdPSessionsInfo = {}
    result = self._query("SELECT DISTINCT ID, Provider, Session FROM `Sessions`")
    if not result['OK']:
      return result
    for ID, idP, session in result['Value']:
      if (idPs and idP not in idPs) or (IDs and ID not in IDs):
        continue
      if ID not in IdPSessionsInfo:
        IdPSessionsInfo[ID] = {'Providers': []}
      if idP not in IdPSessionsInfo[ID]:
        result = IdProviderFactory().getIdProvider(idP)
        if not result['OK']:
          return result
        __provObj = result['Value']
        result = __provObj.getUserProfile(session)
        if not result['OK']:
          self.log.error(result['Message'])
          kill = self.killSession(session)
          self.log.warn('Cannot get user profile for %s session, removed.' % session, kill.get('Value') or kill.get('Message'))
          continue
        userProfile = result['Value']
        result = self.getTokensBySession(session)
        if not result['OK']:
          return result
        tokens = result['Value']
        if not tokens:
          result = self.killSession(session)
          self.log.warn('Not found tokens for %s session, removed.' % session, result.get('Value') or result.get('Message'))
          continue
        IdPSessionsInfo[ID][idP] = {session: tokens}
        IdPSessionsInfo[ID]['Providers'] = list(set(IdPSessionsInfo[ID]['Providers'] + [idP]))
        # Fill user profile
        for key, value in userProfile.items():
          if key in IdPSessionsInfo[ID]:
            continue
          IdPSessionsInfo[ID][key] = value
      else:
        result = self.getTokensBySession(session)
        if not result['OK']:
          return result
        tokens = result['Value']
        if not tokens:
          result = self.killSession(session)
          self.log.warn('Not found tokens for %s session, removed.' % session, result.get('Value') or result.get('Message'))
          continue
        IdPSessionsInfo[ID][idP][session] = tokens
      
    return S_OK(IdPSessionsInfo)

  def getAuthorization(self, providerName, session=None):
    """ Register new session and return dict with authorization url and session id
    
        :param basestring providerName: provider name
        :param basestring session: here is able to set session id(optional)

        :return: S_OK(dict)/S_ERROR() -- dictionary contain Status, Session, etc.
    """
    self.log.info('Get authorization for %s.' % providerName, 'Session: %s' % session if session else '')
    result = IdProviderFactory().getIdProvider(providerName)
    if not result['OK']:
      return result
    __provObj = result['Value']
    result = __provObj.checkStatus(session=session)
    if not result['OK']:
      return result
    statusDict = result['Value']
    
    # Create new session
    if statusDict['Status'] == 'needToAuth':
      result = self.insertFields('Sessions', ['Session', 'Provider', 'Comment', 'LastAccess'],
                                             [statusDict['Session'], providerName, statusDict['URL'],
                                              'UTC_TIMESTAMP()'])
      if not result['OK']:
        return result
      self.log.info(statusDict['Session'], 'session for %s created' % providerName)
      statusDict['URL'] = '%s/auth/%s' % (getAuthAPI().strip('/'), statusDict['Session'])
    return S_OK(statusDict)

  def parseAuthResponse(self, response, session):
    """ Fill session by user profile, tokens, comment, OIDC authorize status, etc.
        Prepare dict with user parameters, if DN is absent there try to get it.
        Create new or modify existend DIRAC user and store the session

        :param dict response: authorization response dictionary
        :param basestring session: session id

        :return: S_OK(dict)/S_ERROR() -- dictionary contain session status, comment and user profile
    """
    result = self.updateSession({'Status': 'finishing'}, session=session)
    if not result['OK']:
      return result
    
    self.log.info("%s session, parse authentication response:" % session, response)
    result = self.__parse(response, session)
    if not result['OK']:
      self.log.error(session, 'session error: %s' % result['Message'])
      self.updateSession({'Status': 'failed', 'Comment': result['Message']}, session=session)
      return result
    parseDict, status, comment, mail = result['Value']

    if mail:
      for addresses in Registry.getEmailsForGroup('dirac_admin'):
        result = NotificationClient().sendMail(addresses, mail['subject'], mail['body'], localAttempt=False)
        if not result['OK']:
          self.updateSession({'Status': 'failed', 'Comment': result['Message']}, session=session)
          self.log.error(session, 'session error: %s' % result['Message'])
          return result
      self.log.info("%s session, mails to admins:", result['Value'])
    
    return S_OK({'Status': status, 'Comment': comment, 'UserProfile': parseDict})

  def __parse(self, response, session):
    """ Parsing response

        :param dict response: authorization response dictionary
        :param basestring session: session id

        :return: S_OK(dict)/S_ERROR
    """
    # Search provider by session
    result = self.__getFields(['Provider'], session=session)
    if not result['OK']:
      return result
    providerName = result['Value']['Provider']
    result = IdProviderFactory().getIdProvider(providerName)
    if not result['OK']:
      return result
    __provObj = result['Value']
    
    # Parsing response
    self.log.info(session, 'session, parsing "%s" authentication response.' % providerName)
    result = __provObj.parseAuthResponse(response)
    if not result['OK']:
      return result
    parseDict = result['Value']

    status = 'authed'
    comment = ''
    __mail = {}
    result = Registry.getUsernameForID(parseDict['UsrOptns']['ID'])
    if not result['OK']:
      groups = []
      for dn in parseDict['UsrOptns']['DNs'].keys():
        result = Registry.getGroupsForDN(dn)
        if not result['OK']:
          return result
        groups = list(set(groups + result['Value']))
      if groups:
        status = 'authed and notify'
        comment = 'Administrators was notified about you. Found new groups %s' % groups
        __mail['subject'] = "[OAuthManager] User %s to be added." % parseDict['username']
        __mail['body'] = 'User %s was authenticated by ' % parseDict['UsrOptns']['FullName']
        __mail['body'] += providerName
        __mail['body'] +=   "\n\nAuto updating of the user database is not allowed."
        __mail['body'] += " New user %s to be added," % parseDict['username']
        __mail['body'] += "with the following information:\n"
        __mail['body'] += "\nUser name: %s\n" % parseDict['username']
        __mail['body'] += "\nUser profile:\n%s" % pprint.pformat(parseDict['UsrOptns'])
        __mail['body'] += "\n\n------"
        __mail['body'] += "\n This is a notification from the DIRAC OAuthManager service, please do not reply.\n"
      else:
        status = 'visitor'
        comment = 'We not found any registred DIRAC groups that mached with your profile. '
        comment += 'So, your profile has the same access that Visitor DIRAC user.'
        comment += 'Your ID: 100492713487956493716'

    if not parseDict['Tokens'].get('RefreshToken'):
      return S_ERROR('No refresh token found in response.')

    result = self.updateSession({'ID': parseDict['UsrOptns']['ID'], 'ExpiresIn': parseDict['Tokens']['ExpiresIn'], 
                                 'TokenType': parseDict['Tokens']['TokenType'], 'AccessToken': parseDict['Tokens']['AccessToken'],
                                 'RefreshToken': parseDict['Tokens']['RefreshToken'], 'Status': status, 'Comment': comment},
                                 session=session)
    if not result['OK']:
      return result
    return S_OK((parseDict, status, comment, __mail))

  def getLinkBySession(self, session):
    """ Return authorization URL from session

        :param basestring session: session id

        :return: S_OK(basestring)/S_ERROR()
    """
    __conn = 'Status = "prepared" and TIMESTAMPDIFF(SECOND,LastAccess,UTC_TIMESTAMP()) < 300'
    result = self.__getFields(['Comment'], conn=__conn, session=session)
    if not result['OK']:
      return result
    url = result['Value']['Comment']
    if not url:
      return S_ERROR('No link found.')
    result = self.updateSession({'Status': 'in progress', 'Comment': ''}, session=session)
    if not result['OK']:
      return result
    return S_OK(url)

  def getTokensBySession(self, session):
    """ Get tokens dict by session

        :param basestring session: session number

        :return: S_OK(dict)/S_ERROR()
    """
    return self.__getFields(["AccessToken", "ExpiresIn", "RefreshToken", "TokenType"], session=session)
  
  def getStatusBySession(self, session):
    """ Get status dictionary by session id

        :param basestring session: session id

        :return: S_OK(dict)/S_ERROR()
    """
    return self.__getFields(fields=['ID', 'Session', 'Status', 'Comment', 'Provider'], session=session)

  def killSession(self, session):
    """ Remove session
    
        :param basestring session: session id

        :return: S_OK()/S_ERROR()
    """
    return self.deleteEntries('Sessions', condDict={'Session': session})

  def logOutSession(self, session):
    """ Remove session
    
        :param basestring session: session id

        :return: S_OK()/S_ERROR()
    """
    # Log out from provider
    result = self.__getFields(['Provider'], session=session)
    if not result['OK']:
      return result
    provider = result['Value']
    result = IdProviderFactory().getIdProvider(provider)
    if result['OK']:
      providerObj = result['Value']
      result = self.getTokensBySession(session)
      if not result['OK']:
        return result
      result = providerObj.logOut(result['Value'])
    self.log.debug('%s log out:', result.get('Message') or result.get('Value'))
    return self.killSession(session)
  
  def updateSession(self, fieldsToUpdate=None, conn=None, condDict=None, session=None):
    """ Update session record

        :param dict fieldsToUpdate: fields content that need to update
        :param basestring conn: search filter
        :param dict condDict: parameters that need add to search filter
        :params basestring session: session id

        :return: S_OK()/S_ERROR()
    """
    condDict = {'Session': session} if not condDict and session else condDict
    self.log.verbose(session or '', 'session update')
    fieldsToUpdate = fieldsToUpdate or {}
    fieldsToUpdate['LastAccess'] = 'UTC_TIMESTAMP()'
    # Convert seconds to datetime
    if 'ExpiresIn' in fieldsToUpdate and isinstance(fieldsToUpdate['ExpiresIn'], int):
      self.log.debug(session or '', 'session, convert access token live time %s seconds to date.' % fieldsToUpdate['ExpiresIn'])
      result = self._query("SELECT ADDDATE(UTC_TIMESTAMP(), INTERVAL %s SECOND)" % fieldsToUpdate['ExpiresIn'])
      if not result['OK']:
        return result
      fieldsToUpdate['ExpiresIn'] = result['Value'][0][0] if result['Value'] else 'UTC_TIMESTAMP()'
    return self.updateFields('Sessions', updateDict=fieldsToUpdate, condDict=condDict, conn=conn)
  
  def __getFields(self, fields=None, conn=None, timeStamp=False, session=None, **kwargs):
    """ Get list of dict of fields that found in DB

        :param list fields: field names
        :param basestring conn: search filter in records
        :param bool timeStamp: if need to add field "timeStamp" with current datetime to dictionaries
        :param basestring session: session number
        :param basestring `**kwargs`: parameters that need add to search filter

        :return: S_OK(list(dict), dict)/S_ERROR() -- if searching by session dict will return
    """
    fields = fields or self.tableDict['Sessions']['Fields'].keys()
    result = self.getFields('Sessions', outFields=fields, condDict={'Session': session} if session else kwargs, conn=conn)
    if not result['OK']:
      return result

    # Read time stamp
    if timeStamp:
      timeStamp = datetime
      try:
        timeStamp = self._query("SELECT UTC_TIMESTAMP()")['Value'][0][0]
      except IndexError:
        return S_ERROR('Cannot get time stamp.')

    # Collect result with adding time stamp
    resList = []
    for i in range(0, len(result['Value'])):
      d = {}
      for j, field in list(enumerate(fields)):
        d[field] = result['Value'][i][j]
      if timeStamp:
        d['TimeStamp'] = timeStamp
      if d:
        resList.append(d)
    if not resList and session:
      return S_ERROR('No %s session found.' % session)
    return S_OK(resList[0] if session else restList)


  # def prepareUserParameters(self, parseDict, sourceDict=None):
  #   """ Convert user profile to parameters dictionaries and user name that needed to modify CS:
  #         - dictionary with user parameters that got from response:
  #           DN as list, Groups, ID, Email, etc.
  #         - DIRAC user name
  #         - dictionary of exist DIRAC user if found

  #       :param dict parseDict: parsed user parameters that will be added to CS
  #       :param dict sourceDict: parsed user parameters by previous authentication flow which
  #              initiate current

  #       :return: S_OK(dict)/S_ERROR() -- contain merged dictionary
  #   """
  #   def mergeDicts(baseDict, addDict):
  #     """ Dictionary merger

  #         :param dict baseDict: base dictionary
  #         :param dict addDict: dictionary that need to add

  #         :return tuple(dict, dict) -- contain merged and with difference dictionaries
  #     """
  #     diffDict = {}
  #     for k, vAdd in addDict.items():
  #       if vAdd:
  #         if not isinstance(vAdd, list):
  #           try:
  #             vAdd = vAdd.split(', ')
  #           except BaseException:
  #             vAdd = [vAdd]
  #         if k in baseDict.keys():
  #           vBase = baseDict[k]
  #           if not isinstance(vBase, list):
  #             try:
  #               vBase = vBase.split(', ')
  #             except BaseException:
  #               vBase = [vBase]
  #           diff = list(set(vAdd) - set(vBase))
  #           if diff:
  #             diffDict[k] = diff
  #             baseDict[k] = vBase + diff
  #         else:
  #           baseDict[k] = vAdd
  #     return (baseDict, diffDict)

  #   self.log.info('Convert user profile to parameters dictionaries and user name that needed to modify CS')
  #   self.log.debug('Parse dictionary:\n', pprint.pformat(parseDict))
  #   self.log.debug('Source dictionary:\n', pprint.pformat(sourceDict))
  #   resDict = {}
  #   resDict['username'] = parseDict['username']
  #   resDict['nosupport'] = parseDict['nosupport']
  #   result = gCSAPI.listUsers()
  #   if not result['OK']:
  #     return result
  #   allusrs = result['Value']
    
  #   # Look exist DIRAC user
  #   resDict['UserExist'] = ''
  #   result = Registry.getUsernameForID(parseDict['UsrOptns']['ID'])
  #   if not result['OK']:
  #     result = Registry.getUsernameForDN(parseDict['UsrOptns']['DN'])
  #   if not result['OK']:
  #     if not parseDict['username']:
  #       return S_ERROR('No user exist and cannot generate new name of user.')
  #     if parseDict['username'] in allusrs:
  #       for i in range(0, 100):
  #         if resDict['username'] not in allusrs:
  #           break
  #         resDict['username'] = parseDict['username'] + str(i)
  #     resDict['UsrOptns'] = parseDict['UsrOptns']
  #   else:
  #     # FIXME: If user exist need to save diff changes and allow to continue enter to DIRAC, but show warning
  #     resDict['username'] = result['Value']
  #     result = Registry.getDNForUsername(resDict['username'])
  #     if not result['OK']:
  #       return result
  #     result = Registry.getUserDict(resDict['username'])
  #     if not result['OK']:
  #       return result
  #     resDict['UsrOptns'] = result['Value']
  #     result = Registry.getGroupsForUser(resDict['username'])
  #     if not result['OK']:
  #       return result
  #     resDict['UsrOptns']['Groups'] = result['Value']
  #     resDict['UserExist'] = 'Yes'
  #     self.log.debug('Found existed user "%s"' % resDict['username'],
  #                    'with next profile\n: %s' % pprint.pformat(resDict['UsrOptns']))

  #     # Merge information existing user with in response
  #     resDict['UsrOptns'], diffD = mergeDicts(resDict['UsrOptns'], parseDict['UsrOptns'])
  #     resDict['AddedUsrOptns'] = diffD

  #   # If curret authentication initiated by previous flow
  #   if sourceDict:
  #     # If we found some exist user we will write new changes to there,
  #     # if found two users or no one we will write changes to user that match with first authentication flow
  #     baseDict = resDict if not sourceDict['UserExist'] and resDict['UserExist'] else sourceDict
  #     addDict = sourceDict if baseDict == resDict else resDict

  #     # Merge information
  #     # No registred groups
  #     baseDict['nosupport'] = list(set(addDict['nosupport'] + baseDict['nosupport']))

  #     # User options
  #     resDict = baseDict.copy()
  #     resDict['UsrOptns'], diffD = mergeDicts(resDict['UsrOptns'], addDict['UsrOptns'])
  #     resDict['AddedUsrOptns'] = diffD
    
  #   # Convert to string all, but not "Groups"
  #   for k, v in resDict['UsrOptns'].items():
  #     if isinstance(v, list):
  #       if k == 'Groups':
  #         resDict['UsrOptns'][k] = list(set(resDict['UsrOptns'][k]))
  #       else:
  #         resDict['UsrOptns'][k] = ', '.join(v)
    
  #   self.log.debug('User information merged:\n', pprint.pformat(resDict))
  #   return S_OK(resDict)
