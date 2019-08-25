""" OAuth class is a front-end to the OAuth Database
"""

import re
import json
import pprint

from ast import literal_eval
from datetime import datetime

from DIRAC import gConfig, S_OK, S_ERROR
from DIRAC.Core.Base.DB import DB
from DIRAC.Core.Security.X509Chain import X509Chain  # pylint: disable=import-error
from DIRAC.ConfigurationSystem.Client.CSAPI import CSAPI
from DIRAC.ConfigurationSystem.Client.Helpers import Registry
from DIRAC.ConfigurationSystem.Client.Helpers.Resources import getInfoAboutProviders
from DIRAC.Resources.ProxyProvider.ProxyProviderFactory import ProxyProviderFactory
from DIRAC.FrameworkSystem.Client.NotificationClient import NotificationClient

from OAuthDIRAC.Resources.IdProvider.IdProviderFactory import IdProviderFactory

__RCSID__ = "$Id$"

gCSAPI = CSAPI()


class OAuthDB(DB):
  """ OAuthDB class is a front-end to the OAuth Database
  """
  tableDict = {'Sessions': {'Fields': {'Id': 'INTEGER AUTO_INCREMENT NOT NULL',
                                       'Sub': 'VARCHAR(128)',
                                       'State': 'VARCHAR(64) NOT NULL',
                                       'Status': 'VARCHAR(32) DEFAULT "prepared"',
                                       'Comment': 'MEDIUMBLOB',
                                       'Provider': 'VARCHAR(255) NOT NULL',
                                       'TokenType': 'VARCHAR(32) DEFAULT "bearer"',
                                       'AccessToken': 'VARCHAR(1000)',
                                       'RefreshToken': 'VARCHAR(1000)',
                                       'LastAccess': 'DATETIME',
                                       'ExpiresIn': 'DATETIME',                                     
                                       'UserName': 'VARCHAR(16)',
                                       'UserDN': 'VARCHAR(128)'},
                            'PrimaryKey': 'Id',
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
    
        :return: S_OK()/S_ERROR()
    """
    result = self.__getFields(['State'], conn='TIMESTAMPDIFF(SECOND,LastAccess,UTC_TIMESTAMP()) > 43200')
    if not result['OK']:
      return result
    sessions = result['Value']
    self.log.notice('Found %s old sessions' % len(sessions))
    for i in range(0, len(sessions)):
      if sessions[i].get('State'):
        result = self.killSession(state=sessions[i]['State'])
        if not result['OK']:
          self.log.error(result['Message'])
    self.log.notice('Old sessions was killed')
    return S_OK()

  # FIXME: state to session
  def getAuthorization(self, providerName, state):
    """ Register new session and return dict with authorization url and state(session number)
    
        :param basestring providerName: provider name
        :param basestring state: here is able to set session number(optional)

        :return: S_OK(dict)/S_ERROR()
    """
    result = IdProviderFactory().getIdProvider(providerName)
    if not result['OK']:
      return result
    __provObj = result['Value']

    # Search active session
    sessionDict = {'State': state}
    if state:
      self.log.info('Search %s session for' % state, providerName)
      result = self.__getFields(conn="State IN ( 'in progress', 'authed' )", State=state, Provider=providerName)
      if not result['OK']:
        return result
      self.log.notice('Search result -->:', result['Value'])
      sessionDict = result['Value'] and result['Value'][0] or sessionDict

    # Check work status
    result = __provObj.checkStatus(sessionDict)
    if not result['OK']:
      return result
    statusDict = result['Value']

    if statusDict['Status'] == 'ready':
      # Session actuality, lets use it
      # Convert to seconds and save resfreshing tokens existing session
      result = self._query("SELECT ADDDATE(UTC_TIMESTAMP(), INTERVAL %s SECOND)" % statusDict['Tokens']['ExpiresIn'])
      if not result['OK']:
        return result
      expInSec = result.get('Value') and result['Value'][0] or 0
      result = self.updateSession({'TokenType': statusDict['Tokens']['TokenType'],
                                   'AccessToken': statusDict['Tokens']['AccessToken'],
                                   'RefreshToken': statusDict['Tokens']['RefreshToken'],
                                   'ExpiresIn': expInSec}, state=statusDict['Session'])
      if not result['OK']:
        return result
      self.log.notice(statusDict['Session'], 'authorization session of %s updated' % providerName)

    if statusDict['Status'] == 'needToAuth':
      # Need authentication
      if not statusDict['URL'] or not statusDict['Session']:
        return S_ERROR('No authentication URL or status created.')

      # Create new session
      self.log.info("StatusDict to insert DB:", statusDict)
      result = self.insertFields('Sessions', ['State', 'Provider', 'Comment', 'LastAccess'],
                                             [statusDict['Session'], providerName, statusDict['URL'],
                                              'UTC_TIMESTAMP()'])
      if not result['OK']:
        return result
      self.log.notice(statusDict['Session'], 'authorization session of %s created' % providerName)

    return S_OK(statusDict)

  def getLinkByState(self, state):
    """ Return authorization URL from session

        :param basestring state: session number

        :return: S_OK(basestring)/S_ERROR()
    """
    __conn = 'Status = "prepared" and TIMESTAMPDIFF(SECOND,LastAccess,UTC_TIMESTAMP()) < 300'
    result = self.__getFields(['Comment'], conn=__conn, State=state)
    if not result['OK']:
      return result
    commentedLink = result['Value'] and result['Value'][0].get('Comment')
    if not commentedLink:
      return S_ERROR('No link found.')
    return S_OK(commentedLink)

  def parseAuthResponse(self, response, state):
    """ Fill session by user profile, tokens, comment, OIDC authorize status, etc.
        Prepare dict with user parameters, if DN is absent there try to get it.
        Create new or modify existend DIRAC user and store the session

        :param dict response: authorization response dictionary
        :param basestring state: session number

        :return: S_OK(dict)/S_ERROR
    """
    result = self.updateSession({'Status': 'in progress'}, state=state)
    if not result['OK']:
      return result
    
    self.log.info("%s session, parse auth response:" % state, response)
    result = self.__parse(response, state)
    if result['OK']:
      __proxyProvider = result['Value']['proxyProviderName']
      if __proxyProvider:
        self.log.info("%s session, check proxy provider" % state, __proxyProvider)
        result = self.__proxyProviderCheck(result['Value']['providerName'], __proxyProvider,
                                           result['Value']['parseDict'], result['Value']['sessionDict'], state)
        if result['OK']:
          if 'redirect' in result['Value']:
            self.log.info("%s session, redirect to second flow:" % state, result['Value']['redirect'])
            return result
          __parseDict = result['Value']['parseDict']
          self.log.info("%s session, merge dictionary:" % state, __parseDict)
          result = self.__modifyUser(__parseDict, state)
    
    if not result['OK']:
      for __state in list(set([state, state.replace('_redirect', '')])):
        self.updateSession({'Status': 'failed', 'Comment': result['Message']}, state=__state)
      self.log.error(state, 'session error: %s' % result['Message'])
      return result
    __status = result['Value']['Status']
    comment = result['Value']['Notify']
    __mail = result['Value'].get('EMailObj')
    
    if __mail:
      addresses = Registry.getEmailsForGroup('dirac_admin')
      self.log.info("%s session, send mail to admins:" % state, addresses)
      result = NotificationClient().sendMail('andrii.lytovchenko.workmail@gmail.com', subject=__mail['subject'], body=__mail['body'])
      if not result['OK']:
        for __state in list(set([state, state.replace('_redirect', '')])):
          self.updateSession({'Status': 'failed', 'Comment': result['Message']}, state=__state)
        self.log.error(state, 'session error: %s' % result['Message'])
        return result
    
    for __state in list(set([state, state.replace('_redirect', '')])):
      result = self.updateSession({'Status': __status, 'Comment': comment}, state=__state)
      if not result['OK']:
        return result

    return S_OK({'redirect': '', 'Messages': comment})

  def __parse(self, response, state):
    """ Parsing response

        :param dict response: authorization response dictionary
        :param basestring state: session number

        :return: S_OK(dict)/S_ERROR
    """
    # Search provider by state
    result = self.__getFields(['Provider'], State=state)
    if not result['OK']:
      return result
    providerName = result['Value'] and result['Value'][0].get('Provider')
    result = IdProviderFactory().getIdProvider(providerName)
    if not result['OK']:
      return result
    __provObj = result['Value']
    
    # Parsing response
    self.log.info(state, 'session, parsing "%s" authentification response.' % providerName)
    result = __provObj.parseAuthResponse(response)
    if not result['OK']:
      return result
    parseDict = result['Value']

    if 'RefreshToken' not in parseDict['Tokens']:
      return S_ERROR('No refresh token')

    # Convert to seconds and save tokens
    result = self._query("SELECT ADDDATE(UTC_TIMESTAMP(), INTERVAL %s SECOND)" % parseDict['Tokens']['ExpiresIn'])
    if not result['OK']:
      return result
    expInSec = result.get('Value') and result['Value'][0] or 0
    __sessionDict = parseDict['Tokens'].copy()
    __sessionDict['ID'] = parseDict['UsrOptns']['ID']
    __sessionDict['State'] = state
    result = self.updateSession({'Sub': __sessionDict['ID'], 'ExpiresIn': expInSec, 'TokenType': __sessionDict['TokenType'],
                                 'AccessToken': __sessionDict['AccessToken'], 'RefreshToken': __sessionDict['RefreshToken']},
                                state=state)
    if not result['OK']:
      return result

    # Search if exist source state(without "_redirect")
    sourceDict = {}
    if re.search('_redirect$', state):
      self.log.info(state, 'session, getting information about previous authetication flow')
      result =  self.__getFields(['Provider', 'Comment'], State=state[:-9])
      if not result['OK']:
        return result
      try:
        sourceIdP = result['Value'][0]['Provider']
        sourceDict = literal_eval(result['Value'] and result['Value'][0].get('Comment'))
      except BaseException as ex:
        return S_ERROR('Cannot get IdP info dict from "Comment" field: %s' % ex)
      if not isinstance(sourceDict, dict):
        return S_ERROR('Cannot get IdP info dict from "Comment" field: it`s not dict')

    # Prepare user parameters to modify CS and merge with source authentication flow snapshot
    self.log.info(state, 'session, mergin information collected from responses and that found in CS')
    result = self.prepareUserParameters(parseDict, sourceDict)
    if not result['OK']:
      return result
    parseDict = result['Value']

    # Save user name
    __sessionDict['UserName'] = parseDict['username']
    result = self.updateSession({'UserName': parseDict['username']}, state=state)
    if not result['OK']:
      return result
    return S_OK({'proxyProviderName': __provObj.parameters.get('ProxyProvider') or sourceDict.get('SourceProxyProvider'),
                 'parseDict': parseDict, 'sessionDict': __sessionDict, 'providerName': providerName})

  def __proxyProviderCheck(self, providerName, proxyProviderName, parseDict, sessionDict, state):
    """ Check proxy provider after take authetication response

        :param basestring providerName: identity provider that send response
        :param basestring proxyProviderName: proxy provider name
        :param dict parseDict: dictionary with parsing response
        :param dict sessionDict: dictionary with tokens and so on
        :param basestring state: session number

        :return: S_OK(dict)/S_ERROR
    """
    # Check proxyprovider
    self.log.info(state, 'session, checking %s proxy provider' % proxyProviderName)
    result = ProxyProviderFactory().getProxyProvider(proxyProviderName)
    if not result['OK']:
      return result
    __pProvider = result['Value']
    __idPOfProxyProvider = __pProvider.parameters.get('IdProvider')

    if __idPOfProxyProvider and not __idPOfProxyProvider == providerName:
      # Current identity provider is not correct for proxy provider, so this state is not match
      sessionDict['State'] = None

    # Check if proxy provider ready
    __userDict = parseDict['UsrOptns'].copy()
    __userDict['UserName'] = parseDict['username']
    result = __pProvider.checkStatus(__userDict, sessionDict)
    if not result['OK']:
      return result
    ppStatus = result['Value']['Status']

    if not ppStatus == 'ready':

      if ppStatus == 'needToAuth':
        # Initiate second authentication flow
        if not __idPOfProxyProvider:
          return S_ERROR('Cannot find IdProvider for %s' % proxyProviderName)
        if __idPOfProxyProvider == providerName:
          return S_ERROR('%s ask authentication in current IdProvider after authentication response.' % proxyProviderName)
        self.log.info(state, 'session, %s proxy provider ask authentication throught %s' % (proxyProviderName, __idPOfProxyProvider))
        result = self.getAuthorization(__idPOfProxyProvider, state + '_redirect')
        if not result['OK']:
          return result
        # self.log.notice('Result ===>>>', result)
        if result['Value']['Status'] == 'needToAuth':
          url = result['Value']['URL']
          parseDict['SourceProxyProvider'] = proxyProviderName
          
          # Make bakup of current dict
          sourceDict = json.dumps(parseDict)
          # self.log.info('sourceDict STORED INFO ++++++', sourceDict)
          result = self.updateSession({'Status': 'in progress', 'Comment': sourceDict}, state=state)
          if not result['OK']:
            return result
          
          # Redirection
          self.log.info(state, 'session, submit one more authentication flow for %s' % __idPOfProxyProvider)
          return S_OK({'redirect': url})

      # Fail
      for __state in list(set([state, state.replace('_redirect', '')])):
        self.updateSession({'Status': 'fail', 'Comment': 'Not correct proxy provider status: %s' % ppStatus}, state=__state)
        if not result['OK']:
          return result
      return S_ERROR('Not correct proxy provider status')

    # Get user DN
    self.log.info(state, 'session, %s proxy provider ready to work, try to get user DN' % proxyProviderName)
    result = __pProvider.getUserDN(__userDict, sessionDict)
    if not result['OK']:
      return result
    proxyDN = result['Value']
    self.log.info(state, 'session, %s userDN from %s' % (proxyDN, __idPOfProxyProvider))
    # Add user DN to information dictionary
    if proxyDN not in parseDict['UsrOptns']['DN'].split(', '):
      parseDict['UsrOptns']['DN'] += ', ' + proxyDN
    secDN = 'DNProperties/' + proxyDN.replace('/', '-').replace('=', '_')
    groups = secDN + '/Groups'
    provs = secDN + '/ProxyProviders'
    prepGroups = parseDict['UsrOptns'].get('Groups') or []
    if groups not in parseDict['UsrOptns']:
      parseDict['UsrOptns'][groups] = prepGroups
    if not isinstance(parseDict['UsrOptns'][groups], list):
      parseDict['UsrOptns'][groups] = parseDict['UsrOptns'][groups].split(', ')
    parseDict['UsrOptns'][groups] += list(set(prepGroups) - set(parseDict['UsrOptns'][groups]))
    if provs not in parseDict['UsrOptns']:
      parseDict['UsrOptns'][provs] = [proxyProviderName]
    if not isinstance(parseDict['UsrOptns'][provs], list):
      parseDict['UsrOptns'][provs] = parseDict['UsrOptns'][provs].split(', ')
    parseDict['UsrOptns'][provs] += list(set([proxyProviderName]) - set(parseDict['UsrOptns'][provs]))

    # Save user DN
    self.log.info(state, 'session, user DN taken: %s' % proxyDN)
    result = self.updateSession({'UserDN': proxyDN}, state=state)
    if not result['OK']:
      return result
    return S_OK({'parseDict': parseDict})
  
  def __modifyUser(self, parseDict, state):
    """ Create or modify DIRAC user if he not visitor

        :param dict parseDict: prepared dictionary with parsed response
        :param basestring state: session number
        
        :return: S_OK(basestring)/S_ERROR() -- basestring contain message
    """
    __mail = {}
    __mail['subject'] = "[DIRAC:OAuthManager] %s user" % parseDict['username']
    __mail['body'] = '\n%s was autheticated.\n' % parseDict['UsrOptns']['FullName']

    # Notify about no registred VOs that exist in response information
    notify = ''
    if parseDict.get('nosupport'):
      notify = "In authetication response information was found unsupported by DIRAC next VOMSes:"
      notify += "\n%s" % '\n'.join(parseDict['nosupport'])
      __mail['body'] += notify
      notify += "\nPlease contact with administrators to register it in DIRAC."

    # Visitor check
    if not parseDict['UserExist']:
      if not parseDict['UsrOptns']['Groups']:
        comment = 'We not found any registred DIRAC groups that mached with your profile. '
        comment += 'So, your profile has the same access that Visitor DIRAC user.'
        comment += notify and '\nOne more thing.. \n    ' + notify or ''
        return S_OK({'Status': 'visitor', 'Notify': comment})
      elif not parseDict['UsrOptns']['DN']:
        comment = 'No any user DN found. '
        comment += 'So, your profile has the same access that Visitor DIRAC user.'
        comment += notify and '\nOne more thing.. \n    ' + notify or ''
        return S_OK({'Status': 'visitor', 'Notify': comment})

    # Add new user to CS or modify existed
    self.log.info("%s session, user parameters to add to CS: %s" % (state, pprint.pformat(parseDict['UsrOptns'])))
    
    # Read allowed flag in CS
    __mergeAllow = gConfig.getValue('/Systems/Framework/Production/Services/OAuthManager/AutoMerge', False)

    # Add user profile to report letter
    if __mergeAllow:
      __mail['body'] += "\nAuto merge is allow."
      if parseDict['UserExist']:
        __mail['subject'] += " was modified."
        __mail['body'] += " User %s was modified." % parseDict['username']
      else:
        __mail['subject'] += " was added."
        __mail['body'] += "  New user %s was added." % parseDict['username']
    else:
      __mail['body'] += "\n\nAuto merge is not allow."
      if parseDict['UserExist']:
        __mail['subject'] += " need to modify."
        __mail['body'] += " User %s need to modify." % parseDict['username']
      else:
        __mail['subject'] += " need to add."
        __mail['body'] += "  New user %s need to add." % parseDict['username']
    __mail['body'] += "\n\nUser name: %s\n" % parseDict['username']
    __mail['body'] += "\nUser profile:\n%s" % pprint.pformat(parseDict['UsrOptns'])
    __mail['body'] += "\n\n------"
    __mail['body'] += "\nThis notification from DIRAC OAuthManager service, please do not replay.\n"


    if not __mergeAllow:
      return S_OK({'Status': 'authed and reported', 'Notify': notify, 'EMailObj': __mail})

    # Refresh CS
    result = gCSAPI.downloadCSData()
    if not result['OK']:
      return result

    # # Add new groups
    # for group in parseDict['Groups']:
    #   groupName, groupParams = group.items()[0]
    #   groupParams['Users'] = parseDict['username']
    #   result = gCSAPI.addGroup(groupName, groupParams)
    #   if not result['OK']:
    #     return result
    # __mail['body'] += "\n  Groups that was added to CS with user %s:\n  %s" % (parseDict['username'], parseDict['Groups'])
    
    # Modify/add user
    for k, v in parseDict['UsrOptns'].items():
      if isinstance(v, list) and not k == 'Groups':
        parseDict['UsrOptns'][k] = ', '.join(v)
    result = gCSAPI.modifyUser(parseDict['username'], parseDict['UsrOptns'], True)
    if not result['OK']:
      return result

    if result['Value']:
      # Commit
      result = gCSAPI.commitChanges()
      if not result['OK']:
        return result

      # Force refresh
      result = gCSAPI.forceGlobalConfigurationUpdate()
      if not result['OK']:
        return result

    return S_OK({'Status': 'authed', 'Notify': notify, 'EMailObj': __mail})

  def getUsrnameForState(self, state):
    """ Get username by session number

        :param basestring state: session number

        :return: S_OK(dict)/S_ERROR()
    """
    result = self.__getFields(fields=['UserName', 'State'], State=state)
    if not result['OK']:
      return result
    userName = result['Value'] and result['Value'][0].get('UserName')
    if not userName:
      return S_ERROR('No user for %s state found.' % state)
    return S_OK({'username': userName, 'state': state})

  def getStatusByState(self, state):
    """ Get username by session number

        :param basestring state: session number

        :return: S_OK(dict)/S_ERROR()
    """
    result = self.__getFields(fields=['Sub', 'State', 'Status', 'Comment', 'Provider', 'UserName'], State=state)
    if not result['OK']:
      return result
    resD = result['Value'] and result['Value'][0]
    if not resD or resD and not resD.get('Status'):
      return S_ERROR('Cannot get status for state.')
    return S_OK(resD)

  def getSessionDict(self, conn, condDict):
    """ Get fields from session

        :param basestring conn: search filter
        :param dict condDict: parameters that need add to search filter

        :result: S_OK(list(dict))/S_ERROR()
    """
    if "State" in condDict:
      result = self.updateSession(conn=conn, condDict=condDict)
      if not result['OK']:
        return result
    return self.__getFields(conn=conn, timeStamp=True, **condDict)

  def killSession(self, state):
    """ Remove session
    
        :param basestring state: session number

        :return: S_OK()/S_ERROR()
    """
    # Delete entries
    result = self.__getFields(['Provider', 'AccessToken', 'RefreshToken'], State=state)
    if not result['OK']:
      return result
    rmDict = result['Value'] and result['Value'][0] or None
    if not rmDict:
      self.log.notice(state, ' session not found.')
      return S_OK()
    result = self.deleteEntries('Sessions', condDict={'State': state})
    if not result['OK']:
      return result

    # Log out from provider
    result = IdProviderFactory().getIdProvider(rmDict['Provider'])
    if not result['OK']:
      return result
    __provider = result['Value']
    result = __provider.logOut(rmDict)
    if not result['OK']:
      return result
    self.log.notice(state, 'session was killed')
    return S_OK()
  
  def updateSession(self, fieldsToUpdate=None, conn=None, condDict=None, state=None):
    """ Update session record

        :param dict fieldsToUpdate: fields content that need to update
        :param basestring conn: search filter
        :param dict condDict: parameters that need add to search filter
        :params basestring state: session number

        :return: S_OK()/S_ERROR()
    """
    condDict = not condDict and state and {'State': state} or condDict
    self.log.info(state or '', 'session update')
    fieldsToUpdate = fieldsToUpdate or {}
    fieldsToUpdate['LastAccess'] = 'UTC_TIMESTAMP()'
    return self.updateFields('Sessions', updateDict=fieldsToUpdate, condDict=condDict, conn=conn)

  def prepareUserParameters(self, parseDict, sourceDict=None):
    """ Convert user profile to parameters dictionaries and user name that needed to modify CS:
          - dictionary with user parameters that got from response:
            DN as list, Groups, ID, email, etc.
          - DIRAC user name
          - dictionary of exist DIRAC user if found

        :param dict parseDict: parsed user parameters that will be added to CS
        :param dict sourceDict: parsed user parameters by previous authentication flow which
               initiate current

        :return: S_OK(dict,basestring)/S_ERROR()
    """
    self.log.info('Convert user profile to parameters dictionaries and user name that needed to modify CS')
    self.log.info('Parse dictionary:', parseDict)
    self.log.info('Source dictionary:', sourceDict)
    resDict = {}
    # resDict['Groups'] = parseDict['Groups']
    resDict['username'] = parseDict['username']
    resDict['nosupport'] = parseDict['nosupport']
    result = gCSAPI.listUsers()
    if not result['OK']:
      return result
    allusrs = result['Value']
    
    # Look exist DIRAC user
    resDict['UserExist'] = ''
    result = Registry.getUsernameForID(parseDict['UsrOptns']['ID'])
    if not result['OK']:
      result = Registry.getUsernameForDN(parseDict['UsrOptns']['DN'])
    if not result['OK']:
      if not parseDict['username']:
        return S_ERROR('No user exist and cannot generate new name of user.')
      if parseDict['username'] in allusrs:
        for i in range(0, 100):
          if resDict['username'] not in allusrs:
            break
          resDict['username'] = parseDict['username'] + str(i)
      resDict['UsrOptns'] = parseDict['UsrOptns']
    else:
      resDict['username'] = result['Value']
      result = Registry.getDNForUsername(resDict['username'])
      if not result['OK']:
        return result['Message']
      result = Registry.getUserDict(resDict['username'])
      if not result['OK']:
        return result
      self.log.info('Found existed user "%s"' % resDict['username'], 'with next profile: %s' % result['Value'])
      resDict['UsrOptns'] = result['Value']
      resDict['UserExist'] = 'Yes'

      # Merge information existing user with in response
      for k, vParse in parseDict['UsrOptns'].items():
        if vParse:
          if not isinstance(vParse, list):
            try:
              vParse = vParse.split(', ')
            except BaseException:
              vParse = [vParse]
          if k in resDict['UsrOptns'].keys():
            vRes = resDict['UsrOptns'][k]
            if not isinstance(vRes, list):
              try:
                vRes = vRes.split(', ')
              except BaseException:
                vRes = [vRes]
            resDict['UsrOptns'][k] = vRes + list(set(vParse) - set(vRes))
          else:
            resDict['UsrOptns'][k] = vParse

    # If curret authentication initiated by previous flow
    if sourceDict:
      # If we found some exist user we will write new changes to there,
      # if found two users or no one we will write changes to user that match with first authentication flow
      baseDict = resDict if not sourceDict['UserExist'] and resDict['UserExist'] else sourceDict
      addDict = sourceDict if baseDict == resDict else resDict

      # Merge information
      # # New groups
      # baseGroups, addGroups = [], []
      # for __groups, __dict in [(baseGroups, baseDict), (addGroups, addDict)]:
      #   for d in __dict['Groups'] or [{}]:
      #     if d.keys():
      #       __groups.append(d.keys()[0])

      # for __group in list(set(addGroups) - set(baseGroups)):
      #   baseDict['Groups'].append(addDict['Groups'][__group])

      # No registred groups
      baseDict['nosupport'] = list(set(addDict['nosupport'] + baseDict['nosupport']))

      # User options
      for k, vAdd in addDict['UsrOptns'].items():
        if vAdd:
          if not isinstance(vAdd, list):
            try:
              vAdd = vAdd.split(', ')
            except BaseException:
              vAdd = [vAdd]
          if k in baseDict['UsrOptns'].keys():
            vBase = baseDict['UsrOptns'][k]
            if not isinstance(vBase, list):
              try:
                vBase = vBase.split(', ')
              except BaseException:
                vBase = [vBase]
            baseDict['UsrOptns'][k] = vBase + list(set(vAdd) - set(vBase))
          else:
            baseDict['UsrOptns'][k] = vAdd
      resDict = baseDict.copy()
    
    # Convert to string all, but not "Groups"
    for k, v in resDict['UsrOptns'].items():
      if isinstance(v, list):
        if k == 'Groups':
          resDict['UsrOptns'][k] = list(set(resDict['UsrOptns'][k]))
        else:
          resDict['UsrOptns'][k] = ', '.join(v)
    self.log.info('Information merged:', resDict)
    return S_OK(resDict)

  def __getFields(self, fields=None, conn=None, timeStamp=False, **kwargs):
    """ Get list of dict of fields that found in DB

        :param list fields: field names
        :param basestring conn: search filter in records
        :param bool timeStamp: if need to add field "timeStamp" with current datetime to dictionaries
        :param basestring `**kwargs`: parameters that need add to search filter

        :return: S_OK(list(dict))/S_ERROR()
    """
    fields = fields or self.tableDict['Sessions']['Fields'].keys()
    result = self.getFields('Sessions', outFields=fields, condDict=kwargs, conn=conn)
    if not result['OK']:
      return result

    # Read time stamp
    if timeStamp:
      timeStamp = datetime
      try:
        timeStamp = self._query("SELECT UTC_TIMESTAMP()")['Value'][0][0]
      except IndexError:
        return S_ERROR(result.get('Message') or 'Cannot get time stamp.')

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
    return S_OK(resList)
