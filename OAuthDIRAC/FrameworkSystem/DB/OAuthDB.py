""" OAuth class is a front-end to the OAuth Database
"""
#TODO: go to sqlalchemy
import re
import json
import pprint
import random
import string

from ast import literal_eval
from datetime import datetime

from DIRAC import gConfig, S_OK, S_ERROR, gLogger
from DIRAC.Core.Base.DB import DB
# from DIRAC.ConfigurationSystem.Client.CSAPI import CSAPI
# from DIRAC.ConfigurationSystem.Client.Helpers.Registry import getGroupsForDN, getUsernameForID, getEmailsForGroup
from DIRAC.Resources.IdProvider.IdProviderFactory import IdProviderFactory
#from DIRAC.Resources.ProxyProvider.ProxyProviderFactory import ProxyProviderFactory
#from DIRAC.FrameworkSystem.Client.NotificationClient import NotificationClient

__RCSID__ = "$Id$"

# gCSAPI = CSAPI()


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
  
  def getSessionsInfo(self, idPs=None, IDs=None, session=None):
    """ Get information about sessions
        
        :param list idPs: list of identity providers that sessions need to update, if None - update all
        :param list IDs: list of IDs that need to update, if None - update all
        :param str session: session to update

        :return: S_OK(dict)/S_ERROR()
    """
    resDict = {}
    conn = []
    if IDs:
      conn.append('ID IN ("%s") ' % ", ".join(IDs))
    if idPs:
      conn.append('Provider IN ("%s") ' % ", ".join(idPs))
    if session:
      conn.append('Session = "%s" ' % session)
    where = 'WHERE %s' % ' AND '.join(conn) if conn else ''
    result = self._query("SELECT DISTINCT ID, Provider, Session FROM `Sessions` %s" % where)
    if not result['OK']:
      return result
    for userID, idP, session in result['Value']:
      resDict[session] = {'ID': userID, 'Provider': idP}
      result = self.getSessionTokens(session)
      if not result['OK']:
        return result
      resDict[session]['Tokens'] = result['Value'] or {}
    return S_OK(resDict)

  def updateIdPSessionsInfoCache(self, idPs=None, IDs=None):
    """ Update cache with information about active session with identity provider
        Must return following structure:
          { 
            <ID>: {
              Providers: {
                <idetntity provider>: {
                  <session>: { tokens dictionary }
                }
              },
              DNs: {
                <DN>: { some metadata }
              }
            }
          }

        :param list idPs: list of identity providers that sessions need to update, if None - update all
        :param list IDs: list of IDs that need to update, if None - update all

        :return: S_OK(dict)/S_ERROR()
    """
    IdPSessionsInfo = {}
    conn = []
    if IDs:
      conn.append('ID IN ("%s") ' % ", ".join(IDs))
    if idPs:
      conn.append('Provider IN ("%s") ' % ", ".join(idPs))
    where = 'WHERE %s' % ' AND '.join(conn) if conn else ''
    result = self._query("SELECT DISTINCT ID, Provider, Session FROM `Sessions` %s" % where)
    #result = self.__getFields(session=session, conn=' AND '.join(conn))
    if not result['OK']:
      return result
    for ID, idP, session in result['Value']:
      # if (idPs and idP not in idPs) or (IDs and ID not in IDs):
      #   continue
      if ID not in IdPSessionsInfo:
        IdPSessionsInfo[ID] = {'Providers': {}, 'DNs': {}}
      if idP not in IdPSessionsInfo[ID]['Providers']:
        
      #   result = IdProviderFactory().getIdProvider(idP, sessionManager=self)
      #   if not result['OK']:
      #     return result
      #   provObj = result['Value']
      #   result = provObj.getUserProfile(session)
      #   if not result['OK']:
      #     self.log.error(result['Message'])
      #     continue
      #   userProfile = result['Value']['UsrOptns']
      #   result = self.getSessionTokens(session)
      #   if not result['OK']:
      #     return result
      #   tokens = result['Value']
      #   if not tokens:
      #     result = self.killSession(session)
      #     self.log.warn('Not found tokens for %s session, removed.' % session, result.get('Value') or result.get('Message'))
      #     continue
      #   IdPSessionsInfo[ID]['Providers'][idP] = {session: tokens}
      #   # Fill user profile
      #   for key, value in userProfile.items():
      #     if key not in IdPSessionsInfo[ID]:
      #       IdPSessionsInfo[ID][key] = value
      # else:
        result = self.getSessionTokens(session)
        if not result['OK']:
          return result
        tokens = result['Value']
        if not tokens:
          result = self.killSession(session)
          self.log.warn('Not found tokens for %s session, removed.' % session, result.get('Value') or result.get('Message'))
          continue
        IdPSessionsInfo[ID]['Providers'][idP][session] = tokens
      
    return S_OK(IdPSessionsInfo)

  def createNewSession(self, provider, session=None):
    """ Generates a state string to be used in authorizations

        :param str provider: provider
        :param str session: session number
    
        :return: S_OK(str)/S_ERROR()
    """
    if not session:
      result = self._query('SELECT Session FROM `Sessions`')
      if not result['OK']:
        return result
      allSessions = [s[0] for s in result['Value']]
      for i in range(100):
        num = ''.join(random.choice(string.ascii_letters + string.digits) for x in range(30))
        if num not in allSessions:
          session = num
          break

    if not session:
      return S_ERROR("Need to modify Session manager!")

    result = self.insertFields('Sessions', ['Session', 'Provider', 'LastAccess'],
                                           [session, provider, 'UTC_TIMESTAMP()'])
    return S_OK(session) if result['OK'] else result

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
    result = self.updateSession(session, {'Status': 'in progress', 'Comment': ''})
    if not result['OK']:
      return result
    return S_OK(url)

  def getReservedSession(self, userID, provider):
    """ Find reserved session

        :param str userID: user ID
        :param str provider: provider

        :return: S_OK(list)/S_ERROR()
    """
    reservedSessions = []
    cmd = 'SELECT Session FROM `Sessions` WHERE Status="reserved" AND'
    result = self._query('%s ID="%s" AND Provider="%s"' % (cmd, userID, provider))
    if not result['OK']:
      return result
    for data in result['Value']:
      session = data[0]
      #if re.match('^reserved_.*', session):
      reservedSessions.append(session)

    return S_OK(list(set(reservedSessions)))

  def getSessionTokens(self, session):
    """ Get tokens dict by session

        :param basestring session: session number

        :return: S_OK(dict)/S_ERROR()
    """
    return self.__getFields(["AccessToken", "ExpiresIn", "RefreshToken", "TokenType"], session=session)
  
  def getProviderBySession(self, session):
    """ Get tokens dict by session

        :param basestring session: session number

        :return: S_OK(dict)/S_ERROR()
    """
    result = self.__getFields(['Provider'], session=session)
    if not result['OK']:
      return result
    return S_OK(result['Value']['Provider'])
  
  def getStatusBySession(self, session):
    """ Get status dictionary by session id

        :param basestring session: session id

        :return: S_OK(dict)/S_ERROR()
    """
    return self.__getFields(fields=['ID', 'Session', 'Status', 'Comment', 'Provider'], session=session)

  def fetchReservedSessions(self):
    """ Fetch reserved sessions

        :return: S_OK(int)/S_ERROR()
    """
    result = self.__getFields(Status="reserved")
    if not result['OK']:
      return result
    sessionsData = result['Value']
    self.log.info('Found %s reserved sessions to fetch' % len(sessionsData))
    for i in range(0, len(sessions)):
      result = IdProviderFactory().getIdProvider(sessions[i]['Provider'])
      if result['OK']:
        providerObj = result['Value']
        result = providerObj.fetch(sessions[i])

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
      # If its reserved session
      if re.match('^reserved_.*', sessions[i]['Session']):
        continue
      if sessions[i].get('Session'):
        result = self.logOutSession(sessions[i]['Session'])
        self.log.debug(result['Message'] or result['Value'])
    return S_OK(len(sessions))

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
      result = self.getSessionTokens(session)
      if not result['OK']:
        return result
      result = providerObj.logOut(result['Value'])
    self.log.debug('%s log out:', result.get('Message') or result.get('Value'))
    return self.killSession(session)
  
  def updateSession(self, session, fieldsToUpdate=None, conn=None, condDict=None):
    """ Update session record

        :params basestring session: session id
        :param dict fieldsToUpdate: fields content that need to update
        :param basestring conn: search filter
        :param dict condDict: parameters that need add to search filter

        :return: S_OK()/S_ERROR()
    """
    self.log.verbose(session, 'session update..')
    condDict = condDict or {}
    condDict['Session'] = session
    
    fieldsToUpdate = fieldsToUpdate or {}
    fieldsToUpdate['LastAccess'] = 'UTC_TIMESTAMP()'

    # Convert seconds to datetime
    if 'ExpiresIn' in fieldsToUpdate and isinstance(fieldsToUpdate['ExpiresIn'], int):
      self.log.debug(session, 'session, convert access token live time %s seconds to date.' % fieldsToUpdate['ExpiresIn'])
      result = self._query("SELECT ADDDATE(UTC_TIMESTAMP(), INTERVAL %s SECOND)" % fieldsToUpdate['ExpiresIn'])
      if not result['OK']:
        return result
      fieldsToUpdate['ExpiresIn'] = result['Value'][0][0] if result['Value'] else 'UTC_TIMESTAMP()'
    return self.updateFields('Sessions', updateDict=fieldsToUpdate, condDict=condDict, conn=conn)
  
  def getSessionID(self, session):
    """ Get user ID by session

        :param str session: session

        :return: S_OK(str)/S_ERROR()
    """
    result = self.__getFields(['ID'], session=session)
    return S_OK(result['Value']['ID']) if result['OK'] else result

  def getSessionLifetime(self, session):
    """ Get lifetime of session

        :param str session: session number

        :return: S_OK(int)/S_ERROR() -- lifetime in a seconds
    """
    result = self.__getFields(['ExpiresIn'], session=session)
    if result['OK']:
      exp = result['Value']
      result = self._query("SELECT TIME_TO_SEC(TIMEDIFF('%s', UTC_TIMESTAMP()))" % exp)

    return result['Value'][0][0] if result['OK'] else result

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
