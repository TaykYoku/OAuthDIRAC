""" The OAuth service provides a toolkit to authoticate throught OIDC session.
"""
import re

from DIRAC import gLogger, S_OK, S_ERROR
from DIRAC.Core.DISET.RequestHandler import RequestHandler
from DIRAC.Core.Utilities import ThreadSafe
from DIRAC.Core.Utilities.DictCache import DictCache
from DIRAC.Core.Utilities.ThreadScheduler import gThreadScheduler
from DIRAC.ConfigurationSystem.Client.Helpers.Registry import getUsernameForID, getIDsForUsername
from DIRAC.Resources.IdProvider.IdProviderFactory import IdProviderFactory
from DIRAC.ConfigurationSystem.Client.Utilities import getAuthAPI

from OAuthDIRAC.FrameworkSystem.DB.OAuthDB import OAuthDB

__RCSID__ = "$Id$"

# Session statuses

SESSION_READY = "ready"
SESSION_FAILED = "failed"
SESSION_REDIRECT = "redirect"
SESSION_PREPARED = "prepared"
SESSION_PROGRESS = "in progress"
SESSION_NEEDAUTH = "needToAuth"
SESSION_FINISHING = "finishing"


gCacheSessions = ThreadSafe.Synchronizer()
gCacheProfiles = ThreadSafe.Synchronizer()


class OAuthManagerHandler(RequestHandler):
  """ Authentication manager

      __cacheSessions cache, with next structure:
      {
        <session1>: {
          ID: ..,
          Provider: ..,
          Tokens: { <tokens> }
        },
        <session2>: { ... }
      }

      __cacheProfiles cache, with next structure:
      {
        <ID1>: {
          Provider: ..,
          Sessions: ..,
          DNs: {
            <DN1>: {
              ProxyProvider: [ <proxy providers> ],
              VOMSRoles: [ <VOMSRoles> ],
              ...
            },
            <DN2>: { ... },
          }
        },
        <ID2>: { ... }
      }
  """

  __db = None
  __cacheSessions = DictCache()
  __cacheProfiles = DictCache()

  @classmethod
  @gCacheProfiles
  def __getProfiles(cls, userID=None):
    """ Get cache information

        :param str userID: user ID

        :return: dict
    """
    if userID:
      return cls.__cacheProfiles.get(userID)
    return cls.__cacheProfiles.getDict()

  @classmethod
  @gCacheProfiles
  def __addProfiles(cls, data, time=3600 * 24):
    """ Caching information

        :param dict data: ID information data
        :param int time: lifetime
    """
    if data:
      for oid, info in data.items():
        cls.__cacheProfiles.add(oid, time, value=info)

  @classmethod
  @gCacheSessions
  def __getSessions(cls, session=None):
    """ Get cache information

        :param str userID: user ID

        :return: dict
    """
    if not session:
      return cls.__cacheSessions.getDict()
    return cls.__cacheSessions.get(session) or {}

  @classmethod
  @gCacheSessions
  def __addSessions(cls, data, time=3600 * 24):
    """ Caching information

        :param dict data: ID information data
        :param int time: lifetime
    """
    if data:
      for oid, info in data.items():
        cls.__cacheSessions.add(oid, time, value=info)

  @classmethod
  def __updateSessionsFromDB(cls, idPs=None, IDs=None, session=None):
    """ Update information about sessions

        :param list idPs: list of identity providers that sessions need to update, if None - update all
        :param list IDs: list of IDs that need to update, if None - update all
        :param str session: session to update

        :return: S_OK()/S_ERROR()
    """
    result = cls.__db.getSessionsInfo(idPs=idPs, IDs=IDs, session=session)
    if result['OK']:
      cls.__addSessions(result['Value'])
    return result

  @classmethod
  def __refreshReservedSessions(cls):
    """ Refresh reserved sessions
    """
    result = cls.__db.getReservedSessions()
    if not result['OK']:
      return result
    freshDict = {}
    for data in result['Value']:
      session = data['Session']
      provider = data['Provider']
      if provider not in freshDict:
        freshDict[provider] = []
      freshDict[provider] = list(set(freshDict[provider] + [session]))
    
    for idP, sessions in freshDict.items():
      result = IdProviderFactory().getIdProvider(providerName, sessionManager=cls.__db)
      if result['OK']:
        provObj = result['Value']
        result = provObj.checkStatus(session=session)
        if result['OK']:
          status = result['Value']['Status']
          if status == 'ready':
            cls.log.verbose(session, 'session refreshed!')
            continue
          result = S_ERROR('"%s" status is not "ready".' % status)  
      if not result['OK']:
        cls.log.error('%s session not refreshed:' % session, result['Message'])

  @staticmethod
  def __cleanOAuthDB():
    """ Check OAuthDB for zombie sessions and clean

        :return: S_OK()/S_ERROR()
    """
    cls.log.info("Kill zombie sessions")
    SESSION_READY = "ready"
    SESSION_FAILED = "failed"
    SESSION_RESERVED = "reserved"
    SESSION_PREPARED = "prepared"
    SESSION_PROGRESS = "in progress"
    SESSION_NEEDAUTH = "needToAuth"
    SESSION_FINISHING = "finishing"
    # "prepared", "in progress", 15 * 60
    #
    result = self.__db.cleanZombieSessions()
    if not result['OK']:
      gLogger.error(result['Message'])
      return result
    gLogger.notice("Cleaning is done!")
    return S_OK()

  @classmethod
  def initializeHandler(cls, serviceInfo):
    """ Handler initialization
    """
    cls.__db = OAuthDB()
    cls.__updateSessionsFromDB()
    gThreadScheduler.addPeriodicTask(15 * 60, cls.__refreshReservedSessions)
    gThreadScheduler.addPeriodicTask(3600, cls.__db.cleanZombieSessions)
    gThreadScheduler.addPeriodicTask(3600, cls.__updateSessionsFromDB) # TODO: update all
    return S_OK()

  def __checkAuth(self, session=None):
    """ Check authorization rules

        :param str session: session number

        :return: S_OK(tuple)/S_ERROR() -- tuple contain username and IDs
    """
    credDict = self.getRemoteCredentials()
    if credDict['group'] == 'hosts':
      if 'TrustedHost' not in credDict['properties']:
        return S_OK((None, 'all'))
      return S_ERROR('To access host must be "TrustedHost".')
    
    userIDs = getIDsForUsername(credDict["username"])
    if not userIDs:
      return S_ERROR('No registred IDs for %s user.' % credDict["username"])
    
    if session:
      result = self.__db.getSessionID(session)
      if not result['OK']:
        return result
      sID = result['Value']
      if sID not in userIDs:
        return S_ERROR('%s user not have access to %s ID information.' % (user, sID))

    return S_OK((credDict["username"], userIDs))

  types_getIdProfiles = []

  def export_getIdProfiles(self, userID=None):
    """ Return fresh info from identity providers about users with actual sessions

        :params: str userID: user ID

        :return: S_OK(dict)/S_ERROR()
    """
    result = self.__checkAuth()
    if not result['OK']:
      return result
    user, ids = result["Value"]

    # For host
    if ids == 'all':
      return S_OK(self.__getProfiles(userID=userID))

    # For user
    if userID:
      if userID not in ids:
        return S_ERROR('%s user not have access to %s ID information.' % (user, userID))
      return self.__getProfiles(userID=userID)

    data = {}
    for uid in ids:
      idDict = self.__getProfiles(userID=uid)
      if idDict:
        data[uid] = idDict

    return S_OK(data)
  
  types_getSessionsInfo = []

  def export_getSessionsInfo(self, session=None):
    """ Return fresh info from identity providers about users with actual sessions

        :param str session: session

        :return: S_OK(dict)/S_ERROR()
    """
    result = self.__checkAuth()
    if not result['OK']:
      return result
    user, ids = result["Value"]
    
    sDict = self.__getSessions(session=session)
    
    # For host
    if ids == "all":
      return S_OK(sDict)
    
    # For user
    if session:
      if sDict.get(session) and sDict[session]['ID'] not in ids:
        return S_ERROR('%s user not have access to %s ID information.' % (user, userID))
      return S_OK(sDict.get(session))

    data = {}
    for session, data in sDict.items():
      if data['ID'] in ids:
        data[session] = data

    return S_OK(data)

  types_submitAuthorizeFlow = [str]

  def export_submitAuthorizeFlow(self, providerName, session=None):
    """ Register new session and return dict with authorization url and session number
    
        :param str providerName: provider name
        :param str session: session identificator

        :return: S_OK(dict)/S_ERROR()
    """
    gLogger.info('Get authorization for %s.' % providerName, 'Session: %s' % session if session else '')
    
    if self.__db.isReservedSession(session):
      return S_ERROR('You cannot submit authorization flow with reserved session!')

    result = IdProviderFactory().getIdProvider(providerName, sessionManager=self.__db)
    if not result['OK']:
      return result
    provObj = result['Value']
    if session:
      result = provObj.checkStatus(session=session)
      if not result['OK']:
        return result
      if result['Value']['Status'] == 'ready':
        user = getUsernameForID(self.__getSessions(session).get('ID'))
        if user['OK']:
          result['Value']['UserName'] = user['Value']
        return result if user['OK'] else user

    result = provObj.submitNewSession()
    if not result['OK']:
      return S_ERROR('Cannot create authority request URL:', result['Message'])
    session = result['Value']
    return S_OK({'Status': 'needToAuth', 'Session': session,
                 'URL': '%s/auth/%s' % (getAuthAPI().strip('/'), session)})
  
  types_parseAuthResponse = [dict, str]

  def export_parseAuthResponse(self, response, session):
    """ Fill session by user profile, tokens, comment, OIDC authorize status, etc.
        Prepare dict with user parameters, if DN is absent there try to get it.
        Create new or modify existend DIRAC user and store the session

        :param dict response: authorization response
        :param str session: session number

        :return: S_OK(dict)/S_ERROR()
    """
    result = self.__db.getSessionStatus(session)
    if result['OK']:
      if result['Value']['Status'] not in ['prepared', 'in progress']:
        return S_ERROR('The current session has already been submitted.')
    
      result = self.__db.updateSession(session, {'Status': 'finishing'})
      if result['OK']:
        result = self.__parseAuthResponse(response, session)
    
    if not result['OK']:
      cansel = self.__db.updateSession(session, {'Status': 'failed', 'Comment': result['Message']})
      return result if cansel['OK'] else cansel

    responseData = result['Value']
    if responseData['Status'] in ['authed', 'redirect']:
      # Cached data
      provider = responseData['Provider']
      profile = responseData['UserProfile']['UsrOptns']
      cacheData = self.__getProfiles(userID=profile['ID']) or {}
      cacheData['Provider'] = provider
      cacheData['DNs'] = profile['DNs']
      cacheData['Sessions'] = list(set(cacheData.get('Sessions', []) + [session]))
      self.__addProfiles({profile['ID']: cacheData})
      result = self.__updateSessionsFromDB(session=session)
      if not result['OK']:
        return result
      responseData['upProfile'] = {profile['ID']: cacheData}
      responseData['upSession'] = result['Value']

    return S_OK(responseData)
  
  def __parseAuthResponse(self, response, session):
    """ Fill session by user profile, tokens, comment, OIDC authorize status, etc.
        Prepare dict with user parameters, if DN is absent there try to get it.
        Create new or modify existend DIRAC user and store the session

        :param dict response: authorization response
        :param str session: session number

        :return: S_OK(dict)/S_ERROR()
    """
    # Search provider by session
    result = self.__db.getSessionProvider(session)
    if not result['OK']:
      return result
    provider = result['Value']
    result = IdProviderFactory().getIdProvider(provider, sessionManager=self.__db)
    if not result['OK']:
      return result
    provObj = result['Value']

    # Parsing response
    result = provObj.parseAuthResponse(response, session)
    if not result['OK']:
      return result
    parseDict = result['Value']

    status = 'authed'
    comment = ''

    # Is ID registred?
    userID = parseDict['UsrOptns']['ID']
    result = getUsernameForID(userID)
    if not result['OK']:
      status = 'authed and notify'

      result = self.__registerNewUser(provider, parseDict)
      if not result['OK']:
        return result
    
    else:
      # This session to reserve?
      if not self.__db.isReservedSession(session):
        # If not, search reserved session
        result = self.__db.getReservedSessions([userID], [provider])
        if not result['OK']:
          return result
        
        if not result['Value']:
          # If no found reserved session, submit second flow to create it
          result = provObj.submitNewSession(session='reserved_%s' % session)
          if not result['OK']:
            return result
          session = result['Value']

          status = 'redirect'
          comment = '%s/auth/%s' % (getAuthAPI().strip('/'), session)

      else:
        # Update status in source session
        result = self.__db.updateSession(session.replace('reserved_', ''), {'Status': status})
        if not result['OK']:
          return result

    # Update status in current session
    result = self.__db.updateSession(session, {'Status': status})
    if not result['OK']:
      return result
    
    return S_OK({'Status': status, 'Comment': comment, 'UserProfile': parseDict, 'Provider': provider})

  def __registerNewUser(self, parseDict):
    """ Register new user

        :param str provider: provider
        :param dict parseDict: user information dictionary

        :return: S_OK()/S_ERROR()
    """
    from DIRAC.FrameworkSystem.Client.NotificationClient import NotificationClient

    mail = {}
    mail['subject'] = "[SessionManager] User %s to be added." % parseDict['username']
    mail['body'] = 'User %s was authenticated by ' % parseDict['UsrOptns']['FullName']
    mail['body'] += provider
    mail['body'] +=   "\n\nAuto updating of the user database is not allowed."
    mail['body'] += " New user %s to be added," % parseDict['username']
    mail['body'] += "with the following information:\n"
    mail['body'] += "\nUser name: %s\n" % parseDict['username']
    mail['body'] += "\nUser profile:\n%s" % pprint.pformat(parseDict['UsrOptns'])
    mail['body'] += "\n\n------"
    mail['body'] += "\n This is a notification from the DIRAC OAuthManager service, please do not reply.\n"
    for addresses in getEmailsForGroup('dirac_admin'):
      result = NotificationClient().sendMail(addresses, mail['subject'], mail['body'], localAttempt=False)
      if not result['OK']:
        self.log.error(session, 'session error: %s' % result['Message'])
    if result['OK']:
      self.log.info("%s session, mails to admins:", result['Value'])
    return result

  types_updateSession = [str, dict]

  def export_updateSession(self, session, fieldsToUpdate):
    """ Update session record

        :param str session: session number
        :param dict fieldsToUpdate: fields content that need to update

        :return: S_OK()/S_ERROR()
    """
    res = self.__checkAuth(session)
    return self.__db.updateSession(session, fieldsToUpdate) if res['OK'] else res

  types_killSession = [str]

  def export_killSession(self, session):
    """ Remove session record from DB
    
        :param str session: session number

        :return: S_OK()/S_ERROR()
    """
    res = self.__checkAuth(session)
    return self.__db.killSession(session) if res['OK'] else res

  types_logOutSession = [str]

  def export_logOutSession(self, session):
    """ Remove session record from DB and logout form identity provider
    
        :param str session: session number

        :return: S_OK()/S_ERROR()
    """
    result = self.__checkAuth(session)
    if not result['OK']:
      return result

    result = self.__db.getSessionProvider(session)
    if result['OK']:
      provider = result['Value']
      result = IdProviderFactory().getIdProvider(provider, sessionManager=self.__db)
      if result['OK']:
        provObj = result['Value']
        result = provObj.logOut(session)
    if not result['OK']:
      self.log.error(result['Message'])
    return self.__db.killSession(session)

  types_getSessionAuthLink = [str]

  def export_getSessionAuthLink(self, session):
    """ Get authorization URL by session number

        :param str session: session number

        :return: S_OK(str)/S_ERROR()
    """
    return self.__db.getSessionAuthLink(session)
  
  types_getSessionStatus = [str]

  def export_getSessionStatus(self, session):
    """ Listen DB to get status of authorization session

        :param str session: session number

        :return: S_OK(dict)/S_ERROR()
    """
    result = self.__db.getSessionStatus(session)
    if result['OK']:
      if result['Value']['Status'] == 'authed':
        user = getUsernameForID(result['Value']['ID'])
        if user['OK']:
          result['Value']['UserName'] = user['Value']
    return result
  
  types_getSessionTokens = [str]

  def export_getSessionTokens(self, session):
    """ Get tokens by session number

        :param str session: session number

        :return: S_OK(dict)/S_ERROR()
    """
    res = self.__checkAuth(session)
    return self.__db.getSessionTokens(session) if res['OK'] else res
