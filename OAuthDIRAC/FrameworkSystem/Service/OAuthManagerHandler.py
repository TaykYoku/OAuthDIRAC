""" The OAuth service provides a toolkit to authoticate throught OIDC session.
"""
import re

from DIRAC import gLogger, S_OK, S_ERROR
from DIRAC.Core.DISET.RequestHandler import RequestHandler
from DIRAC.Core.Utilities import ThreadSafe
from DIRAC.Core.Utilities.DictCache import DictCache
from DIRAC.Core.Utilities.ThreadScheduler import gThreadScheduler
from DIRAC.ConfigurationSystem.Client.Helpers.Registry import getUsernameForID, getIDsForUsername

from OAuthDIRAC.FrameworkSystem.DB.OAuthDB import OAuthDB

__RCSID__ = "$Id$"


gIdPsCacheSync = ThreadSafe.Synchronizer()


class OAuthManagerHandler(RequestHandler):
  """ Authentication manager

      Contain __IdPsCache cache, with next structure:
      {
        <ID1>: {
          Providers: {
            <identity provider>: {
              <sessions number1>: { <tokens> },
              <sessions number2>: { ... }
          },
          DNs: {
            <DN1>: {
              ProxyProvider: [ <proxy providers> ],
              VOMSRoles: [ <VOMSRoles> ],
              ...
            },
            <DN2>: { ... },
          }
        },
        <ID2>: { ... },
      }
  """

  __db = None
  __IdPsCache = DictCache()

  @classmethod
  @gIdPsCacheSync
  def __refreshIdPsIDsCache(cls, idPs=None, IDs=None, idDict=None):
    """ Update information about sessions

        :param list idPs: list of identity providers that sessions need to update, if None - update all
        :param list IDs: list of IDs that need to update, if None - update all
        :param dict idDict: information that need to update

        :return: S_OK()/S_ERROR()
    """
    if not idDict:
      result = cls.__db.updateIdPSessionsInfoCache(idPs=idPs, IDs=IDs)
      if not result['OK']:
        return result
      idDict = result['Value']
    for oid, data in idDict.items():
      cls.__IdPsCache.add(oid, 3600 * 24, value=data)
    return result

  @classmethod
  def initializeHandler(cls, serviceInfo):
    """ Handler initialization
    """
    cls.__db = OAuthDB()
    gThreadScheduler.addPeriodicTask(3600, cls.__db.cleanZombieSessions)
    gThreadScheduler.addPeriodicTask(3600 * 24, cls.__refreshIdPsIDsCache)
    #return cls.__refreshIdPsIDsCache()
    return S_OK()

  @gIdPsCacheSync
  def __checkAuth(self, session=None):
    """ Check authorization rules

        :param str session: session number

        :return: S_OK(list)/S_ERROR()
    """
    credDict = self.getRemoteCredentials()
    if credDict['group'] == 'hosts':
      if 'TrustedHost' in credDict['properties']:
        return S_OK()
      return S_ERROR('To access host must be "TrustedHost".')
    
    userIDs = getIDsForUsername(credDict["username"])
    
    if session:
      for r in [True, False]:
        idpDict = self.__IdPsCache.getDict()
        for oid in userIDs:
          if oid in idpDict:
            for prov in idpDict[oid].get('Provisers', []):
              if session in idpDict[oid][prov]:
                return S_OK()
        if r:
          result = self.__refreshIdPsIDsCache(IDs=userIDs)
          if not result['OK']:
            return result
      return S_ERROR('%s session not found for %s user.' % (session, credDict['username']))

    return S_OK(userIDs)

  types_getIdPsIDs = []
  @gIdPsCacheSync
  def export_getIdPsIDs(self):
    """ Return fresh info from identity providers about users with actual sessions

        :return: S_OK(dict)/S_ERROR()
    """
    res = self.__checkAuth()
    if not res['OK']:
      return res
    if not res["Value"]:
      return S_OK(self.__IdPsCache.getDict())
    
    data = {}
    for oid in result['Value']:
      idDict = self.__IdPsCache.get(oid)
      if idDict:
        data[oid] = idDict
    return S_OK(data)

  types_submitAuthorizeFlow = [basestring]

  def export_submitAuthorizeFlow(self, providerName, session=None):
    """ Register new session and return dict with authorization url and session number
    
        :param basestring providerName: provider name
        :param basestring session: session identificator

        :return: S_OK(dict)/S_ERROR()
    """
    if session:
      res = self.__checkAuth(session)
      if not res['OK']:
        return res
    
    gLogger.info('Get authorization for %s.' % providerName, 'Session: %s' % session if session else '')
    result = IdProviderFactory().getIdProvider(providerName, sessionMananger=self.__db)
    if not result['OK']:
      return result
    provObj = result['Value']
    if session:
      result = provObj.checkStatus(session=session)
      if not result['OK']:
        return result
      if result['Value']['Status'] == 'ready':
        return result
    
    result = provObj.submitNewSession()
    if not result['OK']:
      return S_ERROR('Cannot create authority request URL:', result['Message'])
    session = result['Value']
    return S_OK({'Status': 'needToAuth', 'URL': '%s/auth/%s' % (getAuthAPI().strip('/'), session)})
  
  types_parseAuthResponse = [dict, basestring]

  def export_parseAuthResponse(self, response, session):
    """ Fill session by user profile, tokens, comment, OIDC authorize status, etc.
        Prepare dict with user parameters, if DN is absent there try to get it.
        Create new or modify existend DIRAC user and store the session

        :param dict response: authorization response
        :param basestring session: session number

        :return: S_OK(dict)/S_ERROR()
    """
    res = self.__checkAuth(session)
    if not res['OK']:
      return res

    result = self.__parseAuthResponse(response, session)
    if not result['OK']:
      cansel = self.__db.updateSession({'Status': 'failed', 'Comment': result['Message']},
                                       session=session)
      return result if cansel['OK'] else cansel

    if result['Value']['Status'] in ['authed', 'redirect']:
      refresh = self.__refreshIdPsIDsCache(IDs=[result['Value']['UserProfile']['UsrOptns']['ID']])
      if not refresh['OK']:
        return refresh
      result['Value']['sessionIDDict'] = refresh['Value']
    return result
  
  def __parseAuthResponse(self, response, session):
    """ Fill session by user profile, tokens, comment, OIDC authorize status, etc.
        Prepare dict with user parameters, if DN is absent there try to get it.
        Create new or modify existend DIRAC user and store the session

        :param dict response: authorization response
        :param basestring session: session number

        :return: S_OK(dict)/S_ERROR()
    """
    result = self.__db.updateSession({'Status': 'finishing'}, session=session)
    if not result['OK']:
      return result

    # Search provider by session
    result = self.__db.getProviderBySession(session)
    if not result['OK']:
      return result
    provider = result['Value']
    result = IdProviderFactory().getIdProvider(provider, sessionMananger=self.__db)
    if not result['OK']:
      return result
    provObj = result['Value']

    # Parsing response
    result = provObj.parseAuthResponse(response)
    if not result['OK']:
      return result
    parseDict = result['Value']

    status = 'authed'
    comment = ''

    # Is ID registred?
    userID = parseDict['UsrOptns']['ID']
    result = getUsernameForID(userID)
    if result['OK']:
      # This session to reserve?
      if re.match('^reserved_.*', session):
        # Update status in source session
        result = self.__db.updateSession({'Status': status},
                                          session=session.replace('reserved_', ''))
        if not result['OK']:
          return result
        
        # Update status in current session
        result = self.__db.updateSession({'Status': 'reserved'}, session=session)
        if not result['OK']:
          return result

      else:
        # If not, search reserved session
        result = self.__db.getReservedSession(userID, provider)
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

          result = self.__db.updateSession({'Status': status}, session=session)
          if not result['OK']:
            return result

    else:

      status = 'authed and notify'

      result = self.__registerNewUser(provider, parseDict)
      if not result['OK']:
        return result
    
    return S_OK({'Status': status, 'Comment': comment, 'UserProfile': parseDict})


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

  types_updateSession = [basestring, dict]

  def export_updateSession(self, session, fieldsToUpdate):
    """ Update session record

        :param basestring session: session number
        :param dict fieldsToUpdate: fields content that need to update

        :return: S_OK()/S_ERROR()
    """
    res = self.__checkAuth(session)
    return self.__db.updateSession(fieldsToUpdate, session=session) if res['OK'] else res

  types_killSession = [basestring]

  def export_killSession(self, session):
    """ Remove session record from DB
    
        :param basestring session: session number

        :return: S_OK()/S_ERROR()
    """
    res = self.__checkAuth(session)
    return self.__db.killSession(session) if res['OK'] else res

  types_logOutSession = [basestring]

  def export_logOutSession(self, session):
    """ Remove session record from DB and logout form identity provider
    
        :param basestring session: session number

        :return: S_OK()/S_ERROR()
    """
    res = self.__checkAuth(session)
    return self.__db.logOutSession(session) if res['OK'] else res

  types_getLinkBySession = [basestring]

  def export_getLinkBySession(self, session):
    """ Get authorization URL by session number

        :param basestring session: session number

        :return: S_OK(basestring)/S_ERROR()
    """
    res = self.__checkAuth(session)
    return self.__db.getLinkBySession(session) if res['OK'] else res
  
  types_getSessionStatus = [basestring]

  def export_getSessionStatus(self, session):
    """ Listen DB to get status of authorization session

        :param basestring session: session number

        :return: S_OK(dict)/S_ERROR()
    """
    res = self.__checkAuth(session)
    return self.__db.getStatusBySession(session) if res['OK'] else res
    # if not result['OK']:
    #   return result
    # if result['Value']['Status'] == 'authed':
    #   user = getUsernameForID(result['Value']['ID'])
    #   if user['OK']:
    #     result['Value']['UserName'] = user['Value']
    # return result
  
  types_getSessionTokens = [basestring]

  def export_getSessionTokens(self, session):
    """ Get tokens by session number

        :param basestring session: session number

        :return: S_OK(dict)/S_ERROR()
    """
    res = self.__checkAuth(session)
    return self.__db.getTokensBySession(session) if res['OK'] else res

  @staticmethod
  def __cleanOAuthDB():
    """ Check OAuthDB for zombie sessions and clean

        :return: S_OK()/S_ERROR()
    """
    gLogger.notice("Killing zombie sessions")
    result = self.__db.cleanZombieSessions()
    if not result['OK']:
      gLogger.error(result['Message'])
      return result
    gLogger.notice("Cleaning is done!")
    return S_OK()
