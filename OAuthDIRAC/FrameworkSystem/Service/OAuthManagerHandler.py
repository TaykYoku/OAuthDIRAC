""" The OAuth service provides a toolkit to authoticate throught OIDC session.
"""
from DIRAC import gLogger, S_OK, S_ERROR
from DIRAC.Core.DISET.RequestHandler import RequestHandler
from DIRAC.Core.Utilities.DictCache import DictCache
from DIRAC.Core.Utilities.ThreadScheduler import gThreadScheduler
from DIRAC.ConfigurationSystem.Client.Helpers.Registry import getUsernameForID, getIDsForUsername

from OAuthDIRAC.FrameworkSystem.DB.OAuthDB import OAuthDB

__RCSID__ = "$Id$"


class OAuthManagerHandler(RequestHandler):
  """ Authentication manager

      Contain __IdPsIDsCache cache, with next structure:
      {
        <ID1>: {
          Providers: [ <identity providers> ],
          <identity provider>: [
            {
              <sessions number>: { <tokens> }
            },
            { ... }
          ],
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

  __oauthDB = None
  __IdPsIDsCache = DictCache()

  @classmethod
  def __refreshIdPsIDsCache(cls, idPs=None, IDs=None):
    """ Update information about sessions

        :param list idPs: list of identity providers that sessions need to update, if None - update all
        :param list IDs: list of IDs that need to update, if None - update all

        :return: S_OK()/S_ERROR()
    """
    result = cls.__oauthDB.updateIdPSessionsInfoCache(idPs=idPs, IDs=IDs)
    if not result['OK']:
      return result
    for ID, infoDict in result['Value'].items():
      cls.__IdPsIDsCache.add(ID, 3600 * 24, value=infoDict)
    return result

  @classmethod
  def initializeHandler(cls, serviceInfo):
    """ Handler initialization
    """
    cls.__oauthDB = OAuthDB()
    gThreadScheduler.addPeriodicTask(3600, cls.__oauthDB.cleanZombieSessions)
    gThreadScheduler.addPeriodicTask(3600 * 24, cls.__refreshIdPsIDsCache)
    return cls.__refreshIdPsIDsCache()

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

    idpDict = self.__IdPsIDsCache.getDict()

    for oid in userIDs:
      if oid not in idpDict:
        userIDs.remove(oid)
      elif session:
        for prov in idpDict[oid].get('Provisers', []):
          if session in idpDict[oid][prov]:
            return S_OK()
        return S_ERROR('%s session not found for %s user.' % (session, credDict['username']))

    return S_OK(userIDs)

  types_getIdPsIDs = []

  def export_getIdPsIDs(self):
    """ Return fresh info from identity providers about users with actual sessions

        :return: S_OK(dict)/S_ERROR()
    """
    res = self.__checkAuth()
    if not res['OK']:
      return res
    if not res["Value"]:
      return S_OK(self.__IdPsIDsCache.getDict())
    
    data = {}
    for oid in result['Value']:
      idDict = self.__IdPsIDsCache.get(oid)
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
    gLogger.notice("Request to create authority URL for '%s'." % providerName)
    result = self.__oauthDB.getAuthorization(providerName, session=session)
    if not result['OK']:
      return S_ERROR('Cannot create authority request URL:', result['Message'])
    return result
  
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
    gLogger.notice('%s session get response "%s"' % (session, response))
    result = self.__oauthDB.parseAuthResponse(response, session)
    if not result['OK']:
      return result
    if result['Value']['Status'] in ['authed', 'redirect']:
      refresh = self.__refreshIdPsIDsCache(idPs=None, IDs=[result['Value']['UserProfile']['UsrOptns']['ID']])
      if not refresh['OK']:
        return refresh
      result['Value']['sessionIDDict'] = refresh['Value']
    return result

  types_updateSession = [basestring, dict]

  def export_updateSession(self, session, fieldsToUpdate):
    """ Update session record

        :param basestring session: session number
        :param dict fieldsToUpdate: fields content that need to update

        :return: S_OK()/S_ERROR()
    """
    res = self.__checkAuth(session)
    return self.__oauthDB.updateSession(fieldsToUpdate, session=session) if res['OK'] else res

  types_killSession = [basestring]

  def export_killSession(self, session):
    """ Remove session record from DB
    
        :param basestring session: session number

        :return: S_OK()/S_ERROR()
    """
    res = self.__checkAuth(session)
    return self.__oauthDB.killSession(session) if res['OK'] else res

  types_logOutSession = [basestring]

  def export_logOutSession(self, session):
    """ Remove session record from DB and logout form identity provider
    
        :param basestring session: session number

        :return: S_OK()/S_ERROR()
    """
    res = self.__checkAuth(session)
    return self.__oauthDB.logOutSession(session) if res['OK'] else res

  types_getLinkBySession = [basestring]

  def export_getLinkBySession(self, session):
    """ Get authorization URL by session number

        :param basestring session: session number

        :return: S_OK(basestring)/S_ERROR()
    """
    res = self.__checkAuth(session)
    return self.__oauthDB.getLinkBySession(session) if res['OK'] else res
  
  types_getSessionStatus = [basestring]

  def export_getSessionStatus(self, session):
    """ Listen DB to get status of authorization session

        :param basestring session: session number

        :return: S_OK(dict)/S_ERROR()
    """
    res = self.__checkAuth(session)
    return self.__oauthDB.getStatusBySession(session) if res['OK'] else res
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
    return self.__oauthDB.getTokensBySession(session) if res['OK'] else res

  @staticmethod
  def __cleanOAuthDB():
    """ Check OAuthDB for zombie sessions and clean

        :return: S_OK()/S_ERROR()
    """
    gLogger.notice("Killing zombie sessions")
    result = self.__oauthDB.cleanZombieSessions()
    if not result['OK']:
      gLogger.error(result['Message'])
      return result
    gLogger.notice("Cleaning is done!")
    return S_OK()
