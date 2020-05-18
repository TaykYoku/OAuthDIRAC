""" The OAuth service provides a toolkit to authoticate throught OIDC session.
"""
from DIRAC import gLogger, S_OK, S_ERROR
from DIRAC.Core.DISET.RequestHandler import RequestHandler
from DIRAC.Core.Utilities.DictCache import DictCache
from DIRAC.Core.Utilities.ThreadScheduler import gThreadScheduler
from DIRAC.ConfigurationSystem.Client.Helpers.Registry import getUsernameForID

from OAuthDIRAC.FrameworkSystem.DB.OAuthDB import OAuthDB

__RCSID__ = "$Id$"


class OAuthManagerHandler(RequestHandler):

  gOAuthDB = None
  __IdPsIDsCache = DictCache()

  @classmethod
  def __refreshIdPsIDsCache(cls, idPs=None, IDs=None):
    """ Update information about sessions

        :param list idPs: list of identity providers that sessions need to update, if None - update all
        :param list IDs: list of IDs that need to update, if None - update all

        :return: S_OK()/S_ERROR()
    """
    result = gOAuthDB.updateIdPSessionsInfoCache(idPs=idPs, IDs=IDs)
    if not result['OK']:
      return result
    for ID, infoDict in result['Value'].items():
      cls.__IdPsIDsCache.add(ID, 3600 * 24, value=infoDict)
    return result

  @classmethod
  def initializeOAuthManagerHandler(cls, serviceInfo):
    """ Handler initialization
    """
    cls.gOAuthDB = OAuthDB()
    gThreadScheduler.addPeriodicTask(3600, gOAuthDB.cleanZombieSessions)
    gThreadScheduler.addPeriodicTask(3600 * 24, cls.__refreshIdPsIDsCache)
    return cls.__refreshIdPsIDsCache()

  types_getIdPsIDs = []

  def export_getIdPsIDs(self):
    """ Return fresh info from identity providers about users with actual sessions

        :return: S_OK(dict)/S_ERROR()
    """
    return S_OK(self.__IdPsIDsCache.getDict())

  types_submitAuthorizeFlow = [basestring]

  def export_submitAuthorizeFlow(self, providerName, session=None):
    """ Register new session and return dict with authorization url and session number
    
        :param basestring providerName: provider name
        :param basestring session: session identificator

        :return: S_OK(dict)/S_ERROR()
    """
    gLogger.notice("Request to create authority URL for '%s'." % providerName)
    result = gOAuthDB.getAuthorization(providerName, session)
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
    gLogger.notice('%s session get response "%s"' % (session, response))
    result = gOAuthDB.parseAuthResponse(response, session)
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
    return gOAuthDB.updateSession(fieldsToUpdate, session=session)

  types_killSession = [basestring]

  def export_killSession(self, session):
    """ Remove session record from DB
    
        :param basestring session: session number

        :return: S_OK()/S_ERROR()
    """
    return gOAuthDB.killSession(session)

  types_logOutSession = [basestring]

  def export_logOutSession(self, session):
    """ Remove session record from DB and logout form identity provider
    
        :param basestring session: session number

        :return: S_OK()/S_ERROR()
    """
    return gOAuthDB.logOutSession(session)

  types_getLinkBySession = [basestring]

  def export_getLinkBySession(self, session):
    """ Get authorization URL by session number

        :param basestring session: session number

        :return: S_OK(basestring)/S_ERROR()
    """
    return gOAuthDB.getLinkBySession(session)
  
  types_getSessionStatus = [basestring]

  def export_getSessionStatus(self, session):
    """ Listen DB to get status of authorization session

        :param basestring session: session number

        :return: S_OK(dict)/S_ERROR()
    """
    result = gOAuthDB.getStatusBySession(session)
    if not result['OK']:
      return result
    if result['Value']['Status'] == 'authed':
      user = getUsernameForID(result['Value']['ID'])
      if user['OK']:
        result['Value']['UserName'] = user['Value']
    return result
  
  types_getSessionTokens = [basestring]

  def export_getSessionTokens(self, session):
    """ Get tokens by session number

        :param basestring session: session number

        :return: S_OK(dict)/S_ERROR()
    """
    return gOAuthDB.getTokensBySession(session)

  @staticmethod
  def __cleanOAuthDB():
    """ Check OAuthDB for zombie sessions and clean

        :return: S_OK()/S_ERROR()
    """
    gLogger.notice("Killing zombie sessions")
    result = gOAuthDB.cleanZombieSessions()
    if not result['OK']:
      gLogger.error(result['Message'])
      return result
    gLogger.notice("Cleaning is done!")
    return S_OK()
