""" The OAuth service provides a toolkit to authoticate throught OIDC session.
"""
import time

from DIRAC import gConfig, gLogger, S_OK, S_ERROR
from DIRAC.Core.DISET.RequestHandler import RequestHandler
from DIRAC.Core.Utilities.ThreadScheduler import gThreadScheduler
from DIRAC.FrameworkSystem.Client.ProxyManagerClient import gProxyManager
from DIRAC.ConfigurationSystem.Client.Helpers import Registry

from OAuthDIRAC.FrameworkSystem.DB.OAuthDB import OAuthDB

__RCSID__ = "$Id$"

gOAuthDB = None


def initializeOAuthManagerHandler(serviceInfo):
    """ Handler initialization
    """
    global gOAuthDB
    gOAuthDB = OAuthDB()
    result = gThreadScheduler.addPeriodicTask(3600, gOAuthDB.cleanZombieSessions)
    return S_OK()


class OAuthManagerHandler(RequestHandler):

  @classmethod
  def initializeOAuthManagerHandler(cls, serviceInfo):
    """ Handler initialization
    """
    return S_OK()

  def initialize(self):
    """ Response initialization
    """

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
      return S_ERROR('Cannot create authority request URL.')
    return result

  types_checkToken = [basestring]
  # FIXME: its needed?
  def export_checkToken(self, token):
    """ Check status of tokens, refresh and back dict.

        :param basestring token: access token

        :return: S_OK(dict)/S_ERROR()
    """
    gLogger.notice("Check token %s." % token)
    return gOAuthDB.fetchToken(accessToken=token)

  types_getSessionDict = [basestring, dict]

  def export_getSessionDict(self, conn, connDict):
    """ Get username by session number

        :param basestring conn: search filter
        :param dict connDict: parameters that need add to search filter

        :return: S_OK(list(dict))/S_ERROR()
    """
    return gOAuthDB.getSessionDict(conn, connDict)

  types_updateSession = [dict, dict]

  def export_updateSession(self, fieldsToUpdate, condDict):
    """ Update session record

        :param dict fieldsToUpdate: fields content that need to update
        :param dict condDict: parameters that need add to search filter

        :return: S_OK()/S_ERROR()
    """
    return gOAuthDB.updateSession(fieldsToUpdate, condDict=condDict)

  types_getUsrnameForState = [basestring]

  def export_getUsrnameForState(self, state):
    """ Get username by session number

        :param basestring state: session number

        :return: S_OK(dict)/S_ERROR()
    """
    return gOAuthDB.getUsrnameForState(state)

  types_killState = [basestring]

  def export_killState(self, state):
    """ Remove session
    
        :param basestring state: session number

        :return: S_OK()/S_ERROR()
    """
    return gOAuthDB.killSession(state)

  types_getLinkByState = [basestring]

  def export_getLinkByState(self, state):
    """ Get authorization URL by session number

        :param basestring state: session number

        :return: S_OK(basestring)/S_ERROR()
    """
    return gOAuthDB.getLinkByState(state)
  
  types_getSessionStatus = [basestring]

  def export_getSessionStatus(self, session):
    """ Listen DB to get status of auth and proxy if needed
    """
    return gOAuthDB.getStatusByState(session)

  types_waitStateResponse = [basestring, int]

  def export_waitStateResponse(self, session, timeOut):
    """ Listen DB to get status of auth and proxy if needed

        :param basestring session: session number
        :param int timeOut: time in a seconds needed to wait result

        :return: S_OK(dict)/S_ERROR
    """
    timeOut = timeOut > 300 and 300 or timeOut
    gLogger.notice(session, "session, waiting authorization status")
    start = time.time()
    for _i in range(int(timeOut // 5)):
      result = gOAuthDB.getStatusByState(session)
      time.sleep(5)
      if (time.time() - start) > timeOut:
        gOAuthDB.killSession(session)
        return S_ERROR('Timeout')
      gLogger.verbose('%s session' % session, result['Value']['Status'])
      if result['OK'] and result['Value']['Status'] in ['prepared', 'in progress']:
        continue
      return result

  types_parseAuthResponse = [dict, basestring]

  def export_parseAuthResponse(self, response, state):
    """ Fill session by user profile, tokens, comment, OIDC authorize status, etc.
        Prepare dict with user parameters, if DN is absent there try to get it.
        Create new or modify existend DIRAC user and store the session

        :param dict response: authorization response
        :param basestring state: session number

        :return: S_OK(dict)/S_ERROR
    """
    gLogger.notice('%s session get response "%s"' % (state, response))
    return gOAuthDB.parseAuthResponse(response, state)

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
