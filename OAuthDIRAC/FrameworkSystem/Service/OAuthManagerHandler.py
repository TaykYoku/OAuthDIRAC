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

  type_updateSession = [dict, dict]

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

  types_waitStateResponse = [basestring, basestring, bool, basestring, int, int, int]

  def export_waitStateResponse(self, state, group, needProxy, voms, proxyLifeTime, timeOut, sleepTime):
    """ Listen DB to get status of auth and proxy if needed

        :param basestring state: session number
        :param basestring group: group name for proxy DIRAC group extentional
        :param boolean needProxy: need proxy or not
        :param basestring voms: voms name
        :param int proxyLifeTime: requested proxy live time
        :param int timeOut: time in a seconds needed to wait result
        :param int sleepTime: time needed to wait between requests

        :return: S_OK(dict)/S_ERROR
    """
    timeOut = timeOut > 300 and 300 or timeOut
    sleepTime = sleepTime >= timeOut and timeOut - 1 or sleepTime
    gLogger.notice(state, "session, waiting authorization status")
    start = time.time()
    runtime = 0
    for _i in range(int(timeOut // sleepTime)):
      time.sleep(sleepTime)
      runtime = time.time() - start
      if runtime > timeOut:
        gOAuthDB.killSession(state)
        return S_ERROR('Timeout')
      result = gOAuthDB.getStatusByState(state)
      if not result['OK']:
        return result
      resD = result['Value']

      # Looking status of OIDC authorization session
      status = resD['Status']
      gLogger.notice('%s session' % state, status)
      if status in ['prepared', 'in progress']:
        continue
      elif status in ['visitor', 'authed and reported']:
        return S_OK(resD)
      elif status == 'failed':
        return S_ERROR(resD['Comment'])
      elif status == 'authed':
        if not needProxy:
          return S_OK(resD)

        # Need group to continue
        gLogger.notice("%s session, try return proxy" % state)
        if not group:
          result = Registry.findDefaultGroupForUser(resD['UserName'])
          if not result['OK']:
            return result
          group = result['Value']
        elif group not in Registry.getGroupsForUser(resD['UserName'])['Value']:
          return S_ERROR('%s group is not found for %s user.' % (group, resD['UserName']))
        
        # Get proxy to string
        result = Registry.getDNForUsername(resD['UserName'])
        if not result['OK']:
          return S_ERROR('Cannot get proxy')
        if not Registry.getGroupsForUser(resD['UserName'])['OK']:
          return S_ERROR('Cannot get proxy')
        for DN in result['Value']:
          result = Registry.getDNProperty(DN, 'Groups')
          if not result['OK']:
            return S_ERROR('Cannot get proxy, %s' % result['Message'])
          groupList = result['Value'] or []
          if not isinstance(groupList, list):
            groupList = groupList.split(', ')
          if group in groupList:
            if voms:
              voms = Registry.getVOForGroup(group)
              result = gProxyManager.downloadVOMSProxy(DN, group, requiredVOMSAttribute=voms,
                                                       requiredTimeLeft=proxyLifeTime)
            else:
              result = gProxyManager.downloadProxy(DN, group, requiredTimeLeft=proxyLifeTime)
            if result['OK']:
              break
        if not result['OK']:
          gLogger.notice('Proxy was not created.')
          return result
        gLogger.notice('Proxy was created.')
        result = result['Value'].dumpAllToString()
        if not result['OK']:
          return result
        return S_OK({'Status': status, 'proxy': result['Value']})
      else:
        return S_ERROR('Not correct status of your request')
    return S_ERROR('Timeout')

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
