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

  types_checkToken = [basestring]

  def export_checkToken(self, token):
    """ Check status of tokens, refresh and back dict.

        :param basestring token: access token
        :return: S_OK(dict)/S_ERROR()
    """
    gLogger.notice("Check token %s." % token)
    return gOAuthDB.fetchToken(accessToken=token)

  types_getStringProxy = [basestring]

  def export_getStringProxy(self, proxyProvider, userDict):
    """ Get proxy from OAuthDB
        
        :param basestring proxyProvider: proxy provider name
        :param dict userDict: user parameters
        :return: S_OK(basestring)/S_ERROR()
    """
    return gOAuthDB.getProxy(proxyProvider, userDict)

  types_getUserDN = [basestring]

  def export_getUserDN(self, proxyProvider, userDict):
    """ Get DN from OAuthDB
        
        :param basestring proxyProvider: proxy provider name
        :param dict userDict: user parameters
        :return: S_OK(basestring)/S_ERROR()
    """
    return gOAuthDB.getUserDN(proxyProvider, userDict)

  types_getUsrnameForState = [basestring]

  def export_getUsrnameForState(self, state):
    """ Get username by session number

        :param basestring state: session number
        :result: S_OK(dict)/S_ERROR()
    """
    result = gOAuthDB.getFieldByState(state, ['UserName', 'State'])
    if not result['OK']:
      return result
    return S_OK({'username': result['Value']['UserName'], 'state': result['Value']['State']})

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
        :result: S_OK(basestring)/S_ERROR()
    """
    return gOAuthDB.getLinkByState(state)

  types_waitStateResponse = [basestring]

  def export_waitStateResponse(self, state, group=None, needProxy=False,
                               voms=None, proxyLifeTime=43200, time_out=20, sleeptime=5):
    """ Listen DB to get status of auth and proxy if needed

        :param basestring state: session number
        :param boolen needProxy: need proxy or not
        :param basestring group: group name for proxy DIRAC group extentional
        :param basestring voms: voms name
        :param int proxyLifeTime: requested proxy live time
        :param int time_out: time in a seconds needed to wait result
        :param int sleeptime: time needed to wait between requests
        :return: S_OK(dict)/S_ERROR
    """
    gLogger.notice("%s session, waiting authorization status" % state)
    start = time.time()
    runtime = 0
    for _i in range(int(int(time_out) // int(sleeptime))):
      time.sleep(sleeptime)
      runtime = time.time() - start
      if runtime > time_out:
        gOAuthDB.kill_state(state)
        return S_ERROR('Timeout')
      result = gOAuthDB.getFieldByState(state)
      if not result['OK']:
        return result

      # Looking status of OIDC authorization session
      status = result['Value']['Status']
      comment = result['Value']['Comment']
      gLogger.notice("%s session %s" % (state, status))
      if status == 'prepared':
        continue
      elif status == 'visitor':
        return S_OK({'Status': status, 'Message': comment})
      elif status == 'failed':
        return S_ERROR(comment)
      elif status == 'authed':
        resD = result['Value']
        if not needProxy:
          return result

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
          groupList = result['Value']
          if not isinstance(groupList, list):
            groupList = groupList.split()
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

  types_createAuthRequestURL = [basestring]

  def export_createAuthRequestURL(self, idp):
    """ Register new session and return dict with authorization url and session number
    
        :param basestring OAuthProvider: provider name
        :return: S_OK(dict)/S_ERROR()
    """
    gLogger.notice("Creating authority request URL for '%s' IdP." % idp)
    result = gOAuthDB.getAuthorizationURL(idp)
    if not result['OK']:
      return S_ERROR('Cannot create authority request URL.')
    return result

  types_parseAuthResponse = [basestring]

  def export_parseAuthResponse(self, code, state):
    """ Fill session by user profile, tokens, comment, OIDC authorize status, etc.
        Prepare dict with user parameters, if DN is absent there try to get it.
        Create new or modify existend DIRAC user and store the session

        :param basestring code: authorization code
        :param basestring state: session number
        :return: S_OK(dict)/S_ERROR
    """
    gLogger.notice('%s session get response with code "%s" to process' % (state, code))
    return gOAuthDB.parseAuthResponse(code, state)

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
