""" ProxyProvider implementation for the proxy generation using OIDC flow
"""

import datetime

from DIRAC import S_OK, S_ERROR, gLogger
from DIRAC.Core.Security.X509Chain import X509Chain  # pylint: disable=import-error
from DIRAC.ConfigurationSystem.Client.Helpers import Registry
from DIRAC.Resources.ProxyProvider.ProxyProvider import ProxyProvider

from OAuthDIRAC.FrameworkSystem.Utilities.OAuth2 import OAuth2
from OAuthDIRAC.FrameworkSystem.Client.OAuthManagerClient import OAuthManagerClient

__RCSID__ = "$Id$"


class OAuth2ProxyProvider(ProxyProvider):

  def __init__(self, parameters=None):
    super(OAuth2ProxyProvider, self).__init__(parameters)
    self.log = gLogger.getSubLogger(__name__)

  def setParameters(self, parameters):
    self.parameters = parameters
    self.oauth2 = OAuth2(parameters['IdProvider'])
    self.oauth = OAuthManagerClient()
  
  def checkStatus(self, userDict=None, sessionDict=None):
    """ Read ready to work status of proxy provider

        :param dict userDict: user description dictionary with possible fields:
               FullName, UserName, DN, EMail, DiracGroup
        :param dict sessionDict: session dictionary

        :return: S_OK(dict)/S_ERROR() -- dictionary contain fields:
                 - 'Status' with ready to work status[ready, needToAuth]
                 - 'AccessTokens' with list of access token
    """
    __params = {}
    __params['Provider'] = self.parameters['IdProvider']
    __conn = " Status IN ( 'authed', 'in progress' ) "
    
    # We need access token to continue
    sessionDict = not sessionDict and userDict or sessionDict or {}
    accessTokens = sessionDict.get('AccessToken') and [sessionDict['AccessToken']] or []
    if not self.parameters['IdProvider'] == sessionDict.get('Provider'):
      accessTokens = []
    if not accessTokens:
      if sessionDict.get('State'):
        __params['State'] = sessionDict['State']
      else:
        dn = sessionDict.get('UserDN') or sessionDict.get('DN')
        sub = sessionDict.get('Sub') or sessionDict.get('UserID') or sessionDict.get('ID')
        userName = sessionDict.get('UserName') or sessionDict.get('username')
        if userName:
          __params['UserName'] = userName
        if sub:
          if isinstance(sub, list):
            __conn += "AND Sub IN ( '%s' ) " % "', '".join(sub)
          else:
            __params['Sub'] = sub
        elif dn:
          if isinstance(dn, list):
            __conn = "AND UserDN IN ( '%s' ) " % "', '".join(dn)
          else:
            __params['UserDN'] = dn
        else:
          return S_ERROR('No accses token token, session number, user DN found in request.')

      # Search access tokens
      self.log.notice('Search access token for proxy request')
      result = self.oauth.getSessionDict(__conn, __params)
      if not result['OK']:
        return result
      self.log.notice('Search access token result: ', result)

      # Trying to update every access token
      accessTokens = []
      for i in range(0, len(result['Value'])):
        sessionDict = result['Value'][i]
        if not sessionDict.get('AccessToken'):
          continue
        self.log.notice('Try %s access token.' % sessionDict['AccessToken'])

        # Check access token time left
        timeLeft = 0
        if isinstance(sessionDict['ExpiresIn'], datetime.datetime):
          timeLeft = (sessionDict['ExpiresIn'] - sessionDict['TimeStamp']).total_seconds()
        self.log.notice('Left %s seconds of access token' % str(timeLeft))

        if timeLeft < 1800:
          # Refresh tokens
          result = self.oauth2.fetchToken(refreshToken=sessionDict['RefreshToken'])
          if not result['OK']:
            self.log.error(result['Message'])
            continue
          self.log.notice('Tokens of %s successfully updated.' % sessionDict['Provider'])
          tD = result['Value']
          exp_datetime = 'ADDDATE(UTC_TIMESTAMP(), INTERVAL %s SECOND)' % tD.get('expires_in') or 0
          result = self.oauth.updateSession({'ExpiresIn': exp_datetime,
                                                       'Token_type': tD['token_type'],
                                                       'AccessToken': tD['access_token']},
                                                      {'AccessToken': sessionDict['Access_token']})
          if not result['OK']:
            self.log.error(result['Message'])
            continue
          accessTokens.append(tD['access_token'])
        accessTokens.append(sessionDict['AccessToken'])
    if not accessTokens:
      return S_OK({'Status': 'needToAuth', 'IdP': self.parameters['IdProvider']})
    return S_OK({'Status': 'ready', 'AccessTokens': accessTokens})

  def getProxy(self, userDict=None, sessionDict=None, voms=None):
    """ Generate user proxy with OIDC flow authentication

        :param dict userDict: user description dictionary with possible fields:
               FullName, UserName, DN, EMail, DiracGroup
        :param dict sessionDict: session dictionary

        :return: S_OK/S_ERROR, Value is a proxy string
    """
    sessionDict = not sessionDict and userDict or sessionDict or {}
    result = self.checkStatus(sessionDict)
    if not result['OK']:
      return result
    if not result['Value']['Status'] == 'ready':
      return S_ERROR('To get proxy need authentication.')

    # Get proxy request
    for accessToken in result['Value']['AccessTokens']:
      self.log.info('Get proxy from %s request with access token:' % self.parameters['ProviderName'], accessToken)
      result = self.__getProxyRequest(accessToken, voms)
      if result['OK']:
        self.log.info('Proxy is taken')
        break
      
      # Kill session
      res = self.oauth.getSessionDict('', {'AccessToken': accessToken, 'Provider': self.parameters['IdProvider']})
      if not res['OK']:
        return res
      # self.log.info('======>>>>:', res['Value'])
      for i in range(0, len(res['Value'])):
        state = res['Value'][i]['State']
        res = self.oauth.killState(state)
        if not res['OK']:
          self.log.error('Cannot kill %s' % state, res['Message'])

    if not result['OK']:
      return result
    proxyStr = result['Value']
    if not proxyStr:
      return S_ERROR('Returned proxy is empty.')

    # Get DN
    chain = X509Chain()
    result = chain.loadProxyFromString(proxyStr)
    if not result['OK']:
      return result
    result = chain.getCredentials()
    if not result['OK']:
      return result
    DN = result['Value']['identity']
    return S_OK({'proxy': proxyStr, 'DN': DN})

  def getUserDN(self, userDict=None, sessionDict=None, userDN=None):
    """ Get DN of the user certificate that will be created

        :param dict userDict: user description dictionary with possible fields:
               FullName, UserName, DN, EMail, DiracGroup
        :param dict sessionDict: session dictionary

        :return: S_OK/S_ERROR, Value is the DN string
    """
    gotDN = None
    __conn = ''
    __params = {}
    __params['Status'] = "authed"
    __params['Provider'] = self.parameters['IdProvider']

    sessionDict = not sessionDict and userDict or sessionDict or {}
    userName = sessionDict.get('UserName') or sessionDict.get('username')
    if userName:
      __params['UserName'] = userName
    sub = sessionDict.get('Sub') or sessionDict.get('UserID') or sessionDict.get('ID')
    if sub:
      if isinstance(sub, list):
        conn += "Sub IN ( '%s' ) " % "', '".join(sub)
      else:
        __params['Sub'] = sub
      
      # Search user DN in DB
      result = self.oauth.getSessionDict(__conn, __params)
      if not result['OK']:
        return result
      gotDN = result['Value'] and result['Value'][0].get('DN')

    # Generate proxy and read user DN
    if not gotDN:
      self.log.info('Try to generate proxy.')
      result = self.getProxy(sessionDict)
      if not result['OK'] or not result['Value'].get('DN'):
        return S_ERROR(result['Message'] or 'Cannot get user DN.')
      gotDN = result['Value']['DN']
    
    # Check DN
    if userDN and not userDN == gotDN:
      return S_ERROR('%s is not match with DN %s that from genrated proxy' % (userDict['DN'], userDN))

    return S_OK(gotDN)

  def __getProxyRequest(self, accessToken, voms, **kwargs):
    """ Get user proxy from proxy provider
    
        :param basestring access_token: access token that will be use to get proxy
        :param basestring voms: VOMS name to get proxy with voms extentions
        :param basestring,list `**kwargs`: OAuth2 parameters that will be added to request url,
              e.g. **{authorization_endpoint='http://domain.ua/auth', scope=['openid','profile']}

        :return: S_OK(basestring)/S_ERROR()
    """
    kwargs = kwargs or {}
    kwargs['access_type'] = 'offline'
    kwargs['access_token'] = accessToken
    kwargs['proxylifetime'] = self.parameters['MaxProxyLifetime']
    if voms:
      result = Registry.getVOs()
      if not result['OK']:
        return result
      if voms not in result['Value']:
        return S_ERROR('%s vo is not registred in DIRAC.' % voms)
      result = Registry.getVOMSServerInfo(voms)
      if not result['OK']:
        return result
      self.log.info('"%s" VOMS found' % voms)
      vomsname = result['Value'][voms]['VOMSName']
      hostname = result['Value'][voms]['Servers'][0]
      hostDN = result['Value'][voms]['Servers'][hostname]['DN']
      port = result['Value'][voms]['Servers'][hostname]['Port']
      kwargs['vomses'] = '"%s" "%s" "%s" "%s" "%s"' % (vomsname, hostname, port, hostDN, vomsname)
      kwargs['voname'] = vomsname
    
    # Get proxy request
    self.log.notice('Get proxy request to %s' % self.parameters['GetProxyEndpoint'])
    kwargs['client_id'] = self.oauth2.get('client_id')
    kwargs['client_secret'] = self.oauth2.get('client_secret')
    try:
      r = self.oauth2.request('GET', self.parameters['GetProxyEndpoint'], params=kwargs, headers={})
      r.raise_for_status()
      return S_OK(r.text)
    except self.oauth2.exceptions.RequestException as e:
      return S_ERROR(e.message)
