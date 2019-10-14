""" ProxyProvider implementation for the proxy generation using OIDC flow
"""

import pprint
import datetime

from DIRAC import S_OK, S_ERROR, gLogger
from DIRAC.Core.Security.X509Chain import X509Chain  # pylint: disable=import-error
from DIRAC.ConfigurationSystem.Client.Helpers import Registry
from DIRAC.Resources.ProxyProvider.ProxyProvider import ProxyProvider
from DIRAC.Resources.IdProvider.IdProviderFactory import IdProviderFactory

from OAuthDIRAC.FrameworkSystem.Utilities.OAuth2 import OAuth2
from OAuthDIRAC.FrameworkSystem.Client.OAuthManagerClient import gSessionManager

__RCSID__ = "$Id$"


class OAuth2ProxyProvider(ProxyProvider):

  def __init__(self, parameters=None):
    super(OAuth2ProxyProvider, self).__init__(parameters)
    self.log = gLogger.getSubLogger(__name__)

  def setParameters(self, parameters):
    self.log = gLogger.getSubLogger('%s/%s' % (__name__, parameters['ProviderName']))
    self.parameters = parameters
    self.idProvider = None
    self.oauth2 = None
  
  def checkStatus(self, userDN):
    """ Read ready to work status of proxy provider

        :param dict userDict: user description dictionary with possible fields:
               FullName, UserName, DN, Email, DiracGroup
        :param dict sessionDict: session dictionary

        :return: S_OK(dict)/S_ERROR() -- dictionary contain fields:
                 - 'Status' with ready to work status[ready, needToAuth]
                 - 'AccessTokens' with list of access token
    """
    result = Registry.getUserNameForDN(userDN)
    if not result['OK']:
      return result
    self.userName = result['Value']
    result = IdProviderFactory().getIdProvider(self.parameters['IdProvider'])
    if not result['OK']:
      return result
    self.idProvider = result['Value']
    self.oauth2 = OAuth2(self.parameters['IdProvider'])
    return self.idProvider.checkStatus(self.userName)
  
  def getProxy(self, userDN):
    """ Generate user proxy with OIDC flow authentication

        :param dict userDict: user description dictionary with possible fields:
               FullName, UserName, DN, Email, DiracGroup
        :param dict sessionDict: session dictionary

        :return: S_OK/S_ERROR, Value is a proxy string
    """
    result = self.checkStatus(userDN)
    if not result['OK']:
      return result
    if result['Value']['Status'] == 'needToAuth':
      return S_ERROR('To get proxy need authentication.', result['Value'])
    elif result['Value']['Status'] != 'ready':
      return S_ERROR('Some unexpexted status.')

    for session in result['Value']['Sessions']:
      self.log.verbose('For proxy request use session:', session)
      # Get tokens
      result = gSessionManager.getTokensBySession(session)
      if not result['OK']:
        return result
      tokens = result['Value']

      # Get proxy request
      result = self.__getProxyRequest(tokens['AccessToken'])
      if not result['OK']:
        self.log.error(result['Message'])
        # Refresh tokens
        tokens['State'] = session
        result = self.idProvider.fetchTokensAndUpdateSession(tokens)
        if not result['OK']:
          self.log.error(result['Message'])
          continue
        tokens = result['Value']

        # Try to get proxy request again
        result = self.__getProxyRequest(tokens['AccessToken'])
        if not result['OK']:
          self.log.error(result['Message'])
          continue
      
      self.log.info('Proxy is taken')
      break

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

  def __getProxyRequest(self, accessToken):
    """ Get user proxy from proxy provider
    
        :param basestring accessToken: access token

        :return: S_OK(basestring)/S_ERROR()
    """
    kwargs = {'access_token': accessToken}
    kwargs['access_type'] = 'offline'
    kwargs['proxylifetime'] = self.parameters['MaxProxyLifetime'] or 3600 * 24
    
    # Get proxy request
    self.log.verbose('Send proxy request to %s' % self.parameters['GetProxyEndpoint'])
    kwargs['client_id'] = self.oauth2.get('client_id')
    kwargs['client_secret'] = self.oauth2.get('client_secret')
    try:
      r = self.oauth2.request('GET', self.parameters['GetProxyEndpoint'], params=kwargs, headers={})
      r.raise_for_status()
      return S_OK(r.text)
    except self.oauth2.exceptions.RequestException as e:
      return S_ERROR("%s: %s" % (e.message, r.text))
