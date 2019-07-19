""" ProxyProvider implementation for the proxy generation using OIDC flow
"""

from DIRAC import S_OK, S_ERROR
from DIRAC.Core.Security.X509Chain import X509Chain  # pylint: disable=import-error
from DIRAC.ConfigurationSystem.Client.Helpers import Registry
from DIRAC.Resources.ProxyProvider.ProxyProvider import ProxyProvider

from OAuthDIRAC.FrameworkSystem.Client.OAuthManagerClient import OAuthManagerClient

__RCSID__ = "$Id$"


class OAuth2ProxyProvider(ProxyProvider):

  def __init__(self, parameters=None):

    super(OAuth2ProxyProvider, self).__init__(parameters)

  def getProxy(self, userDict):
    """ Generate user proxy

        :param dict userDict: user description dictionary with possible fields:
                              FullName, UserName, DN, EMail, DiracGroup
        :return: S_OK/S_ERROR, Value is a proxy string
    """
    if not self.name:
      return S_ERROR('No found ProxyProviderName option')

    # Create proxy
    result = OAuthManagerClient().getStringProxy(self.name, userDict)
    if not result['OK']:
      return result
    proxyStr = result['Value']
    chain = X509Chain()
    result = chain.loadProxyFromString(proxyStr)
    if not result['OK']:
      return result
    result = chain.getRemainingSecs()
    if not result['OK']:
      return result
    remainingSecs = result['Value']

    # Add DIRAC group if requested
    diracGroup = userDict.get('DiracGroup')
    if diracGroup:
      result = Registry.getGroupsForDN(userDN)
      if not result['OK']:
        return result
      if diracGroup not in result['Value']:
        return S_ERROR('Requested group is not valid for the user')

    return chain.generateProxyToString(remainingSecs, diracGroup=diracGroup, rfc=True)

  def getUserDN(self, userDict):
    """ Get DN of the user certificate that will be created

        :param dict userDict:
        :return: S_OK/S_ERROR, Value is the DN string
    """
    if not self.name:
      return S_ERROR('No found ProxyProviderName option')

    result = OAuthManagerClient().getUserDN(self.name, userDict)
    
    if result['OK'] and 'DN' in userDict:
      if userDict['DN'] == result['Value']:
        result = S_OK(userDict['DN'])
      else:
        result = S_ERROR('%s is not match with DN %s that from genrated proxy' % (userDict['DN'], result['Value']))

    return result
