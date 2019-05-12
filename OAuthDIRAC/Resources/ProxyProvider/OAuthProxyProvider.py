""" ProxyProvider implementation for the proxy generation using local (DIRAC)
    CA credentials
"""

import os
import commands
import glob
import shutil
import tempfile

from DIRAC import S_OK, S_ERROR
from DIRAC.Resources.ProxyProvider.ProxyProvider import ProxyProvider
from DIRAC.Core.Security.X509Chain import X509Chain
from DIRAC.ConfigurationSystem.Client.Helpers import Registry

from OAuthDIRAC.FrameworkSystem.Client.OAuthManagerClient import OAuthManagerClient

__RCSID__ = "$Id$"


class OAuthProxyProvider(ProxyProvider):

  def __init__(self, parameters=None):

    super(OAuthProxyProvider, self).__init__(parameters)

  def getProxy(self, userDict):
    """ Generate user proxy

        :param dict userDict: user description dictionary with possible fields:
                              FullName, UserName, DN, EMail, DiracGroup
        :return: S_OK/S_ERROR, Value is a proxy string
    """
    # Create proxy
    result = OAuthManagerClient().getStringProxy(proxyProvider, userDict)
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
    if "DN" in userDict:
      return S_OK(userDict['DN'])

    return OAuthManagerClient().getUserDN(proxyProvider, userDict)
