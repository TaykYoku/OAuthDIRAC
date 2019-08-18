""" IdProvider based on user certificate information
"""

import re
import ssl

from DIRAC import gLogger, S_OK, S_ERROR
from DIRAC.Core.Security.X509Chain import X509Chain  # pylint: disable=import-error
from DIRAC.ConfigurationSystem.Client.Helpers import Registry

from OAuthDIRAC.Resources.IdProvider.IdProvider import IdProvider

__RCSID__ = "$Id$"


class CertificateIdProvider(IdProvider):

  def __init__(self, parameters=None):
    super(CertificateIdProvider, self).__init__(parameters)

  def getCredentials(self, kwargs):
    """ Collect user credentials to dict
    """
    __credDict = {}
    # NGINX
    if kwargs.get('balancer') == "nginx":
      headers = kwargs.get('headers')
      if not headers:
        return S_ERROR('No headers found.')
      if headers.get('X-Scheme') == "https" and headers.get('X-Ssl_client_verify') == 'SUCCESS':
        DN = headers['X-Ssl_client_s_dn']
        if not DN.startswith('/'):
          items = DN.split(',')
          items.reverse()
          DN = '/' + '/'.join(items)
        __credDict['DN'] = DN
        __credDict['issuer'] = headers['X-Ssl_client_i_dn']
        result = Registry.getUsernameForDN(DN)
        if not result['OK']:
          __credDict['validDN'] = False
        else:
          __credDict['validDN'] = True
          __credDict['username'] = result['Value']
      return S_OK({'Session': '', 'credDict': __credDict})

    # TORNADO
    derCert = kwargs.get('certificate')
    if not derCert:
      return S_ERROR('No certificate found.')
    pemCert = ssl.DER_cert_to_PEM_cert(derCert)
    chain = X509Chain()
    chain.loadChainFromString(pemCert)
    result = chain.getCredentials()
    if not result['OK']:
      return S_ERROR("Could not get client credentials %s" % result['Message'])
    __credDict = result['Value']
    # Hack. Data coming from OSSL directly and DISET difer in DN/subject
    try:
      __credDict['DN'] = __credDict['subject']
    except KeyError:
      pass
    return S_OK({'Session': '', 'credDict': __credDict})
