""" DIRAC OAuthManager Client class encapsulates the methods exposed
    by the OAuthManager service.
"""

from DIRAC import gLogger, S_OK, S_ERROR
from DIRAC.Core.Base.Client import Client, createClient
from DIRAC.Core.Utilities import DIRACSingleton
from OAuthDIRAC.FrameworkSystem.Client.OAuthManagerData import gOAuthManagerData

__RCSID__ = "$Id$"


@createClient('Framework/OAuthManager')
class OAuthManagerClient(Client):
  """ Authentication manager
  """
  __metaclass__ = DIRACSingleton.DIRACSingleton

  def __init__(self, **kwargs):
    """ Constructor
    """
    super(OAuthManagerClient, self).__init__(**kwargs)
    self.setServer('Framework/OAuthManager')

  def parseAuthResponse(self, response, state):
    """ Fill session by user profile, tokens, comment, OIDC authorize status, etc.
        Prepare dict with user parameters, if DN is absent there try to get it.
        Create new or modify existend DIRAC user and store the session

        :param dict response: authorization response
        :param basestring state: session number

        :return: S_OK(dict)/S_ERROR()
    """
    result = self._getRPC().parseAuthResponse(response, state)
    if not result['OK']:
      return result
    if result['Value']['Status'] in ['authed', 'redirect']:
      refresh = gOAuthManagerData.updateProfiles(result['Value']['upProfile'])
      if refresh['OK']:
        refresh = gOAuthManagerData.updateSessions(result['Value']['upSession'])
      if not refresh['OK']
        return refresh
    return result

gSessionManager = OAuthManagerClient()
