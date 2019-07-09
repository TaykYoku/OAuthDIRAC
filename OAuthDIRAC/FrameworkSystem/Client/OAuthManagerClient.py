""" DIRAC OAuthManager Client class encapsulates the methods exposed
    by the OAuthManager service.
"""

__RCSID__ = "$Id$"

from DIRAC import gLogger, S_ERROR
from DIRAC.Core.Base.Client import Client


class OAuthManagerClient(Client):

  def __init__(self, **kwargs):
    """ Constructor
    """
    super(OAuthManagerClient, self).__init__(**kwargs)

    self.log = gLogger.getSubLogger('OAuthManagerClient')
    self.setServer('Framework/OAuthManager')
