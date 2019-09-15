""" DIRAC OAuthManager Client class encapsulates the methods exposed
    by the OAuthManager service.
"""

__RCSID__ = "$Id$"

from DIRAC.Core.Base.Client import Client, createClient

@createClient('Framework/OAuthManager')
class OAuthManagerClient(Client):

  def __init__(self, **kwargs):
    """ Constructor
    """
    super(OAuthManagerClient, self).__init__(**kwargs)
    self.setServer('Framework/OAuthManager')
