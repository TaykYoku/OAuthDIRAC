""" IdProvider base class for various identity providers
"""

from DIRAC import gLogger

__RCSID__ = "$Id$"


class IdProvider(object):

  def __init__(self, parameters=None):
    self.log = gLogger.getSubLogger('OAuth2IdProvider')
    self.parameters = parameters

  def setParameters(self, parameters):
    self.parameters = parameters
