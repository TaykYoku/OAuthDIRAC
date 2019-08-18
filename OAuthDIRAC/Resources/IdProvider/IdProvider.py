""" IdProvider base class for various identity providers
"""

__RCSID__ = "$Id$"


class IdProvider(object):

  def __init__(self, parameters=None):
    self.parameters = parameters

  def setParameters(self, parameters):
    self.parameters = parameters
