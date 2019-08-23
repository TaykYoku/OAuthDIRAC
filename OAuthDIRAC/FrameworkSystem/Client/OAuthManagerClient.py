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

  def waitStateResponse(self, state, group=None, needProxy=None, voms=None,
                        proxyLifeTime=None, timeOut=None, sleepTime=None):
    """ Listen DB to get status of auth and proxy if needed

        :param basestring state: session number
        :param basestring group: group name for proxy DIRAC group extentional
        :param boolean needProxy: need proxy or not
        :param basestring voms: voms name
        :param int proxyLifeTime: requested proxy live time
        :param int timeOut: time in a seconds needed to wait result
        :param int sleepTime: time needed to wait between requests

        :return: S_OK(dict)/S_ERROR
    """
    voms = voms or ''
    group = group or ''
    needProxy = bool(needProxy)
    timeOut = timeOut and int(timeOut) or 10
    sleepTime = sleepTime and int(sleepTime) or 5
    proxyLifeTime = proxyLifeTime and int(proxyLifeTime) or 43200
    return self._getRPC().waitStateResponse(state, group, needProxy, voms, proxyLifeTime, timeOut, sleepTime)
