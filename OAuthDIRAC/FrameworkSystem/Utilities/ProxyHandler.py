""" Handler to serve the DIRAC proxy data
"""
import re
import time
import base64

from tornado import web, gen
from tornado.template import Template

from DIRAC import S_OK, S_ERROR, gConfig, gLogger
from DIRAC.ConfigurationSystem.Client.Helpers import Registry
from DIRAC.FrameworkSystem.Client.ProxyManagerClient import gProxyManager

from WebAppDIRAC.Lib.WebHandler import WebHandler, asyncGen, WErr

__RCSID__ = "$Id$"


class ProxyHandler(WebHandler):
  OVERPATH = True
  AUTH_PROPS = "authenticated"
  LOCATION = "/"

  def initialize(self):
    super(ProxyHandler, self).initialize()
    self.args = {}
    for arg in self.request.arguments:
      if len(self.request.arguments[arg]) > 1:
        self.args[arg] = self.request.arguments[arg]
      else:
        self.args[arg] = self.request.arguments[arg][0] or ''
    return S_OK()

  @asyncGen
  def web_proxy(self):
    """ Proxy management endpoint, use:
          GET /proxy/<DN>?<options> -- retrieve proxy
            * DN - user DN(optional)
            * options:
              * voms - VOMS name(optional)
              * group - DIRAC group(optional)
              * lifetime - requested proxy live time(optional)

          GET /proxy/<DN>/metadata?<options> -- retrieve proxy metadata
            * options:

        :return: json
    """
    __dn, __obj = None, None
    optns = self.overpath.strip('/').split('/')
    try:
      __dn = base64.urlsafe_b64decode(str(re.match("([A-z0-9=-_]+)?", optns[0]).group())).rstrip("/")
    except TypeError, e:
      raise WErr(400, "Cannot decode path")
    
    if not __dn or (len(optns) == 2 and __dn):
      __obj = re.match("(metadata)?", optns[-1]).group()
    else:
      raise WErr(404, "Wrone way")

    # GET
    if self.request.method == 'GET':
      
      # Return content of Proxy DB
      if __obj == 'metadata':
        pass

      # Return proxy
      else:
        group = self.args.get('group')
        userName = self.getUserName()
        proxyLifeTime = 3600 * 12
        if re.match('[0-9]+', self.args.get('lifetime') or ''):
          proxyLifeTime = int(self.args.get('lifetime'))

        # Need group to continue
        if not group:
          result = Registry.findDefaultGroupForUser(userName)
          if not result['OK']:
            raise WErr(500, result['Message'])
          group = result['Value']
        result = Registry.getGroupsForUser(userName)
        if not result['OK']:
          raise WErr(500, result['Message'])
        elif group not in result['Value']:
          raise WErr(500, '%s group is not found for %s user.' % (group, userName))
        
        # Get proxy to string
        result = Registry.getDNForUsernameInGroup(userName, group)
        if not result['OK']:
          raise WErr(500, result['Message'])
        __dn = result['Value']
        if not __dn:
          raise WErr(500, 'No DN found for %s@%s' % (userName, group))
        if self.args.get('voms'):
          voms = Registry.getVOForGroup(group)
          result = gProxyManager.downloadVOMSProxy(__dn, group, requiredVOMSAttribute=voms,
                                                   requiredTimeLeft=proxyLifeTime)
        else:
          result = gProxyManager.downloadProxy(__dn, group, requiredTimeLeft=proxyLifeTime)
        if not result['OK']:
          raise WErr(500, result['Message'])
        self.log.notice('Proxy was created.')
        result = result['Value'].dumpAllToString()
        if not result['OK']:
          raise WErr(500, result['Message'])
        self.finishJEncode(result['Value'])
