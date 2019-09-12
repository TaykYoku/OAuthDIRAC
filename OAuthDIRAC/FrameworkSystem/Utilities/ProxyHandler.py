""" Handler to serve the DIRAC proxy data
"""
import re
import json
import time
import base64
import tornado

from tornado import web, gen
from tornado.template import Template

from DIRAC import S_OK, S_ERROR, gConfig, gLogger
from DIRAC.FrameworkSystem.Client.NotificationClient import NotificationClient
from DIRAC.ConfigurationSystem.Client.Utilities import getOAuthAPI
from DIRAC.FrameworkSystem.Client.ProxyManagerClient import gProxyManager
from DIRAC.ConfigurationSystem.Client.Helpers import Registry

from OAuthDIRAC.FrameworkSystem.Client.OAuthManagerClient import OAuthManagerClient

from WebAppDIRAC.Lib.WebHandler import WebHandler, asyncGen, WErr

__RCSID__ = "$Id$"

gOAuthCli = OAuthManagerClient()


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
    """ Proxy management endpoint
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
        proxyLifeTime = self.args.get('lifetime') or 3600 * 12

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
        if not __dn:
          result = Registry.getDNForUsername(userName)
          if not result['OK']:
            raise WErr(500, 'Cannot get proxy')
          if not Registry.getGroupsForUser(userName)['OK']:
            raise WErr(500, 'Cannot get proxy')
          for DN in result['Value']:
            result = Registry.getDNProperty(DN, 'Groups')
            if not result['OK']:
              raise WErr(500, 'Cannot get proxy, %s' % result['Message'])
            groupList = result['Value'] or []
            if not isinstance(groupList, list):
              groupList = groupList.split(', ')
            if group in groupList:
              __dn = DN
              break
        if not __dn:
          raise WErr(500, 'No DN found for %s@%s' % (userName, group))
        if self.args.get('voms'):
          voms = Registry.getVOForGroup(group)
          result = gProxyManager.downloadVOMSProxy(DN, group, requiredVOMSAttribute=voms,
                                                   requiredTimeLeft=proxyLifeTime)
        else:
          result = gProxyManager.downloadProxy(DN, group, requiredTimeLeft=proxyLifeTime)
        if not result['OK']:
          raise WErr(500, result['Message'])
        self.log.notice('Proxy was created.')
        result = result['Value'].dumpAllToString()
        if not result['OK']:
          raise WErr(500, result['Message'])
        self.finish(result['Value'])
