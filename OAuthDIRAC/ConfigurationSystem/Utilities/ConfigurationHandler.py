""" HTTP API of the DIRAC configuration data
"""

import json
import time
import tornado

from tornado import web, gen
from tornado.template import Template

from DIRAC import S_OK, S_ERROR, gConfig, gLogger
from DIRAC.ConfigurationSystem.Client.ConfigurationData import gConfigurationData

from WebAppDIRAC.Lib.WebHandler import WebHandler, asyncGen, WErr

__RCSID__ = "$Id$"


class ConfigurationHandler(WebHandler):
  AUTH_PROPS = "all"
  LOCATION = "configuration"

  def initialize(self):
    super(ConfigurationHandler, self).initialize()
    self.args = {}
    for arg in self.request.arguments:
      if len(self.request.arguments[arg]) > 1:
        self.args[arg] = self.request.arguments[arg]
      else:
        self.args[arg] = self.request.arguments[arg][0] or ''
    return S_OK()

  @asyncGen
  def web_get(self):
    """ Authentication endpoint, used to:
          get configuration information, with arguments:
           option - path to opinion with opinion name, e.g /DIRAC/Extensions
           options - section path where need to get list of opinions
           section - section path to get dict of all opinions, values there
           sections - section path where need to get list of sections
           version - client version
        
        :return: json with requested data
    """
    self.log.notice('Request configuration information')

    if 'version' in self.args and (self.args.get('version') or '0') >= gConfigurationData.getVersion():
      self.finish()

    result = {}    
    if 'fullCFG' in self.args:
      remoteCFG = yield self.threadTask(gConfigurationData.getRemoteCFG)
      result['Value'] = str(remoteCFG)
    elif 'option' in self.args:
      result = yield self.threadTask(gConfig.getOption, self.args['option'])
    elif 'section' in self.args:
      result = yield self.threadTask(gConfig.getOptionsDict, self.args['section'])
    elif 'options' in self.args:
      result = yield self.threadTask(gConfig.getOptions, self.args['options'])
    elif 'sections' in self.args:
      result = yield self.threadTask(gConfig.getSections, self.args['sections'])
    else:
      raise WErr(500, 'Invalid argument')

    if not result['OK']:
      raise WErr(404, result['Message'])
    self.finish(json.dumps(result['Value']) if isinstance(result['Value'], dict) else result['Value'])

  @asyncGen
  def post(self):
    """ Post method
    """
    pass
