""" HTTP API of the DIRAC configuration data
"""

import json
import time
import tornado

from tornado import web, gen
from tornado.template import Template

from DIRAC import S_OK, S_ERROR, gConfig, gLogger

from WebAppDIRAC.Lib.WebHandler import WebHandler, asyncGen

__RCSID__ = "$Id$"


class ConfigurationHandler(WebHandler):
  OFF = False
  AUTH_PROPS = "all"
  LOCATION = "configuration"

  @asyncGen
  def web_get(self):
    """ Authentication endpoint, used to:
          get configuration information, with arguments:
           option - path to opinion with opinion name, e.g /DIRAC/Extensions
           options - section path where need to get list of opinions
           section - section path to get dict of all opinions, values there
           sections - section path where need to get list of sections
        
        :return: json with requested data
    """
    args = self.request.arguments
    key = args.keys()[0]
    path = args.values()[0][0]
    gLogger.notice('Request configuration information')

    if key == 'option':
      result = yield self.threadTask(gConfig.getOption, path)
      if not result['OK']:
        raise tornado.web.HTTPError(404, result['Message'])
      self.finish(json.dumps(result['Value']))
    elif key == 'section':
      result = yield self.threadTask(gConfig.getOptionsDict, path)
      if not result['OK']:
        raise tornado.web.HTTPError(404, result['Message'])
      self.finish(json.dumps(result['Value']))
    elif key == 'options':
      result = yield self.threadTask(gConfig.getOptions, path)
      if not result['OK']:
        raise tornado.web.HTTPError(404, result['Message'])
      self.finish(json.dumps(result['Value']))
    elif key == 'sections':
      result = yield self.threadTask(gConfig.getSections, path)
      if not result['OK']:
        raise tornado.web.HTTPError(404, result['Message'])
      self.finish(json.dumps(result['Value']))
    else:
      raise tornado.web.HTTPError(500, 'Invalid argument')

  @asyncGen
  def post(self):
    """ Post method
    """
    pass
