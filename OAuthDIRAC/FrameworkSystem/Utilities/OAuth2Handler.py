""" Handler to serve the DIRAC configuration data
"""

import json
import time
import tornado

from tornado import web, gen
from tornado.template import Template

from DIRAC import S_OK, S_ERROR, gConfig, gLogger
from DIRAC.FrameworkSystem.Client.NotificationClient import NotificationClient
from DIRAC.ConfigurationSystem.Client.Utilities import getOAuthAPI

from OAuthDIRAC.FrameworkSystem.Client.OAuthManagerClient import OAuthManagerClient

from WebAppDIRAC.Lib.WebHandler import WebHandler, asyncGen

__RCSID__ = "$Id$"

gOAuthCli = OAuthManagerClient()


class OAuth2Handler(WebHandler):
  OFF = False
  AUTH_PROPS = "all"
  LOCATION = "authentication"

  def initialize(self):
    super(OAuth2Handler, self).initialize()
    self.loggin = gLogger.getSubLogger(__name__)
    self.args = {}
    for arg in self.request.arguments:
      if len(self.request.arguments[arg]) > 1:
        self.args[arg] = self.request.arguments[arg]
      else:
        self.args[arg] = self.request.arguments[arg][0] or ''
    return S_OK()

  @asyncGen
  def web_auth(self):
    """ Authentication endpoint, used to:
          search authorization URL in OAuthDB by session number, with arguments:
            getlink - contain session number where stored authorization URL

          create new authorization URL and session, with arguments:
            provider - provider name where need authorize
            email - optional, mail where need to send authorization URL

        :return: json with requested data
    """
    if 'getlink' in self.args:
      if not self.args.get('getlink'):
        self.finish('"getlink" argument is emppty.')
      else:
        # Redirect to authentication endpoint
        self.loggin.notice(self.args['getlink'],' authorization session flow')
        result = yield self.threadTask(gOAuthCli.getLinkByState, self.args['getlink'])
        if not result['OK']:
          self.loggin.error(result['Message'])
          self.finish('%s link has expired!' % self.args['getlink'])
        else:
          self.loggin.notice('Redirect to', result['Value'])
          self.redirect(result['Value'])
    
    elif 'provider' not in self.args:
      self.finish('No "provider" or "getlink" arguments set.')
    elif not self.args.get('provider'):
      self.finish('"provider" argument is empty.')
    else:
      # Create new authenticate session
      self.loggin.notice('Initialize "%s" authorization flow' % self.args['provider'])
      result = yield self.threadTask(gOAuthCli.submitAuthorizeFlow, self.args['provider'], self.args.get('state'))
      if not result['OK']:
        self.loggin.error(result['Message'])
        raise tornado.web.HTTPError(500, result['Message'])

      if result['Value']['Status'] == 'ready':
        pass
      elif result['Value']['Status'] == 'needToAuth':
        state = result['Value']['Session']
        oauthAPI = getOAuthAPI('Production')
        if not oauthAPI:
          raise tornado.web.HTTPError(500, 'Cannot find redirect URL.')
        url = '%s/auth?getlink=%s' % (oauthAPI, state)
        if self.args.get('email'):
          result = yield self.threadTask(NotificationClient().sendMail, self.args['email'],
                                         'Authentication throught %s' % self.args['provider'],
                                         'Please, go throught the link %s to authorize.' % url)
          result['Value'] = {'state': state}
        self.loggin.notice('%s authorization session "%s" provider was created' % (state, self.args['provider']))
      else:
        result = S_ERROR('Not correct status "%s" of %s' % (result['Value']['Action']['State'], typeAuth))

      self.finish(json.dumps(result))

  @asyncGen
  def web_status(self):
    """ Endpoint to get authorization status, proxy(optional) from session, with arguments:
          status - contain session number where stored authorization URL
          proxy - optional, if need to return proxy
          group - optional(need to set if proxy argument is enable), requested dirac group
          voms - optional, requested voms extengion
          proxyLifeTime - optinal, requested proxy live time 

        :return: json with requested data
    """
    if 'status' not in self.args:
      self.finish('"status" argument not set.')
    elif not self.args.get('status'):
      self.finish('"status" argument is empty.')
    else:
      self.loggin.notice('%s session, get status of authorization' % self.args['status'],
                         self.args.get('proxy') and 'and try to return proxy' or '')
      result = yield self.threadTask(gOAuthCli.waitStateResponse, self.args['status'], self.args.get('group'),
                                    self.args.get('proxy'), self.args.get('voms'), self.args.get('proxyLifeTime'),
                                    self.args.get('timeOut'), self.args.get('sleepTime'))
      if not result['OK']:
        self.loggin.error(result['Message'])
        raise tornado.web.HTTPError(500, result['Message'])
      self.finish(json.dumps(result))

  @asyncGen
  def web_redirect(self):
    """ Redirect endpoint, used to parse response of authentication request, with arguments:
          some response arguments, like as authorization code
          state - authorization session number

        :return: json with requested data
    """
    if self.args.get('error'):
      about = self.args.get('error_description') and ', '.join(self.args['error_description']) or ''
      state = self.args.get('state') and 'State: %s' % self.args.get('state') or ''
      error = ', '.join(self.args['error'])
      t = Template('State: {{state}}<br>Error: {{error}}<br>Description: {{about}}')
      self.finish(t.generate(about=about, state=state, error=error))
    elif 'state' not in self.args:
      self.finish('"state" argument not set.')
    elif not self.args.get('state'):
      self.finish('"state" argument is empty.')
    else:
      self.loggin.info(self.args['state'], 'session, parsing authorization response %s' % self.args)
      result = yield self.threadTask(gOAuthCli.parseAuthResponse, self.args, self.args['state'])
      if not result['OK']:
        self.loggin.error(result['Message'])
        raise tornado.web.HTTPError(500, result['Message'])
      else:
        oDict = result['Value']
        if oDict.get('redirect'):
          self.loggin.info(self.args['state'], 'session, redirect to new authorization flow "%s"' % oDict['redirect'])
          self.redirect(oDict['redirect'])
        else:
          t = Template('''<!DOCTYPE html>
          <html><head><title>Authetication</title>
            <meta charset="utf-8" /></head><body>
              {{ Messages }} <br>
              Done! You can close this window.
              <script type="text/javascript">
                window.close();
              </script>
            </body>
          </html>''')
          self.loggin.info(self.args['state'], 'session, authorization complete')
          self.loggin.info(oDict['Messages'])
          self.finish(t.generate(Messages=oDict['Messages']))

  def __convertHashToArgs(self):
    """ Convert hash to request arguments
    """
    self.loggin.debug('Convert hash to request arguments')
    t = Template('''<!DOCTYPE html>
      <html><head><title>Authetication</title>
        <meta charset="utf-8" /></head><body>
          Waiting...
          <script type="text/javascript">
            var xhr = new XMLHttpRequest();
            xhr.onreadystatechange = function() {
              if (xhr.readyState === 4) {
                if (xhr.response == 'Done') {
                  opener.location.protocol = "https:"
                } else {
                  opener.alert('Not registered user')
                }
                close()
              }
            }
            xhr.open("GET", "{{ redirect_uri }}?" + location.hash.substring(1), true);
            xhr.send();
          </script>
        </body>
      </html>''')
    self.finish(t.generate(redirect_uri=getOAuthAPI('Production') + '/redirect'))

  @asyncGen
  def post(self):
    """ Post method
    """
    pass
