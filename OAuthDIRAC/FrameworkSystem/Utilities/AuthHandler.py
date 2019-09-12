""" Handler to serve the DIRAC configuration data
"""

import json
import time
import tornado

from tornado import web, gen
from tornado.template import Template

from DIRAC import S_OK, S_ERROR, gConfig, gLogger
from DIRAC.FrameworkSystem.Client.NotificationClient import NotificationClient

from OAuthDIRAC.FrameworkSystem.Client.OAuthManagerClient import OAuthManagerClient

from WebAppDIRAC.Lib.WebHandler import WebHandler, asyncGen, WErr

__RCSID__ = "$Id$"

gOAuthCli = OAuthManagerClient()


class AuthHandler(WebHandler):
  OVERPATH = True
  AUTH_PROPS = "all"
  LOCATION = "authentication"

  def initialize(self):
    super(AuthHandler, self).initialize()
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
        raise WErr(404, '"getlink" argument is emppty.')
      
      # Redirect to authentication endpoint
      self.log.notice(self.args['getlink'],' authorization session flow')
      result = yield self.threadTask(gOAuthCli.getLinkByState, self.args['getlink'])
      if not result['OK']:
        raise WErr(500, '%s session not exist or expired!' % self.args['getlink'])
      self.log.notice('Redirect to', result['Value'])
      self.redirect(result['Value'])
    
    if 'provider' not in self.args:
      raise WErr(404, 'No "provider" or "getlink" arguments set.')
    if not self.args.get('provider'):
      raise WErr(404, '"provider" argument is empty.')
    
    # Create new authenticate session
    self.log.notice('Initialize "%s" authorization flow' % self.args['provider'])
    result = yield self.threadTask(gOAuthCli.submitAuthorizeFlow, self.args['provider'], self.args.get('state'))
    if not result['OK']:
      raise WErr(500, result['Message'])
    if result['Value']['Status'] == 'needToAuth':
      state = result['Value']['Session']
      authAPI = gConfig.getValue("/Systems/Framework/Production/URLs/AuthAPI")
      if not authAPI:
        raise WErr(500, 'Cannot find redirect URL.')
      if self.args.get('email'):
        url = '%s/auth?getlink=%s' % (authAPI, state)
        notify = yield self.threadTask(NotificationClient().sendMail, self.args['email'],
                                        'Authentication throught %s' % self.args['provider'],
                                        'Please, go throught the link %s to authorize.' % url)
        if not notify['OK']:
          result['Value']['Comment'] = '%s\n%s' % (result['Value'].get('Comment') or '', notify['Message'])
      self.log.notice('%s authorization session "%s" provider was created' % (state, self.args['provider']))
    elif result['Value']['Status'] != 'ready':
      raise WErr(500, 'Not correct status "%s" of %s' % (result['Value']['Status'], self.args['provider']))

    gLogger.notice(result['Value'], '<<<<<<<<')
    self.finish(json.dumps(result['Value']) if isinstance(result['Value'], dict) else result['Value'])

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
      raise WErr(404, '"status" argument not set.')
    if not self.args.get('status'):
      raise WErr(404, '"status" argument is empty.')
    self.log.notice('%s session, get status of authorization' % self.args['status'],
                    self.args.get('proxy') and 'and try to return proxy' or '')
    result = yield self.threadTask(gOAuthCli.getSessionStatus, self.args['status'])
    if not result['OK']:
      raise WErr(500, result['Message'])
    self.finish(json.dumps(result['Value']))

  @asyncGen
  def web_redirect(self):
    """ Redirect endpoint, used to parse response of authentication request, with arguments:
          some response arguments, like as authorization code
          state - authorization session number

        :return: json with requested data
    """
    self.log.info('REDIRECT RESPONSE:\n', self.request)
    if self.args.get('error'):
      about = self.args.get('error_description') and ', '.join(self.args['error_description']) or ''
      state = self.args.get('state') and 'State: %s' % self.args.get('state') or ''
      error = ', '.join(self.args['error'])
      t = Template('State: {{state}}<br>Error: {{error}}<br>Description: {{about}}')
      self.finish(t.generate(about=about, state=state, error=error))
    if 'state' not in self.args:
      raise WErr(404, '"state" argument not set.')
    if not self.args.get('state'):
      raise WErr(404, '"state" argument is empty.')
    self.log.info(self.args['state'], 'session, parsing authorization response %s' % self.args)
    result = yield self.threadTask(gOAuthCli.parseAuthResponse, self.args, self.args['state'])
    if not result['OK']:
      raise WErr(500, result['Message'])
    oDict = result['Value']
    t = Template('''<!DOCTYPE html>
      <html><head><title>Authetication</title>
        <meta charset="utf-8" /></head><body>
          %s <br>
          <script type="text/javascript"> 
            if ("%s" != "") { window.open("%s","_self") }
            else { window.close() }
          </script>
        </body>
      </html>''' % (oDict.get('Messages') or '', oDict.get('redirect') or '', oDict.get('redirect') or ''))
    self.log.info('>>>REDIRECT:\n', oDict.get('redirect'))
    self.finish(t.generate())
    # if oDict.get('redirect'):
    #   self.log.info('<<<<<:\n', self.request)
    #   self.log.info(self.args['state'], 'session, redirect to new authorization flow "%s"' % oDict['redirect'])
    #   self.redirect(oDict['redirect'], 303)
    # else:
    #   t = Template('''<!DOCTYPE html>
    #   <html><head><title>Authetication</title>
    #     <meta charset="utf-8" /></head><body>
    #       {{ Messages }} <br>
    #       Done! You can close this window.
    #       <script type="text/javascript">
    #         window.close();
    #       </script>
    #     </body>
    #   </html>''')
    #   self.log.info(self.args['state'], 'session, authorization complete')
    #   self.log.info(oDict['Messages'])
    #   self.finish(t.generate(Messages=oDict['Messages']))

  def __convertHashToArgs(self):
    """ Convert hash to request arguments
    """
    self.log.debug('Convert hash to request arguments')
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
