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
  LOCATION = "oauth2"

  def initialize(self):
    super(OAuth2Handler, self).initialize()
    self.loggin = gLogger.getSubLogger("OAuth2Handler")
    return S_OK()

  @asyncGen
  def web_oauth(self):
    """ Authentication endpoint, used to:
          search authorization URL in OAuthDB by session number, with arguments:
            getlink - contain session number where stored authorization URL

          create new authorization URL and session, with arguments:
            IdP - provider name where need authorize
            email - optional, mail where need to send authorization URL

        :return: json with requested data
    """
    args = self.request.arguments

    if args:
      idp = 'IdP' in args and args['IdP'][0]
      email = 'email' in args and args['email'][0]
      getlink = 'getlink' in args and args['getlink'][0]
      
      if getlink:
        # Redirect to authentication endpoint
        self.loggin.notice(getlink,' authorization session flow')
        result = yield self.threadTask(gOAuthCli.getLinkByState, getlink)
        if not result['OK']:
          self.loggin.error(result['Message'])
          self.finish('%s link has expired!' % getlink)
        else:
          self.loggin.notice('Redirect to %s' % result['Value'])
          self.redirect(result['Value'])
      
      elif idp:
        # Create new authenticate session
        self.loggin.notice('Initialize "%s" authorization flow' % idp)
        result = yield self.threadTask(gOAuthCli.createAuthRequestURL, idp)
        if not result['OK']:
          self.loggin.error(result['Message'])
          raise tornado.web.HTTPError(500, result['Message'])
        state = result['Value']['state']
        oauthAPI = getOAuthAPI('Production')
        if not oauthAPI:
          raise tornado.web.HTTPError(500, 'Cannot find redirect URL.')
        url = '%s/oauth?getlink=%s' % (oauthAPI, state)
        if email:
          result = yield self.threadTask(NotificationClient().sendMail, email,
                                         'Authentication throught %s' % idp,
                                         'Please, go throught the link %s to authorize.' % url)
          result['Value'] = {'state': state}
        self.loggin.notice('%s authorization session "%s" provider was created' % (state, idp))
        self.finish(json.dumps(result))

  @asyncGen
  def web_redirect(self):
    """ Redirect endpoint, used to:
          parse response of authentication request, with arguments:
            code - authorization code in response of authorization code flow
            state - authorization session number

          get authorization status, proxy(optional) from session, with arguments:
            status - contain session number where stored authorization URL
            proxy - optional, if need to return proxy
            group - optional(need to set if proxy argument is enable), requested dirac group
            voms - optional, requested voms extengion
            proxyLifeTime - optinal, requested proxy live time 

        :return: json with requested data
    """
    args = self.request.arguments
    self.loggin.info(args)
    if args:
      code = 'code' in args and args['code'][0]
      voms = 'voms' in args and args['voms'][0] or ''
      state = 'state' in args and args['state'][0]
      group = 'group' in args and args['group'][0] or ''
      status = 'status' in args and args['status'][0]
      needProxy = 'proxy' in args and (args['proxy'][0] and True)
      error = 'error' in args and ', '.join(args['error'])
      timeOut = 'timeOut' in args and args['timeOut'][0] or None
      proxyLifeTime = 'proxyLifeTime' in args and int(args['proxyLifeTime'][0]) or None
      error_description = 'error_description' in args and ', '.join(args['error_description']) or ''
    
      # Parse response of authentication request
      if code:
        if not state:
          self.finish('No state argument found.')
        else:
          self.loggin.notice('%s session, parsing response with authorization code "%s"' % (state, code))
          result = yield self.threadTask(gOAuthCli.parseAuthResponse, code, state)
          if not result['OK']:
            self.loggin.error(result['Message'])
            raise tornado.web.HTTPError(500, result['Message'])
          else:
            oDict = result['Value']
            if oDict['redirect']:
              self.loggin.notice('%s session, redirect to new authorization flow "%s"' % (state, oDict['redirect']))
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
              self.loggin.notice('%s session, authorization complete' % state)
              self.finish(t.generate(Messages='\n'.join(oDict['Messages'])))
      
      # Get status of authorization and proxy
      elif status:
        self.loggin.notice('%s session, get status of authorization' % status,
                           needProxy and 'and try to return proxy' or '')
        self.loggin.notice([status, group, needProxy, voms, proxyLifeTime, timeOut])
        result = yield self.threadTask(gOAuthCli.waitStateResponse, status, group,
                                       needProxy, voms, proxyLifeTime, timeOut)
        if not result['OK']:
          self.loggin.error(result['Message'])
          raise tornado.web.HTTPError(500, result['Message'])
        self.finish(json.dumps(result))

      # Catch errors
      elif error:
        t = Template('''State: {{state}}<br>Error: {{error}}<br>Description: {{about}}''')
        self.finish(t.generate(state=state, error=error, about=error_description))
      else:
        self.finish('No supported args!')
    
    # Convert hash to request arguments
    else:
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
