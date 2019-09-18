""" Handler to serve the DIRAC configuration data
"""
import re

from tornado import web, gen
from tornado.template import Template

from DIRAC import S_OK, S_ERROR, gConfig, gLogger
from DIRAC.ConfigurationSystem.Client.Helpers import Resources
from DIRAC.FrameworkSystem.Client.NotificationClient import NotificationClient

from OAuthDIRAC.FrameworkSystem.Client.OAuthManagerClient import OAuthManagerClient

from WebAppDIRAC.Lib.WebHandler import WebHandler, asyncGen, WErr

__RCSID__ = "$Id$"

gOAuthCli = OAuthManagerClient()


class AuthHandler(WebHandler):
  OVERPATH = True
  AUTH_PROPS = "all"
  LOCATION = "/"

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
    """ Authentication endpoint, used:
          GET /auth/<IdP>?<options> -- submit authentication flow, retrieve session with status and describe
            * IdP - Identity provider name for authentication
            * options:
              * email - email to get authentcation URL(optional)
              * state - session number(optional)

          GET /auth/<session> -- will redirect to authentication endpoint
          GET /auth/<session>/status -- retrieve session with status and describe
            * session - session number

          GET /redirect?<options> -- redirect endpoint to catch authentication responce
            * options - responce options

        :return: json
    """
    optns = self.overpath.strip('/').split('/')
    if not optns or len(optns) > 2:
      raise WErr(404, "Wrone way")
    result = Resources.getInfoAboutProviders(of='Id')
    if not result['OK']:
      raise WErr(500, result['Message'])
    idPs = result['Value']
    idP = re.match("(%s)?" % '|'.join(idPs), optns[0]).group()
    session = re.match("([A-z0-9]+)?", optns[0]).group()

    if idP:
      # Create new authenticate session
      self.log.info('Initialize "%s" authorization flow' % idP)
      result = yield self.threadTask(gOAuthCli.submitAuthorizeFlow, idP, self.args.get('state'))
      if not result['OK']:
        raise WErr(500, result['Message'])
      if result['Value']['Status'] == 'needToAuth':
        state = result['Value']['Session']
        authAPI = gConfig.getValue("/Systems/Framework/Production/URLs/AuthAPI")
        if not authAPI:
          raise WErr(500, 'Cannot find redirect URL.')
        if self.args.get('email'):
          url = '%s/%s' % (authAPI, state)
          notify = yield self.threadTask(NotificationClient().sendMail, self.args['email'],
                                          'Authentication throught %s' % idP,
                                          'Please, go throught the link %s to authorize.' % url)
          if not notify['OK']:
            result['Value']['Comment'] = '%s\n%s' % (result['Value'].get('Comment') or '', notify['Message'])
        self.log.notice('%s authorization session "%s" provider was created' % (state, idP))
      elif result['Value']['Status'] != 'ready':
        raise WErr(500, 'Not correct status "%s" of %s' % (result['Value']['Status'], idP))
      self.finishJEncode(result['Value'])

    elif optns[0] == 'redirect':
      # Redirect endpoint for response
      self.log.info('REDIRECT RESPONSE:\n', self.request)
      if self.args.get('error'):
        raise WErr(500, '%s session crashed with error:\n%s\n%s' % (self.args.get('state') or '',
                                                                    self.args['error'],
                                                                    self.args.get('error_description') or ''))
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

    elif session:
      if optns[-1] == session:
        # Redirect to authentication endpoint
        self.log.info(session,' authorization session flow')
        result = yield self.threadTask(gOAuthCli.getLinkByState, session)
        if not result['OK']:
          raise WErr(500, '%s session not exist or expired!' % session)
        self.log.notice('Redirect to', result['Value'])
        self.redirect(result['Value'])

      elif optns[-1] == 'status':
        # Get session authentication status
        self.log.notice('%s session, get status of authorization' % session)
        result = yield self.threadTask(gOAuthCli.getSessionStatus, session)
        if not result['OK']:
          raise WErr(500, result['Message'])
        self.finishJEncode(result['Value'])

      else:
        raise WErr(404, "Wrone way")

    else:
      raise WErr(404, "Wrone way")
