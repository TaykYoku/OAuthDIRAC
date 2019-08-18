""" OAuth2

    OAuth2 included all methods to work with OID providers.
"""

import re
import random
import string
from requests import Session, exceptions

from DIRAC import gLogger, S_OK, S_ERROR
from DIRAC.ConfigurationSystem.Client.Helpers import Registry
from DIRAC.ConfigurationSystem.Client.Helpers.Resources import getInfoAboutProviders
from DIRAC.ConfigurationSystem.Client.Utilities import getOAuthAPI

__RCSID__ = "$Id$"


class OAuth2(Session):
  def __init__(self, name=None,
               scope=[], prompt=None,
               issuer=None, jwks_uri=None,
               client_id=None, redirect_uri=None,
               client_secret=None, proxy_endpoint=None,
               token_endpoint=None, providerOfWhat=None,
               scopes_supported=None, userinfo_endpoint=None,
               max_proxylifetime=None, revocation_endpoint=None,
               registration_endpoint=None, grant_types_supported=None,
               authorization_endpoint=None, introspection_endpoint=None,
               response_types_supported=None, **kwargs):
    """ OIDCClient constructor
    """
    super(OAuth2, self).__init__()
    self.log = gLogger.getSubLogger('OAuth2')
    self.exceptions = exceptions
    self.verify=False

    __optns = {}
    self.parameters = {}
    self.parameters['name'] = name or kwargs.get('ProviderName')

    # Get information from CS
    for instance in (providerOfWhat and [providerOfWhat] or getInfoAboutProviders().get('Value') or []):
      result = getInfoAboutProviders(of=instance, providerName=self.parameters['name'])
      if result['OK']:
        break
    self.parameters['providerOfWhat'] = instance or None
    if not result['OK']:
      return result
    __csDict = result.get('Value') or {}

    # Get configuration from providers server
    self.parameters['issuer'] = issuer or kwargs.get('issuer') or __csDict.get('issuer')
    if self.parameters['issuer']:
      result = self.getWellKnownDict()
      if not result['OK']:
        self.log.warn('Cannot get settins from %s provider:' % result['Message'])
      elif isinstance(result['Value'], dict):
        __optns = result['Value']

    for d in [__csDict, kwargs]:
      for key, value in d.iteritems():
        __optns[key] = value

    # Get redirect URL from CS
    oauthAPI = getOAuthAPI('Production')
    if oauthAPI:
      redirect_uri = '%s/redirect' % oauthAPI

    # Check client Id
    self.parameters['client_id'] = client_id or __optns.get('client_id')
    if not self.parameters['client_id']:
      raise Exception('client_id parameter is absent.')
    
    # Create list of all possible scopes
    self.parameters['scope'] = scope or __optns.get('scope') or []
    if not isinstance(self.parameters['scope'], list):
      self.parameters['scope'] = self.parameters['scope'].split(',')
    self.parameters['scope'] += __optns.get('scopes_supported') or []

    # Init main OAuth2 options
    self.parameters['prompt'] = prompt or __optns.get('prompt')
    self.parameters['redirect_uri'] = redirect_uri or __optns.get('redirect_uri')
    self.parameters['client_secret'] = client_secret or __optns.get('client_secret')
    self.parameters['token_endpoint'] = token_endpoint or __optns.get('token_endpoint')
    self.parameters['proxy_endpoint'] = proxy_endpoint or __optns.get('proxy_endpoint')
    self.parameters['scopes_supported'] = scopes_supported or __optns.get('scopes_supported')
    self.parameters['userinfo_endpoint'] = userinfo_endpoint or __optns.get('userinfo_endpoint')
    self.parameters['max_proxylifetime'] = max_proxylifetime or __optns.get('max_proxylifetime') or 86400
    self.parameters['revocation_endpoint'] = revocation_endpoint or __optns.get('revocation_endpoint')
    self.parameters['registration_endpoint'] = registration_endpoint or __optns.get('registration_endpoint')
    self.parameters['authorization_endpoint'] = authorization_endpoint or __optns.get('authorization_endpoint')
    self.parameters['introspection_endpoint'] = introspection_endpoint or __optns.get('introspection_endpoint')

  def get(self, parameter):
    return self.parameters.get(parameter)

  def createAuthRequestURL(self, state=None, **kwargs):
    """ Create link for authorization and state of authorization session

        :param basestring,list `**kwargs`: OAuth2 parameters that will be added to request url,
               e.g. **{authorization_endpoint='http://domain.ua/auth', scope=['openid','profile']}

        :return: S_OK(basestring url, basestring state)/S_ERROR()
    """
    state = state or self.createState()
    self.log.info(state, 'session, generate URL for authetication.')
    url = kwargs.get('authorization_endpoint') or self.parameters['authorization_endpoint']
    if not url:
      return S_ERROR('No found authorization endpoint.')
    url += '?state=%s&response_type=code&client_id=%s&access_type=offline' % (state, self.parameters['client_id'])
    if self.parameters['prompt']:
      url += '&prompt=%s' % self.parameters['prompt']
    kwargs['redirect_uri'] = kwargs.get('redirect_uri') or self.parameters['redirect_uri']
    kwargs['scope'] = kwargs.get('scope') or [] + self.parameters['scope']
    for key in kwargs:
      if isinstance(kwargs[key],list):
        kwargs[key] = '+'.join(kwargs[key])
      url += '&%s=%s' % (key, kwargs[key])
    return S_OK({'URL': url, 'Session': state})

  def parseAuthResponse(self, code):
    """ Collecting information about user
    
        :param basestring code: authorize code that come with response(authorize code flow)

        :result: S_OK(dict)/S_ERROR()
    """
    oaDict = {}

    # Get tokens
    result = self.fetchToken(code)
    if not result['OK']:
      return result
    oaDict['Tokens'] = result['Value']

    # Get user profile
    result = self.getUserProfile(oaDict['Tokens']['access_token'])
    if not result['OK']:
      return result
    oaDict['UserProfile'] = result['Value']
    return S_OK(oaDict)

  def getUserProfile(self, accessToken):
    """ Get user profile
    
        :param basestring access_token: access token

        :return: S_OK(dict)/S_ERROR()
    """
    if not self.parameters['userinfo_endpoint']:
      return S_ERROR('Not found userinfo endpoint.')
    try:
      r = self.request('GET', self.parameters['userinfo_endpoint'],
                       headers={'Authorization': 'Bearer ' + accessToken})
      r.raise_for_status()
      return S_OK(r.json())
    except (self.exceptions.RequestException, ValueError) as e:
      return S_ERROR(e.message)

  def revokeToken(self, accessToken=None, refreshToken=None):
    """ Revoke token
    
        :param basestring access_token: access token
        :param basestring refresh_token: refresh token

        :return: S_OK()/S_ERROR()
    """
    if not accessToken and not refreshToken:
      return S_ERROR('Not found any token to revocation.')
    if not self.parameters['revocation_endpoint']:
      return S_ERROR('Not found revocation endpoint.')
    for key, value in [('access_token', accessToken), ('refresh_token', refreshToken)]:
      if not value:
        continue
      self.params = {'token': key, 'token_type_hint': value}
      try:
        self.request('POST', self.parameters['token_endpoint']).raise_for_status()
      except self.exceptions.RequestException as e:
        return S_ERROR(e.message)

  def fetchToken(self, code=None, refreshToken=None):
    """ Update tokens
    
        :param basestring code: authorize code that come with response(authorize code flow)
        :param basestring refreshToken: refresh token

        :return: S_OK(dict)/S_ERROR()
    """
    if not self.parameters['token_endpoint']:
      return S_ERROR('Not found token_endpoint for %s provider' % self.parameters['name'])
    self.params = {'access_type': 'offline'}
    for arg in ['client_id', 'client_secret', 'prompt']:
      self.params[arg] = self.parameters[arg]
    if code:
      if not self.parameters['redirect_uri']:
        return S_ERROR('Not found redirect_uri for %s provider' % self.parameters['name'])
      self.params['code'] = code
      self.params['grant_type'] = 'authorization_code'
      self.params['redirect_uri'] = self.parameters['redirect_uri']
    elif refreshToken:
      self.params['grant_type'] = 'refresh_token'
      self.params['refresh_token'] = refreshToken
    else:
      return S_ERROR('No authorization code or refresh token found.')
    try:
      r = self.request('POST', self.parameters['token_endpoint'])
      r.raise_for_status()
      return S_OK(r.json())
    except (self.exceptions.RequestException, ValueError) as e:
      return S_ERROR(e.message)

  def createState(self):
    """ Generates a state string to be used in authorizations
    
        :return: basestring
    """
    return ''.join(random.choice(string.ascii_letters + string.digits) for x in range(30))

  def getWellKnownDict(self, url=None, issuer=None):
    """ Returns OpenID Connect metadata related to the specified authorization server
        of provider, enough one parameter

        :param basestring wellKnown: complete link to provider oidc configuration
        :param basestring issuer: base URL of provider

        :return: S_OK(dict)/S_ERROR()
    """
    url = url or self.parameters['issuer'] and '%s/.well-known/openid-configuration' % self.parameters['issuer']
    if not url:
      return S_ERROR('Cannot get %s provider issuer/wellKnow url' % oauthProvider)
    try:
      r = self.request('GET', url)
      r.raise_for_status()
      return S_OK(r.json())
    except (self.exceptions.RequestException, ValueError) as e:
      return S_ERROR(e.message)
