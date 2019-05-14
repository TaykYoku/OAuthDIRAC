""" OAuth2

    OAuth2 included all methods to work with OID providers.
"""

import random
import string
import requests

from DIRAC import S_OK, S_ERROR, gLogger
from DIRAC.ConfigurationSystem.Client.Helpers import Registry, Resources
from DIRAC.ConfigurationSystem.Client.Utilities import getOAuthAPI

__RCSID__ = "$Id$"


def getIdPWellKnownDict(oauthProvider=None, issuer=None, wellKnown=None):
  """ Returns OpenID Connect metadata related to the specified authorization server
      of provider, enough one parameter

      :param basestring oauthProvider: name provider on OAuth2 protocol e.g. CheckIn
      :param basestring issuer: base URL of provider
      :param basestring wellKnown: complete link to provider oidc configuration
      :return: S_OK(dict)/S_ERROR()
  """
  url = wellKnown or issuer and '%s/.well-known/openid-configuration' % issuer
  if not url:
    if not oauthProvider:
      return S_ERROR('Need at least one parametr')
    issuer = Resources.getIdPOption(oauthProvider, 'issuer')
    url = Resources.getIdPOption(oauthProvider, 'well_known') or \
        issuer and '%s/.well-known/openid-configuration' % issuer
    if not url:
      return S_ERROR('Cannot get %s provider issuer/wellKnow url' % oauthProvider)
  # FIXME: in production need to remove 'verify' parametr
  r = requests.get(url, verify=False)
  if not r.status_code == 200:
    return S_ERROR(r.status_code)
  if not r.json():
    return S_ERROR('No expected response.')
  return S_OK(r.json())


def getIdPSyntax(idp, section):
  """ Get claim and regexs from CS to parse response with user information
      to get VO/Role

      :param basestring idp: provider name
      :param basestring section: about what need to collect information, e.g. VOMS
      :return: S_OK(dict)/S_ERROR
  """
  resDict = {}
  result = Resources.getIdPSections(idp)
  if not result['OK']:
    return result
  result = Resources.getIdPSections(idp, '/Syntax')
  if not result['OK']:
    return result
  opts = result['Value']
  if section not in opts:
    return S_ERROR('In /Resources/%s/Syntax/ not found %s section' % (idp,section))
  result = Resources.getIdPOptions(idp, '/Syntax/%s' % section)
  if not result['OK']:
    return result
  keys = result['Value']
  if 'claim' not in keys:
    return S_ERROR('No claim found for %s in CFG.' % section)
  resDict['claim'] = Resources.getIdPOption(idp, '/Syntax/%s/claim' % section)
  for key in keys:
    resDict[key] = Resources.getIdPOption(idp, '/Syntax/%s/%s' % (section, key))
  return S_OK(resDict)


class OIDCClient(requests.Session):

  def __init__(self, idp=None, client_id=None, client_secret=None, redirect_uri=None,
               scope=[], issuer=None, authorization_endpoint=None, token_endpoint=None,
               introspection_endpoint=None, proxy_endpoint=None, max_proxylifetime=None,
               response_types_supported=None, grant_types_supported=None, revocation_endpoint=None,
               userinfo_endpoint=None, jwks_uri=None, registration_endpoint=None, prompt=None,
               scopes_supported=None, addDict={}):
    """ OIDCClient constructor
    """
    __optns = {}

    # Provider name
    self.idp = idp or addDict.get('ProxyProviderName')
    
    # Get information from CS
    result = Resources.getIdPDict(idp)
    if not result['OK']:
      result = Resources.getProxyProviderDict(idp)
    __csDict = result.get('Value') or {}

    # Get configuration from providers server
    self.issuer = issuer or addDict.get('issuer') or __csDict.get('issuer')
    if self.issuer:
      result = getIdPWellKnownDict(oauthProvider=self.idp, issuer=self.issuer)
      if result['OK']:
        if isinstance(result['Value'], dict):
          __optns = result['Value']

    for d in [__csDict, addDict]:
      for key, value in d.iteritems():
        __optns[key] = value

    self.name = idp
    self.client_id = client_id or __optns.get('client_id')
    if not self.client_id:
      raise Exception('client_id parameter is absent.')
    self.scope = scope or __optns.get('scope') or []
    if not isinstance(self.scope,list):
      self.scope = self.scope.split(',')
    self.scope += __optns.get('scopes_supported') or []
    self.prompt = prompt or __optns.get('prompt')
    self.redirect_uri = redirect_uri or __optns.get('redirect_uri')
    self.client_secret = client_secret or __optns.get('client_secret')
    self.token_endpoint = token_endpoint or __optns.get('token_endpoint')
    self.proxy_endpoint = proxy_endpoint or __optns.get('proxy_endpoint')
    self.scopes_supported = scopes_supported or __optns.get('scopes_supported')
    self.userinfo_endpoint = userinfo_endpoint or __optns.get('userinfo_endpoint')
    self.max_proxylifetime = max_proxylifetime or __optns.get('max_proxylifetime') or 86400
    self.revocation_endpoint = revocation_endpoint or __optns.get('revocation_endpoint')
    self.registration_endpoint = registration_endpoint or __optns.get('registration_endpoint')
    self.authorization_endpoint = authorization_endpoint or __optns.get('authorization_endpoint')
    self.introspection_endpoint = introspection_endpoint or __optns.get('introspection_endpoint')


class OAuth2(OIDCClient):

  def __init__(self, idp=None, state=None, client_id=None, client_secret=None, redirect_uri=None,
               scope=[], issuer=None, authorization_endpoint=None, token_endpoint=None, introspection_endpoint=None,
               proxy_endpoint=None, max_proxylifetime=None, response_types_supported=None, grant_types_supported=None,
               revocation_endpoint=None, userinfo_endpoint=None, jwks_uri=None, registration_endpoint=None, prompt=None,
               scopes_supported=None, addDict={}):
    """ OAuth2 constructor
    """

    super(OAuth2, self).__init__(idp, client_id, client_secret, redirect_uri, scope, issuer, proxy_endpoint,
                                 max_proxylifetime, authorization_endpoint, token_endpoint, introspection_endpoint,
                                 response_types_supported, grant_types_supported, revocation_endpoint,
                                 userinfo_endpoint, jwks_uri, registration_endpoint, prompt, scopes_supported,
                                 addDict={})

    self.state = state or self.createState()
    oauthAPI = getOAuthAPI()
    if oauthAPI:
      self.redirect_uri = '%s/redirect' % oauthAPI

  def createAuthRequestURL(self, **kwargs):
    """ Create link for authorization and state of authorization session

        :param basestring,list `**kwargs`: OAuth2 parameters that will be added to request url,
          e.g. **{authorization_endpoint='http://domain.ua/auth', scope=['openid','profile']}
        :return: basestring url, basestring state
    """
    gLogger.info('Create auth URL..')
    authURL = kwargs.get('authorization_endpoint') or self.authorization_endpoint
    url = '%s?state=%s&response_type=code&client_id=%s&access_type=offline' % \
        (authURL, self.state, self.client_id)
    if self.prompt:
      url += '&prompt=%s' % self.prompt
    kwargs['redirect_uri'] = kwargs.get('redirect_uri') or self.redirect_uri
    kwargs['scope'] = kwargs.get('scope') or [] + self.scope
    for key in kwargs:
      if isinstance(kwargs[key],list):
        kwargs[key] = '+'.join(kwargs[key])
      url += '&%s=%s' % (key, kwargs[key])
    return url, self.state

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
    oaDict['idp'] = self.idp
    return S_OK(oaDict)

  def getProxy(self, access_token, proxylifetime=None, voms=None, **kwargs):
    """ Get user proxy from proxy provider
    
        :param basestring access_token: access token that will be use to get proxy
        :param int proxylifetime: period in second that proxy must to live
        :param basestring voms: VOMS name to get proxy with voms extentions
        :param basestring,list `**kwargs`: OAuth2 parameters that will be added to request url,
            e.g. **{authorization_endpoint='http://domain.ua/auth', scope=['openid','profile']}
        :return: S_OK(basestring)/S_ERROR()
    """
    # Prepare URL
    proxylifetime = proxylifetime or self.max_proxylifetime
    url = self.proxy_endpoint or kwargs.get('proxy_endpoint')
    if not url:
      return S_ERROR('No get proxy endpoind found for %s IdP.' % self.idp)
    client_id = self.client_id
    client_secret = self.client_secret
    url += '?client_id=%s&client_secret=%s' % (client_id, client_secret)
    url += '&access_token=%s&proxylifetime=%s' % (access_token, proxylifetime)
    url += '&access_type=offline'
    if self.prompt:
      url += "&prompt=consent"
    if voms:
      result = Registry.getVOs()
      if not result['OK']:
        return result
      if voms not in result['Value']:
        return S_ERROR('%s vo is not registred in DIRAC.' % voms)
      result = Registry.getVOMSServerInfo(voms)
      if not result['OK']:
        return result
      gLogger.info('"%s" VOMS found' % voms)
      vomsname = result['Value'][voms]['VOMSName']
      hostname = result['Value'][voms]['Servers'][0]
      hostDN = result['Value'][voms]['Servers'][hostname]['DN']
      port = result['Value'][voms]['Servers'][hostname]['Port']
      vomses = '"%s" "%s" "%s" "%s" "%s"' % (vomsname, hostname, port, hostDN, vomsname)
      url += '&voname=%s&vomses=%s' % (vomsname, vomses)
    for key in kwargs:
      if isinstance(kwargs[key],list):
        kwargs[key] = '+'.join(kwargs[key])
      url += '&%s=%s' % (key, kwargs[key])
    
    # Get proxy request
    gLogger.notice('Get proxy request: %s' % url)
    r = requests.get(url, verify=False)
    if not r.status_code == 200:
      gLogger.error('HTTP error %s' % r.status_code)
      return S_ERROR(r.status_code)
    gLogger.notice('Success')
    return S_OK(r.text)

  def getUserProfile(self, access_token):
    """ Get user profile
    
        :param basestring access_token: access token
        :return: S_OK(dict)/S_ERROR()
    """
    headers = {'Authorization': 'Bearer ' + access_token}
    r = requests.get(self.userinfo_endpoint, headers=headers, verify=False)
    if not r.status_code == 200:
      return S_ERROR(r.status_code)
    if not r.json():
      return S_ERROR('No expected response.')
    return S_OK(r.json())

  def revokeToken(self, access_token=None, refresh_token=None):
    """ Revoke token
    
        :param basestring access_token: access token
        :param basestring refresh_token: refresh token
        :return: S_OK()/S_ERROR()
    """
    if not self.revocation_endpoint:
      return S_ERROR('Not found revocation endpoint.')
    for key in {'access_token': access_token, 'refresh_token': refresh_token}:
      if tDict[key]:
        r = requests.post("%s?token=%s&token_type_hint=%s" %
                          (self.revocation_endpoint, tDict[key], key), verify=False)
    return S_OK()

  def fetchToken(self, code=None, refresh_token=None):
    """ Update tokens
    
        :param basestring code: authorize code that come with response(authorize code flow)
        :param basestring refresh_token: refresh token
        :return: S_OK(dict)/S_ERROR()
    """
    url = self.token_endpoint
    if not url:
      return S_ERROR('Not found token_endpoint for %s provider' % self.name)
    url += "?client_id=%s&client_secret=%s" % (self.client_id, self.client_secret)
    url += "&access_type=offline"
    if self.prompt:
      url += "&prompt=consent"
    if code:
      if not self.redirect_uri:
        return S_ERROR('Not found redirect_uri for %s provider' % self.name)
      url += "&grant_type=authorization_code&code=%s&redirect_uri=%s" % (code, self.redirect_uri)
    elif refresh_token:
      url += "&grant_type=refresh_token&refresh_token=%s" % refresh_token
    else:
      return S_ERROR('No get any authorization code or refresh token')
    # FIXME: in production need to remove 'verify' parametr
    r = requests.post(url, verify=False)
    if not r.status_code == 200:
      return S_ERROR(r.status_code)
    if 'access_token' not in r.json():
      return S_ERROR('No expected response.')
    return S_OK(r.json())

  def createState(self):
    """ Generates a state string to be used in authorizations
    
        :return: basestring
    """
    return ''.join(random.choice(string.ascii_letters + string.digits) for x in range(30))
