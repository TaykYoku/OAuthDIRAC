""" OAuth class is a front-end to the OAuth Database
"""

import re
import time
import json

from ast import literal_eval
from datetime import datetime

from DIRAC import gConfig, gLogger, S_OK, S_ERROR
from DIRAC.Core.Base.DB import DB
from DIRAC.Core.Security.X509Chain import X509Chain
from DIRAC.ConfigurationSystem.Client.CSAPI import CSAPI
from DIRAC.ConfigurationSystem.Client.Helpers import Registry, Resources

from OAuthDIRAC.FrameworkSystem.Utilities.OAuth2 import OAuth2, getIdPSyntax

__RCSID__ = "$Id$"

gCSAPI = CSAPI()


class OAuthDB(DB):
  """ OAuthDB class is a front-end to the OAuth Database
  """
  tableDict = {'Tokens': {'Fields': {'Id': 'INTEGER AUTO_INCREMENT NOT NULL',
                                     'State': 'VARCHAR(64) NOT NULL',
                                     'Status': 'VARCHAR(32) DEFAULT "prepared"',
                                     'Comment': 'VARCHAR(1000) DEFAULT ""',
                                     'OAuthProvider': 'VARCHAR(255) NOT NULL',
                                     'Token_type': 'VARCHAR(32) DEFAULT "bearer"',
                                     'Access_token': 'VARCHAR(1000)',
                                     'Expires_in': 'DATETIME',
                                     'Refresh_token': 'VARCHAR(1000)',
                                     'Sub': 'VARCHAR(128)',
                                     'UserName': 'VARCHAR(16)',
                                     'UserDN': 'VARCHAR(128)',
                                     'UserSetup': 'VARCHAR(32)',
                                     'Pem': 'BLOB',
                                     'LastAccess': 'DATETIME',
                                     },
                          'PrimaryKey': 'Id',
                          'Engine': 'InnoDB',
                          },
               }

  def __init__(self):
    """ Constructor
    """
    self.__oauth = None
    self.__permValues = ['USER', 'GROUP', 'VO', 'ALL']
    self.__permAttrs = ['ReadAccess', 'PublishAccess']
    DB.__init__(self, 'OAuthDB', 'Framework/OAuthDB')
    retVal = self.__initializeDB()
    if not retVal['OK']:
      raise Exception("Can't create tables: %s" % retVal['Message'])

  def _checkTable(self):
    """ Make sure the tables are created
    """
    return self.__initializeDB()

  def __initializeDB(self):
    """ Create the tables
    """
    retVal = self._query("show tables")
    if not retVal['OK']:
      return retVal

    tablesInDB = [t[0] for t in retVal['Value']]
    tablesD = {}

    if 'Tokens' not in tablesInDB:
      tablesD['Tokens'] = self.tableDict['Tokens']

    return self._createTables(tablesD)

  def cleanZombieSessions(self):
    """ Kill sessions with old states
    
        :return: S_OK()/S_ERROR()
    """
    result = self.__getFromWhere('State', conn='TIMESTAMPDIFF(SECOND,LastAccess,UTC_TIMESTAMP()) > 43200')
    if not result['OK']:
      return result
    states = result['Value']
    if states is not None:
      if len(states) > 1:
        gLogger.notice('Found %s old sessions' % len(states))
        for i in range(0, len(states)):
          result = self.killSession(state=states[i][0])
          if not result['OK']:
            return result
    gLogger.notice('Old sessions was killed')
    return S_OK()

  def getAuthorizationURL(self, OAuthProvider, state=None):
    """ Register new session and return dict with authorization url and state(session number)
    
        :param basestring OAuthProvider: provider name
        :param basestring state: here is able to set session number(optional)
        :return: S_OK(dict)/S_ERROR()
    """
    url, state = OAuth2(OAuthProvider, state=state).createAuthRequestURL()
    # Recording new session
    result = self.insertFields('Tokens', ['State', 'OAuthProvider', 'Comment', 'LastAccess'],
                                         [state, OAuthProvider, url, 'UTC_TIMESTAMP()'])
    if not result['OK']:
      return result
    gLogger.notice('New %s authorization session for %s provider was created' % (state, OAuthProvider))
    return S_OK({'url': url, 'state': state})

  def getLinkByState(self, state):
    """ Return authorization URL from session

        :param basestring state: session number
        :return: S_OK(basestring)/S_ERROR()
    """
    result = self.__getFromWhere('Comment', 'Tokens', State=state,
                                conn='Status = "prepared" and TIMESTAMPDIFF(SECOND,LastAccess,UTC_TIMESTAMP()) < 300')
    if not result['OK']:
      return result
    if result['Value'] is None:
      return S_ERROR('No link found.')
    return S_OK(result['Value'][0][0])

  def proxyRequest(self, proxyProvider, userDict):
    """ Get proxy from proxy provider with OIDC flow authentication

        :param basestring proxyProvider: proxy provider name
        :param dict userDict: user parameters
        :return: S_OK(basestring)/S_ERROR
    """
    __conn = ''
    __params = {'OAuthProvider': proxyProvider}
    DN = 'DN' in userDict and userDict['DN']
    voms = 'voms' in userDict and userDict['voms']
    state = 'state' in userDict and userDict['state']
    userID = 'userID' in userDict and userDict['userID']
    username = 'username' in userDict and userDict['username']
    access_token = 'access_token' in userDict and userDict['access_token']
    proxylivetime = 'proxylivetime' in userDict and userDict['proxylivetime']
    
    # Check provider
    result = Resources.getProxyProviders()
    if not result['OK']:
      return result
    if proxyProvider not in result['Value']:
      return S_ERROR('%s is not proxy provider.' % proxyProvider)
    
    # We need access token to continue
    if not access_token:
      if state:
        __params['State'] = state
      else:
        __conn += 'Status = "authed"'
        if DN:
          __params['UserDN'] = DN
        elif username:
          __params['UserName'] = username
        else:
          return S_ERROR('DN or username need to set.')
        if userID:
          __params['Sub'] = userID
      gLogger.notice('Search access token for proxy request')

      # Search access tokens
      result = self.__getFromWhere(field='Access_token', conn=__conn, **__params)
      if not result['OK']:
        return result
      access_tokens = result['Value']
      if access_tokens is None:
        return S_ERROR('No access_token found.')  
      gLogger.notice('Found %s tokens for proxy request' % len(access_tokens))

      # Trying to update every access token
      for i in range(0, len(access_tokens)):
        gLogger.notice('Try %s' % access_tokens[i][0])
        result = self.fetchToken(accessToken=access_tokens[i][0])
        if not result['OK']:
          gLogger.error(result['Message'])
          continue
        access_token = result['Value']['Access_token']
      if not access_token:
        return S_ERROR('No working access token found')

    # Get proxy request
    result = OAuth2(proxyProvider).getProxy(access_token, proxylivetime, voms)
    if not result['OK']:
      return result
    gLogger.info('Proxy is taken')

    # Get DN
    proxyStr = result['Value']
    chain = X509Chain()
    result = chain.loadProxyFromString(proxyStr)
    if not result['OK']:
      return result
    result = chain.getCredentials()
    if not result['OK']:
      return result

    # Record DN to session
    DN = result['Value']['identity']
    result = self.updateFields('Tokens', ['Expires_in', 'UserDN', 'LastAccess'],
                                         ['UTC_TIMESTAMP()', DN, 'UTC_TIMESTAMP()'],
                               {'Access_token': access_token})
    if not result['OK']:
      return result
    return S_OK({'proxy': proxyStr, 'DN': DN})

  def getProxy(self, proxyProvider, userDict):
    """ Get proxy from generated proxy
        
        :param basestring proxyProvider: proxy provider name
        :param dict userDict: user parameters
        :return: S_OK(basestring)/S_ERROR()
    """
    gLogger.info('Getting proxy from %s provider' % proxyProvider)
    result = self.proxyRequest(proxyProvider, userDict)
    if not result['OK']:
      gLogger.error(result['Message'])
      return result
    return S_OK(result['Value']['proxy'])

  def getUserDN(self, proxyProvider, userDict):
    """ Get DN from generated proxy
        
        :param basestring proxyProvider: proxy provider name
        :param dict userDict: user parameters
        :return: S_OK(basestring)/S_ERROR()
    """
    gLogger.info('Getting proxy from %s provider' % proxyProvider)
    result = self.proxyRequest(proxyProvider, userDict)
    if not result['OK']:
      gLogger.error(result['Message'])
      return result
    return S_OK(result['Value']['DN'])

  def parseAuthResponse(self, code, state):
    """ Fill session by user profile, tokens, comment, OIDC authorize status, etc.
        Prepare dict with user parameters, if DN is absent there try to get it.
        Create new or modify existend DIRAC user and store the session

        :param basestring code: authorization code
        :param basestring state: session number
        :return: S_OK(dict)/S_ERROR
    """
    def __statusComment(comment, status='failed'):
      """ Record comment about some error

          :param basestring comment: some comment
          :param basestring status: authentication status
      """
      for s in [state, state.replace('_proxy', '')]:
        self.updateFields('Tokens', ['Status', 'Comment', 'LastAccess'],
                                    [status, comment, 'UTC_TIMESTAMP()'], {'State': s})
    comment = ''
    status = 'prepared'
    exp_datetime = 'UTC_TIMESTAMP()'

    # Search provider
    result = self.__getFromWhere('OAuthProvider', 'Tokens', State=state)
    if not result['OK']:
      __statusComment(result['Message'])
      return result
    if result['Value'] is None:
      __statusComment('No any provider found.')
      return S_ERROR('No any provider found.')
    OAuthProvider = result['Value'][0][0]
    self.__oauth = OAuth2(OAuthProvider)

    # Parsing response
    gLogger.info('%s: Parsing authentification response.' % state)
    result = self.__oauth.parseAuthResponse(code)
    if not result['OK']:
      __statusComment(result['Message'])
      return result
    oauthDict = result['Value']
    oauthDict['redirect'] = ''
    oauthDict['messages'] = []
    oauthDict['username'] = False
    csModDict = {'UsrOptns': {}, 'Groups': []}
    if 'expires_in' in oauthDict['Tokens']:
      result = self.__datetimePlusSeconds(oauthDict['Tokens']['expires_in'])
      if not result['OK']:
        __statusComment(result['Message'])
        return result
      exp_datetime = result['Value']
    if 'refresh_token' not in oauthDict['Tokens']:
      __statusComment('No refresh token')
      return S_ERROR('No refresh token')

    if OAuthProvider in Resources.getProxyProviders()['Value']:
      # For proxy provider
      gLogger.info('%s: Proxy provider: %s' % (state, OAuthProvider))
      result = self.__getFromWhere('Comment', 'Tokens', State=state.replace('_proxy', ''))
      if not result['OK']:
        __statusComment(result['Message'])
        return result
      if result['Value'] is None:
        __statusComment('Cannot get IdP info dict from "Comment" field: it`s empty')
        return S_ERROR('Cannot get IdP info dict from "Comment" field: it`s empty')
      try:
        csModDict = literal_eval(result['Value'][0][0])
      except Exception as ex:
        __statusComment('Cannot get IdP info dict from "Comment" field: %s' % ex)
        return S_ERROR('Cannot get IdP info dict from "Comment" field: %s' % ex)
      if not isinstance(csModDict, dict):
        __statusComment('Cannot get IdP info dict from "Comment" field: it`s not dict')
        return S_ERROR('Cannot get IdP info dict from "Comment" field: it`s not dict')
      status = 'authed'
      result = self.updateFields('Tokens', ['Status', 'Token_type', 'Access_token', 'Expires_in',
                                            'Refresh_token', 'Sub', 'UserName', 'LastAccess'],
                                           [status, oauthDict['Tokens']['token_type'],
                                            oauthDict['Tokens']['access_token'],
                                            exp_datetime, oauthDict['Tokens']['refresh_token'],
                                            oauthDict['UserProfile']['sub'],
                                            csModDict['username'], 'UTC_TIMESTAMP()'],
                                 {'State': state})
      if not result['OK']:
        __statusComment(result['Message'])
        return result
      result = self.getUserDN(OAuthProvider, {"state": state})
      if not result['OK']:
        __statusComment(result['Message'])
        return result
      proxyDN = result['Value']
      if proxyDN not in csModDict['UsrOptns']['DN']:
        csModDict['UsrOptns']['DN'].append(proxyDN)
      csModDict['UsrOptns']['DN'] = ','.join(csModDict['UsrOptns']['DN'])
      if 'Groups' not in csModDict['UsrOptns']:
        __statusComment('Cannot found any groups in IdP record field')
        return S_ERROR('Cannot found any groups in IdP record field')
      secDN = proxyDN.replace('/', '-').replace('=', '_')
      csModDict['UsrOptns']['DNProperties/%s/Groups' % secDN] = ','.join(csModDict['UsrOptns']['Groups'])
      csModDict['UsrOptns']['DNProperties/%s/ProxyProviders' % secDN] = OAuthProvider

    elif OAuthProvider in Resources.getIdPs()['Value']:
      # For identity provider
      gLogger.info('%s: Identity provider: %s' % (state, OAuthProvider))
      result = self.prepareUserParameters(OAuthProvider, **oauthDict['UserProfile'])
      if not result['OK']:
        __statusComment(result['Message'])
        return result
      csModDict = result['Value']
      oauthDict['username'] = csModDict['username']
      if not csModDict['UsrOptns']['Groups'] and not csModDict['Groups'] and not csModDict['UsrExist']:
        comment = 'We not found any registred DIRAC groups that mached with your profile. '
        comment += 'So, your profile has the same access that Visitor DIRAC user.'
        __statusComment(comment, status='visitor')
        return S_OK({'redirect': '', 'Messages': comment})
      else:
        proxyProvider = Resources.getIdPOption(OAuthProvider, 'proxy_provider')
        
        if proxyProvider:
          # Looking DN in user configuration
          gLogger.notice('Search user DN in configuration')
          result = Registry.getDNFromProxyProviderForUserID(proxyProvider, oauthDict['UserProfile']['sub'])
          
          if not result['OK']:
            # Try to get DN from proxy provider as default
            gLogger.notice('Getting user DN throught %s proxy provider as default' % proxyProvider)
            result = ProxyProviderFactory().getProxyProvider(proxyProvider)
            if not result['OK']:
              __statusComment(result['Message'])
              return result
            providerObj = result['Value']
            userDict = {"username": csModDict['username'], 
                        "userID": csModDict['UsrOptns']['ID']}
            result = providerObj.getDN(userDict)
          
          if result['OK']:
            # Add DN to user parameters
            proxyDN = result['Value']
            gLogger.notice('DN is %s' % proxyDN)
            if proxyDN not in csModDict['UsrOptns']['DN']:
              csModDict['UsrOptns']['DN'].append(proxyDN)
            csModDict['UsrOptns']['DN'] = ','.join(csModDict['UsrOptns']['DN'])
            if 'Groups' not in csModDict['UsrOptns']:
              __statusComment('Cannot found any groups in IdP record field')
              return S_ERROR('Cannot found any groups in IdP record field')
            secDN = proxyDN.replace('/', '-').replace('=', '_')
            csModDict['UsrOptns']['DNProperties/%s/Groups' % secDN] = ','.join(csModDict['UsrOptns']['Groups'])
            csModDict['UsrOptns']['DNProperties/%s/ProxyProviders' % secDN] = proxyProvider
            result = self.updateFields('Tokens', ['UserDN', 'LastAccess'],
                                                  [proxyDN, 'UTC_TIMESTAMP()'],
                                        {'State': state})
            if not result['OK']:
              __statusComment(result['Message'])
              return result
          
          elif Resources.getProxyProviderOption(proxyProvider, 'method') == 'oAuth2':
            # If cannot get DN and proxy provider with OIDC authorization flow
            #   need to initialize new OIDC authorization flow
            gLogger.notice('Initialize new authorization flow to %s provider to get user DN' % proxyProvider)
            result = self.getAuthorizationURL(proxyProvider, state + '_proxy')
            if not result['OK']:
              __statusComment(result['Message'])
              return result
            oauthDict['redirect'] = result['Value']['url']
            comment = json.dumps(csModDict)
          elif not csModDict['UsrOptns']['DN']:
            __statusComment('No DN returned from %s OAuth provider' % OAuthProvider)
            return S_ERROR('No DN returned from %s OAuth provider' % OAuthProvider)
        elif not csModDict['UsrOptns']['DN']:
          __statusComment('No DN returned from %s OAuth provider' % OAuthProvider)
          return S_ERROR('No DN returned from %s OAuth provider' % OAuthProvider)
      result = self.updateFields('Tokens', ['Status', 'Comment', 'Token_type', 'Access_token', 'Expires_in',
                                            'Refresh_token', 'Sub', 'UserName', 'LastAccess'],
                                           [status, comment, oauthDict['Tokens']['token_type'],
                                            oauthDict['Tokens']['access_token'], exp_datetime,
                                            oauthDict['Tokens']['refresh_token'], oauthDict['UserProfile']['sub'],
                                            oauthDict['username'], 'UTC_TIMESTAMP()'],
                                 {'State': state})
      if not result['OK']:
        __statusComment(result['Message'])
        return result
    else:
      __statusComment('No configuration found for %s provider' % OAuthProvider)
      return S_ERROR('No configuration found for %s provider' % OAuthProvider)

    if not oauthDict['redirect']:
      # If not need additional authorization to proxy provider add new user to CS or modify existed
      gLogger.notice("%s: Prepring parameters for registeration new DIRAC user:\n %s" % (state, csModDict))
      if 'noregvos' in csModDict:
        msg = '%s unsupported by DIRAC. ' % str(csModDict['noregvos'])
        msg += 'Please contact with administrators of this VOs to register it in DIRAC.'
        oauthDict['messages'].append(msg)
      for group in csModDict['Groups']:
        result = gCSAPI.addGroup(group, csModDict['Groups'][group])
        if not result['OK']:
          __statusComment(result['Message'])
          return result
      result = gCSAPI.modifyUser(csModDict['username'], csModDict['UsrOptns'], True)
      if not result['OK']:
        __statusComment(result['Message'])
        return result
      result = gCSAPI.commitChanges()
      if not result['OK']:
        __statusComment(result['Message'])
        return result
      __statusComment('', status='authed')
    return S_OK({'redirect': oauthDict['redirect'], 'Messages': oauthDict['messages']})

  def getFieldByState(self, state, value=['OAuthProvider', 'Sub', 'State', 'Status', 'Comment', 'Token_type',
                                          'Access_token', 'Expires_in', 'Refresh_token', 'UserName', 'LastAccess']):
    """ Get fields from session

        :param basestring state: session number
        :param basestring,list value: fields that need to return from session record
        :result: S_OK(dict)/S_ERROR()
    """
    result = self.updateFields('Tokens', ['LastAccess'], ['UTC_TIMESTAMP()'], {'State': state})
    if not resul['OK']:
      return result
    if not isinstance(value,list):
      value = list(value)
    return self.__getListFromWhere(value, 'Tokens', State=state)

  def killSession(self, state=None, accessToken=None):
    """ Remove session
    
        :param basestring state: session number
        :param basestring accessToken: access token as a filter for searching
        :return: S_OK()/S_ERROR()
    """
    conDict = {}
    if state:
      conDict['State'] = state
    if accessToken:
      conDict['Access_token'] = accessToken
    result = self.__getListFromWhere(['OAuthProvider', 'Access_token', 'Refresh_token', 'State'], 'Tokens', conn=conn)
    if not result['OK']:
      return result
    rmDict = result['Value']
    OAuth2(rmDict['OAuthProvider']).revokeToken(rmDict['Access_token'], rmDict['Refresh_token'])
    if state:
      result = self.deleteEntries('Tokens', condDict={'State': rmDict['State']})
      if not result['OK']:
        return result
    gLogger.notice('%s session was killed')
    return S_OK()

  def fetchToken(self, accessToken=None, state=None):
    """ Refresh tokens and return tokens dict

        :param basestring token: access token
        :param basestring state: session number where are store tokens
        :return: S_OK(dict)/S_ERROR()
    """
    params = {'Status': 'authed'}
    if state:
      params['State'] = state
      gLogger.notice('Fetching tokens in %s session' % state)
    elif accessToken:
      params['Access_token'] = accessToken
      gLogger.notice('Fetching tokens by access token')
    else:
      return S_ERROR('Need set access token or state')
    gLogger.notice('Search session record')
    result = self.__getListFromWhere(['Access_token', 'Expires_in', 'Refresh_token', 'OAuthProvider', 'State'],
                                    'Tokens', **params)
    if not result['OK']:
      return result
    resD = result['Value']
    if not resD['OAuthProvider']:
      return S_ERROR('No OAuthProvider found.')
    
    # Check access tokek time left
    timeLeft = 0
    if resD['Expires_in']:
      result = self.__leftSeconds(resD['Expires_in'])
      if not result['OK']:
        return result
      timeLeft = result['Value']
    gLogger.notice('Left seconds of access token: %s' % str(timeLeft))
    tD = {}
    
    if timeLeft < 1800:
      # Refresh tokens
      result = OAuth2(resD['OAuthProvider']).fetchToken(refresh_token=resD['Refresh_token'])
      if not result['OK']:
        return result
      gLogger.notice('Fechted from %s proxy provider' % resD['OAuthProvider'])
      tD = result['Value']
      exp_datetime = 'UTC_TIMESTAMP()'
      if 'expires_in' in tD:
        result = self.__datetimePlusSeconds(tD['expires_in'])
        if not result['OK']:
          return result
        exp_datetime = result['Value']
      refresh_token = 'refresh_token' in tD and tD['refresh_token'] or None
      result = self.updateFields('Tokens', ['Token_type', 'Access_token', 'Expires_in',
                                            'Refresh_token', 'LastAccess'],
                                           [tD['token_type'], tD['access_token'], exp_datetime,
                                            refresh_token, 'UTC_TIMESTAMP()'],
                                 {'Access_token': token})
      if not result['OK']:
        return result
      for k in tD.keys():
        resD[k.capitalize()] = tD[k]
    return S_OK(resD)

  def prepareUserParameters(self, idp, **kwargs):
    """ Convert user profile to parameters dict that needed to modify user in CS:
          username, DN as list, Groups, ID, email, etc.
        
        :param basestring idp: provider name
        :param basestring,list `**kwargs`: user parameters that will be added to CS
        :return: S_OK(dict)/S_ERROR()
    """
    prepDict = {'UsrOptns': {}, 'Groups': []}
    prepDict['noregvos'] = []
    prepDict['UsrExist'] = ''
    prepDict['UsrOptns']['DN'] = []
    prepDict['UsrOptns']['Groups'] = []
    for param in ['sub', 'email', 'name']:
      if param not in kwargs:
        return S_ERROR('No found %s parameter on dict.' % param)
    
    # Set ID, EMail
    prepDict['UsrOptns']['ID'] = kwargs['sub']
    prepDict['UsrOptns']['Email'] = kwargs['email']
    result = gCSAPI.listUsers()
    if not result['OK']:
      return result
    allusrs = result['Value']
    
    # Look username
    result = Registry.getUsernameForID(kwargs['sub'])
    if result['OK']:
      prepDict['UsrExist'] = 'Yes'
      pre_usrname = result['Value']
      result = Registry.getDNForUsername(pre_usrname)
      if not result['OK']:
        return result
      prepDict['UsrOptns']['DN'].extend(result['Value'])
    
    else:
      # Gernerate new username
      if 'preferred_username' in kwargs:
        pre_usrname = kwargs['preferred_username'].lower()
      else:
        if 'family_name' in kwargs and 'given_name' in kwargs:
          pre_usrname = '%s %s' % (kwargs['given_name'], kwargs['family_name'])
        else:
          pre_usrname = kwargs['name']
        pre_usrname = pre_usrname.lower().split(' ')[0][0] + pre_usrname.lower().split(' ')[1]
        pre_usrname = pre_usrname[:6]
      for i in range(0, 100):
        if pre_usrname not in allusrs:
          break
        pre_usrname = pre_usrname + str(i)
    
    # Set username
    prepDict['username'] = pre_usrname
    
    # Set DN
    if 'DN' in kwargs:
      prepDict['UsrOptns']['DN'].append(kwargs['DN'])
    
    # Parse VO/Role from IdP
    defGroup = Resources.getIdPOption(idp, 'dirac_groups')
    prepDict['UsrOptns']['Groups'].append(defGroup) 
    result = getIdPSyntax(idp, 'VOMS')
    if result['OK']:
      synDict = result['Value']
      if synDict['claim'] not in kwargs:
        return S_ERROR('No found needed claim: %s.' % synDict['claim'])
      voFromClaimList = kwargs[synDict['claim']]
      if not isinstance(voFromClaimList, (list,)):
        voFromClaimList = voFromClaimList.split(',')
      for item in voFromClaimList:
        r = synDict['vo'].split('<VALUE>')
        if not re.search(r[0], item):
          continue
        
        # Parse VO
        vo = re.sub(r[1], '', re.sub(r[0], '', item))
        allvos = Registry.getVOs()
        if not allvos['OK']:
          return allvos
        if vo not in allvos['Value']:
          prepDict['noregvos'].append(vo)
          continue
        r = synDict['role'].split('<VALUE>')
        
        # Parse Role
        role = re.sub(r[1], '', re.sub(r[0], '', item))
        result = Registry.getVOMSRoleGroupMapping(vo)
        if not result['OK']:
          return result
        roleGroup = result['Value']['VOMSDIRAC']
        groupRole = result['Value']['DIRACVOMS']
        noVoms = result['Value']['NoVOMS']
        
        for group in noVoms:
          # Set groups with no role
          prepDict['UsrOptns']['Groups'].append(group)
        
        if role not in roleGroup:
          # Create new group
          group = vo + '_' + role
          properties = {'VOMSRole': role, 'VOMSVO': vo, 'VO': vo, 'Properties': 'NormalUser', 'Users': pre_usrname}
          prepDict['Groups'].append({group: properties})
        
        else:
          # Set groups with role
          for group in groupRole:
            if role == groupRole[group]:
              prepDict['UsrOptns']['Groups'].append(group)
    elif not prepDict['UsrOptns']['Groups']:
      return S_ERROR('No "dirac_groups", no Syntax section in configuration file.')
    return S_OK(prepDict)

  def __getFromWhere(self, field='*', table='Tokens', conn='', **kwargs):
    """ Get field from table where some filter
    """
    if conn:
      conn += ' and '
    for key in kwargs:
      conn += '%s = "%s" and ' % (key, str(kwargs[key]))
    result = self._query('SELECT %s FROM %s WHERE %s True' % (field, table, conn))
    if not result['OK']:
      return result
    if len(result['Value']) == 0:
      result['Value'] = None
    else:
      result['Value'] = list(result['Value'])
    return result

  def __getListFromWhere(self, fields=[], table='Tokens', conn='', **kwargs):
    """ Get fields from table where some filter
    """
    resD = {}
    for i in fields:
      result = self.__getFromWhere(field=i, table=table, conn=conn, **kwargs)
      if not result['OK']:
        return result
      if result['Value'] is not None:
        resD[i] = result['Value'][0][0]
      else:
        resD[i] = None
    return S_OK(resD)

  def __datetimePlusSeconds(self, seconds):
    """ Add seconds to time in parameter

        :param int seconds: seconds that need to add
        :return S_OK(datetime)/S_ERROR()
    """
    result = self._query('SELECT ADDDATE(UTC_TIMESTAMP(), INTERVAL %s SECOND)' % seconds)
    if not result['OK']:
      return result
    if len(result['Value']) == 0:
      return S_OK(datetime.now().strftime('%Y-%m-%d %H:%M:%S'))
    return S_OK(result['Value'][0][0].strftime('%Y-%m-%d %H:%M:%S'))

  def __leftSeconds(self, date):
    """ Return difference in a seconds of time in parameter and current time

        :param datetime date: time that need to check with current
        :return S_OK(int)/S_ERROR()
    """
    result = self._query('SELECT TIMESTAMPDIFF(SECOND,UTC_TIMESTAMP(),"%s");' % date)
    if not result['OK']:
      return result
    if len(result['Value']) == 0:
      return S_OK(0)
    return S_OK(result['Value'][0][0])
