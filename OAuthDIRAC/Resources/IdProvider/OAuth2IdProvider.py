""" IdProvider based on OAuth2 protocol
"""

import re
import urllib
import pprint

from DIRAC import S_OK, S_ERROR, gLogger
from DIRAC.Core.Security.X509Chain import X509Chain  # pylint: disable=import-error
from DIRAC.Resources.IdProvider.IdProvider import IdProvider
from DIRAC.ConfigurationSystem.Client.Helpers import Registry

from OAuthDIRAC.FrameworkSystem.Utilities.OAuth2 import OAuth2
from OAuthDIRAC.FrameworkSystem.Client.OAuthManagerClient import gSessionManager

__RCSID__ = "$Id$"


class OAuth2IdProvider(IdProvider):

  def __init__(self, parameters=None):
    super(OAuth2IdProvider, self).__init__(parameters)
  
  def setParameters(self, parameters):
    self.log = gLogger.getSubLogger('%s/%s' % (__name__, parameters['ProviderName']))
    self.parameters = parameters
    self.oauth2 = OAuth2(parameters['ProviderName'])

  def checkStatus(self, username=None, session=None):
    """ Read ready to work status of identity provider

        :param basestring username: DIRAC user
        :param basestring session: if need to check session

        :return: S_OK(dict)/S_ERROR() -- dictionary contain fields:
                 - 'Status' with ready to work status[ready, needToAuth]
                 - 'AccessToken' with list of access token
    """
    sessions = []
    if session:
      result = self.fetchTokensAndUpdateSession(session)
      if result['OK']:
        sessions += [session]
    if username:
      result = gSessionManager.getSessionsForUserNameProviderName(username, self.parameters['ProviderName'])
      if not result['OK']:
        return result
      sessions += result['Value']
    if not sessions:
      result = self.oauth2.createAuthRequestURL(session)
      if not result['OK']:
        return result
      result['Value']['Status'] = 'needToAuth'
      return result
    return S_OK({'Status': 'ready', 'Sessions': list(set(sessions))})

  def parseAuthResponse(self, response):
    """ Make user info dict:
          - username(preferd user name)
          - nosupport(VOs in response that not in DIRAC)
          - UsrOptns(User profile that convert to DIRAC user options)
          - Tokens(Contain refreshed tokens, type and etc.)
          - Groups(New DIRAC groups that need created)

        :param dict response: response on request to get user profile

        :return: S_OK(dict)/S_ERROR()
    """
    resDict = {}
    result = self.oauth2.fetchToken(response['code'])
    if not result['OK']:
      return result
    tokens = self.__parseTokens(result['Value'])
    result = self.oauth2.getUserProfile(tokens['AccessToken'])
    if not result['OK']:
      return result
    result = self.__parseUserProfile(result['Value'])
    if not result['OK']:
      return result
    userProfile = result['Value']

    for key, value in userProfile.items():
      resDict[key] = value
    result = self.__fetchTokens(tokens)
    if not result['OK']:
      return result
    resDict['Tokens'] = result['Value']
    self.log.debug('Got response dictionary:\n', pprint.pformat(resDict))
    return S_OK(resDict)

  def fetchTokensAndUpdateSession(self, session):
    """ Fetch tokens and update session in DB

        :param basestring,dict session: session number or dictionary

        :return: S_OK()/S_ERROR()
    """
    tokens = session
    if isinstance(session, basestring):
      result = gSessionManager.getSessionTokens(session)
      if not result['OK']:
        return result
      tokens = result['Value']
    result = self.__fetchTokens(tokens)
    if not result['OK']:
      kill = gSessionManager.killSession(session)
      return result if kill['OK'] else kill
    return gSessionManager.updateSession(session, result['Value'])
  
  def __fetchTokens(self, tokens):
    """ Fetch tokens

        :param dict tokens: tokens

        :return: S_OK(dict)/S_ERROR() -- dictionary contain tokens
    """
    result = self.oauth2.fetchToken(refreshToken=tokens['RefreshToken'])
    if not result['OK']:
      return result
    return S_OK(self.__parseTokens(result['Value']))

  def __parseTokens(self, tokens):
    """ Parse session tokens

        :param dict tokens: tokens

        :return: dict
    """
    resDict = {}
    resDict['ExpiresIn'] = tokens.get('expires_in') or 0
    resDict['TokenType'] = tokens.get('token_type') or 'bearer'
    resDict['AccessToken'] = tokens.get('access_token')
    resDict['RefreshToken'] = tokens.get('refresh_token')
    return resDict
  
  def __parseUserProfile(self, userProfile):
    """ Parse user profile

        :param dict userProfile: user profile in OAuht2 format

        :return: S_OK()/S_ERROR()
    """
    resDict = {}
    gname = userProfile.get('given_name')
    fname = userProfile.get('family_name')
    pname = userProfile.get('preferred_username')
    name = userProfile.get('name') and userProfile['name'].split(' ')
    resDict['username'] = pname or gname and fname and gname[0] + fname or name and len(name) > 1 and name[0][0] + name[1] or ''
    resDict['username'] = re.sub('[^A-Za-z0-9]+', '', resDict['username'].lower())[:13]
    self.log.debug('Parse user name:', resDict['username'])

    # Collect user info
    resDict['UsrOptns'] = {}
    resDict['UsrOptns']['DNs'] = {}
    resDict['UsrOptns']['ID'] = userProfile.get('sub')
    if not resDict['UsrOptns']['ID']:
      return S_ERROR('No ID of user found.')
    resDict['UsrOptns']['Email'] = userProfile.get('email')
    resDict['UsrOptns']['FullName'] = gname and fname and ' '.join([gname, fname]) or name and ' '.join(name) or ''
    self.log.debug('Parse user profile:\n', resDict['UsrOptns'])

    # Default DIRAC groups
    resDict['UsrOptns']['Groups'] = self.parameters.get('DiracGroups') or []
    if not isinstance(resDict['UsrOptns']['Groups'], list):
      resDict['UsrOptns']['Groups'] = resDict['UsrOptns']['Groups'].replace(' ','').split(',')
    self.log.debug('Default for groups:', ', '.join(resDict['UsrOptns']['Groups']))
    

    # FIXME: parse DN:VO:Role:ProxyProvider to resDict['UsrOptns'][DNs] = []
    # # Get regex syntax to parse VOs info
    # resDict['nosupport'] = []

    # Read regex syntax to get DNs describe dictionary
    dnClaim = self.parameters.get('Syntax/DNs/claim')
    dnItemRegex = self.parameters.get('Syntax/DNs/item')
    if not dnClaim or not dnItemRegex and not resDict['UsrOptns']['Groups']:
      self.log.warn('No "DiracGroups", no claim with DNs decsribe in Syntax/DNs section found.')
    elif not userProfile.get(dnClaim) and not resDict['UsrOptns']['Groups']:
      self.log.warn('No "DiracGroups", no claim "%s" that decsribe DNs found.' % dnClaim)
    else:
      claimDNsList = userProfile[dnClaim]
      if not isinstance(claimDNsList, list):
        claimDNsList = claimDNsList.split(',')
      
      __prog = re.compile(dnItemRegex)
      for item in claimDNsList:
        result = __prog.match(item)
        if result:
          __parse = result.groupdict()
          resDict['UsrOptns']['DNs'][__parse['DN']] = __parse

    # vomsClaim = self.parameters.get('Syntax/VOMS/claim')
    # vomsItemRegex = self.parameters.get('Syntax/VOMS/item')
    # if not vomsClaim or not vomsItemRegex and not resDict['UsrOptns']['Groups']:
    #   self.log.warn('No "DiracGroups", no claim with VO decsribe in Syntax/VOMS section found.')
    # elif not userProfile.get(vomsClaim) and not resDict['UsrOptns']['Groups']:
    #   self.log.warn('No "DiracGroups", no claim "%s" that decsribe VOs found.' % vomsClaim)
    # else:
    #   claimVOList = userProfile[vomsClaim]
    #   if not isinstance(claimVOList, list):
    #     claimVOList = claimVOList.split(',')
      
      # # Parse claim info to find DIRAC groups
      # self.log.debug('Parse VO VOMSes')
      # result = Registry.getVOs()
      # if not result['OK']:
      #   return result
      # realToDIRACVONames = {}
      # for diracVOName in result['Value']:
      #   vomsName = Registry.getVOOption(diracVOName, 'VOMSName')
      #   if vomsName:
      #     realToDIRACVONames[vomsName] = diracVOName

      # __prog = re.compile(vomsItemRegex)
      # for item in claimVOList:
      #   result = __prog.match(item)
      #   if result:
      #     __parse = result.groupdict()
          
      #     # Convert role to DIRAC record type
      #     __parse['ROLE'] = "/%s%s" % (__parse['VO'], '/Role=%s' % __parse['ROLE'] if __parse['ROLE'] else '')
          
      #     # Parse VO
      #     if __parse['VO'] not in realToDIRACVONames:
      #       resDict['nosupport'].append(__parse['ROLE'])
      #       continue

      #     # Convert to DIRAC group
      #     result = Registry.getVOMSRoleGroupMapping(realToDIRACVONames[__parse['VO']])
      #     if not result['OK']:
      #       return result
      #     noVoms = result['Value']['NoVOMS']
      #     roleGroup = result['Value']['VOMSDIRAC']
      #     groupRole = result['Value']['DIRACVOMS']
          
      #     for group in noVoms:
      #       # Set groups with no role
      #       resDict['UsrOptns']['Groups'].append(group)
          
      #     if __parse['ROLE'] not in roleGroup:
      #       __parse['ROLE'] = __parse['ROLE'].replace('/Role=member', '')
      #       if __parse['ROLE'] not in roleGroup:
      #         resDict['nosupport'].append(__parse['ROLE'])
      #         continue

      #     # Set groups with role
      #     for group in groupRole:
      #       if __parse['ROLE'] == groupRole[group]:
      #         resDict['UsrOptns']['Groups'].append(group)
    # resDict['nosupport'].sort()
    return S_OK(resDict)
  
  def getUserProfile(self, session):
    """ Get user information from identity provider

        :param basestring,dict session: session number or dictionary

        :return: S_OK(dict)/S_ERROR() -- dictionary contain user profile information
    """
    tokens = session
    if isinstance(session, basestring):
      result = gSessionManager.getSessionTokens(session)
      if not result['OK']:
        return result
      tokens = result['Value']
    result = self.oauth2.getUserProfile(tokens['AccessToken'])
    if not result['OK']:
      result = self.__fetchTokens(tokens)
      if result['OK']:
        tokens = result['Value']
        result = self.oauth2.getUserProfile(result['Value']['AccessToken'])
    if not result['OK']:
      kill = gSessionManager.killSession(session)
      return result if kill['OK'] else kill
    userProfile = result['Value']
    result = gSessionManager.updateSession(session, tokens)
    if not result['OK']:
      return result
    return self.__parseUserProfile(userProfile)

  def logOut(self, session):
    """ Revoke tokens

        :param basestring,dict session: session number or dictionary

        :return: S_OK()/S_ERROR()
    """
    tokens = session
    if isinstance(session, basestring):
      result = gSessionManager.getSessionTokens(session)
      if not result['OK']:
        return result
      tokens = result['Value']
    return self.oauth2.revokeToken(tokens['AccessToken'], tokens['RefreshToken'])
