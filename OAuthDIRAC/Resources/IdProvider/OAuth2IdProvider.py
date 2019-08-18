""" IdProvider based on OAuth2 protocol
"""

import re
import urllib

from DIRAC import S_OK, S_ERROR, gLogger
from DIRAC.Core.Security.X509Chain import X509Chain  # pylint: disable=import-error
from DIRAC.ConfigurationSystem.Client.Helpers import Registry

from OAuthDIRAC.Resources.IdProvider.IdProvider import IdProvider
from OAuthDIRAC.FrameworkSystem.Utilities.OAuth2 import OAuth2
from OAuthDIRAC.FrameworkSystem.Client.OAuthManagerClient import OAuthManagerClient

__RCSID__ = "$Id$"


class OAuth2IdProvider(IdProvider):

  def __init__(self, parameters=None):
    super(OAuth2IdProvider, self).__init__(parameters)
    self.log = gLogger.getSubLogger(__name__)
  
  def setParameters(self, parameters):
    self.parameters = parameters
    self.oauth2 = OAuth2(parameters['ProviderName'])

  def checkStatus(self, sessionDict):
    """ Read ready to work status of identity provider

        :param dict sessionDict: session dictionary

        :return: S_OK(dict)/S_ERROR() -- dictionary contain fields:
                 - 'Status' with ready to work status[ready, needToAuth]
                 - 'AccessToken' with list of access token
    """
    refreshToken = sessionDict and sessionDict.get('RefreshToken')
    state = sessionDict and sessionDict.get('State')
    if state:
      result = self.oauth2.fetchToken(refreshToken=refreshToken)
      if result['OK']:
        tD = {}
        tD['ExpiresIn'] = result['Value'].get('expires_in') or 0
        tD['TokenType'] = result['Value'].get('token_type') or 'bearer'
        tD['AccessToken'] = result['Value'].get('access_token')
        tD['RefreshToken'] = result['Value'].get('refresh_token')
        return S_OK({'Status': 'ready', 'Tokens': tD, 'Session': state})
    result = self.oauth2.createAuthRequestURL(state=state)
    if result['OK']:
      result['Value']['Status'] = 'needToAuth'   
    return result

  def parseAuthResponse(self, response):
    """ Make user info dict:
          - username(preferd user name)
          - noregvos(VOs in response that not in DIRAC)
          - UsrOptns(User profile that convert to DIRAC user options)
          - Tokens(Contain refreshed tokens, type and etc.)
          - Groups(New DIRAC groups that need created)

        :param dict response: response on request to get user profile

        :return: S_OK(dict)/S_ERROR()
    """
    result = self.oauth2.parseAuthResponse(response['code'])
    if not result['OK']:
      return result
    responseD = result['Value']

    resDict = {}

    # Collect tokens info
    resDict['Tokens'] = {}
    resDict['Tokens']['ExpiresIn'] = responseD['Tokens'].get('expires_in') or 0
    resDict['Tokens']['TokenType'] = responseD['Tokens'].get('token_type') or 'bearer'
    resDict['Tokens']['AccessToken'] = responseD['Tokens'].get('access_token')
    resDict['Tokens']['RefreshToken'] = responseD['Tokens'].get('refresh_token')

    # Parse user name
    gname = responseD['UserProfile'].get('given_name')
    fname = responseD['UserProfile'].get('family_name')
    pname = responseD['UserProfile'].get('preferred_username')
    name = responseD['UserProfile'].get('name') and responseD['UserProfile']['name'].split(' ')
    resDict['username'] = pname or gname and fname and gname[0] + fname or name and len(name) > 1 and name[0][0] + name[1] or ''
    resDict['username'] = re.sub('[^A-Za-z0-9]+', '', resDict['username'].lower())[:13]

    # Collect user info
    resDict['UsrOptns'] = {}
    resDict['UsrOptns']['DN'] = responseD['UserProfile'].get('dn') or []
    resDict['UsrOptns']['ID'] = responseD['UserProfile'].get('sub')
    if not resDict['UsrOptns']['ID']:
      return S_ERROR('No ID of user found.')
    resDict['UsrOptns']['EMail'] = responseD['UserProfile'].get('email')
    resDict['UsrOptns']['Groups'] = self.parameters.get('DiracGroups') or []
    if not isinstance(resDict['UsrOptns']['Groups'], list):
      resDict['UsrOptns']['Groups'] = resDict['UsrOptns']['Groups'].replace(' ','').split(',')
    resDict['UsrOptns']['FullName'] = gname and fname and ' '.join([gname, fname]) or name and ' '.join(name) or ''
    
    # Get regex syntax to parse VOs info
    resDict['Groups'] = []
    resDict['noregvos'] = []
    vomsClaim = self.parameters.get('Syntax/VOMS/claim')
    vomsVORegex = self.parameters.get('Syntax/VOMS/vo')
    vomsRoleRegex = self.parameters.get('Syntax/VOMS/role')
    if not vomsClaim or not vomsVORegex or not vomsRoleRegex and not resDict['UsrOptns']['Groups']:
      self.log.warn('No "DiracGroups", no claim with VO decsribe in Syntax/VOMS section found.')
    else:
      claimVOList = responseD['UserProfile'][vomsClaim]
      if not isinstance(claimVOList, list):
        claimVOList = claimVOList.split(',')
      
      # Parse claim info to find DIRAC groups
      for item in claimVOList:
        if re.search(vomsVORegex.replace('<VALUE>', '.*'), item):

          # Parse VO
          regex = vomsVORegex.split('<VALUE>')
          vo = re.sub(regex[1], '', re.sub(regex[0], '', item))
          allvos = Registry.getVOs()
          if not allvos['OK']:
            return allvos
          if vo not in allvos['Value']:
            resDict['noregvos'].append(vo)
            continue

          # Parse Role
          regex = vomsRoleRegex.split('<VALUE>')
          role = re.sub(regex[1], '', re.sub(regex[0], '', item))
          
          # Convert to DIRAC group
          result = Registry.getVOMSRoleGroupMapping(vo)
          if not result['OK']:
            return result
          noVoms = result['Value']['NoVOMS']
          roleGroup = result['Value']['VOMSDIRAC']
          groupRole = result['Value']['DIRACVOMS']
          
          for group in noVoms:
            # Set groups with no role
            resDict['UsrOptns']['Groups'].append(group)
          
          if role not in roleGroup:
            # Create new group
            group = vo + '_' + role
            properties = {'VOMSRole': role, 'VOMSVO': vo, 'VO': vo, 'Properties': 'NormalUser'}
            resDict['Groups'].append({group: properties})
          
          else:
            # Set groups with role
            for group in groupRole:
              if role == groupRole[group]:
                resDict['UsrOptns']['Groups'].append(group)

    return S_OK(resDict)

  def getCredentials(self, kwargs):
    """ Collect user credentials to dict

        :param basestring kwargs: parameters that need add to search filter

        :return: S_OK(dict)/S_ERROR()
    """
    stateAuth = kwargs.get('stateAuth') or ''
    __credDict = {}
    result = OAuthManagerClient().getUsrnameForState(stateAuth)
    if not result['OK']:
      return result
    if 'state' not in result['Value'] or 'username' not in result['Value']:
      return S_ERROR('Cannot get session state or user name')
    stateNew = result['Value']['state']
    __credDict['username'] = result['Value']['username']
    result = Registry.getDNForUsername(__credDict['username'])
    if not result['OK']:
      __credDict['validDN'] = False
      return S_ERROR("Cannot get DN for %s" % __credDict['username'])
    __credDict['validDN'] = True
    __credDict['DN'] = result['Value'][0]
    result = Registry.getCAForUsername(__credDict['username'])
    if result['OK']:
      __credDict['issuer'] = result['Value'][0]
    return S_OK({'Session': stateNew, 'credDict': __credDict})

  def logOut(self, sessionDict):
    """ Revoke tokens

        :param dict sessionDict: session dictionary

        :return: S_OK()/S_ERROR()
    """
    return self.oauth2.revokeToken(sessionDict['AccessToken'], sessionDict['RefreshToken'])
