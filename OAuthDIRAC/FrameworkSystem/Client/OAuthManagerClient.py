""" DIRAC OAuthManager Client class encapsulates the methods exposed
    by the OAuthManager service.
"""

__RCSID__ = "$Id$"

from DIRAC import gConfig, gLogger, S_OK, S_ERROR
from DIRAC.Core.Base.Client import Client, createClient
from DIRAC.Core.DISET.RPCClient import RPCClient
from DIRAC.Core.Utilities import DIRACSingleton
from DIRAC.Core.Utilities.DictCache import DictCache

# FIXME: Add cron every 15 min
@createClient('Framework/OAuthManager')
class OAuthManagerClient(Client):
  """ Authentication manager

      Contain IdPsCache cache, with next structure:
      {
        <ID1>: {
          Providers: [ <identity providers> ],
          <identity provider>: [
              {
                <sessions number>: { <tokens> }
              },
              { ... }
            ]
          ],
          DNs: [
            <DN1>: {
              ProxyProvider: [ <proxy providers> ],
              VOMSRoles: [ <VOMSRoles> ],
              ...
            },
            <DN2>: { ... },
          ]
        },
        <ID1>: { ... },
      }
  """
  __metaclass__ = DIRACSingleton.DIRACSingleton

  IdPsCache = DictCache()

  def __init__(self, **kwargs):
    """ Constructor
    """
    super(OAuthManagerClient, self).__init__(**kwargs)
    self.setServer('Framework/OAuthManager')
    self.refreshIdPs()

  def refreshIdPs(self, IDs=None, sessionIDDict=None):
    """ Update cache from OAuthDB

        :param list IDs: list of IDs
        :param dict sessionIDDict: session ID dictionary

        :return: S_OK()/S_ERROR()
    """ 
    if sessionIDDict:
      for ID, infoDict in sessionIDDict.items():
        self.IdPsCache.add(ID, 3600 * 24, value=infoDict)
      return S_OK()

    result = self._getRPC().getIdPsIDs()
    if not result['OK']:
      return result
    for ID, infoDict in result['Value'].items():
      if len(infoDict['Providers']) > 1:
        gLogger.warn('%s user ID used by more that one providers:' % ID, ', '.join(infoDict['Providers']))
      self.IdPsCache.add(ID, 3600 * 24, infoDict)
    return S_OK()
  
  def getIdPsCache(self, IDs=None):
    """ Return IdPs cache

        :param list IDs: IDs

        :return: S_OK(dict)/S_ERROR() -- dictionary contain ID as key and information collected from IdP
    """
    # FIXME: Howto fresh
    __IdPsCache = self.IdPsCache.getDict()
    if not IDs:
      return S_OK(__IdPsCache)
    resDict = {}
    for ID, idDict in __IdPsCache.items():
      if ID in IDs:
        resDict[ID] = idDict
    return S_OK(resDict)
  
  def getIDForSession(self, session):
    """ Find ID for session
    
        :param basestring session: session number
        
        :return: S_OK()/S_ERROR()
    """
    for ID, infoDict in self.IdPsCache.getDict().items():
      for prov in infoDict['Providers']:
        if session in infoDict[prov]:
          return S_OK(ID)
    return S_ERROR('No ID found for session %s' % session)
  
  def getProviderForSession(self, session):
    """ Find identity provider for session
    
        :param basestring session: session number
        
        :return: S_OK()/S_ERROR()
    """
    for ID, infoDict in self.IdPsCache.getDict().items():
      for prov in infoDict['Providers']:
        if session in infoDict[prov]:
          return S_OK(prov)
    return S_ERROR('No provider found for session %s' % session)

  def parseAuthResponse(self, response, state):
    """ Fill session by user profile, tokens, comment, OIDC authorize status, etc.
        Prepare dict with user parameters, if DN is absent there try to get it.
        Create new or modify existend DIRAC user and store the session

        :param dict response: authorization response
        :param basestring state: session number

        :return: S_OK(dict)/S_ERROR()
    """
    result = self._getRPC().parseAuthResponse(response, state)
    if not result['OK']:
      return result
    if result['Value']['Status'] == 'authed':
      refresh = self.refreshIdPs(sessionIDDict=result['Value']['sessionIDDict'])
      if not refresh['OK']:
        return refresh
    return result

gSessionManager = OAuthManagerClient()
