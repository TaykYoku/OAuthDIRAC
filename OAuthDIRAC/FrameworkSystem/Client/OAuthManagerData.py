""" DIRAC OAuthManager Client class encapsulates the methods exposed
    by the OAuthManager service.
"""

from DIRAC import gLogger, S_OK, S_ERROR
from DIRAC.Core.Utilities import DIRACSingleton
from DIRAC.Core.Utilities.DictCache import DictCache
from DIRAC.Core.DISET.RPCClient import RPCClient

__RCSID__ = "$Id$"


class OAuthManagerData(object):
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
          ],
          DNs: {
            <DN1>: {
              ProxyProvider: [ <proxy providers> ],
              VOMSRoles: [ <VOMSRoles> ],
              ...
            },
            <DN2>: { ... },
          }
        },
        <ID2>: { ... },
      }
  """
  __metaclass__ = DIRACSingleton.DIRACSingleton


  def __init__(self):
    """ Constructor
    """
    IdPsCache = DictCache()
    self.refreshIdPs()

  def refreshIdPs(self, IDs=None, sessionIDDict=None):
    """ Update cache from OAuthDB or dictionary

        :param list IDs: list of IDs
        :param dict sessionIDDict: session ID dictionary

        :return: S_OK()/S_ERROR()
    """
    # Update cache from dictionary
    if sessionIDDict:
      for ID, infoDict in sessionIDDict.items():
        self.IdPsCache.add(ID, 3600 * 24, value=infoDict)
      return S_OK()

    # Update cache from DB
    self.IdPsCache.add('Fresh', 60 * 15, value=True)
    rpcClient = RPCClient("Framework/OAuthManager", timeout=120)
    retVal = rpcClient.getIdPsIDs()
    if result['OK']:
      for ID, infoDict in result['Value'].items():
        if len(infoDict['Providers']) > 1:
          gLogger.warn('%s user ID used by more that one providers:' % ID, ', '.join(infoDict['Providers']))
        self.IdPsCache.add(ID, 3600 * 24, infoDict)
    return S_OK() if result['OK'] else result
  
  def getIdPsCache(self, IDs=None):
    """ Return IdPs cache

        :param list IDs: IDs

        :return: S_OK(dict)/S_ERROR() -- dictionary contain ID as key and information collected from IdP
    """
    # Update cache if not actual
    if not self.IdPsCache.get('Fresh'):
      result = self.refreshIdPs()
      if not result['OK']:
        return result
    __IdPsCache = self.IdPsCache.getDict()

    # Return cache without Fresh key
    __IdPsCache.pop('Fresh', None)
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
    __IdPsCache = self.IdPsCache.getDict()
    __IdPsCache.pop('Fresh', None)
    for ID, infoDict in __IdPsCache.items():
      for prov in infoDict['Providers']:
        if session in infoDict[prov]:
          return S_OK(ID)
    result = self.refreshIdPs()
    if not result['OK']:
      return result
    __IdPsCache = self.IdPsCache.getDict()
    __IdPsCache.pop('Fresh', None)
    for ID, infoDict in __IdPsCache.items():
      for prov in infoDict['Providers']:
        if session in infoDict[prov]:
          return S_OK(ID)
    return S_ERROR('No ID found for session %s' % session)


gOAuthManagerData = OAuthManagerData()
