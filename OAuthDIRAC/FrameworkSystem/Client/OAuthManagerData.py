""" DIRAC OAuthManager Client class encapsulates the methods exposed
    by the OAuthManager service.
"""

from DIRAC import gLogger, S_OK, S_ERROR
from DIRAC.Core.Utilities import ThreadSafe, DIRACSingleton
from DIRAC.Core.Utilities.DictCache import DictCache

__RCSID__ = "$Id$"


gIdPsIDsSync = ThreadSafe.Synchronizer()


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
    self.__IdPsCache = DictCache()
    self.refreshIdPs()

  @gIdPsIDsSync
  def refreshIdPs(self, IDs=None, sessionIDDict=None):
    """ Update cache from OAuthDB or dictionary

        :param list IDs: list of IDs
        :param dict sessionIDDict: session ID dictionary

        :return: S_OK()/S_ERROR()
    """
    # Update cache from dictionary
    if sessionIDDict:
      for ID, infoDict in sessionIDDict.items():
        self.__IdPsCache.add(ID, 3600 * 24, value=infoDict)
      return S_OK()

    # Update cache from DB
    self.__IdPsCache.add('Fresh', 60 * 15, value=True)
    try:
      from OAuthDIRAC.FrameworkSystem.Client.OAuthManagerClient import gSessionManager
    except Exception:
      return S_ERROR('OAuthManager not ready.')
    result = gSessionManager.getIdPsIDs()
    if result['OK']:
      for ID, infoDict in result['Value'].items():
        if len(infoDict['Providers']) > 1:
          gLogger.warn('%s user ID used by more that one providers:' % ID, ', '.join(infoDict['Providers']))
        self.__IdPsCache.add(ID, 3600 * 24, infoDict)
    return S_OK() if result['OK'] else result
  
  def getIdPsCache(self, IDs=None):
    """ Return IdPs cache

        :param list IDs: IDs

        :return: S_OK(dict)/S_ERROR() -- dictionary contain ID as key and information collected from IdP
    """
    # Update cache if not actual
    if not self.__IdPsCache.get('Fresh'):
      result = self.refreshIdPs()
      if not result['OK']:
        return result
    idPsCache = self.__IdPsCache.getDict()

    # Return cache without Fresh key
    idPsCache.pop('Fresh', None)
    if not IDs:
      return S_OK(idPsCache)
    resDict = {}
    for ID, idDict in idPsCache.items():
      if ID in IDs:
        resDict[ID] = idDict
    return S_OK(resDict)

  def getIDForSession(self, session):
    """ Find ID for session
    
        :param basestring session: session number
        
        :return: S_OK()/S_ERROR()
    """
    idPsCache = self.__IdPsCache.getDict()
    idPsCache.pop('Fresh', None)
    for ID, infoDict in idPsCache.items():
      for prov in infoDict['Providers']:
        if session in infoDict[prov]:
          return S_OK(ID)
    result = self.refreshIdPs()
    if not result['OK']:
      return result
    idPsCache = self.__IdPsCache.getDict()
    idPsCache.pop('Fresh', None)
    for ID, infoDict in idPsCache.items():
      for prov in infoDict['Providers']:
        if session in infoDict[prov]:
          return S_OK(ID)
    return S_ERROR('No ID found for session %s' % session)


gOAuthManagerData = OAuthManagerData()
