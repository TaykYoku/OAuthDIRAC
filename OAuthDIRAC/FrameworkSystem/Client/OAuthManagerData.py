""" DIRAC OAuthManager Client class encapsulates the methods exposed
    by the OAuthManager service.
"""

from DIRAC import gLogger, S_OK, S_ERROR
from DIRAC.Core.Utilities import ThreadSafe, DIRACSingleton
from DIRAC.Core.Utilities.DictCache import DictCache

__RCSID__ = "$Id$"


# gIdPsIDsSync = ThreadSafe.Synchronizer()
gCacheProfiles = ThreadSafe.Synchronizer()
gCacheSessions = ThreadSafe.Synchronizer()


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

      __cacheSessions cache, with next structure:
      {
        <session1>: {
          ID: ..,
          Provider: ..,
          Tokens: { <tokens> }
        },
        <session2>: { ... }
      }

      __cacheProfiles cache, with next structure:
      {
        <ID1>: {
          Provider: ..,
          DNs: {
            <DN1>: {
              ProxyProvider: [ <proxy providers> ],
              VOMSRoles: [ <VOMSRoles> ],
              ...
            },
            <DN2>: { ... },
          }
        },
        <ID2>: { ... }
      }
  """
  __metaclass__ = DIRACSingleton.DIRACSingleton

  __cacheSessions = DictCache()
  __cacheProfiles = DictCache()

  # def __init__(self):
  #   """ Constructor
  #   """
  #   pass
  #   # self.__IdPsCache = DictCache()
  #   #self.refreshIdPs()

  @gCacheProfiles
  def getProfiles(self, userID=None):
    """ Get cache information

        :param str userID: user ID

        :return: dict
    """
    if userID:
      return self.__cacheProfiles.get(userID)
    return self.__cacheProfiles.getDict()

  @gCacheProfiles
  def updateProfiles(self, data, time=3600 * 24):
    """ Get cache information

        :param dict data: ID information data
        :param int time: lifetime
    """
    for oid, info in data.items():
      self.__cacheProfiles.add(oid, time, value=info)

  @gCacheSessions
  def getSessions(self, session=None):
    """ Get cache information

        :param str userID: user ID

        :return: dict
    """
    if session:
      return self.__cacheSessions.get(session)
    return self.__cacheSessions.getDict()

  @gCacheSessions
  def updateSessions(self, data, time=3600 * 24):
    """ Get cache information

        :param dict data: ID information data
        :param int time: lifetime
    """
    for oid, info in data.items():
      self.__cacheSessions.add(oid, time, value=info)

  def resfreshSessions(self, session=None):
    """ Refresh session cache from service

        :param str session: session to update

        :return: S_OK()/S_ERROR()
    """
    from DIRAC.Core.DISET.RPCClient import RPCClient
    result = RPCClient('Framework/OAuthManager').getSessionsInfo(session=session)
    if result['OK']:
      self.updateSessions(result['Value'])
    return result
  
  def resfreshProfiles(self, userID=None):
    """ Refresh profiles cache from service

        :param str userID: userID to update

        :return: S_OK()/S_ERROR()
    """
    from DIRAC.Core.DISET.RPCClient import RPCClient
    result = RPCClient('Framework/OAuthManager').getIdProfiles(userID=userID)
    if result['OK']:
      self.updateProfiles(result['Value'])
    return result

  # @gIdPsIDsSync
  # def refreshIdPs(self, IDs=None, sessionIDDict=None):
  #   """ Update cache from OAuthDB or dictionary

  #       :param list IDs: refresh IDs
  #       :param dict sessionIDDict: add session ID dictionary

  #       :return: S_OK()/S_ERROR()
  #   """
  #   # Update cache from dictionary
  #   if sessionIDDict:
  #     for ID, infoDict in sessionIDDict.items():
  #       self.__IdPsCache.add(ID, 3600 * 24, value=infoDict)
  #     return S_OK()

  #   # Update cache from DB
  #   self.__IdPsCache.add('Fresh', 60 * 15, value=True)
  #   try:
  #     from OAuthDIRAC.FrameworkSystem.Client.OAuthManagerClient import gSessionManager
  #   except Exception:
  #     return S_ERROR('OAuthManager not ready.')
  #   result = gSessionManager.getIdPsIDs()
  #   if result['OK']:
  #     for ID, infoDict in result['Value'].items():
  #       if len(infoDict['Providers'].keys()) > 1:
  #         gLogger.warn('%s user ID used by more that one providers:' % ID, ', '.join(infoDict['Providers'].keys()))
  #       self.__IdPsCache.add(ID, 3600 * 24, infoDict)
  #   return S_OK() if result['OK'] else result
  
  # def getIdPsCache(self, IDs=None):
  #   """ Return IdPs cache

  #       :param list IDs: IDs

  #       :return: S_OK(dict)/S_ERROR() -- dictionary contain ID as key and information collected from IdP
  #   """
  #   resDict = {}

  #   # Update cache if not actual
  #   if not self.__IdPsCache.get('Fresh'):
  #     result = self.refreshIdPs()
  #     if not result['OK']:
  #       return result

  #   # Return cache without Fresh key
  #   idPsCache = self.__IdPsCache.getDict()
  #   idPsCache.pop('Fresh', None)

  #   for ID, idDict in idPsCache.items():
  #     if IDs and ID not in IDs:
  #       continue
  #     resDict[ID] = idDict
  #   return S_OK(resDict)

  def getIDsForDN(self, dn):
    """ Find ID for DN
    
        :param str dn: user DN
        
        :return: list
    """
    userIDs = []
    profile = self.getProfiles() or {}
    for uid, data in profile.items():
      if dn in data.get('DNs', []):
        userIDs.append(uid)
    return userIDs
  
  def getDNsForID(self, uid):
    """ Find ID for DN
    
        :param str uid: user ID
        
        :return: list
    """
    profile = self.getProfiles(userID=uid) or {}
    return profile.get('DNs', [])
  
  def getDNOptionForID(self, uid, dn, option):
    """ Find option for DN
    
        :param str uid: user ID
        :param str dn: user DN
        :param str option: option to find
        
        :return: str or None
    """
    profile = self.getProfiles(userID=uid) or {}
    if dn in profile.get('DNs', []):
      return profile['DNs'][dn].get('PROVIDER')
    return None
  
  def getIdPForID(self, uid):
    """ Find option for DN
    
        :param str uid: user ID
        
        :return: str or None
    """
    profile = self.getProfiles(userID=uid) or {}
    return profile.get('Provider')

  def getIDForSession(self, session):
    """ Find ID for session
    
        :param basestring session: session number
        
        :return: S_OK()/S_ERROR()
    """
    data = self.getSessions(session=session)
    if not data:
      result = self.resfreshSessions(session=session)
      if not result['OK']:
        return result
      data = result['Value']
    return S_OK(data['ID']) if data.get('ID') else S_ERROR('No ID found for session %s' % session)

gOAuthManagerData = OAuthManagerData()
