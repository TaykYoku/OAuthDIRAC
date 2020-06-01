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

        :param dict data: session information data
        :param int time: lifetime
    """
    for session, info in data.items():
      self.__cacheSessions.add(session, time, value=info)

  def resfreshSessions(self, session=None):
    """ Refresh session cache from service

        :param str session: session to update

        :return: S_OK()/S_ERROR()
    """
    from DIRAC.Core.DISET.RPCClient import RPCClient
    result = RPCClient('Framework/OAuthManager').getSessionsInfo(session)
    if result['OK'] and result['Value']:
      self.updateSessions({session: result['Value']})
    return result
  
  def resfreshProfiles(self, userID=None):
    """ Refresh profiles cache from service

        :param str userID: userID to update

        :return: S_OK()/S_ERROR()
    """
    from DIRAC.Core.DISET.RPCClient import RPCClient
    result = RPCClient('Framework/OAuthManager').getIdProfiles(userID)
    if result['OK'] and result['Value']:
      self.updateProfiles({userID: result['Value']})
    return result

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
    
    if not userIDs:
      result = self.resfreshProfiles()
      if not result['OK']:
        return result
      for uid, data in result['Value'].items():
        if dn in data.get('DNs', []):
          userIDs.append(uid)
    
    return userIDs
  
  def getDNsForID(self, uid):
    """ Find ID for DN
    
        :param str uid: user ID
        
        :return: list
    """
    profile = self.getProfiles(userID=uid)
    if not profile:
      result = self.resfreshProfiles()
      if not result['OK']:
        return result
      profile = result['Value']
    return profile.get('DNs', [])
  
  def getDNOptionForID(self, uid, dn, option):
    """ Find option for DN
    
        :param str uid: user ID
        :param str dn: user DN
        :param str option: option to find
        
        :return: str or None
    """
    profile = self.getProfiles(userID=uid)
    if not profile:
      result = self.resfreshProfiles()
      if not result['OK']:
        return result
      profile = result['Value']

    if dn in profile.get('DNs', []):
      return profile['DNs'][dn].get('PROVIDER')
    return None
  
  def getIdPForID(self, uid):
    """ Find option for DN
    
        :param str uid: user ID
        
        :return: str or None
    """
    profile = self.getProfiles(userID=uid)
    if not profile:
      result = self.resfreshProfiles()
      if not result['OK']:
        return result
      profile = result['Value']
  
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
