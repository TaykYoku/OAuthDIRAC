import re
import json
import types
import base64

from tornado import web, gen

from DIRAC import S_OK, S_ERROR, gLogger
from DIRAC.Core.Utilities import List, Time
from DIRAC.Core.DISET.RPCClient import RPCClient

from WebAppDIRAC.Lib.WebHandler import WebHandler, asyncGen, WErr

__RCSID__ = "$Id$"


class FileCatalogHandler(WebHandler):

  AUTH_PROPS = "authenticated"
  LOCATION = "filecatalogue"

  def initialize(self):
    self.args = self.getArgs()
    self.did, self.obj = re.match("(?:/([a-zA-Z0-9=-_]+)(?:/([a-z]+))?)?", self.overpath)
    super(FileCatalogHandler, self).initialize()
    self.loggin = gLogger.getSubLogger(__name__)
    self.__rpc = RPCClient("DataManagement/FileCatalog")
    return S_OK()
  
  @asyncGen
  def web_directory(self):
    """ Retrieve contents of the specified directory
    """
    if not self.obj:
      path = self.__decodePath(self.did)
      try:
        pageSize = max(0, int(self.request.arguments['page_size'][-1]))
      except (ValueError, KeyError):
        pageSize = 0
      try:
        verbose = bool(self.request.arguments['extra'][-1])
      except KeyError:
        verbose = False
      result = yield self.threadTask(self.rpc.listDirectory, path, verbose)
      if not result['OK']:
        self.log.error("Cannot list directory for %s:%s" % (path, result['Message']))
        raise WErr.fromError(result)
      data = result['Value']
      if not path in data['Successful']:
        raise WErr(404, data['Failed'][path])
      contents = data['Successful'][path]
      ch = {}
      for kind in contents:
        ch[kind] = {}
        for sp in contents[kind]:
          ch[kind][sp[len(path) + 1:]] = contents[kind][sp]
      self.finish(self.__sanitizeForJSON(ch))
    elif 'metadata' == self.obj:
      # Search compatible metadata for this directory
      path = self.__decodePath(self.did)
      cond = self.__decodeMetadataQuery()
      result = yield self.threadTask(self.rpc.getCompatibleMetadata, cond, path)
      if not result["OK"]:
        raise WErr.fromError(result)
      self.finish(self.__sanitizeForJSON(result['Value']))
    elif 'search' == self.obj:
      # Search directories with metadata restrictions
      path = self.__decodePath(self.did)
      cond = self.__decodeMetadataQuery()
      result = yield self.threadTask(self.rpc.findDirectoriesByMetadata, cond, path)
      if not result['OK']:
        raise WErr.fromError(result)
      data = self.__filterChildrenOf(path, result['Value'])
      result = yield self.threadTask(self.rpc.getDirectorySize, data, False, False)
      if not result['OK']:
        raise WErr.fromError(result)
      tree = self.__buildDirTree(path, result['Value']['Successful'])
      self.finish(self.__sanitizeForJSON(tree))
    else:
      raise WErr(404, "WTF?")

  @asyncGen
  def web_metadata(self):
    """ Retrieve all metadata keys with their type and possible values that are
          compatible with the metadata restriction. Accepts metadata condition:
        
        :return: json with requested data
    """
    cond = self.__decodeMetadataQuery()
    result = yield self.threadTask(self.__rpc.getMetadataFields)
    if not result['OK']:
      raise WErr.fromError(result)
    data = result['Value']
    fields = {}
    for k in data['DirectoryMetaFields']:
      fields[k] = data['DirectoryMetaFields'][k].lower()
    result = yield self.threadTask(self.__rpc.getCompatibleMetadata, cond, "/")
    if not result['OK']:
      raise WErr.fromError(result)
    values = result['Value']
    data = {}
    for k in fields:
      if k not in values:
        continue
      data[k] = {'type': fields[k], 'values': values[k]}
    self.finish(data)
  
  @asyncGen
  def web_file(self):
    """ Get the file information
    """
    if self.obj == "attributes":
      path = self.__decodePath(self.did)
      result = yield self.threadTask(self.rpc.getFileMetadata, path)
      if not result['OK'] or path not in result['Value']['Successful']:
        raise WErr.fromError(result)
      self.finish(self.__sanitizeForJSON(result['Value']['Successful'][path]))
    elif self.obj == "metadata":
      path = self.decodePath(self.did)
      result = yield self.threadTask(self.rpc.getFileUserMetadata, path)
      if not result['OK']:
        raise WErr.fromError(result)
      self.finish(self.__sanitizeForJSON(result['Value']))
    else:
      raise WErr(404, "WTF?")

  def __decodePath(self):
    """ All directories that have to be set in a URL have to be encoded in url safe base 64
          (RFC 4648 Spec where ‘+’ is encoded as ‘-‘ and ‘/’ is encoded as ‘_’).
          There are several implementations for different languages already.

        :return: basestring
    """
    if not self.did:
      return "/"
    try:
      return base64.urlsafe_b64decode(str(self.did)).rstrip("/") or "/"
    except TypeError, e:
      raise WErr(400, "Cannot decode path")

  def __decodeMetadataQuery(self):
    """ Decode metadata query

        :return: dict
    """
    cond = {}
    for k in self.args:
      for val in self.args[k]:
        if val.find("|") == -1:
          continue
        val = val.split("|")
        op = val[0]
        val = "|".join(val[1:])
        if 'in' == op:
          val = List.fromChar(val, ",")
        if k not in cond:
          cond[k] = {}
        cond[k][op] = val
    self.log.info("Metadata condition is %s" % cond)
    return cond

  def __sanitizeForJSON(self, val):
    vType = type(val)
    if vType in Time._allTypes:
      return Time.toString(val)
    elif vType == types.DictType:
      for k in val:
        val[k] = self.__sanitizeForJSON(val[k])
    elif vType == types.ListType:
      for iP in range(len(val)):
        val[iP] = self.__sanitizeForJSON(val[iP])
    elif vType == types.TupleType:
      nt = []
      for iP in range(len(val)):
        nt[iP] = self.__sanitizeForJSON(val[iP])
      val = tuple(nt)
    return val

  def __filterChildrenOf(self, root, dirDict):
    filtered = []
    for self.did in list(dirDict):
      path = dirDict[self.did]
      if len(path) > len(root) or path == root:
        filtered.append(path)
    return filtered