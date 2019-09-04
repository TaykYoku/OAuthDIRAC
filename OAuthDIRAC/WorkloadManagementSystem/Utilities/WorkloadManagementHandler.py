import re, os, shutil, tempfile
import json
import types
import time
import tornado

from tornado import web, gen

from DIRAC import S_OK, S_ERROR, gConfig, gLogger
from DIRAC.Core.DISET.RPCClient import RPCClient
from DIRAC.Core.Utilities import List, CFG
from DIRAC.Core.Utilities.JDL import loadJDLAsCFG, dumpCFGAsJDL
from DIRAC.FrameworkSystem.Client.NotificationClient import NotificationClient
from DIRAC.WorkloadManagementSystem.Client.SandboxStoreClient import SandboxStoreClient

from WebAppDIRAC.Lib.WebHandler import WebHandler, asyncGen, WErr, WOK

__RCSID__ = "$Id$"


class WorkloadManagementHandler(WebHandler):
  OVERPATH = True
  AUTH_PROPS = "authenticated"
  LOCATION = "workloadmanager"

  ATTRIBUTES = [('status', 'Status'),
                ('minorStatus', 'MinorStatus'),
                ('appStatus', 'ApplicationStatus'),
                ('jid', 'JobID'),
                ('reschedules', 'ReschefuleCounter'),
                ('cpuTime', 'CPUTime'),
                ('jobGroup', 'JobGroup'),
                ('name', 'JobName'),
                ('site', 'Site'),
                ('setup', 'DIRACSetup'),
                ('priority', 'UserPriority'),
                ('ownerDN', 'ownerDN'),
                ('ownerGroup', 'OwnerGroup'),
                ('owner', 'Owner')]

  NUMERICAL = ('jid', 'cpuTime', 'priority')

  FLAGS = [('verified', 'VerifiedFlag'),
           ('retrieved', 'RetrievedFlag'),
           ('accounted', 'AccountedFlag'),
           ('outputSandboxReady', 'OSandboxReadyFlag'),
           ('inputSandboxReady', 'ISandboxReadyFlag'),
           ('deleted', 'DeletedFlag'),
           ('killed', 'KilledFlag')]

  TIMES = [('lastSOL', 'LastSignOfLife'),
           ('startExecution', 'StartExecTime'),
           ('submission', 'SubmissionTime'),
           ('reschedule', 'RescheduleTime'),
           ('lastUpdate', 'LastUpdateTime'),
           ('heartBeat', 'HeartBeatTime'),
           ('endExecution', 'EndExecTime')]

  def initialize(self):
    self.args = self.getArgs()
    self.jid = re.match("(?:/([0-9]+))?", self.overpath)
    super(WorkloadManagementHandler, self).initialize()
    self.jid = re.match("(?:/([0-9]+))?", self.overpath)
    self.loggin = gLogger.getSubLogger(__name__)
    return S_OK()

  @asyncGen
  def web_jobs(self):
    """ Retrieve a list of jobs matching the requirements
    """
    if self.request.method == 'GET':
      startJob = 0
      maxJobs = 100
      if self.jid:
        selDict = {'JobID': int(self.jid)}
      else:
        selDict = {}
        for convList in (self.ATTRIBUTES, self.FLAGS):
          for attrPair in convList:
            jAtt = attrPair[0]
            if jAtt in self.request.arguments:
              selDict[attrPair[1]] = self.request.arguments[jAtt]
        if 'allOwners' not in self.request.arguments:
          selDict['Owner'] = self.getUserName()
        if 'startJob' in self.request.arguments:
          try:
            startJob = max(startJob, int(self.request.arguments['startJob'][-1]))
          except ValueError:
            raise WErr(400, reason="startJob has to be an integer")
        if 'maxJobs' in self.request.arguments:
          try:
            maxJobs = max(maxJobs, int(self.request.arguments['maxJobs'][-1]))
          except ValueError:
            raise WErr(400, reason="maxJobs has to be an integer")

      result = yield self.threadTask(self._getJobs, selDict, startJob, maxJobs)
      if not result.ok:
        raise result
      data = result.data
      if not self.jid:
        self.finish(data)
        return
      if data['entries'] == 0:
        raise WErr(404, "Unknown jid")
      self.finish(data['jobs'][0])
    elif self.request.method == 'POST':
      if self.jid:
        self.send_error(404)
        return
      if 'manifest' not in self.request.arguments:
        raise WErr(400, "No manifest")
      manifests = []
      for manifest in self.request.arguments['manifest']:
        try:
          manifest = json.loads(manifest)
        except ValueError:
          raise WErr(400, "Manifest is not JSON")
        if type(manifest) != types.DictType:
          raise WErr(400, "Manifest is not an associative array")
        manifests.append(manifest)

      # Upload sandbox
      files = self.request.files
      if files:
        result = yield self.threadTask(self.uploadSandbox, files)
        if not result.ok:
          self.log.error("Cannot upload sandbox: %s" % result.msg)
          raise result
        sb = result.data
        self.log.info("Uploaded to %s" % sb)
        for manifest in manifests:
          isb = manifest.get('InputSandbox', [])
          if type(isb) != types.ListType:
            isb = [isd]
          isb.append(sb)
          manifest['InputSandbox'] = isb

      # Send jobs
      jids = []
      rpc = RPCClient('WorkloadManagement/JobManager')
      for manifest in manifests:
        jdl = dumpCFGAsJDL(CFG.CFG().loadFromDict(manifest))
        result = yield self.threadTask(rpc.submitJob, str(jdl))
        if not result['OK']:
          self.log.error("Could not submit job: %s" % result['Message'])
          raise WErr(500, result['Message'])
        data = result['Value']
        if type(data) == types.ListType:
          jids.extend(data)
        else:
          jids.append(data)
      self.log.info("Got jids %s" % jids)
      self.finish({'jids': jids})

    elif self.request.method == 'DELETE':
      if not self.jid:
        self.send_error(404)
        return
      try:
        self.jid = int(self.jid)
      except ValueError:
        raise WErr(400, "Invalid jid")
      rpc = RPCClient('WorkloadManagement/JobManager')
      if 'killonly' in self.request.arguments and self.request.arguments['killonly']:
        result = yield self.threadTask(rpc.killJob, [self.jid])
      else:
        result = yield self.threadTask(rpc.deleteJob, [self.jid])
      if not result['OK']:
        if 'NonauthorizedJobIDs' in result:
          # Not authorized
          raise WErr(401, "Not authorized")
        if 'InvalidJobIDs' in result:
          # Invalid jid
          raise WErr(400, "Invalid jid")
        if 'FailedJobIDs' in result:
          # "Could not delete JID"
          raise WErr(500, "Could not delete")
      self.finish({'jid': self.jid})

  def __findIndexes(self, paramNames):
    indexes = {}
    for k, convList in (('attrs', self.ATTRIBUTES), ('flags', self.FLAGS), ('times', self.TIMES)):
      indexes[k] = {}
      for attrPair in convList:
        try:
          iP = paramNames.index(attrPair[1])
        except ValueError:
          # Not found
          pass
        indexes[k][attrPair[0]] = iP
    return indexes


  def _getJobs(self, selDict, startJob=0, maxJobs=500):
    result = RPCClient("WorkloadManagement/JobMonitoring").getJobPageSummaryWeb(selDict, [('JobID', 'DESC')],
                                                                                startJob, maxJobs, True)
    if not result['OK']:
      return WErr(500, result['Message'])
    origData = result['Value']
    totalRecords = origData['TotalRecords']
    retData = {'entries': totalRecords, 'jobs': []}
    if totalRecords == 0:
      return WOK(retData)
    indexes = self.__findIndexes(origData['ParameterNames'])
    records = origData['Records']
    for record in records:
      job = {}
      for param in indexes['attrs']:
        job[param] = record[indexes['attrs'][param]]
        if param in self.NUMERICAL:
          job[param] = int(float(job[param]))
      for k in ('flags', 'times'):
        job[k] = {}
        for field in indexes[k]:
          value = record[indexes[k][field]]
          if value.lower() == "none":
            continue
          if k == 'flags':
            job[k][field] = value.lower() == 'true'
          else:
            job[k][field] = value
      retData['jobs'].append(job)
    return WOK(retData)

  def uploadSandbox(self, fileData):
    with TmpDir() as tmpDir:
      fileList = []
      for fName in fileData:
        for entry in fileData[fName]:
          tmpFile = os.path.join(tmpDir, entry.filename)
          if tmpFile not in fileList:
            fileList.append(tmpFile)
          dfd = open(tmpFile, "w")
          dfd.write(entry.body)
          dfd.close()
      sbClient = SandboxStoreClient()
      result = sbClient.uploadFilesAsSandbox(fileList)
      if not result['OK']:
        return WErr(500, result['Message'])
      return WOK(result['Value'])

class TmpDir( object ):
  def __init__( self ):
    self.__tmpDir = False
  def __enter__( self ):
    return self.get()
  def __exit__( self, *exc_info ):
    try:
      shutil.rmtree( self.__tmpDir )
      self.__tmpDir = False
    except:
      pass
  def get( self ):
    if not self.__tmpDir:
      base = os.path.join( "/tmp" )
      if not os.path.isdir( base ):
        try:
          os.makedirs( base )
        except Exception, e:
          gLogger.exception( "Cannot create work dir %s: %s" % ( base, e) )
          raise
      self.__tmpDir = tempfile.mkdtemp( dir = base )
    return self.__tmpDir