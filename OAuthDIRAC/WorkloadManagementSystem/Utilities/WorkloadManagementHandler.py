""" Rewrite from RESTDIRAC project """
import re
import os
import json
import time
import types
import shutil
import tempfile

from tornado import web, gen

from DIRAC import S_OK, S_ERROR, gConfig, gLogger
from DIRAC.Core.DISET.RPCClient import RPCClient
from DIRAC.Core.Utilities import List, CFG
from DIRAC.Core.Utilities.JDL import loadJDLAsCFG, dumpCFGAsJDL
from DIRAC.FrameworkSystem.Client.NotificationClient import NotificationClient
from DIRAC.WorkloadManagementSystem.Client.SandboxStoreClient import SandboxStoreClient
from DIRAC.AccountingSystem.Client.ReportsClient import ReportsClient

from WebAppDIRAC.Lib.WebHandler import WebHandler, asyncGen, WErr, WOK

__RCSID__ = "$Id$"


class WorkloadManagementHandler(WebHandler):
  OVERPATH = True
  AUTH_PROPS = "authenticated"
  LOCATION = "/"

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
    super(WorkloadManagementHandler, self).initialize()
    self.loggin = gLogger.getSubLogger(__name__)
    return S_OK()

  @asyncGen
  def web_jobs(self):
    """ Retrieve a list of jobs matching the requirements, use:
        GET /jobs?<options> -- retrieve a list of jobs matching the requirements.
          * options:
            Any job attribute can also be defined as a restriction in a HTTP list form. For instance:
              Site=DIRAC.Site.com&Site=DIRAC.Site2.com&Status=Waiting
            * allOwners - show jobs from all owners instead of just the current user. By default is set to false.
            * maxJobs - maximum number of jobs to retrieve. By default is set to 100.
            * startJob - starting job for the query. By default is set to 0.
          
        GET /jobs/<jid> -- retrieve info about job with id=*jid*
        GET /jobs/<jid>/manifest -- retrieve the job manifest
        GET /jobs/<jid>/inputsandbox -- retrieve the job input sandbox
        GET /jobs/<jid>/outputsandbox -- retrieve the job output sandbox
          * jid - job identity number
        
        POST /jobs -- submit a job. The API expects a manifest to be sent as a JSON object.
             Files can also be sent as a multipart request. If files are sent,
             they will be added to the input sandbox and the manifest will be modified accordingly.
             An example of manifest can be:
              {Executable: "/bin/echo",
               Arguments: "Hello World",
               Sites: ["DIRAC.Site.com", "DIRAC.Site2.com"]}

        DELETE /jobs/<jid> -- kill a job. The user has to have privileges over a job.
          * jid - job identity number
    """
    optns = self.overpath.strip('/').split('/')
    if len(optns) > 2:
      raise WErr(404, "Wrone way")
    __jid = re.match("([0-9]+)?", optns[0]).group()
    __obj = re.match("([a-z]+)?", optns[1]).group() if len(optns) > 1 else None
    self.loggin.info(__jid, '<<<')
    self.loggin.info(__obj, '<<<')

    # GET
    if self.request.method == 'GET':

      # manifest
      if __obj == "manifest":
        result = yield self.threadTask(self._getJobManifest, __jid)
        if not result.ok:
          self.log.error(result.msg)
          raise result
        self.finish(result.data)

      # outputsandbox, inputsandbox
      elif __obj in ("outputsandbox", "inputsandbox"):
        result = yield self.threadTask(self._getJobSB, __jid, __obj)
        if not result.ok:
          self.log.error(result.msg)
          raise result
        data = result.data
        self.clear()
        self.set_header("Content-Type", "application/x-tar")
        cacheTime = 86400
        self.set_header("Expires", datetime.datetime.utcnow() + datetime.timedelta(seconds=cacheTime))
        self.set_header("Cache-Control", "max-age=%d" % cacheTime)
        self.set_header("ETag", '"%s"' % hashlib.sha1(data).hexdigest)
        self.set_header("Content-Disposition", 'attachment; filename="%s-%s.tar.gz"' % (__jid, __obj))
        self.finish(data)

      # summary
      elif __obj == 'summary':
        selDict = {}
        if 'allOwners' not in self.request.arguments:
          selDict[ 'Owner' ] = self.getUserName()
        rpc = RPCClient( "WorkloadManagement/JobMonitoring" )
        if 'group' not in self.request.arguments:
          group = [ 'Status' ]
        else:
          group = self.request.arguments[ 'group' ]
        result = yield self.threadTask( rpc.getCounters, group, selDict )
        if not result[ 'OK' ]:
          self.log.error( "Could not retrieve job counters", result[ 'Message' ] )
          raise WErr( 500 )
        data = {}
        for cDict, count in result[ 'Value' ]:
          cKey = "|".join( [ cDict[ k ] for k in group ] )
          data[ cKey ] = count
        self.finish( data )
      
      # history
      elif __obj == 'history':
        condDict = {}
        if 'allOwners' not in self.request.arguments:
          condDict['Owner'] = self.getUserName()
        timespan = 86400
        if 'timeSpan' in self.request.arguments:
          try:
            timespan = int(self.request.arguments['timeSpan'][-1])
          except ValueError:
            raise WErr(400, reason="timeSpan has to be an integer!")
        rpc = ReportsClient()
        end = datetime.datetime.utcnow()
        start = end - datetime.timedelta(seconds=timespan)
        result = yield self.threadTask(rpc.getReport, "WMSHistory", "NumberOfJobs", start, end, condDict, "Status")
        if not result['OK']:
          self.log.error(result['Message'])
          raise WErr(500)
        data = result['Value']
        self.finish(data)
      
      # invalid
      elif __obj:
        raise WErr(404, "Invalid job object")

      # With/without job ID
      startJob = 0
      maxJobs = 100
      if __jid:
        selDict = {'JobID': int(__jid)}
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
      if not __jid:
        self.finish(data)
        return
      if data['entries'] == 0:
        raise WErr(404, "Unknown jid")
      self.finish(data['jobs'][0])
    
    # POST
    elif self.request.method == 'POST':
      if __jid:
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

    # DELETE
    elif self.request.method == 'DELETE':
      if not __jid:
        self.send_error(404)
        return
      try:
        __jid = int(__jid)
      except ValueError:
        raise WErr(400, "Invalid jid")
      rpc = RPCClient('WorkloadManagement/JobManager')
      if 'killonly' in self.request.arguments and self.request.arguments['killonly']:
        result = yield self.threadTask(rpc.killJob, [__jid])
      else:
        result = yield self.threadTask(rpc.deleteJob, [__jid])
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
      self.finish({'jid': __jid})

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

  def _getJobManifest( self, jid ):
    result = RPCClient( "WorkloadManagement/JobMonitoring" ).getJobJDL( int( jid  ) )
    if not result[ 'OK' ]:
      return WErr( 500, result[ 'Message' ] )
    result = loadJDLAsCFG( result[ 'Value' ] )
    if not result[ 'OK' ]:
      return WErr( 500, result[ 'Message' ] )
    cfg = result[ 'Value' ][0]
    jobData = {}
    stack = [ ( cfg, jobData ) ]
    while stack:
      cfg, level = stack.pop( 0 )
      for op in cfg.listOptions():
        val = List.fromChar( cfg[ op ] )
        if len( val ) == 1:
          val = val[0]
        level[ op ] = val
      for sec in cfg.listSections():
        level[ sec ] = {}
        stack.append( ( cfg[ sec ], level[ sec ] ) )
    return WOK( jobData )
  
  def _getJobSB( self, jid, objName ):
    with TmpDir() as tmpDir:
      if objName == "outputsandbox":
        objName = "Output"
      else:
        objName = "Input"
      result = SandboxStoreClient().downloadSandboxForJob( int( jid ), objName, tmpDir, inMemory = True )
      if not result[ 'OK' ]:
        msg = result[ 'Message' ]
        if msg.find( "No %s sandbox" % objName ) == 0:
          return WErr( 404, "No %s sandbox defined for job %s" % ( jid, objName.lower() ) )
        return WErr( 500, result[ 'Message' ] )
      return WOK( result[ 'Value' ] )

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