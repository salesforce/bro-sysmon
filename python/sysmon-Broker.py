# This script parses Windows Event Logs in JSON format and forwards events to the Bro Platform.
# Version 1.0 (November 2018)
#
# Authors: Jeff Atkinson (jatkinson@salesforce.com)
#
# Copyright (c) 2017, salesforce.com, inc.
# All rights reserved.


#!/usr/bin/python
# -*- coding: utf-8 -*-

import broker
import broker.bro
import json, sys, pprint

#Setup Bro comms
endpoint = broker.Endpoint()
endpoint.peer("localhost",9999)


#-- Sysmon Process Created --- EventID1 --#

def procCreation(myJson):               #### Event ID: 1 ####
  computerName = myJson["computer_name"]
  event = myJson["event_data"]
  company = event["Company"]
  currentDirectory = event["CurrentDirectory"]
  if 'Description' in event:
    description = event["Description"]
  else:
    description = "None"
  fileVersion = event["FileVersion"]
  ##### Need to separate MD5 and SHA256
  hashes = event["Hashes"]
  image = event["Image"]
  integrityLevel = event["IntegrityLevel"]
  logonGuid = event["LogonGuid"]
  logonId = event["LogonId"]
  parentCommandline = event["ParentCommandLine"]
  parentImage = event["ParentImage"]
  parentProcessGuid = event["ParentProcessGuid"]
  parentProcessId = event["ParentProcessId"]
  processGuid = event["ProcessGuid"]
  processId = event["ProcessId"]
  product = event["Product"]
  terminalSessionId = event["TerminalSessionId"]
  user = event["User"]
  utcTime = event["UtcTime"] 

  #print computerName,company,currentDirectory,description,fileVersion,hashes,image,integrityLevel,logonGuid,logonId,parentCommandline,parentImage,parentProcessGuid,parentProcessId,processGuid,processId,product,terminalSessionId,user,utcTime
  #pprint.pprint(myJson)

  event = broker.bro.Event("sysmonProcCreation",str(computerName),company.encode('ascii','ignore'),str(currentDirectory),description.encode('ascii','ignore'),str(fileVersion),str(hashes),str(image),str(integrityLevel),str(logonGuid),str(logonId),str(parentCommandline),str(parentImage),str(parentProcessGuid),str(parentProcessId),str(processGuid),str(processId),product.encode('ascii','ignore'),str(terminalSessionId),str(user),str(utcTime))
  endpoint.publish("/sysmon", event)


def procChangeFile(myJson):             #### Event ID: 2 ####
   #pprint.pprint(myJson["event_data"])
   computerName =  myJson["computer_name"]
   event = myJson["event_data"]
   utcTime = event["UtcTime"]
   processGuid = event["ProcessGuid"]
   processId = event["ProcessId"]
   image = event["Image"]
   targetFilename = event["TargetFilename"]
   creationUtcTime = event["CreationUtcTime"]
   previousCreationUtcTime = event["PreviousCreationUtcTime"]

   #print comptuerName,utcTime,processGuid,processId,targetFilename,creationUtcTime,previousCreationUtcTime
   event = broker.bro.Event("sysmonProcChangeFile",str(computerName),str(utcTime),str(processGuid),str(processId),str(targetFilename),str(creationUtcTime),str(previousCreationUtcTime))
   endpoint.publish("/sysmon", event)



#-- Sysmon Process Network Connect --- EventID3 --#
def procnetconn(myJson):	#-- Event ID: 3 --#
   computerName =  myJson["computer_name"]
   event = myJson["event_data"]
   proto = myJson["event_data"]["Protocol"]
   dstip = event["DestinationIp"]
   dstprt = event["DestinationPort"]
   srcip = event["SourceIp"]
   srcprt = event["SourcePort"]
   procImage = event["Image"]
   procId = event["ProcessId"]
   if 'User' in event:
     user = event["User"]
   else:
     user = "NA"
   myTime = event["UtcTime"]
   
   #print computerName,srcip+"  ==>  "+dstip+":"+dstprt+"/"+proto,procId,procImage,user,myTime

   event = broker.bro.Event("sysmonProcNetConn",str(computerName),str(proto),str(srcip),str(srcprt),str(dstip),str(dstprt),str(procId),str(procImage))
   #event = broker.bro.Event("sysmonProcNetConn",str(computerName),str(proto),str(srcip),str(srcprt),str(dstip),str(dstprt),str(procId),str(procImage))
   endpoint.publish("/sysmon", event)


#-- Sysmon Process Network Connect --- EventID5 --#
def sysmonProcessTerminated(myJson):            #### EventID-5 ####
   #print "EventID-5"
   computerName = myJson["computer_name"]
   event = myJson["event_data"]
   image = event["Image"]
   processGuid = event["ProcessGuid"]
   processId = event["ProcessId"]
   utcTime = event["UtcTime"]
   # Create and send Bro Event  
   event = broker.bro.Event("sysmonProcessTerminated",str(computerName),str(image),str(processGuid),str(processId),str(utcTime))
   endpoint.publish("/sysmon", event)


#-- Sysmon Driver Loaded --- EventID6 --#
def driverLoad(myJson):                         #### EventID-6 ####
   #print "Entering driverLoad"
   computerName = myJson["event_data"]
   procId = myJson["process_id"]
   #pprint.pprint(myJson)   
   event = myJson["event_data"]
   if "Hashes" in event:
     hashes = event["Hashes"]
   if "ImageLoaded" in event:
     imageLoaded = event["ImageLoaded"]
   signature = event["Signature"]
   signatureStatus = event["SignatureStatus"]
   signed = event["Signed"]
   utcTime = event["UtcTime"]
   event = broker.bro.Event("sysmonDriverLoaded",str(computerName),int(procId),str(hashes),str(imageLoaded),str(signature),str(signatureStatus),str(signed),str(utcTime))
   endpoint.publish("/sysmon", event)


#-- Sysmon Image Loaded --- EventID7 --#
# List of Events
def imageLoaded(myJson):                          #### EventID-7 ####
   computerName = myJson["event_data"]
   event = myJson["event_data"]
   utcTime = event["UtcTime"] 
   procGuid = event["ProcessGuid"]
   procId = event["ProcessId"]
   image = event["Image"]
   imageLoaded = event["ImageLoaded"]
   hashes = event["Hashes"]
   signed = event["Signed"]
   sigStatus = event["SignatureStatus"]
   if sigStatus == "Unavailable":
     sig = "None"
     #print "NO SIGNATURE AVAILABLE"
   else:
     sig = event["Signature"]

   #print utcTime,procGuid,procId,image,imageLoaded,hashes,signed,sig,sigStatus
   event = broker.bro.Event("sysmonImageLoaded",str(computerName),str(utcTime),str(procGuid),str(procId),str(image),str(imageLoaded),str(hashes),str(signed),str(sig),str(sigStatus))
   endpoint.publish("/sysmon", event)



#-- Sysmon Image Loaded --- EventID8 --#
def createRemoteThread(myJson):                 #### EventID-8 ####
   #print "Entering createRemoteThread"
   event = myJson["event_data"]
   #pprint.pprint(event)
   computerName = myJson["computer_name"]
   utcTime = event["UtcTime"]
   sourceProcessGuid = event["SourceProcessGuid"]
   sourceProcessId = event["SourceProcessId"]
   sourceImage = event["SourceImage"] 
   targetProcessId = event["TargetProcessId"]
   targetImage = event["TargetImage"]
   newThreadId = event["NewThreadId"]
   startAddress = event["StartAddress"]
   if 'StartModule' in event:
     startModule = event["StartModule"]
   else:
     startModule = "NA"
   if 'StartFunction' in event:
     startFunction = event["StartFunction"]
   else:
     startFunction = "NA"
   #print utcTime, sourceProcessGuid, sourceProcessId, sourceImage, targetProcessId, targetImage, newThreadId, startAddress, startModule, startFunction
   event = broker.bro.Event("sysmonCreateRemoteThread",str(computerName),str(utcTime), str(sourceProcessGuid), str(sourceProcessId), str(sourceImage), str(targetProcessId), str(targetImage), str(newThreadId), str(startAddress), str(startModule), str(startFunction))
   endpoint.publish("/sysmon", event)


#-- Sysmon Raw Access Read --- EventID9 --#
def rawAccessRead(myJson):                      #### Event-ID-9 ####
   event = myJson["event_data"]
   computerName = myJson["computer_name"]
   utcTime = event["UtcTime"]
   processGuid = event["ProcessGuid"] 
   processId = event["ProcessId"]
   image = event["Image"]
   device = event["Device"]
   #print utcTime, processGuid, processId, image, device

   event = broker.bro.Event("sysmonRawAccessRead",str(computerName),str(utcTime), str(processGuid), str(processId), str(image), str(device))
   endpoint.publish("/sysmon", event)

#-- Sysmon Process access --- EventID10 --#
def processAccess(myJson):   #### Event ID: 10 ####
   event = myJson["event_data"]
   computerName = myJson["computer_name"]
   grantedAccess = event["GrantedAccess"]
   sourceImage = event["SourceImage"]
   sourceProcGuid = event["SourceProcessGUID"]
   sourceProcId = event["SourceProcessId"]
   sourceThreadId = event["SourceThreadId"]
   targetImage = event["TargetImage"]
   targetProcGuid = event["TargetProcessGUID"]
   targetProcId = event["TargetProcessId"]
   utcTime = event["UtcTime"]
   #pprint.pprint(myJson["event_data"])

   #print computerName,grantedAccess,sourceImage,sourceProcGuid,sourceProcId,sourceThreadId,targetImage,targetProcGuid,targetProcId,utcTime

   event = broker.bro.Event("sysmonProcAccess",str(computerName),str(grantedAccess),str(sourceImage),str(sourceProcGuid),str(sourceProcId),str(sourceThreadId),str(targetImage),str(targetProcGuid),str(targetProcId),str(utcTime))
   endpoint.publish("/sysmon", event)
  

#-- Sysmon File Create --- EventID11 --#
def sysmonFileCreate(myJson):           #### EventID-11 ####
   event = myJson["event_data"]
   computerName = myJson["computer_name"]
   image = event["Image"]
   processGuid = event["ProcessGuid"]
   processId = event["ProcessId"]
   targetFilename = event["TargetFilename"]
   utcTime = event["UtcTime"]
   #print ""
   #print computerName,image,processGuid,processId,targetFilename,utcTime
   #pprint.pprint(myJson)
   event = broker.bro.Event("sysmonFileCreate",str(computerName),str(image),str(processGuid),str(processId),str(targetFilename),str(utcTime))
   #print event
   endpoint.publish("/sysmon", event)


#-- Sysmon File Create --- EventID12,13,14 --#
def regEventAddDel(myJson):             #### EventID-12 & 13 & 14 ####
   event = myJson["event_data"]
   computerName = myJson["computer_name"]
   eventType = event["EventType"]  
   utcTime = event["UtcTime"] 
   processGuid = event["ProcessGuid"]
   processId= event["ProcessId"]
   image = event["Image"]
   targetObject = event["TargetObject"]
   if 'Details' in event:
     details = event["Details"]
   else:
     details = "NA"

   if 'NewName' in event:
     newName = event["NewName"]
   else:
     newName = "NA"

   #print eventType, utcTime, processGuid, processId, image, targetObject, details, newName
   event = broker.bro.Event("sysmonRegEvent", str(computerName), str(eventType), str(utcTime), str(processGuid), str(processId), str(image), str(targetObject),details.encode('ascii','ignore'),newName.encode('ascii','ignore'))
   endpoint.publish("/sysmon", event)

#-- Sysmon File Create --- EventID15 --#
def fileCreateStreamHash(myJson):               #### Event-ID-15 ####
   event = myJson["event_data"]
   computerName = myJson["computer_name"]
   #pprint.pprint(myJson["event_data"])
   utcTime = event["UtcTime"]
   processGuid = event["ProcessGuid"]
   processId = event["ProcessId"]
   image = event["Image"] 
   targetFilename = event["TargetFilename"]
   creationUtcTime = event["CreationUtcTime"]
   hash = event["Hash"]

   #print computerName,utcTime,processGuid,processId,image,targetFilename,creationUtcTime,hash
   event = broker.bro.Event("sysmonFileCreateStreamHash", str(computerName), str(utcTime),str(processGuid),str(processId),str(image),str(targetFilename),str(creationUtcTime),str(hash)) 
   endpoint.publish("/sysmon", event)


#-- Sysmon File Create --- EventID16 --#
def configChange(myJson):                       #### Event-ID-16 ####
   #print "###########################"
   event = myJson["event_data"]
   computerName = myJson["computer_name"]
   #pprint.pprint(myJson)
   utcTime = event["UtcTime"]
   config = event["Configuration"]
   configFileHash = event["ConfigurationFileHash"]
   #print utcTime,config,configFileHash
   event = broker.bro.Event("sysmonConfigChange",str(computerName),str(utcTime),str(config),str(configFileHash))
   endpoint.publish("/sysmon", event)


#-- Sysmon File Create --- EventID17&18 --#
def pipeEvent(myJson,action):                   #### Event-ID-17 & 18 ####
   event = myJson["event_data"]
   computerName = myJson["computer_name"]
   utcTime = event["UtcTime"]
   processGuid = event["ProcessGuid"]
   processId = event["ProcessId"]
   pipeName = event["PipeName"]
   image = event["Image"]
   #print utcTime, processGuid, processId, pipeName, image
   event = broker.bro.Event("sysmonPipeEvent", str(computerName),str(action), str(utcTime), str(processGuid), str(processId), str(pipeName), str(image))
   endpoint.publish("/sysmon", event)


#-- Sysmon File Create --- EventID19 --#
def wmiEvent19(myJson): 
   #pprint.pprint(myJson)
   event = myJson["event_data"]
   computerName = myJson["computer_name"]
   message = myJson["message"]
   serviceGuid = event["serviceGuid"]
   updateGuid = event["updateGuid"]
   updateRevisionNumber = event["updateRevisionNumber"]
   updateTitle = event["updateTitle"]
   #print computerName, serviceGuid, updateGuid, updateRevisionNumber, updateTitle , message
   event = broker.bro.Event("sysmonWmiEvent19", str(computerName),str(message), str(serviceGuid), str(updateGuid), str(updateRevisionNumber), str(updateTitle))
   endpoint.publish("/sysmon", event)

#-- Sysmon WMI Event --- EventID20 --#
def wmiEvent20(myJson): 
   #pprint.pprint(myJson)
   event = myJson["event_data"]
   computerName = myJson["computer_name"]
   bootStatusPolicy = event["BootStatusPolicy"]
   lastBootGood = event["LastBootGood"]
   lastBootId = event["LastBootId"]
   lastShutdownGood = event["LastShutdownGood"]
   #print computerName, serviceGuid, updateGuid, updateRevisionNumber, updateTitle , message
   event = broker.bro.Event("sysmonWmiEvent20", str(computerName),str(bootStatusPolicy), str(lastBootGood),str(lastBootId),str(lastShutdownGood))
   endpoint.publish("/sysmon", event)


#-- Sysmon WMI Event --- EventID20 --#
def wmiEvent21(myJson):
   #print "###################################################"
   #pprint.pprint(myJson)
   #event = myJson["event_data"]
   computerName = myJson["computer_name"]
   #bootStatusPolicy = event["BootStatusPolicy"]
   #lastBootGood = event["LastBootGood"]
   #lastBootId = event["LastBootId"]
   #lastShutdownGood = event["LastShutdownGood"]
   #print computerName, serviceGuid, updateGuid, updateRevisionNumber, updateTitle , message
   #event = broker.bro.Event("sysmonWmiEvent20", str(computerName),str(bootStatusPolicy), str(lastBootGood),str(lastBootId),str(lastShutdownGood))
   #endpoint.publish("/sysmon", event)

   #print "###################################################"

def holyHandGrenade():
   #print "Event 5156"
   event = broker.bro.Event("holyHandGrenade")
   endpoint.publish("/sysmon", event)

def generic_event(myJson):
   message = myJson["message"]
   event = broker.bro.Event("EventLogEvent",str(myJson["computer_name"]),int(myJson["event_id"]),message.encode('ascii','ignore'))
   endpoint.publish("/sysmon", event)

# ASDF - Here is where checking the event_ids start.

for line in sys.stdin:
#with ope('1.txt') as f:
  #for line in f:
    myJson = json.loads(line)
    if 'event_data' not in myJson:
      continue
    event = myJson["event_data"]
    sysmonEventId =  myJson["event_id"]

    if sysmonEventId == 1:   
      #continue					##### 	SUCCESSFULL! #####
      #print "procCreation"
      procCreation(myJson)

    elif sysmonEventId == 2:
      continue					####   SUCCESSFULL!  ####
      #print "A process changed a file creation time"
      procChangeFile(myJson)

    elif sysmonEventId == 3:			####   SUCCESSFULL!  ####
      #continue
      #print "Network connection"
      procnetconn(myJson)

    elif sysmonEventId == 4:
      #continue					#######  TODO
      print "Sysmon service state changed"
      #pprint.pprint(myJson)

    elif sysmonEventId == 5:
      #continue					###### SUCCESSFULL! #######
      #print "Process terminated"
      sysmonProcessTerminated(myJson)

    elif sysmonEventId == 6:
      #continue
      print "Driver loaded"
      driverLoad(myJson)

    elif sysmonEventId == 7:
      #continue
      #print "Image loaded"
      imageLoaded(myJson)

    elif sysmonEventId == 8:
      #continue
      #print "CreateRemoteThread"
      createRemoteThread(myJson)

    elif sysmonEventId == 9:
      #continue
      #print "RawAccessRead"
      rawAccessRead(myJson)

    elif sysmonEventId == 10:
      #continue
      #print "ProcessAccess"
      processAccess(myJson)

    elif sysmonEventId == 11:
      #continue
      #print "sysmonFileCreate"
      sysmonFileCreate(myJson)

    elif sysmonEventId == 12:
      #continue
      #print " RegistryEvent (Object create and delete)"
      regEventAddDel(myJson)

    elif sysmonEventId == 13:
      #continue
      #print "RegistryEvent (Value Set)"
      regEventAddDel(myJson)

    elif sysmonEventId == 14:
      #continue
      #print "RegistryEvent (Key and Value Rename)"
      regEventAddDel(myJson)

    elif sysmonEventId == 15:
      #continue
      #print "FileCreateStreamHash"
      fileCreateStreamHash(myJson)

    elif sysmonEventId == 16:
      #continue
      #print "Sysmon Config Change"
      configChange(myJson)

    elif sysmonEventId == 17:
      #continue
      action = "PipeCreated"
      #print "PipeEvent (Pipe Created)"
      pipeEvent(myJson,action)

    elif sysmonEventId == 18:
      #continue
      action = "PipeConnected"
      #print "PipeEvent (Pipe Connected)"
      pipeEvent(myJson,action)

    elif sysmonEventId == 19:
      #continue
      #print "WmiEvent (WmiEventFilter activity detected)"
      wmiEvent19(myJson)

    elif sysmonEventId == 20:
      #continue
      #print "WmiEvent (WmiEventConsumer activity detected)"
      wmiEvent20(myJson)

    elif sysmonEventId == 21:
      #continue
      #print "WmiEvent (WmiEventConsumerToFilter activity detected)"
      wmiEvent21(myJson)

    elif sysmonEventId == 25:
      #continue
      #pprint.pprint(myJson)
      print "Error"

    elif sysmonEventId == 5156:
      holyHandGrenade();

    elif sysmonEventId == 4624:
      print("#####################")
      print("User Logon")
      pprint.pprint(myJson)
      #userLogon(myJson)
      print("")

    elif sysmonEventId == 4634:
      print("#####################")
      print("User Logoff")
      pprint.pprint(myJson)
      #userLogoff(myJson)
      print("")

    else:
      #continue
      print "EVENT ID NOT FOUND"
      generic_event(myJson)
      #print myJson["event_id"], myJson["message"]
      #pprint.pprint(myJson)


# Sending events to Broker   
#    event = broker.bro.Event("sysmonProcNetConn",str(computerName),str(proto),str(srcip),str(srcprt),str(dstip),str(dstprt),str(procId),str(procImage))
#    endpoint.publish("/sysmon", event)


