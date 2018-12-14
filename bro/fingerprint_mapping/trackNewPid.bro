# This script uses Sysmon Process Create events to keep a table of Process Creation details by computername and PID.
# Version 1.0 (November 2018)
#
# Authors: Jeff Atkinson (jatkinson@salesforce.com)
#
# Copyright (c) 2017, salesforce.com, inc.
# All rights reserved.
# Licensed under the BSD 3-Clause license. 
# For full license text, see LICENSE.txt file in the repo root  or https://opensource.org/licenses/BSD-3-Clause

module Sysmon;

global trackPID: table[string,int] of procCreate &redef;
#global trackPID: table[string,int] of string &redef;


event process_created(computerName: string,processId: string,commandLine: string;company: string,currentDirectory: string,description: string,fileVersion: string,hashes: string,image: string,integrityLevel: string,logonGuid: string,logonId: string,parentCommandline: string,parentImage: string,parentProcessGuid: string,parentProcessId: string,processGuid: string,product: string,terminalSessionId: string,user: string,utcTime: string)
{
#print "New Process created";
# Creating record to add to table.

local r: procCreate;
#print computerName, company, description, hashes, image, parentCommandline;
r$computerName = computerName;
r$company = company;
r$currentDirectory = currentDirectory;
r$description = description;
r$fileVersion = fileVersion;
r$hashes = hashes;
r$image = image;
r$integrityLevel = integrityLevel;
r$logonGuid = logonGuid;
r$logonId = logonId;
r$parentCommandline = parentCommandline;
r$parentImage = parentImage;
r$parentProcessGuid = parentProcessGuid;
r$parentProcessId = parentProcessId;
r$processId = processId;
r$product = product;
r$terminalSessionId = terminalSessionId;
r$user = user;
r$utcTime = utcTime;


  if ( [computerName,to_int(parentProcessId)] !in trackPID ) {
	#print "Adding "+parentImage,computerName, parentProcessId+" to table";
	if ( /putty/ in parentImage ) {
          #print "####### Process Creation ######## Adding "+parentImage,computerName, processId+" to table";
	  }
	trackPID[computerName,to_int(parentProcessId)] = r;
	};
}


event sysmonProcessTerminated(computerName: string, image: string, processGuid: string, processId: string, utcTime: string)
{

#print "Removing "+computerName, processId+" from table";
#delete trackPID[computerName,to_int(processId)];

}

event bro_done()
{
print trackPID;
}
