# This script handles Sysmon Create Process event and writes contents to sysmon_proCreate.log.
# Version 1.0 (November 2018)
#
# Authors: Jeff Atkinson (jatkinson@salesforce.com)
#
# Copyright (c) 2017, salesforce.com, inc.
# All rights reserved.
# Licensed under the BSD 3-Clause license. 
# For full license text, see LICENSE.txt file in the repo root  or https://opensource.org/licenses/BSD-3-Clause

module Sysmon;

export {

    redef enum Log::ID += {LOG};


    type procCreate:record {
	computerName: string		&log &optional;
	processId: string		&log &optional;
        commandLine:	string		&log &optional;
	company: string		&log &optional;
	currentDirectory: string		&log &optional;
	description: string		&log &optional;
	fileVersion: string		&log &optional;
	hashes: string		&log &optional;
	image: string		&log &optional;
	integrityLevel: string		&log &optional;
	logonGuid: string		&log &optional;
	logonId: string		&log &optional;
	parentCommandline: string		&log &optional;
	parentImage: string		&log &optional;
	parentProcessGuid: string		&log &optional;
	parentProcessId: string		&log &optional;
	processGuid: string		&log &optional;
	product: string		&log &optional;
	terminalSessionId: string		&log &optional;
	user: string		&log &optional;
	utcTime: string		&log &optional;
	};


    global log_procCreate: event(rec: procCreate);
}


event bro_init() &priority=5
    {
    Log::create_stream(Sysmon::LOG, [$columns=procCreate, $ev=log_procCreate, $path="sysmon_procCreate"]);
}

event process_created(computerName: string,processId: string,commandLine: string;company: string,currentDirectory: string,description: string,fileVersion: string,hashes: string,image: string,integrityLevel: string,logonGuid: string,logonId: string,parentCommandline: string,parentImage: string,parentProcessGuid: string,parentProcessId: string,processGuid: string,product: string,terminalSessionId: string,user: string,utcTime: string)
{
local r: procCreate;
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

Log::write(Sysmon::LOG, r);
}
