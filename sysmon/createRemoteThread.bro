# This script handles Sysmon Create Remote Thead events and writes content to sysmon_createRemoteThread.log.
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

    redef enum Log::ID += {CreateRemoteThread};


    type createRemoteThread:record {
	computerName: string &log &optional;
 	utcTime: string &log &optional;
	sourceProcessGuid: string &log &optional;
	sourceProcessId: string &log &optional;
	sourceImage: string &log &optional; 
	targetProcessId: string &log &optional;
	targetImage: string &log &optional;
	newThreadId: string &log &optional; 
	startAddress: string &log &optional;
	startModule: string &log &optional;
	startFunction: string &log &optional;
	};


    global log_createRemoteThread: event(rec: createRemoteThread);
}


event bro_init() &priority=5
    {
    Log::create_stream(Sysmon::CreateRemoteThread, [$columns=createRemoteThread, $ev=log_createRemoteThread, $path="sysmon_createRemoteThread"]);
}

event sysmonCreateRemoteThread(computerName: string, utcTime: string, sourceProcessGuid: string, sourceProcessId: string, sourceImage: string, targetProcessId: string, targetImage: string, newThreadId: string, startAddress: string, startModule: string, startFunction: string) 
{
local r: createRemoteThread;
print "HERE";
r$computerName = computerName;
r$utcTime = utcTime;
r$sourceProcessGuid = sourceProcessGuid;
r$sourceProcessId = sourceProcessId;
r$sourceImage = sourceImage;
r$targetProcessId = targetProcessId;
r$targetImage = targetImage;
r$newThreadId = newThreadId;
r$startAddress = startAddress;
r$startModule = startModule;
r$startFunction = startFunction;

print "Writing log";
Log::write(Sysmon::CreateRemoteThread, r);
}
