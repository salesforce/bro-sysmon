# This script handles Sysmon Process Access event and writes contents to sysmon_processAccess.log.
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

    redef enum Log::ID += {ProcessAccess};


    type processAccess:record {
        computerName: string &log &optional;
        sourceProcessId: string &log &optional;
        targetProcessId: string &log &optional;
        grantedAccess: string &log &optional;
        sourceImage: string &log &optional;
        sourceProcGuid: string &log &optional;
        sourceThreadId: string &log &optional;  
        targetImage: string &log &optional;
        targetProcGuid: string &log &optional;
        targetProcessId: string &log &optional;
        utcTime: string &log &optional;
        };


    global log_processAccess: event(rec: processAccess);
}


event bro_init() &priority=5
    {
    Log::create_stream(Sysmon::ProcessAccess, [$columns=processAccess, $ev=log_processAccess, $path="sysmon_processAccess"]);
}

event sysmonProcAccess(computerName: string, grantedAccess: string,sourceImage: string,sourceProcGuid: string,sourceProcessId: string,sourceThreadId: string,targetImage: string,targetProcGuid: string,targetProcessId: string,utcTime: string)
{
local r: processAccess;
#print "HERE";
r$computerName = computerName;
r$utcTime = utcTime;
r$grantedAccess = grantedAccess;
r$sourceImage = sourceImage;
r$sourceProcGuid = sourceProcGuid;
r$sourceProcessId = sourceProcessId;
r$sourceThreadId = sourceThreadId;
r$targetImage = targetImage;
r$targetProcGuid = targetProcGuid;
r$targetProcessId = targetProcessId;

#print "Writing log";
Log::write(Sysmon::ProcessAccess, r);
}

