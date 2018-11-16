# This script handles Sysmon Process Change File Time event and writes contents to sysmon_proChngFileTime.log.
# Version 1.0 (November 2018)
#
# Authors: Jeff Atkinson (jatkinson@salesforce.com)
#
# Copyright (c) 2017, salesforce.com, inc.
# All rights reserved.
module Sysmon;

export {

    redef enum Log::ID += {FileTimeChange};


    type procChngFileTime:record {
        computerName: string &optional &log;
        processId: string &optional &log;
        utcTime: string &optional &log;
        processGuid: string &optional &log;
        targetFilename: string &optional &log;
        creationUtcTime: string &optional &log;
        previousCreationUtcTime: string &optional &log;
        };


    global log_procChngFileTime: event(rec: procChngFileTime);
}


event bro_init() &priority=5
    {
    Log::create_stream(Sysmon::FileTimeChange, [$columns=procChngFileTime, $ev=log_procChngFileTime, $path="sysmon_procChngFileTime"]);
}

event sysmonProcChangeFile(computerName: string,utcTime: string,processGuid: string,processId: string,targetFilename: string,creationUtcTime: string,previousCreationUtcTime: string)
{
local r: procChngFileTime;
#print "HERE";
r$computerName = computerName;
r$utcTime = utcTime;
r$processGuid = processGuid;
r$processId = processId;
r$targetFilename = targetFilename;
r$creationUtcTime = creationUtcTime;
r$previousCreationUtcTime = previousCreationUtcTime;


#print "Writing log";
Log::write(Sysmon::FileTimeChange, r);
}
