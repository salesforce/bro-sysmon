# This script handles Sysmon Process Change File Time event and writes contents to sysmon_proChngFileTime.log.
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

event process_change_file_time(computerName: string,processId: string,utcTime: string,processGuid: string,targetFilename: string,creationUtcTime: string,previousCreationUtcTime: string, image:string)

#event sysmonProcChangeFile(computerName: string,utcTime: string,processGuid: string,processId: string,targetFilename: string,creationUtcTime: string,previousCreationUtcTime: string)
{
local r: procChngFileTime;
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
