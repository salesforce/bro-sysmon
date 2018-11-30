# This script handles Sysmon File Create Logs and writes contents to sysmon_fileCreate.log.
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

    redef enum Log::ID += {FileCreate};


    type fileCreate:record {
        computerName: string &log &optional;
        processId: string &log &optional;
        image: string &log &optional;
        processGuid: string &log &optional;
        targetFilename: string &log &optional;
        utcTime: string &log &optional;
        creationUtcTime: string &log &optional;
        };


    global log_fileCreate: event(rec: fileCreate);
}


event bro_init() &priority=5
    {
    Log::create_stream(Sysmon::FileCreate, [$columns=fileCreate, $ev=log_fileCreate, $path="sysmon_fileCreate"]);
}

event sysmon_fileCreate(computerName: string,image: string,processGuid: string,processId: string,targetFilename: string, creationUtcTime: string, utcTime: string)
{
local r: fileCreate;
r$computerName = computerName;
r$utcTime = utcTime;
r$creationUtcTime = creationUtcTime;
r$processGuid = processGuid;
r$processId = processId;
r$targetFilename = targetFilename;

#print "Writing log";
Log::write(Sysmon::FileCreate, r);
}
