# This script handles Sysmon File Create Steam Hashand writes contents to sysmon_fileCreateStreamHash.log.
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

    redef enum Log::ID += {FileCreateStreamHash};


    type fileCreateStreamHash:record {
        computerName: string &log &optional;
        processId: string &log &optional;
        targetFilename: string &log &optional;
        eventType: string &log &optional;
        image: string &log &optional;
        processGuid: string &log &optional;
        utcTime: string &log &optional;
        creationUtcTime: string &log &optional;
        hash: string &log &optional;
        };


    global log_fileCreateStreamHash: event(rec: fileCreateStreamHash);
}


event bro_init() &priority=5
    {
    Log::create_stream(Sysmon::FileCreateStreamHash, [$columns=fileCreateStreamHash, $ev=log_fileCreateStreamHash, $path="sysmon_fileCreateStreamHash"]);
}

event sysmon_fileCreateStreamHash(computerName: string, utcTime: string, processGuid: string, processId: string, image: string, targetFilename: string, creationUtcTime: string, hash: string)
{
local r: fileCreateStreamHash;
#print "HERE";
r$computerName = computerName;
r$utcTime = utcTime;
r$processGuid = processGuid;
r$processId = processId;
r$image = image;
r$targetFilename = targetFilename;
r$creationUtcTime = creationUtcTime;
r$hash = hash;

#print "Writing log";
Log::write(Sysmon::FileCreateStreamHash, r);
}
