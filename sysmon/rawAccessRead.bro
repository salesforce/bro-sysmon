# This script handles Sysmon Raw Access Read event and writes contents to sysmon_rawAccessRead.log.
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

    redef enum Log::ID += {RawAccessRead};


    type rawAccessRead:record {
	computerName: string &log &optional;
	processId: string &log &optional;
	utcTime: string &log &optional;
	processGuid: string &log &optional;
	image: string &log &optional;
	device: string &log &optional;
	};


    global log_rawAccessRead: event(rec: rawAccessRead);
}


event bro_init() &priority=5
    {
    Log::create_stream(Sysmon::RawAccessRead, [$columns=rawAccessRead, $ev=log_rawAccessRead, $path="sysmon_rawAccessRead"]);
}

event sysmonRawAccessRead(computerName: string, utcTime: string, processGuid: string, processId: string, image: string, device: string)
{
local r: rawAccessRead;
#print "HERE";
r$computerName = computerName;
r$utcTime = utcTime;
r$image = image;
r$processGuid = processGuid;
r$processId = processId;
r$device = device;

#print "Writing log";
Log::write(Sysmon::RawAccessRead, r);
}
