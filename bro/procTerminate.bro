# This script handles Sysmon Process Terminate event and writes contents to sysmon_procTerminate.log.
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

    redef enum Log::ID += {PROCTERMINATE};


    type procTerminate:record {
	computerName: string &log &optional;
	processId: string &log &optional;
	image: string &log &optional;
	processGuid: string &log &optional;
	utcTime: string &log &optional;
	};


    global log_procTerminate: event(rec: procTerminate);
}


event bro_init() &priority=5
    {
    Log::create_stream(Sysmon::PROCTERMINATE, [$columns=procTerminate, $ev=log_procTerminate, $path="sysmon_procTerminate"]);
}

event sysmon_procTerminate(computerName: string, image: string, processGuid: string, processId: string, utcTime: string)
{
local r: procTerminate;
r$computerName = computerName;
r$utcTime = utcTime;
r$image = image;
r$processGuid = processGuid;
r$processId = processId;

Log::write(Sysmon::PROCTERMINATE, r);
}
