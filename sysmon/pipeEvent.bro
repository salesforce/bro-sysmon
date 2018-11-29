# This script handles Sysmon Named Pipe events and writes contents to sysmon_pipeEvent.log.
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

    redef enum Log::ID += {PipeEvent};


    type pipeEvent:record {
	computerName: string &log &optional;
	action: string &log &optional;
	utcTime: string &log &optional;
	processGuid: string &log &optional;
	processId: string &log &optional;
	pipeName: string &log &optional;
	image: string &log &optional;
	};


    global log_pipeEvent: event(rec: pipeEvent);
}


event bro_init() &priority=5
    {
    Log::create_stream(Sysmon::PipeEvent, [$columns=pipeEvent, $ev=log_pipeEvent, $path="sysmon_pipeEvent"]);
}

event sysmon_pipeEvent(computerName: string, action: string,  utcTime: string, processGuid: string, processId: string, pipeName: string, image: string)
{
local r: pipeEvent;
#print "Pipe Event";
r$computerName = computerName;
r$action = action;
r$utcTime = utcTime;
r$processGuid = processGuid;
r$processId = processId;
r$pipeName = pipeName;
r$image = image;

Log::write(Sysmon::PipeEvent, r);
}
