# This script handles Sysmon Named Pipe events and writes contents to sysmon_pipeEvent.log.
# Version 1.0 (November 2018)
#
# Authors: Jeff Atkinson (jatkinson@salesforce.com)
#
# Copyright (c) 2017, salesforce.com, inc.
# All rights reserved.
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

event sysmonPipeEvent(computerName: string, action: string,  utcTime: string, processGuid: string, processId: string, pipeName: string, image: string)
{
local r: pipeEvent;
print "HERE";
r$computerName = computerName;
r$action = action;
r$utcTime = utcTime;
r$processGuid = processGuid;
r$processId = processId;
r$pipeName = pipeName;
r$image = image;

print "Writing log";
Log::write(Sysmon::PipeEvent, r);
}
