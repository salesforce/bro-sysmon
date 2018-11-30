# This script handles Sysmon WMI Event 21 and writes contents to sysmon_wmiEvent21.log.
# TODO: Finish parsing events sent from Broker.
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

    redef enum Log::ID += {WmiEvent};

    type wmiEvent:record {
	computerName: string &log &optional;
	processId: string &log &optional;
	action: string &log &optional;
	utcTime: string &log &optional;
	processGuid: string &log &optional;
	pipeName: string &log &optional;
	image: string &log &optional;
	};

    global log_wmiEvent: event(rec: wmiEvent);
}

event bro_init() &priority=5
    {
    Log::create_stream(Sysmon::WmiEvent, [$columns=wmiEvent, $ev=log_wmiEvent, $path="sysmon_wmiEvent21"]);
}

event sysmon_wmiEvent(computerName: string, action: string,  utcTime: string, processGuid: string, processId: string, pipeName: string, image: string)
{
local r: wmiEvent;
r$computerName = computerName;
r$action = action;
r$utcTime = utcTime;
r$processGuid = processGuid;
r$processId = processId;
r$pipeName = pipeName;
r$image = image;

Log::write(Sysmon::WmiEvent, r);
}
