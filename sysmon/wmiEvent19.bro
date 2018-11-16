# This script handles Sysmon WMI Event 19 and writes contents to sysmon_wmiEvent19.log.
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

    redef enum Log::ID += {WmiEvent19};


    type wmiEvent19:record {
	computerName: string &log &optional;
	utcTime: string &log &optional;
	serviceGuid: string &log &optional;
	updateGuid: string &log &optional;
	updateRevisionNumber: string &log &optional;
	updateTitle: string &log &optional;
	};


    global log_wmiEvent19: event(rec: wmiEvent19);
}


event bro_init() &priority=5
    {
    Log::create_stream(Sysmon::WmiEvent19, [$columns=wmiEvent19, $ev=log_wmiEvent19, $path="sysmon_wmiEvent19"]);
}

event sysmonWmiEvent19(computerName: string,  utcTime: string, serviceGuid: string, updateGuid: string, updateRevisionNumber: string, updateTitle: string)
{
local r: wmiEvent19;
#print "HERE";
r$computerName = computerName;
r$utcTime = utcTime;
r$serviceGuid = serviceGuid;
r$updateGuid = updateGuid;
r$updateRevisionNumber = updateRevisionNumber;
r$updateTitle = updateTitle;

#print "Writing log";
Log::write(Sysmon::WmiEvent19, r);
}
