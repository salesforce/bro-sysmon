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
	process_id: int &log &optional;
	eventNamespace: string &log &optional;
	eventType: string &log &optional;
	name: string &log &optional;
	operation: string &log &optional;
	query: string &log &optional;
	user: string &log &optional;
	utcTime: string &log &optional;
	};


    global log_wmiEvent19: event(rec: wmiEvent19);
}


event bro_init() &priority=5
    {
    Log::create_stream(Sysmon::WmiEvent19, [$columns=wmiEvent19, $ev=log_wmiEvent19, $path="sysmon_wmiEvent19"]);
}

event sysmon_wmiEvent19(computer_name: string, process_id: int, eventNamespace: string, eventType: string, name: string, operation: string, query: string, user: string, utcTime: string)
{
local r: wmiEvent19;
#print "WMI Event 19";
r$computerName = computer_name;
r$process_id = process_id;
r$eventNamespace = eventNamespace;
r$eventType = eventType;
r$name = name;
r$operation = operation;
r$query = query;
r$utcTime = utcTime;

#print "Writing log";
Log::write(Sysmon::WmiEvent19, r);
}
