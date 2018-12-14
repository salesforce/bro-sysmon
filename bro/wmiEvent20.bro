# This script handles Sysmon WMI Event 20 and writes contents to sysmon_wmiEvent20.log.
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

    redef enum Log::ID += {WmiEvent20};


    type wmiEvent20:record {
	computerName: string &log &optional;
	process_id: int &log &optional;
	destination_len: int &log &optional;
	destination: string &log &optional;
	eventType: string &log &optional;
	operation: string &log &optional;
	mytype: string &log &optional;
	user: string &log &optional;
	utc_time: string &log &optional;
	};


    global log_wmiEvent20: event(rec: wmiEvent20);
}


event bro_init() &priority=5
    {
    Log::create_stream(Sysmon::WmiEvent20, [$columns=wmiEvent20, $ev=log_wmiEvent20, $path="sysmon_wmiEvent20"]);
}

event sysmon_wmiEvent20(computer_name: string, process_id: int, destination: string, eventType: string, operation: string, mytype: string, user: string, utc_time: string)
{
local r: wmiEvent20;
#print "HERE WMI 20";
r$computerName = computer_name;
r$process_id = process_id;
r$destination_len = |destination|;
r$destination = destination;
r$eventType = eventType;
r$operation = operation;
r$mytype = mytype;
r$user = user;
r$utc_time = utc_time;

#print "Writing log";
Log::write(Sysmon::WmiEvent20, r);
}
