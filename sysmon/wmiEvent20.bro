# This script handles Sysmon WMI Event 20 and writes contents to sysmon_wmiEvent20.log.
# Version 1.0 (November 2018)
#
# Authors: Jeff Atkinson (jatkinson@salesforce.com)
#
# Copyright (c) 2017, salesforce.com, inc.
# All rights reserved.
module Sysmon;

export {

    redef enum Log::ID += {WmiEvent20};


    type wmiEvent20:record {
	computerName: string &log &optional;
	bootStatusPolicy: string &log &optional;
	lastBootGood: string &log &optional;
	lastBootId: string &log &optional;
	lastShutdownGood: string &log &optional;
	};


    global log_wmiEvent20: event(rec: wmiEvent20);
}


event bro_init() &priority=5
    {
    Log::create_stream(Sysmon::WmiEvent20, [$columns=wmiEvent20, $ev=log_wmiEvent20, $path="sysmon_wmiEvent20"]);
}

event sysmonWmiEvent20(computerName: string, bootStatusPolicy: string,  lastBootGood: string, lastBootId: string, lastShutdownGood: string)
{
local r: wmiEvent20;
#print "HERE";
r$computerName = computerName;
r$bootStatusPolicy = bootStatusPolicy;
r$lastBootGood = lastBootGood;
r$lastBootId = lastBootId;
r$lastShutdownGood = lastShutdownGood;

#print "Writing log";
Log::write(Sysmon::WmiEvent20, r);
}
