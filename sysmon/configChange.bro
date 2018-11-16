# This script handles Sysmon Configuration Change events and writes to sysmon_configChange.log.
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

    redef enum Log::ID += {ConfigChange};


    type configChange:record {
        computerName: string &log &optional;
        utcTime: string &log &optional;
        config: string &log &optional;
        configFileHash: string &log &optional;
        };


    global log_configChange: event(rec: configChange);
}


event bro_init() &priority=5
    {
    Log::create_stream(Sysmon::ConfigChange, [$columns=configChange, $ev=log_configChange, $path="sysmon_configChange"]);
}

event sysmonConfigChange(computerName: string, utcTime: string, config: string, configFileHash: string)
{
local r: configChange;
#print "HERE";
r$computerName = computerName;
r$utcTime = utcTime;
r$config = config;
r$configFileHash = configFileHash;


#print "Writing log";
Log::write(Sysmon::ConfigChange, r);
}
