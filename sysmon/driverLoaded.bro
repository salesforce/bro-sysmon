# This script handles Sysmon's Driver Loaded event and writes content out to sysmon_driverLoaded.log.
# Version 1.0 (November 2018)
#
# Authors: Jeff Atkinson (jatkinson@salesforce.com)
#
# Copyright (c) 2017, salesforce.com, inc.
# All rights reserved.

module Sysmon;

export {

    redef enum Log::ID += {DriverLoaded};


    type driverLoaded:record {
        computerName: string &log &optional;
        processId:      int     &log &optional;
        hashes: string &log &optional;
        imageLoaded: string &log &optional;
        signature: string &log &optional;
        signatureStatus: string &log &optional;
        signed: string &log &optional;
        utcTime: string &log &optional;
        };


    global log_driverLoaded: event(rec: driverLoaded);
}


event bro_init() &priority=5
    {
    Log::create_stream(Sysmon::DriverLoaded, [$columns=driverLoaded, $ev=log_driverLoaded, $path="sysmon_driverLoaded"]);
}

event sysmonDriverLoaded(computerName: string, processId: int, hashes: string; imageLoaded: string, signature: string, signatureStatus: string, signed: string, utcTime: string)
{
local r: driverLoaded;
#print "HERE";
r$computerName = computerName;
r$processId = processId;
r$hashes = hashes;
r$imageLoaded = imageLoaded;
r$signature = signature;
r$signatureStatus = signatureStatus;
r$signed = signed;
r$utcTime = utcTime;


#print "Writing log";
Log::write(Sysmon::DriverLoaded, r);
}
