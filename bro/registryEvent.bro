# This script handles Sysmon Registry Event and writes contents to sysmon_registryEvent.log.
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

    redef enum Log::ID += {RegistryEvent};


    type registryEvent:record {
        computerName: string &log &optional;
        processId: string &log &optional;
        eventType: string &log &optional;
        image: string &log &optional;
        processGuid: string &log &optional;
        utcTime: string &log &optional;
        targetObject: string &log &optional;
        details: string &log &optional;
        newName: string &log &optional;
        };


    global log_registryEvent: event(rec: registryEvent);
}


event bro_init() &priority=5
    {
    Log::create_stream(Sysmon::RegistryEvent, [$columns=registryEvent, $ev=log_registryEvent, $path="sysmon_registryEvent"]);
}

event sysmon_registryEvent(computerName: string,eventType: string, utcTime: string, processGuid: string, processId: string, image: string, targetObject: string, details: string, newName: string)
{
local r: registryEvent;
r$computerName = computerName;
r$utcTime = utcTime;
r$processGuid = processGuid;
r$processId = processId;
r$image = image;
r$targetObject = targetObject;
r$details = details;
r$newName = newName;

Log::write(Sysmon::RegistryEvent, r);
}
