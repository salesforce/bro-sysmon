# This script handles Sysmon Image Loaded event and writes contents to sysmon_imageLoaded.log.
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

    redef enum Log::ID += {ImageLoaded};


    type sysimageLoaded:record {
        computerName: string &log &optional;
        processId: string &log &optional;
        utcTime: string &log &optional;
        procGuid: string &log &optional;
        image: string &log &optional;
        imageLoaded: string &log &optional;
        hashes: string &log &optional;
        signed: string &log &optional;
        sigStatus: string &log &optional;
        };


    global log_imageLoad: event(rec: sysimageLoaded);
}


event bro_init() &priority=5
    {
    Log::create_stream(Sysmon::ImageLoaded, [$columns=sysimageLoaded, $ev=log_imageLoad, $path="sysmon_imageLoaded"]);
}

event sysmon_imageLoaded(computerName: string,utcTime: string,procGuid: string,processId: string,image: string,imageLoaded: string,hashes: string,signed: string,sigStatus: string)
{
local r: sysimageLoaded;
r$computerName = computerName;
r$utcTime = utcTime;
r$procGuid = procGuid;
r$processId = processId;
r$imageLoaded = imageLoaded;
r$hashes = hashes;
r$signed = signed;
r$sigStatus = sigStatus;

Log::write(Sysmon::ImageLoaded, r);
}
