# This script handles Sysmon Network Connection event and writes contents to sysmon_netconnect.log.
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
    redef enum Log::ID += { NETCONN };

    type netConn: record {
        hostname:       string &log &optional;
        processId:              string  &log &optional;
        orig_h:         addr    &log    &optional;
        orig_p:         port    &log    &optional;
        resp_h:         addr    &log    &optional;
        resp_p:         port    &log    &optional;
        procImage:      string  &log &optional;
    };

    global log_sysmon_netconnect: event(rec: netConn);
}

event bro_init() &priority=5
    {
    Log::create_stream(Sysmon::NETCONN, [$columns=netConn, $ev=log_sysmon_netconnect, $path="sysmon_netconnect"]);
}

event sysmon_networkConnection(computerName: string, processId: string, proto: string, srcip: string, srcprt: string, dstip: string, dstprt: string, procImage: string)
{
#print "Network Connection";
  local orig_h = to_addr(srcip);
  local orig_p =  to_port(string_cat(srcprt,"/",proto));
  local resp_h = to_addr(dstip);
  local resp_p =  to_port(string_cat(dstprt,"/",proto));
  local r: netConn;
  
  r$hostname = computerName;
  r$orig_h = orig_h;
  r$orig_p = orig_p;
  r$resp_h = resp_h;
  r$resp_p = resp_p;
  r$processId = processId;
  r$procImage = procImage;

Log::write(Sysmon::NETCONN, r);
}

