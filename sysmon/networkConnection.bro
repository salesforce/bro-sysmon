# This script handles Sysmon Network Connection event and writes contents to sysmon_netconnect.log.
# Version 1.0 (November 2018)
#
# Authors: Jeff Atkinson (jatkinson@salesforce.com)
#
# Copyright (c) 2017, salesforce.com, inc.
# All rights reserved.
module Sysmon;

export {
    redef enum Log::ID += { NETCONN };

    type Info: record {
        hostname:       string &log &optional;
        processId:              string  &log &optional;
        orig_h:         addr    &log    &optional;
        orig_p:         port    &log    &optional;
        resp_h:         addr    &log    &optional;
        resp_p:         port    &log    &optional;
        ja3:            string  &log    &optional;
        procImage:      string  &log &optional;
    };

    global log_sysmon_netconnect: event(rec: Info);
}

event bro_init() &priority=5
    {
    Log::create_stream(Sysmon::NETCONN, [$columns=Info, $ev=log_sysmon_netconnect, $path="sysmon_netconnect"]);
}

event sysmonProcNetConn(computerName: string, proto: string, srcip: string, srcprt: string, dstip: string, dstprt: string, processId: string, procImage: string)
{
  local orig_h = to_addr(srcip);
  local orig_p =  to_port(string_cat(srcprt,"/",proto));
  local resp_h = to_addr(dstip);
  local resp_p =  to_port(string_cat(dstprt,"/",proto));
  local r: Info;
  
  r$hostname = computerName;
  r$orig_h = orig_h;
  r$orig_p = orig_p;
  r$resp_h = resp_h;
  r$resp_p = resp_p;
  r$processId = processId;
  r$procImage = procImage;
  #print r;
  #print "Received Process Network Connect ID 3 ", network_time(); 
Log::write(Sysmon::NETCONN, r);

}

