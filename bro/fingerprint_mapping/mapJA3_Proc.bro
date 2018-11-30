# This script maps JA3 and JA3s TLS fingerprints to host application data and writes content out to mapja3.log.
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
    redef enum Log::ID += { MAPJA3 };

    type mapJA3Proc: record {
        hostname:       string &log &optional;
        processId:      string  &log &optional;
        conn:		conn_id &log	&optional;
        ja3:            string  &log    &optional;
        ja3s:           string  &log    &optional;
        server_name:    string  &log    &optional;
        procImage:      string  &log &optional;
	hashes:		string	&log	&optional;
        subject:	string	&log	&optional;
	issuer:		string	&log	&optional;
    };

    global log_mapja3: event(rec: mapJA3Proc);
}


event bro_init() {
    Log::create_stream(Sysmon::MAPJA3, [$columns=mapJA3Proc, $ev=log_mapja3, $path="mapja3"]);
}

event connection_state_remove(c: connection)
{
if ( !c?$ssl ) { return; }
if ( !c$ssl?$ja3 ) { return; }
print "Looking in table";
if ( c$id in tableNetConns ) {
   print "Found it!";
   local etwNetConn =  tableNetConns[c$id];
   local myComputerName = etwNetConn$computerName;
   local myProcessId = etwNetConn$processId;
   local myProcImage = etwNetConn$procImage;

   #print fmt("Here's the details of that PID %s", trackPID[myComputerName,to_int(myProcessId)]);
  local r: mapJA3Proc;
  r$hostname = myComputerName;
  r$processId = myProcessId;
  r$procImage = myProcImage;
  r$conn = c$id;
  r$ja3 = c$ssl$ja3;
  r$ja3s = c$ssl$ja3s;
  r$server_name = c$ssl$server_name;
  r$hashes = trackPID[myComputerName,to_int(myProcessId)]$hashes;
  r$subject = c$ssl$cert_chain[0]$x509$certificate$subject;
  r$issuer = c$ssl$cert_chain[0]$x509$certificate$issuer;
  Log::write(Sysmon::MAPJA3, r);

  }
}
