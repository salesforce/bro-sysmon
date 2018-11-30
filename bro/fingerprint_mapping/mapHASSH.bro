# This script maps HASSH fingerprints to host applications adn writes them out to maphassh.log
# Version 1.0 (November 2018)
#
# Authors: Jeff Atkinson (jatkinson@salesforce.com)
#
# Copyright (c) 2017, salesforce.com, inc.
# All rights reserved.
# Licensed under the BSD 3-Clause license. 
# For full license text, see LICENSE.txt file in the repo root  or https://opensource.org/licenses/BSD-3-Clause

module Sysmon;

#@load ./trackNewPid.bro
#@load ./trackNetConns.bro

export {
    redef enum Log::ID += { MAPHASSH };

    type mapHASSHProc: record {
        hostname:       string &log &optional;
        processId:      string  &log &optional;
        conn:		conn_id &log	&optional;
        success:	bool	&log	&optional;
	attempts:	int	&log	&optional;
        client_string:	string	&log	&optional;
        hassh:            string  &log    &optional;
        server_string:	string	&log	&optional;
        hasshServer:           string  &log    &optional;
        procImage:      string  &log &optional;
	hashes:		string	&log	&optional;
    };

    global log_maphassh: event(rec: mapHASSHProc);
}


event bro_init() {
    Log::create_stream(Sysmon::MAPHASSH, [$columns=mapHASSHProc, $ev=log_maphassh, $path="maphassh"]);
}

event connection_state_remove(c: connection)
{
if ( !c?$ssh ) { return; }
print "Looking in table";
if ( c$id in tableNetConns ) {
   print "Found it!";
   print fmt("######### %s",tableNetConns[c$id]);
   local etwNetConn =  tableNetConns[c$id];
   local myComputerName = etwNetConn$computerName;
   local myProcessId = etwNetConn$processId;
   local myProcImage = etwNetConn$procImage;
   #print c$ssh;
   print fmt("Here's the details of that PID %s", trackPID[myComputerName,to_int(myProcessId)]);
  local r: mapHASSHProc;
  r$hostname = myComputerName;
  r$processId = myProcessId;
  r$procImage = myProcImage;
  r$conn = c$id;
  r$hassh = c$ssh$hassh;
  r$client_string = c$ssh$client;
  r$server_string = c$ssh$server;
  r$hasshServer = c$ssh$hasshServer;
  #r$hasshs = c$ssh$hasshs;
  r$success = c$ssh$auth_success;
  r$attempts = c$ssh$auth_attempts;
  #print c$ssh$client_host_key_algos;
  r$hashes = trackPID[myComputerName,to_int(myProcessId)]$hashes;
  Log::write(Sysmon::MAPHASSH, r);

  }
}

event bro_done() {
print trackPID;
}
