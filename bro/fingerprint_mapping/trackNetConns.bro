# This script uses the Sysmon Network Connections to create a list of Connection IDs and their associated process details.
# Version 1.0 (November 2018)
#
# Authors: Jeff Atkinson (jatkinson@salesforce.com)
#
# Copyright (c) 2017, salesforce.com, inc.
# All rights reserved.
# Licensed under the BSD 3-Clause license. 
# For full license text, see LICENSE.txt file in the repo root  or https://opensource.org/licenses/BSD-3-Clause

module Sysmon;

type ProcDetails: record {
	computerName:	string 	&log	&optional;
	processId:	string	&log	&optional;
	procImage:	string	&log	&optional;
};

global tableNetConns: table[conn_id] of ProcDetails &redef;

event sysmon_networkConnection(computerName: string, processId: string, proto: string, srcip: string, srcprt: string, dstip: string, dstprt: string, procImage: string)
{
#print "Network Connection";

  local orig_h = to_addr(srcip);
  local orig_p =  to_port(string_cat(srcprt,"/",proto));
  local resp_h = to_addr(dstip);
  local resp_p =  to_port(string_cat(dstprt,"/",proto));
  local myConn: conn_id &redef;

  local r: ProcDetails;
  r$computerName = computerName;
  r$processId = processId;
  r$procImage = procImage;


  myConn$orig_h = orig_h;
  myConn$orig_p = orig_p;
  myConn$resp_h = resp_h;
  myConn$resp_p = resp_p;
  #print fmt("Adding %s", cat(myConn));
  tableNetConns[myConn] = r;
}


event bro_done() {

#print tableNetConns;

}
