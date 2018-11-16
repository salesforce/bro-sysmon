# This script uses multiple events to track and create User sessions.
# TODO: Finish logic for tracking user logins and logoffs.
# Version 1.0 (November 2018)
#
# Authors: Jeff Atkinson (jatkinson@salesforce.com)
#
# Copyright (c) 2017, salesforce.com, inc.
# All rights reserved.
module Sysmon;


export {

  redef enum Log::ID += { USERLOGIN };

  type Info: record {
	hostname:	string	&log	&optional;
	processId:	string	&log	&optional;
	task:		string	&log	&optional;
	logonType:	string	&log	&optional;
	userName:	string	&log	&optional;
	logon_id:	string	&log	&optional;
	domain:		string	&log	&optional;
	workstationName:	string	&log	&optional;
	remoteIP:	string	&log	&optional;
	remotePort:	string	&log	&optional;
	logonProcName:	string	&log	&optional;
	startts:	string	&log	&optional;
	endts:		string	&log	&optional;
	};

  global log_userlogin: event(rec:Info);

}

const userSession: table[string, string] of Info &redef;

const logonTypes: table[int] of string &redef;
redef logonTypes += {
	[2] = "Interactive",
	[3] = "Network",
	[4] = "Batch",
	[5] = "Service",
	[7] = "Unlock",
	[8] = "NetworkCleartext",
	[9] = "NewCredentials",
	[10] = "RemoteInteractive",
	[11] = "CachedInteractive",
	};

event bro_init() {
   Log::create_stream(Sysmon::USERLOGIN, [$columns=Info, $ev=log_userlogin, $path="windows_UserLogin"]);
}

event windowsLogin(ts: string, computerName: string, procId: string, task: string, logonType: string, keywords: string, targetUserName: string, logon_id: string, domain: string, workstationName: string, remoteIpAddress: string, remoteIpPort: string, logonProcName: string)
{

if ( to_int(logonType) ! in logonTypes ) { print "Raise notice for unknown Logon Type",logonTypes; }
local login_type = "";
if ( to_int(logonType) in logonTypes )
    login_type =  logonTypes[to_int(logonType)];

local r: Info;
r$hostname = workstationName;
r$processId = procId;
r$task = task;
r$logonType = login_type;
r$userName = targetUserName;
r$logon_id = logon_id;
r$domain = domain;
r$workstationName = workstationName;
r$remoteIP = remoteIpAddress;
r$remotePort = remoteIpPort;
r$logonProcName = logonProcName;
r$startts = ts;

userSession[computerName,logon_id] = r;

Log::write(Sysmon::USERLOGIN, r);
}

event windowsLogoff(computerName: string, endts: string, task: string, logonId: string, userName: string){
print "Windows Logoff Event";
if ( [computerName,userName] ! in userSession ) { print "Not Found"; }
print fmt("Looking for %s %s in UserSession", computerName, logonId);
if ( [computerName,logonId] in userSession ) {
    userSession[computerName,logonId]$endts = endts;
  }

}


event bro_done() {
  print userSession;
}

#Event IDs:
#13 - Registry Value - Set LogedOnUserName - Details
#4624 - Logon
#4634 - Logoff
