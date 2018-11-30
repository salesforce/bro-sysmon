# This script handles generaic Windows Event logs and simply writes out the message to winevt_generic
# Version 1.0 (November 2018)
#
# Authors: Jeff Atkinson (jatkinson@salesforce.com)
#
# Copyright (c) 2017, salesforce.com, inc.
# All rights reserved..
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
    redef enum Log::ID += {EVENTLOG };

    type Info: record {
        hostname:       string  &log    &optional;
        event_id:       int     &log    &optional;
        log_name:       string     &log    &optional;
        task:       string     &log    &optional;
        opcode:       string     &log    &optional;
        message:        string  &log    &optional;
        event_data:        string  &log    &optional;
    };

    global log_eventLogMessage: event(rec: Info);

}

event bro_init() { 
    Log::create_stream(Sysmon::EVENTLOG, [$columns=Info, $ev=log_eventLogMessage, $path="winevt_generic"]);
}




event WindowsEvent(computerName: string, log_name: string, event_id: int, task: string, opcode: string, message: string, event_data: string) {

local r: Info;

print computerName, event_id, gsub(message,/\x09/,"#####");
  r$hostname = computerName;
  r$event_id = event_id;
  r$log_name = log_name;
  r$task = task;
  r$opcode = opcode;
  local message1 = gsub(message,/\x09/," ");
  local message2 = gsub(message1,/\x0a/," ");
  r$message = message2;
  #r$event_data = event_data;
  

Log::write(Sysmon::EVENTLOG, r);


}
