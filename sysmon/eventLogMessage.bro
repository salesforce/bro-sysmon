# This script handles generaic Windows Event logs and simply writes out the message to a sysmon_# This script parses Windows Event Logs in JSON format and forwards events to the Bro Platform.
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

module Sysmon;

export {
    redef enum Log::ID += {EVENTLOG };

    type Info: record {
        hostname:       string  &log    &optional;
        event_id:       int     &log    &optional;
        message:        string  &log    &optional;
    };

    global log_eventLogMessage: event(rec: Info);

}

event bro_init() { 
    Log::create_stream(Sysmon::EVENTLOG, [$columns=Info, $ev=log_eventLogMessage, $path="sysmon_eventLogMessage"]);
}




event EventLogEvent(computerName: string, event_id: int, message: string) {

local r: Info;

#print computerName, gsub(message,/\x09/,"#####");
  r$hostname = computerName;
  r$event_id = event_id;
  local message1 = gsub(message,/\x09/," ");
  local message2 = gsub(message1,/\x0a/," ");
  r$message = message2;

Log::write(Sysmon::EVENTLOG, r);


}
