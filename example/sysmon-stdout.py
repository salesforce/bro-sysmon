#!/usr/bin/env python
# This script handles Sysmon Configuration Change events and writes to sysmon_configChange.log.
# Version 1.0 (November 2018)
#
# Authors: Jeff Atkinson (jatkinson@salesforce.com)
#
# Copyright (c) 2017, salesforce.com, inc.
# All rights reserved.
# Licensed under the BSD 3-Clause license. 
# For full license text, see LICENSE.txt file in the repo root  or https://opensource.org/licenses/BSD-3-Clause

from argparse import ArgumentParser

import broker
import json
import pprint
import time
import sys
import stat
import os

_DESCRIPTION = '''Convert Windows Event Log data into Bro events and transmit
them via a broker topic.
'''

def generic_event(winevt):
    print("################## Generic Event #########################")
    pprint.pprint(winevt)
    print("#####################################################")  

def logon_success(winevt):
    evt_data = winevt.get('event_data')
    print("################## Logon Success #########################")
    pprint.pprint(winevt)
    print("#####################################################")

def object_sacl_changed(winevt):
    evt_data = winevt.get('event_data')
    print("################## object_sacl_changed #########################")
    pprint.pprint(winevt)
    print("#####################################################")

def process_creation(winevt):
    print("################## Process Created #########################")
    pprint.pprint(winevt)
    print("#####################################################")

def process_change_file(winevt):
    evt_data = winevt['event_data']
    print("################## Process Changed File #########################")
    pprint.pprint(winevt)
    print("#####################################################")

def network_connection(winevt):
    evt_data = winevt['event_data']
    print("################## Network Conneciton #########################")
    pprint.pprint(winevt)
    print("#####################################################")

def service_change(winevt):
    print "service_change"
    print("################## Service Changed #########################")
    pprint.pprint(winevt)
    print("#####################################################")

def process_terminated(winevt):
    evt_data = winevt['event_data']
    print("################## Process Terminated #########################")
    pprint.pprint(winevt)
    print("#####################################################")

def driver_loaded(winevt):
    evt_data = winevt['event_data']
    print("################## Driver Loaded #########################")
    pprint.pprint(winevt)
    print("#####################################################")

def image_loaded(winevt):
    evt_data = winevt['event_data']
    print("################## Image Loaded #########################")
    pprint.pprint(winevt)
    print("#####################################################")

def create_remote_thread(winevt):
    evt_data = winevt['event_data']
    print("################## Create Remote Thread #########################")
    pprint.pprint(winevt)
    print("#####################################################")

def raw_access_read(winevt):
    evt_data = winevt['event_data']
    print("################## Raw Access Read #########################")
    pprint.pprint(winevt)
    print("#####################################################")

def process_access(winevt):
    evt_data = winevt['event_data']
    print("################## Process Access #########################")
    pprint.pprint(winevt)
    print("#####################################################")

def file_create(winevt):
    evt_data = winevt['event_data']
    print("################## File Create #########################")
    pprint.pprint(winevt)
    print("#####################################################")


def registry_event(winevt):
    evt_data = winevt['event_data']
    print("################## Registry Event #########################")
    pprint.pprint(winevt)
    print("#####################################################")

def file_create_stream_hash(winevt):
    evt_data = winevt['event_data']
    print("################## File Stream Hash #########################")
    pprint.pprint(winevt)
    print("#####################################################")

def config_change(winevt):
    evt_data = winevt['event_data']
    print("################## config change #########################")
    pprint.pprint(winevt)
    print("#####################################################")


def pipe_event(winevt):
    if winevt['event_id'] == 17:
        action = "PipeCreated"
    if winevt['event_id'] == 18:
        action = "PipeConnected"
    evt_data = winevt['event_data']

    print("################## Pipe Event #########################")
    pprint.pprint(winevt)
    print("#####################################################")


def wmi_event_19(winevt):
    evt_data = winevt['event_data']
    print("################## Event 19 ##########################")
    pprint.pprint(winevt)
    print("######################################################")

def wmi_event_20(winevt):
    evt_data = winevt['event_data']
    print("################## Event 20 #########################")
    pprint.pprint(winevt)
    print("#####################################################")


def wmi_event_21(winevt):
    evt_data = winevt['event_data']
    print("################## Event 21 #########################")
    pprint.pprint(winevt)
    print("#####################################################")

def sysmon_error(winevt):
    print "Error"
    print("################## Error Message #########################")
    pprint.pprint(winevt)
    print("#####################################################")

_security_event_map = {
    # 4634: logoff_success,
    #4907: object_sacl_changed,
}

_system_event_map = dict(
    
)

_sysmon_event_map = {
	1:   process_creation,
	2:   process_change_file,
	3:   network_connection,
	4:   service_change,
	5:   process_terminated,
	6:   driver_loaded,
	7:   image_loaded,
	8:   create_remote_thread,
	9:   raw_access_read,
	10:  process_access,
	11:  file_create,
	12:  registry_event,
	13:  registry_event,
	14:  registry_event,
	15:  file_create_stream_hash,
	16:  config_change,
	17:  pipe_event,
	18:  pipe_event,
	19:  wmi_event_19,
	20:  wmi_event_20,
	21:  wmi_event_21,
	25:  sysmon_error
}

_event_map = {
    "Security": _security_event_map,
    "System": _system_event_map,
    #Sysmon: _sysmon_event_map
    "Microsoft-Windows-Sysmon/Operational": _sysmon_event_map
}

def main(file_in):
    with open(file_in, 'r') as f:
#     for line in f:
      while 1:
	where = f.tell()
	line = f.readline()
	if not line:
	    time.sleep(1)
	    f.seek(where)
	else:
            try:
                winevt = json.loads(line)
            except JSONDecodeError:
  		print("JSON Decode Error")
                continue

	    if winevt['event_id'] == 19:
		print winevt
	    if str(winevt.get('log_name')) == 'Microsoft-Windows-Sysmon/Operational':
	        myLogName = 'Sysmon'
	    else:
		myLogName = winevt['log_name']

            # this is a bit complicated, so to break it down:
            # 1. Look in _event_map for a log name to map events to a func
            #  if it doesn't match, return a dict so that nothing is wrong
            #  in the following call where:
            # 2. An event is then mapped with event_id using one of the 
            #  specific event log maps. If one doesn't match, then the 
            #  generic event handler is used.
            build_message = _event_map.get(str(winevt.get('log_name')), 
                dict()).get(winevt.get('event_id'), generic_event)
            # use the matched event handler and publish it to the winevt
            # broker topic
            msg = build_message(winevt)
            # if they error, the event handlers return None
            if msg:
		continue

if __name__ == '__main__':
    p = ArgumentParser(description=_DESCRIPTION)
    p.add_argument('file_in',
                    help='File to read events from.')
    args = p.parse_args()


main(args.file_in)
