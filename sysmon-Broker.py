#!/usr/bin/env python

from argparse import ArgumentParser

import broker
import json
import pprint

_DESCRIPTION = '''Convert Windows Event Log data into Bro events and transmit
them via a broker topic.
'''

def generic_event(winevt):
    try:
        message = broker.bro.Event(
            'WindowsEvent',
            str(winevt.get('computer_name')),
            str(winevt.get('log_name')),
            int(winevt.get('event_id')),
            str(winevt.get('opcode')),
            str(winevt.get('task', 'None')),
            str(winevt.get('message', 'None')),
            str(winevt.get('event_data', 'None')),
        )
    except Exception as e:
        print(e)
        return 
        #return None
 
   
    return message

def logon_success(winevt):
    evt_data = winevt.get('event_data')

def object_sacl_changed(winevt):
    evt_data = winevt.get('event_data')


def process_creation(winevt):
    evt_data = winevt['event_data']

    try:
        message = broker.bro.Event(
	    'process_created',
	    winevt.get('computer_name').encode('ascii','ignore'),
	    evt_data.get('ProcessId','ProcessID not provided').encode('ascii','ignore'),
	    evt_data.get('CommandLine','CommandLine not provided').encode('ascii','ignore'),
	    evt_data.get('Company','Company not provided').encode('ascii','ignore'),
	    evt_data.get('CurrentDirectory','CurrentDirectory not provided').encode('ascii','ignore'),
	    evt_data.get('Description','Description not provided').encode('ascii','ignore'),
	    evt_data.get('FileVersion','FileVersion not provided').encode('ascii','ignore'),
	    evt_data.get('Hashes','Hashes not provided').encode('ascii','ignore'),
	    evt_data.get('Image','Image not provided').encode('ascii','ignore'),
	    evt_data.get('IntegrityLevel','IntegrityLevel not provided').encode('ascii','ignore'),
	    evt_data.get('LogonGuid','LogonGuid not provided').encode('ascii','ignore'),
	    evt_data.get('LogonId','LogonId not provided').encode('ascii','ignore'),
	    evt_data.get('ParentCommandLine','ParentCommandLine not provided').encode('ascii','ignore'),
	    evt_data.get('ParentImage','ParentImage not provided').encode('ascii','ignore'),
	    evt_data.get('ParentProcessGuid','ParentProcessGuid not provided').encode('ascii','ignore'),
	    evt_data.get('ParentProcessId','ParentProcessId not provided').encode('ascii','ignore'),
	    evt_data.get('ProcessGuid','ProcessGuid not provided').encode('ascii','ignore'),
	    evt_data.get('Product','Product not provided').encode('ascii','ignore'),
	    evt_data.get('TerminalSessionId','TerminalSessionId not provided').encode('ascii','ignore'),
	    evt_data.get('User','User not provided').encode('ascii','ignore'),
	    evt_data.get('UtcTime','UtcTime not provided').encode('ascii','ignore'),
        )
    except Exception as e:
        return 
    return message

def process_change_file(winevt):
    evt_data = winevt['event_data']
    try:
        message = broker.bro.Event(
            'process_change_file_time',
            winevt.get('computer_name').encode('ascii','ignore'),
            evt_data.get('ProcessId','None').encode('ascii','ignore'),
            evt_data.get('UtcTime','None').encode('ascii','ignore'),
            evt_data.get('ProcessGuid','None').encode('ascii','ignore'),
            evt_data.get('TargetFilename','None').encode('ascii','ignore'),
            evt_data.get('CreationUtcTime','None').encode('ascii','ignore'),
            evt_data.get('PreviousCreationUtcTime','None').encode('ascii','ignore'),
            evt_data.get('Image','None').encode('ascii','ignore'),
        )
    except Exception as e:
        return
    return message

def network_connection(winevt):
    evt_data = winevt['event_data']

    try:
        message = broker.bro.Event(
            'sysmon_networkConnection',
            winevt.get('computer_name').encode('ascii','ignore'),
            evt_data.get('ProcessId','None').encode('ascii','ignore'),
            evt_data.get('Protocol','None').encode('ascii','ignore'),
            evt_data.get('SourceIp','None').encode('ascii','ignore'),
            evt_data.get('SourcePort','None').encode('ascii','ignore'),
            evt_data.get('DestinationIp','None').encode('ascii','ignore'),
            evt_data.get('DestinationPort','None').encode('ascii','ignore'),
            evt_data.get('Image','None').encode('ascii','ignore'),
        )
    except Exception as e:
        return
    return message

def service_change(winevt):
    return
    print "service_change"

def process_terminated(winevt):
    evt_data = winevt['event_data']

    try:
        message = broker.bro.Event(
            'sysmon_procTerminate',
            winevt.get('computer_name').encode('ascii','ignore'),
            evt_data.get('Image','None').encode('ascii','ignore'),
            evt_data.get('ProcessGuid','None').encode('ascii','ignore'),
            evt_data.get('ProcessId','None').encode('ascii','ignore'),
            evt_data.get('UtcTime','None').encode('ascii','ignore'),
        )
    except Exception as e:
        return
    return message

def driver_loaded(winevt):
    evt_data = winevt['event_data']

    try:
        message = broker.bro.Event(
            'sysmon_driverLoaded',
            winevt.get('computer_name').encode('ascii','ignore'),
            winevt.get('process_id','None'),
            evt_data.get('Hashes','None').encode('ascii','ignore'),
            evt_data.get('ImageLoaded','None').encode('ascii','ignore'),
            evt_data.get('Signature','None').encode('ascii','ignore'),
            evt_data.get('SignatureStatus','None').encode('ascii','ignore'),
            evt_data.get('Signed','None').encode('ascii','ignore'),
            evt_data.get('UtcTime','None').encode('ascii','ignore'),
            #evt_data.get('','None').encode('ascii','ignore'),
        )
    except Exception as e:
        return
    return message

def image_loaded(winevt):
    evt_data = winevt['event_data']

    try:
        message = broker.bro.Event(
            'sysmon_imageLoaded',
            winevt.get('computer_name').encode('ascii','ignore'),
            evt_data.get('UtcTime','None').encode('ascii','ignore'),
            evt_data.get('ProcessGuid','None').encode('ascii','ignore'),
            evt_data.get('ProcessId','None').encode('ascii','ignore'),
            evt_data.get('Image','None').encode('ascii','ignore'),
            evt_data.get('ImageLoaded','None').encode('ascii','ignore'),
            evt_data.get('Hashes','None').encode('ascii','ignore'),
            evt_data.get('Signed','None').encode('ascii','ignore'),
            evt_data.get('SignatureStatus','None').encode('ascii','ignore'),
            #evt_data.get('','None').encode('ascii','ignore'),
        )
    except Exception as e:
        return
    return message

def create_remote_thread(winevt):
    evt_data = winevt['event_data']

    try:
        message = broker.bro.Event(
            'sysmon_createRemoteThread',
            winevt.get('computer_name').encode('ascii','ignore'),
            evt_data.get('UtcTime','None').encode('ascii','ignore'),
            evt_data.get('SourceProcessGuid','None').encode('ascii','ignore'),
            evt_data.get('SourceProcessId','None').encode('ascii','ignore'),
            evt_data.get('SourceImage','None').encode('ascii','ignore'),
            evt_data.get('TargetProcessGuid','None').encode('ascii','ignore'),
            evt_data.get('TargetProcessId','None').encode('ascii','ignore'),
            evt_data.get('TargetImage','None').encode('ascii','ignore'),
            evt_data.get('NewThreadId','None').encode('ascii','ignore'),
            evt_data.get('StartAddress','None').encode('ascii','ignore'),
            evt_data.get('StartModule','None').encode('ascii','ignore'),
            evt_data.get('StartFunction','None').encode('ascii','ignore'),
        )
    except Exception as e:
        return
    return message


def raw_access_read(winevt):
    evt_data = winevt['event_data']

    try:
        message = broker.bro.Event(
            'sysmon_rawAccessRead',
            winevt.get('computer_name').encode('ascii','ignore'),
            evt_data.get('UtcTime','None').encode('ascii','ignore'),
            evt_data.get('ProcessGuid','None').encode('ascii','ignore'),
            evt_data.get('ProcessId','None').encode('ascii','ignore'),
            evt_data.get('Image','None').encode('ascii','ignore'),
            evt_data.get('Device','None').encode('ascii','ignore'),
        )
    except Exception as e:
        return
    return message

def process_access(winevt):
    evt_data = winevt['event_data']

    try:
        message = broker.bro.Event(
            'sysmon_processAccess',
            winevt.get('computer_name').encode('ascii','ignore'),
            evt_data.get('GrantedAccess','None').encode('ascii','ignore'),
            evt_data.get('SourceImage','None').encode('ascii','ignore'),
            evt_data.get('SourceProcessGuid','None').encode('ascii','ignore'),
            evt_data.get('SourceProcessId','None').encode('ascii','ignore'),
            evt_data.get('SourceThreadId','None').encode('ascii','ignore'),
            evt_data.get('TargetImage','None').encode('ascii','ignore'),
            evt_data.get('TargetProcessGUID','None').encode('ascii','ignore'),
            evt_data.get('TargetProcessId','None').encode('ascii','ignore'),
            evt_data.get('UtcTime','None').encode('ascii','ignore'),
            evt_data.get('CallTrace','None').encode('ascii','ignore'),
        )
    except Exception as e:
        return
    return message

def file_create(winevt):
    evt_data = winevt['event_data']

    try:
        message = broker.bro.Event(
            'sysmon_fileCreate',
            winevt.get('computer_name').encode('ascii','ignore'),
            evt_data.get('Image','None').encode('ascii','ignore'),
            evt_data.get('ProcessGuid','None').encode('ascii','ignore'),
            evt_data.get('ProcessId','None').encode('ascii','ignore'),
            evt_data.get('TargetFilename','None').encode('ascii','ignore'),
            evt_data.get('CreationUtcTime','None').encode('ascii','ignore'),
            evt_data.get('UtcTime','None').encode('ascii','ignore'),
        )
    except Exception as e:
        return
    return message


def registry_event(winevt):
    evt_data = winevt['event_data']

    try:
        message = broker.bro.Event(
            'sysmon_registryEvent',
            winevt.get('computer_name').encode('ascii','ignore'),
            evt_data.get('Image','None').encode('ascii','ignore'),
            evt_data.get('ProcessGuid','None').encode('ascii','ignore'),
            evt_data.get('ProcessId','None').encode('ascii','ignore'),
            evt_data.get('TargetFilename','None').encode('ascii','ignore'),
            evt_data.get('CreationUtcTime','None').encode('ascii','ignore'),
            evt_data.get('UtcTime','None').encode('ascii','ignore'),
            evt_data.get('Details','None').encode('ascii','ignore'),
            evt_data.get('NewName','None').encode('ascii','ignore'),
        )
    except Exception as e:
        return
    return message

def file_create_stream_hash(winevt):
    evt_data = winevt['event_data']

    try:
        message = broker.bro.Event(
            'sysmon_fileCreateStreamHash',
            winevt.get('computer_name').encode('ascii','ignore'),
            evt_data.get('UtcTime','None').encode('ascii','ignore'),
            evt_data.get('ProcessGuid','None').encode('ascii','ignore'),
            evt_data.get('ProcessId','None').encode('ascii','ignore'),
            evt_data.get('Image','None').encode('ascii','ignore'),
            evt_data.get('TargetFilename','None').encode('ascii','ignore'),
            evt_data.get('CreationUtcTime','None').encode('ascii','ignore'),
            evt_data.get('Hash','None').encode('ascii','ignore'),
        )
    except Exception as e:
        return
    return message


def config_change(winevt):
    evt_data = winevt['event_data']

    try:
        message = broker.bro.Event(
            'sysmon_configChange',
            winevt.get('computer_name').encode('ascii','ignore'),
            evt_data.get('UtcTime','None').encode('ascii','ignore'),
            evt_data.get('Configuration','None').encode('ascii','ignore'),
            evt_data.get('ConfigurationFileHash','None').encode('ascii','ignore'),
        )
    except Exception as e:
        return
    return message


def pipe_event(winevt):
    if winevt['event_id'] == 17:
        action = "PipeCreated"
    if winevt['event_id'] == 18:
        action = "PipeConnected"
    evt_data = winevt['event_data']

    try:
        message = broker.bro.Event(
            'sysmon_pipeEvent',
            winevt.get('computer_name').encode('ascii','ignore'),
            action,
            evt_data.get('UtcTime','None').encode('ascii','ignore'),
            evt_data.get('ProcessGuid','None').encode('ascii','ignore'),
            evt_data.get('ProcessId','None').encode('ascii','ignore'),
            evt_data.get('PipeName','None').encode('ascii','ignore'),
            evt_data.get('Image','None').encode('ascii','ignore'),
        )
    except Exception as e:
        return
    return message


def wmi_event_19(winevt):
    evt_data = winevt['event_data']

    try:
        message = broker.bro.Event(
            'sysmon_wmiEvent19',
            winevt.get('computer_name').encode('ascii','ignore'),
            winevt.get('Message','None').encode('ascii','ignore'),
            evt_data.get('ServiceGuid','None').encode('ascii','ignore'),
            evt_data.get('UpdateRevisionNumber','None').encode('ascii','ignore'),
            evt_data.get('UpdateTitle','None').encode('ascii','ignore'),
        )
    except Exception as e:
        return
    return message

def wmi_event_20(winevt):
    evt_data = winevt['event_data']

    try:
        message = broker.bro.Event(
            'sysmon_wmiEvent20',
            winevt.get('computer_name').encode('ascii','ignore'),
            evt_data.get('BootStatusPolicy','None').encode('ascii','ignore'),
            evt_data.get('LastBootGood','None').encode('ascii','ignore'),
            evt_data.get('LastBootId','None').encode('ascii','ignore'),
            evt_data.get('LastShutdownGood','None').encode('ascii','ignore'),
        )
    except Exception as e:
        return
    return message


def wmi_event_21(winevt):
    evt_data = winevt['event_data']
    
    try:
        message = broker.bro.Event(
            'sysmon_wmiEvent21',
            winevt.get('computer_name').encode('ascii','ignore'),
            evt_data.get('BootStatusPolicy','None').encode('ascii','ignore'),
            evt_data.get('LastBootGood','None').encode('ascii','ignore'),
            evt_data.get('LastBootId','None').encode('ascii','ignore'),
            evt_data.get('LastShutdownGood','None').encode('ascii','ignore'),
        )
    except Exception as e:
        return
    return message

def sysmon_error(winevt):
    print "Error"

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

def main(c, file_in):
    with open(file_in, 'r') as f:
        for line in f:
            try:
                winevt = json.loads(line)
            except JSONDecodeError:
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
                c.publish('/sysmon', msg)

if __name__ == '__main__':
    p = ArgumentParser(description=_DESCRIPTION)
    p.add_argument('broker_peer',
                    help='Peer to connect to.')
    p.add_argument('file_in',
                    help='File to read events from.')
    args = p.parse_args()

    c = broker.Endpoint()
    c.peer(args.broker_peer, 9999)

main(c, args.file_in)
