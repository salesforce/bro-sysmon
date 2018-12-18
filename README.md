# Bro-Sysmon
How to Zeek Sysmon logs.

## Overview
Bro-Sysmon enables Bro to receive Windows Event Logs.  This provide a method to associate Network Monitoring and Host Monitoring.  The work was spurred by the need to associate [JA3](https://engineering.salesforce.com/open-sourcing-ja3-92c9e53c3c41) and [HASSH](https://engineering.salesforce.com/open-sourcing-hassh-abed3ae5044c) fingerprints with the application on the host.  The example below shows the hostname, Process ID, connection information, JA3 fingerprints, Application Path, and binary hashes.
~~~
blocky-PC	3200	192.168.200.100	59356	172.217.7.163	443	
	e7901d17482da52152fff3e9afadfa57	85acb5f1aec131b9897ae1fc1f22aff3
	clientservices.googleapis.com	C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe
	MD5=A42A2C130941F9C979F6F0CE14E03048,SHA256=4462807702DD61C873E73BB9EAB13B6EEFA6464311AA8A1831F0A2675351B5FF
~~~

## How it works
Sysmon-Broker.py uses the Broker Python Bindings to establish peering with Bro.  Bro subsribes to the /sysmon message bus.  Windows event logs are received in JSON format by Symon-Broker.py.  The script parses the JSON object and builds an event which is sent to the /sysmon message bus.  Bro receives the events and makes them available to "script land".  The provided Bro scripts will generate log files prepended with "sysmon_".  Custom scrips can be added to handle the events like mapping JA3 fingerprints to client applications.
```
			Sysmon-Broker.py					Bro
				|						|
				|    ------ Establish Peering  ------>		|
				|						|
				|    <----- Establish Peering  -------		|
				|						|
				|    <----- Subscirbe /sysmon  -------		|
				|						|
Receive Sysmon JSON	-->	|						|
				|						|
				| -- Parse JSON					|
				| -- Build Event				|
				|						|
				|						|
				|    ------ Publish to /sysmon ------>		|
				|						|
				|						|  --> Bro Scipt to Log 
				|						|
				|						|  --> Bro Script Build Map 
											JA3 to Appication
```
## Getting Started

- Install Sysmon on Windows host, tune config as you like.
- Install WinLogBeat on Windows host and configure to forward to Logstash on a Linux box.
- Install Logstash, Broker and Bro on the Linux host.
- Configure Logstash on the Linux host as beats listener and write logs out to file.  
	Example Logstash config:
```
		input {
			beats {
			  port => 9000
			}
		}
		output {
			file {
			  path => "/home/logstash/bro-sysmon/WindowsSysmon.json"
			}
		}
```
- copy the sysmon folder to $bropath/share/bro/site/
- modify local.bro to include sysmon directory  ```@load sysmon```
- start Bro as you see fit, start in foreground until you're happy with it.
- tail -f /home/logstash/WindowsEventLogs.json | python sysmon-Broker.py &


## Output
### Bro-Sysmon events will now be available to Bro Scripts.
~~~
event sysmonProcNetConn(computerName: string, proto: string, 
			srcip: string, srcprt: string, dstip: string, dstprt: string, 
			processId: string, procImage: string) {
		print fmt("Host %s spawned ProcessID %s, %s", computerName, processId, procImage);
		}
Output: Host blocky-PC spawned ProcessID 3968, C:\Users\blocky\Desktop\putty.exe
~~~
### Bro-Sysmon logs will be written to file.
```
#fields computerName    processId       company currentDirectory        description     fileVersion     hashes  image   integrityLevel  logonGuid       logonId parentCommandline       parentImage
     parentProcessGuid       parentProcessId processGuid     product terminalSessionId       user    utcTime
A8A1831F0A2675351B5FF	C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe	Low	{7A15C4BA-936D-5BDC-0100-0020642C5435}	0x135542c64	"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe" 	C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe	{7A15C4BA-F08F-5BEE-0100-00109E978637}	4584	-	?	2	blocky-PC\\blocky	2018-11-16 16:30:09.143
```
## Credits
Bro-Sysmon concept was conceived and developed by Jeff Atkinson ([@4a7361](https://twitter.com/4a7361)).  Special thanks goes out to Kevin Thompson ([@bfist](https://twitter.com/bfist)), [@tenzir_company](https://twitter.com/tenzir_company) and [@0xHosom](https://twitter.com/0xHosom).

## License
Bro-Sysmon comes with a [3-Clause BSD license](./LICENSE.txt)
