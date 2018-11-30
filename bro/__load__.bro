# Loading the different Bro Scripts to handle Sysmon events.
#
# Authors: Jeff Atkinson (jatkinson@salesforce.com)
#
# Copyright (c) 2017, salesforce.com, inc.
# All rights reserved.
# Licensed under the BSD 3-Clause license. 
# For full license text, see LICENSE.txt file in the repo root  or https://opensource.org/licenses/BSD-3-Clause

@load  ./sysmon_subscribe           #-- Subscribe to broker /sysmon --#
@load ./processCreate.bro           #-- Sysmon EventID 1 --#
@load ./procChangeFileTime.bro      #-- Sysmon EventID 2 --#
@load ./networkConnection.bro       #-- Sysmon EventID 3 --#
@load ./procTerminate.bro           #-- Sysmon EventID 5 --#
@load ./driverLoaded.bro            #-- Sysmon EventID 6 --#
@load ./imageLoaded.bro             #-- Sysmon EventID 7 --#
@load ./createRemoteThread.bro      #-- Sysmon EventID 8 --#
@load ./rawAccessRead.bro           #-- Sysmon EventID 9 --#
@load ./processAccess.bro           #-- Sysmon EventID 10 --#
@load ./fileCreate.bro              #-- Sysmon EventID 11 --#
@load ./registryEvent.bro           #-- Sysmon EventID 12,13,14 --#
@load ./fileCreateStreamHash.bro    #-- Sysmon EventID 15 --#
@load ./configChange.bro            #-- Sysmon EventID 16 --#
@load ./pipeEvent.bro               #-- Sysmon EventID 17 & 18 --#
@load ./wmiEvent19.bro              #-- Sysmon EventID 19 --#
@load ./wmiEvent20.bro              #-- Sysmon EventID 20 --#
@load ./eventLogMessage.bro         #-- Log Messages of the rest of Windows Event Logs --#
@load ./mapJA3_Proc.bro
@load ./mapHASSH.bro
