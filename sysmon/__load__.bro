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
