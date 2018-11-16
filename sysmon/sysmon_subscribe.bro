# This script subscribes to Broker's sysmon messages.
# Version 1.0 (November 2018)
#
# Authors: Jeff Atkinson (jatkinson@salesforce.com)
#
# Copyright (c) 2017, salesforce.com, inc.
# All rights reserved.
module Sysmon;

event bro_init()
{
Broker::subscribe("/sysmon");

}
