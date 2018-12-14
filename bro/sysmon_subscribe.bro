# This script subscribes to Broker's sysmon messages.
# Version 1.0 (November 2018)
#
# Authors: Jeff Atkinson (jatkinson@salesforce.com)
#
# Copyright (c) 2017, salesforce.com, inc.
# All rights reserved.
# Licensed under the BSD 3-Clause license. 
# For full license text, see LICENSE.txt file in the repo root  or https://opensource.org/licenses/BSD-3-Clause

module Sysmon;

event bro_init()
{
    Broker::subscribe("/sysmon");

    # Be aware that these variables may be defined by other modules.  eg. Bro-OSQuery
    Broker::listen(broker_ip, broker_port);
}


