# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2016-2023 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-3.0-or-later

"""
This plugin deletes the list of antiviruses for a machine and inserts a newly updated list.
"""

import json
from lib.plugins.xmpp import XmppMasterDatabase
import time
import logging

logger = logging.getLogger()

plugin = {"VERSION": "1.0", "NAME": "checkantivirus", "TYPE": "substitute"}  # fmt: skip

DEBUGPULSEPLUGIN = 25

def action(xmppobject, action, sessionid, data, message, ret, dataobj):
    logger.debug("=====================================================")
    logger.debug(plugin)
    logger.debug("=====================================================")

    unix_time = int(time.time()) #unix timestamp

    uuid_machine = XmppMasterDatabase().getUuidSerialMachineFromJid(message['from'])['uuid_serial'] #retrieve id from jid

    for antivirus in data: #add each antivirus
        u_status = 1 if antivirus["Update Status"] != "[Disabled]" else 0 #update status
        rt_status = 1 if antivirus["Real-time Protection Status"] != "[Disabled]" else 0 #check if realtime protection is enabled
        active_status = 1 if u_status and rt_status else 0 #check if it's the active antivirus in the list
        antivirus_name = str(antivirus['Name'])
        firewall_status = antivirus['Firewall']
        # Handle Last Scan field
        last_scan = antivirus['Last Scan']

        XmppMasterDatabase().update_antivirus_check(uuid_machine, antivirus_name, u_status, rt_status, active_status, unix_time, last_scan, firewall_status) #insert the antivirus 