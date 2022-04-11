#!/usr/bin/env python
# -*- coding: utf-8; -*-
#
# (c) 2016-2017 siveo, http://www.siveo.net
#
# This file is part of Pulse 2, http://www.siveo.net
#
# Pulse 2 is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# Pulse 2 is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Pulse 2; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
# MA 02110-1301, USA.
#
# file pluginsmastersubstitute/plugin_unregister_subscribe.py
import logging
import traceback
import json

from lib.plugins.xmpp import XmppMasterDatabase

logger = logging.getLogger()


plugin = {"VERSION": "1.0", "NAME": "unregister_subscribe", "TYPE" : "substitute", "FEATURE": "subscribe"}


"""
This plugin is called by the client When the machine agent detect a change of domain in his JID.

It must remove the agent from his roster
"""

def action(xmppobject, action, sessionid, data, msg, ret, dataobj):
    logger.debug("-----------------------------------------------------------------------------------------")
    logger.debug(plugin)
    logger.debug("-----------------------------------------------------------------------------------------")

    if "user" in data and "domain" in data and "resource" in data and \
        data['user'].strip() != "" and  data['domain'].strip() != "" and  data['resource'].strip() != "":
        jidmachine = "%s@%s/%s" % (data['user'].strip(),
                                   data['domain'].strip(),
                                   data['resource'].strip())
        xmppobject.send_presence (pto=jidmachine, ptype='unsubscribe')

    else:
        logger.error("The JID is incorrect")
