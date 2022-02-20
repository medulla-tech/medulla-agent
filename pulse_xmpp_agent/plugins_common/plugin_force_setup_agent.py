# -*- coding: utf-8 -*-
#
# (c) 2016 siveo, http://www.siveo.net
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
# file plugin_force_setup_agent.py

import logging
import os

plugin = {"VERSION": "1.4", "NAME": "force_setup_agent", "TYPE": "all"}

logger = logging.getLogger()


def action(objectxmpp, action, sessionid, data, message, dataerreur):
    logger.debug("###################################################")
    logger.debug("call %s from %s" % (plugin, message["from"]))
    logger.debug("###################################################")
    namefilebool = os.path.join(
        os.path.dirname(os.path.realpath(__file__)), "..", "BOOLCONNECTOR"
    )
    file = open(namefilebool, "w")
    file.close()
    force_reconfiguration = os.path.join(
        os.path.dirname(os.path.realpath(__file__)),
        "..",
        "action_force_reconfiguration",
    )
    file = open(force_reconfiguration, "w")
    file.close()
    msg = "QA : Reconfigure machine agent immediately"
    logger.debug(msg)
    objectxmpp.xmpplog(
        msg,
        type="Master",
        sessionname=sessionid,
        priority=0,
        action="xmpplog",
        who=str(objectxmpp.boundjid.bare),
        how="",
        why="Master",
        module="QuickAction | Notify | Reconfigure",
        date=None,
        fromuser="",
        touser="Master",
    )
    # check network and reconfigure machine
    # objectxmpp.networkMonitor()
    objectxmpp.reconfagent()
