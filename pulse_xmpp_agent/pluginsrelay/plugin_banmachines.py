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
# file : pulse_agent_plugins/relay/plugin_cluster.py

import json
import logging
from lib import utils

logger = logging.getLogger()

DEBUGPULSEPLUGIN = 25

plugin = {"VERSION": "0.0.9", "NAME": "banmachines", "VERSIONAGENT": "2.0.0", "TYPE": "relayserver", "DESC": "Ban specified machines from the relay", } # fmt: skip


def action(objectxmpp, action, sessionid, data, message, dataerror):
    logger.debug("###################################################")
    logger.debug("call %s from %s session id %s" % (plugin, message["from"], sessionid))
    logger.debug("###################################################")

    if data["subaction"] == "direct_ban":
        result = []
        for machine in data["jid_machines"]:
            user, host = machine.split("/")[0].split("@")
            _result = utils.simplecommand(
                "ejabberdctl ban_account %s %s %s" % (user, host, data["subaction"])
            )
            result.append(_result)

    if data["subaction"] == "direct_unban":
        result = []
        for machine in data["jid_machines"]:
            user, host = machine.split("/")[0].split("@")
            _result = utils.simplecommand("ejabberdctl unregister %s %s" % (user, host))

            result.append(_result)
