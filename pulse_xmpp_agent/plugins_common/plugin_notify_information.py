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
# file : pluginsrelay/plugin_notify_information.py

import os
import logging
from lib.utils import file_put_contents

plugin = { "VERSION": "1.0", "VERSIONAGENT": "2.1", "NAME": "notify_information",  "TYPE": "all", }  # fmt: skip

logger = logging.getLogger()
DEBUGPULSEPLUGIN = 25


def action(objectxmpp, action, sessionid, data, message, dataerreur):
    logger.debug("###################################################")
    logger.debug("call %s from %s" % (plugin, message["from"]))
    logger.debug("sessionid : %s" % sessionid)
    logger.debug("###################################################")
    if "notify" in data:
        logger.debug("notify : %s" % data["notify"])

        if data["notify"] in ["recording_case1", "recording_case2"]:
            if objectxmpp.config.agenttype in ["relayserver"]:
                # creation fichieronline dans INFOSTMP
                dirtempinfo = os.path.abspath(
                    os.path.join(
                        os.path.dirname(os.path.realpath(__file__)), "..", "INFOSTMP"
                    )
                )
                filename = os.path.join(dirtempinfo, "on_line_ars.ansible")
                file_put_contents(filename, "boolean for ansible")
