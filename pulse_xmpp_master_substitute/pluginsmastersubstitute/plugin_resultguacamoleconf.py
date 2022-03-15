#!/usr/bin/python3
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
# file pluginsmaster/plugin_resultguacamoleconf.py

import traceback
import logging
from lib.plugins.xmpp import XmppMasterDatabase

logger = logging.getLogger()

plugin = {"VERSION": "1.11", "NAME": "resultguacamoleconf", "TYPE": "substitute"} # fmt: skip


def action(xmppobject, action, sessionid, data, msg, ret, objsessiondata):
    logger.debug("=====================================================")
    logger.debug("call %s from %s" % (plugin, msg["from"]))
    logger.debug("=====================================================")
    if "msg" in data:
        logging.getLogger().warning("%s : %s" % (data["msg"], msg["from"]))
        return
    try:
        XmppMasterDatabase().addlistguacamoleidformachineid(
            data["machine_id"], data["connection"]
        )
    except Exception as e:
        if "msg" in data:
            logger.error("recv error from %s : %s\n" % (msg["from"], data["msg"]))
        logger.error("File read error %s\n%s" % (str(e), traceback.format_exc()))
