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
# """
# This plugin restartBot restart agent
# """


import json
import logging

logger = logging.getLogger()

plugin = {"VERSION": "1.3", "NAME": "restartbot", "TYPE": "all"} # fmt: skip


def action(objetxmpp, action, sessionid, data, message, dataerreur):
    logger.debug("###################################################")
    logger.debug("call %s from %s" % (plugin, message["from"]))
    logger.debug("###################################################")
    response = {}
    if action == "restartbot":
        resultaction = "result%s" % action
        response["action"] = resultaction
        response["sessionid"] = sessionid
        response["base64"] = False
        response["ret"] = 0
        response["data"] = {}
        response["data"]["msg"] = "restart %s" % message["to"]
        objetxmpp.send_message(
            mto=message["from"], mbody=json.dumps(response), mtype="chat"
        )
        objetxmpp.restartBot()
