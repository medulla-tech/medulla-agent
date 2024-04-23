# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2016-2023 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-3.0-or-later

"""
 This plugin restartBot restart agent
"""


import json
import logging

logger = logging.getLogger()
plugin = {"VERSION": "1.3", "NAME": "restartbot", "TYPE": "all"}  # fmt: skip


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
