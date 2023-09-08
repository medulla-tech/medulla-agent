# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2016-2023 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-3.0-or-later

import logging
import os
import json

plugin = {"VERSION": "1.0", "NAME": "disable_rescue", "TYPE": "all"}  # fmt: skip

logger = logging.getLogger()


def action(objectxmpp, action, sessionid, data, message, dataerreur):
    logger.debug("###################################################")
    logger.debug(f'call {plugin} from {message["from"]}')
    logger.debug("###################################################")
    namefilebool = os.path.join(
        os.path.dirname(os.path.realpath(__file__)),
        "..",
        "BOOL_LAUNCHER_NO_CHECK_AGENT",
    )
    file = open(namefilebool, "w")
    file.close()
    msg = "QA : Disabling rescue agent"
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
        module="QuickAction | Notify",
        date=None,
        fromuser="",
        touser="Master",
    )
    resultaction = "result%s" % action
    response = {}
    response["action"] = resultaction
    response["sessionid"] = sessionid
    response["base64"] = False
    response["ret"] = 0
    response["data"] = {}
    response["data"]["msg"] = "%s on %s" % (msg, message["to"])
    objectxmpp.send_message(
        mto=message["from"], mbody=json.dumps(response), mtype="chat"
    )
