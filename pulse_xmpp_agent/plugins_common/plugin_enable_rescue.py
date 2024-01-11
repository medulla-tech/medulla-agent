# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2016-2023 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-3.0-or-later

import logging
import os
import json
from lib.utils import set_logging_level

plugin = {"VERSION": "1.1", "NAME": "enable_rescue", "TYPE": "all"}  # fmt: skip

logger = logging.getLogger()


@set_logging_level
def action(objectxmpp, action, sessionid, data, message, dataerreur):
    logger.debug("###################################################")
    logger.debug(f'call {plugin} from {message["from"]}')
    logger.debug("###################################################")
    namefilebool = os.path.join(
        os.path.dirname(os.path.realpath(__file__)),
        "..",
        "BOOL_ENABLE_RESCUE",
    )
    file = open(namefilebool, "w")
    file.close()
    msg = "QA : Enabling rescue agent"
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
