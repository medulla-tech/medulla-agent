#!/usr/bin/python3
# -*- coding: utf-8; -*-

import logging
import traceback
import sys
import json
from lib.plugins.xmpp import XmppMasterDatabase

logger = logging.getLogger()

plugin = {"VERSION": "1.0", "NAME": "resultasynchroremoteQA", "TYPE": "mastersub"}


def action(xmppobject, action, sessionid, data, message, ret, dataobj):
    logger.debug("=====================================================")
    logger.debug(plugin)
    logger.debug("=====================================================")
    try:
        XmppMasterDatabase().setCommand_action(
            data["data"]["data"]["uuid_inventorymachine"],
            data["data"]["data"]["cmdid"],
            sessionid,
            "".join(data["result"]["result"]),
            typemessage="result",
        )

    except Exception as e:
        logger.error("Error loading plugin: %s" % str(e))
        traceback.print_exc(file=sys.stdout)
        pass
