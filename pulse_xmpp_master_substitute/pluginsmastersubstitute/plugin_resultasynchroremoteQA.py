#!/usr/bin/python3
# -*- coding:Utf-8; -*
# SPDX-FileCopyrightText: 2024-2025 Medulla, http://www.medulla-tech.io
# SPDX-License-Identifier: GPL-3.0-or-later

from lib.plugins.xmpp import XmppMasterDatabase
import traceback
import logging
import json
import sys

logger = logging.getLogger()

plugin = {"VERSION": "1.1", "NAME": "resultasynchroremoteQA", "TYPE": "mastersub"}

def action(xmppobject, action, sessionid, data, message, ret, dataobj):
    logger.debug("=====================================================")
    logger.debug(plugin)
    logger.debug("=====================================================")
    try:
        result_data = data["result"]["result"]

        # If it is a list, join the elements (backwards compatibility)
        if isinstance(result_data, list):
            result_string = "".join(result_data)
        else:
            result_string = result_data

        XmppMasterDatabase().setCommand_action(
            data["data"]["data"]["uuid_inventorymachine"],
            data["data"]["data"]["cmdid"],
            sessionid,
            result_string,
            typemessage="result",
        )

    except Exception as e:
        logger.error("Error loading plugin: %s" % str(e))
        traceback.print_exc(file=sys.stdout)
