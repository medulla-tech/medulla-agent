#!/usr/bin/python3
# -*- coding: utf-8; -*-
# SPDX-FileCopyrightText: 2016-2023 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-3.0-or-later

import json
import logging

logger = logging.getLogger()

plugin = {"VERSION": "1.5", "NAME": "force_setup_agent", "TYPE": "mastersub"}


def action(xmppobject, action, sessionid, data, message, dataobj):
    logger.debug("_________________________")
    logger.debug(plugin)
    logger.debug(data["data"][0])
    logger.debug("_________________________")

    command = {
        "action": "force_setup_agent",
        "base64": False,
        "sessionid": sessionid,
        "data": "",
    }
    xmppobject.send_message(
        mto=data["data"][0], mbody=json.dumps(command), mtype="chat"
    )
