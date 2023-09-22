#!/usr/bin/python3
# -*- coding: utf-8; -*-
# SPDX-FileCopyrightText: 2016-2023 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-3.0-or-later

import logging
import traceback
import sys
import json

# ce pluging sert a envoyer des commande au machine distante.
logger = logging.getLogger()

plugin = {"VERSION": "1.0", "NAME": "asynchromeremoteshell", "TYPE": "mastersub"}


def action(xmppobject, action, sessionid, data, message, ret, dataobj):
    logger.debug("=====================================================")
    logger.debug(plugin)
    logger.debug("=====================================================")
    try:
        logger.debug(data["data"][1][0])
        logger.debug(json.dumps(data, indent=4))
        machine = data["data"][0]
        command = data["data"][1][0]["command"]
        uidunique = data["data"][1][0]["uidunique"]
        datasend = {
            "sessionid": uidunique,
            "action": data["action"],
            "data": {"machine": machine, "command": command},
        }
        # logger.debug(datasend["sessionid"])
        # call plugin asynchromeremoteshell to machine or relay
        xmppobject.send_message(
            mto=data["data"][0], mbody=json.dumps(datasend), mtype="chat"
        )

    except Exception as e:
        logger.error("Error loading plugin: %s" % str(e))
        traceback.print_exc(file=sys.stdout)
        pass
