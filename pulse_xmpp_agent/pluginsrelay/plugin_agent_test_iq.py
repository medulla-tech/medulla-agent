# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2016-2023 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-3.0-or-later

# file : /pulse_xmpp_agent/pluginsrelay/plugin_agent_test_iq.py
import asyncio
import base64
import json
import os
import logging
import time
from lib.iq_custom import iq_value
import traceback
import threading
import types

logger = logging.getLogger()
DEBUGPULSEPLUGIN = 25
plugin = {"VERSION": "1.0", "NAME": "agent_test_iq", "TYPE": "substitute"}  # fmt: skip

# plugin test
# Ce plugin agent_test_iq sur ars est appelé par console mmc.
# # MMC utilise les service tcpip de substitut master
# <...> tcpip
# ___> appelle plugin
# <---> iq synchrone

# MMC <...> substitutmaster(master@pulse/MASTER) ___> agent_test_iq sur ARS (rspulse@pulse/mainrelay) <---> to machine dev-deb12-2.zb0@pulse/525400944ac7
# le plugin present affiche le resultat de iq
# timeout
# 2023-07-10 16:40:31,902 - DEBUG - Result iq test {'error': 'IQ type get id [__rspulse__47wq8rbu] to [dev-deb12-2.zb0@pulse/525400944ac7] in Timeout'}
# cool
# 2023-07-10 16:51:39,418 - DEBUG - Result iq test {"action": "test", "data": {"listinformation": ["get_ars_key_id_rsa", "keypub"], "param": {}}}


def action(xmppobject, action, sessionid, data, msg, dataobj):
    try:
        logger.debug("=====================================================")
        logger.error("call %s from %s" % (plugin, msg["from"]))
        logger.debug("=====================================================")
        msgq = {"to": str(msg["to"]), "from": str(msg["from"])}

        logger.info("PLUGIN TEST RESTART INITIALISATION %s " % msgq)
        compteurcallplugin = getattr(xmppobject, "num_call%s" % action)
        logger.debug("compteurcallplugin = %s" % compteurcallplugin)
        if compteurcallplugin == 0:
            # add fonction
            logger.debug("creation fonction process_connection_ssl")
        re = xmppobject.iqsendpulse(
            "dev-deb12-2.zb0@pulse/525400944ac7",
            {
                "action": "test",
                "data": {
                    "listinformation": ["get_ars_key_id_rsa", "keypub"],
                    "param": {},
                },
            },
        )
        logger.debug("Result iq test %s " % re)
    except Exception as e:
        errorstr = "%s" % traceback.format_exc()
        logger.error("END SEND %s" % errorstr)
