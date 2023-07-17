#!/usr/bin/python3
# -*- coding: utf-8; -*-
# SPDX-FileCopyrightText: 2018-2023 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-2.0-or-later
# ce plugin est appeler au demarage de master.
# on log le demarrage de MMC
import logging
import json
from lib.utils import name_random
import traceback
logger = logging.getLogger()

plugin = {"VERSION": "1.0", "NAME": "test_plugin_master", "TYPE": "master"}
def action(xmppobject, action, sessionid, data, message, dataobj):
    logger.debug("=====================================================")
    logger.debug(plugin)
    logger.debug("=====================================================")
    logger.debug("============ test_plugin_master ================")
    logger.info("START/RESTART MMC")
    logger.debug("============ test appelle plugin agent_test_iq sur ars  ================")
    logger.debug("le plugin  agent_test_iq sur ars devra faire 1 iq vers rspulse@pulse/mainrelay")
    logger.debug("APPEL FROM SUBSTITUT %s : to rspulse@pulse/mainrelay " % xmppobject.boundjid.bare)
    # JFKJFK test_plugin_master
    # test appelle d'un plugin sur relay pour test
    logger.debug("SEND")
    try:
        datasend = { "action" : "agent_test_iq",
                 "sessionid" : name_random(5, "agent_test_iq"),
                 "data" : {  "test message" : "test call plugin"} }
        logger.debug("START SEND")
        xmppobject.send_message(mto='rspulse@pulse/mainrelay',
                                mbody=json.dumps(datasend),
                                mtype="chat")
    except Exception as e:
        errorstr = "%s" % traceback.format_exc()
        logger.error("END SEND %s" % errorstr)
