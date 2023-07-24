#!/usr/bin/python3
# -*- coding: utf-8; -*-
# SPDX-FileCopyrightText: 2016-2023 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-3.0-or-later

import traceback
import logging
from lib.plugins.xmpp import XmppMasterDatabase

logger = logging.getLogger()
plugin = {"VERSION": "1.11", "NAME": "resultguacamoleconf", "TYPE": "substitute"}  # fmt: skip


def action(xmppobject, action, sessionid, data, msg, ret, objsessiondata):
    logger.debug("=====================================================")
    logger.debug("call %s from %s" % (plugin, msg["from"]))
    logger.debug("=====================================================")
    if "msg" in data:
        logging.getLogger().warning("%s : %s" % (data["msg"], msg["from"]))
        return
    try:
        XmppMasterDatabase().addlistguacamoleidformachineid(
            data["machine_id"], data["connection"]
        )
    except Exception as e:
        if "msg" in data:
            logger.error("recv error from %s : %s\n" % (msg["from"], data["msg"]))
        logger.error("File read error %s\n%s" % (str(e), traceback.format_exc()))
