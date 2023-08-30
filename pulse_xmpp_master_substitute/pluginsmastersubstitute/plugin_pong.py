# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2021-2023 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-3.0-or-later

"""
    Plugin used to check if the presence machine call asynchome.
"""

import traceback
import os
import logging
from lib.plugins.xmpp import XmppMasterDatabase

logger = logging.getLogger()

plugin = {"VERSION": "1.0", "NAME": "pong", "TYPE": "substitute"}  # fmt: skip


def action(xmppobject, action, sessionid, data, msg, ret, dataobj):
    """
    Used to verify machine on
    """
    try:
        logger.debug("=====================================================")
        logger.debug("call %s from %s" % (plugin, msg["from"]))
        logger.debug("=====================================================")
        result = XmppMasterDatabase().SetPresenceMachine(str(msg["from"]), presence=1)
    except Exception as e:
        logger.error("Plugin pong %s from %s" % (str(e), str(msg["from"])))
        logger.error("We obtained the backtrace %s" % traceback.format_exc())
