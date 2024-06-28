# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2016-2023 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-3.0-or-later

"""
This plugin updates the database everytime the system checks the user password strength.
"""

import datetime
import logging
import time
from lib.plugins.xmpp import XmppMasterDatabase
import traceback


logger = logging.getLogger()

plugin = {"VERSION": "1.0", "NAME": "checkpassword", "TYPE": "substitute"} # fmt: skip


def action(xmpobject, action, sessionid, data, message, ret, dataobj):
    logger.debug("=====================================================")
    logger.debug("call %s from %s" % (plugin, message["from"]))
    logger.debug("=====================================================")
    try:
        #check_time = str(time.time())
        xmpp_db = XmppMasterDatabase()

        for user in data:
            user_name = user["user_name"]
            password_required = 1 if user["password_required"] else 0
            password_complexity = user["password_complexity"]
            password_history = user["password_history"]
            
            success = xmpp_db.check_password_strength(
                user_name,
                password_required,
                password_complexity,
                password_history
            )
        if not success:
                logger.error("Failed to check password strength for user: %s", user_name)
    
    except Exception as e:
        logger.error("Exception occurred in plugin %s : %s", plugin["NAME"], str(e))
        logger.debug(traceback.format_exc())