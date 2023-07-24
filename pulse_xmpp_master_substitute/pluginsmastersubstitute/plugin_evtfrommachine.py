#!/usr/bin/python3
# -*- coding: utf-8; -*-
# SPDX-FileCopyrightText: 2016-2023 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-3.0-or-later

import logging


logger = logging.getLogger()
plugin = { "VERSION": "1.0", "NAME": "evtfrommachine", "TYPE": "substitute", "FEATURE": "assessor", }  # fmt: skip

# This plugin is calling from an AM (windows), if AM is stopped by a user.
# Ctrl + c for example.


def action(xmppobject, action, sessionid, data, msg, ret, dataobj):
    logger.debug(
        "-----------------------------------------------------------------------------------------"
    )
    logger.debug(plugin)
    logger.debug(
        "-----------------------------------------------------------------------------------------"
    )
    logger.debug('EVENT "%s" from %s' % (data["event"], msg["from"]))
    if data["event"] == "SHUTDOWN_EVENT" or data["event"].startswith("CTRL_C_EVENT"):
        msg_changed_status = {"from": data["machine"], "type": "unavailable"}
        xmppobject.changed_status(msg_changed_status)
    else:
        logger.debug(
            "EVENT %s not processed for the machine %s" % (data["event"], msg["from"])
        )
        pass
