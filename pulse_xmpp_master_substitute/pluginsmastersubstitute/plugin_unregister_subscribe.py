#!/usr/bin/env python
# -*- coding: utf-8; -*-
# SPDX-FileCopyrightText: 2016-2023 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-3.0-or-later

import logging

logger = logging.getLogger()


plugin = {"VERSION": "1.0", "NAME": "unregister_subscribe", "TYPE": "substitute", "FEATURE": "subscribe"}  # fmt: skip


"""
This plugin is called by the client When the machine agent detect a change of domain in his JID.

It must remove the agent from his roster
"""


def action(xmppobject, action, sessionid, data, msg, ret, dataobj):
    logger.debug(
        "-----------------------------------------------------------------------------------------"
    )
    logger.debug(plugin)
    logger.debug(
        "-----------------------------------------------------------------------------------------"
    )

    if (
        "user" in data
        and "domain" in data
        and "resource" in data
        and data["user"].strip() != ""
        and data["domain"].strip() != ""
        and data["resource"].strip() != ""
    ):
        jidmachine = "%s@%s/%s" % (
            data["user"].strip(),
            data["domain"].strip(),
            data["resource"].strip(),
        )
        xmppobject.send_presence(pto=jidmachine, ptype="unsubscribe")

    else:
        logger.error("The JID is incorrect")
