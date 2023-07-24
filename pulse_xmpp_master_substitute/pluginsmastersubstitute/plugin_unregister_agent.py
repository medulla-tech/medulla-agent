#!/usr/bin/env python
# -*- coding: utf-8; -*-
# SPDX-FileCopyrightText: 2016-2023 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-3.0-or-later
import logging
import traceback
import json

from lib.plugins.xmpp import XmppMasterDatabase

logger = logging.getLogger()
plugin = {"VERSION": "1.0", "NAME": "unregister_agent", "TYPE": "substitute", "FEATURE": "subscribe",}  # fmt: skip


"""
This plugin is called by the client When the machine agent detect a change of domain in his JID.

When a client connects to a new ARS, this has for consequence a change of ejabberd domain/server.
The old ejabberd account needs to be removed from the roster.
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
        try:
            relayserver = XmppMasterDatabase().getRelayServerfromjiddomain(
                data["domain"]
            )
            msg = {
                "action": "unregister_agent",
                "sessionid": sessionid,
                "data": data,
                "base64": False,
                "ret": 0,
            }
            if relayserver:
                xmppobject.send_message(
                    mto=relayserver["jid"], mbody=json.dumps(msg), mtype="chat"
                )
            else:
                logger.error(
                    "No relay server found for the domain: %s" % data["domain"]
                )

        except Exception as e:
            logger.error(
                "An error occured when trying to unregister old JID. We got the error: %s"
                % str(e)
            )
            logger.error("We hit the backtrace: \n%s" % traceback.format_exc())
    else:
        logger.error("The JID is incorrect")
