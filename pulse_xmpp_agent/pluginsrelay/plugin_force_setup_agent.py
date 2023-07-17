# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2016-2023 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-2.0-or-later

import logging
import os

plugin = {"VERSION": "1.4", "NAME": "force_setup_agent", "TYPE": "all"}  # fmt: skip

logger = logging.getLogger()


def action(objectxmpp, action, sessionid, data, message, dataerreur):
    logger.debug("###################################################")
    logger.debug("call %s from %s" % (plugin, message["from"]))
    logger.debug("###################################################")
    namefilebool = os.path.join(
        os.path.dirname(os.path.realpath(__file__)), "..", "BOOLCONNECTOR"
    )
    file = open(namefilebool, "w")
    file.close()
    force_reconfiguration = os.path.join(
        os.path.dirname(os.path.realpath(__file__)),
        "..",
        "action_force_reconfiguration",
    )
    file = open(force_reconfiguration, "w")
    file.close()
    msg = "QA : Reconfigure machine agent immediately"
    logger.debug(msg)
    objectxmpp.xmpplog(
        msg,
        type="Master",
        sessionname=sessionid,
        priority=0,
        action="xmpplog",
        who=str(objectxmpp.boundjid.bare),
        how="",
        why="Master",
        module="QuickAction | Notify | Reconfigure",
        date=None,
        fromuser="",
        touser="Master",
    )
    # check network and reconfigure machine
    # objectxmpp.networkMonitor()
    objectxmpp.reconfagent()
