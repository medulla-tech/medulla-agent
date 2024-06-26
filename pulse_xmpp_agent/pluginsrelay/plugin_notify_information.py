# -*- coding: utf-8 -*-
"""
Notify Information Plugin

SPDX-FileCopyrightText: 2016-2023 Siveo <support@siveo.net>
SPDX-License-Identifier: GPL-3.0-or-later

This plugin handles actions related to notifying information.
"""

import os
import logging
from lib.utils import file_put_contents

plugin = {"VERSION": "1.0", "VERSIONAGENT": "2.1", "NAME": "notify_information", "TYPE": "all"}  # fmt: skip

logger = logging.getLogger()
DEBUGPULSEPLUGIN = 25


def action(objectxmpp, action, sessionid, data, message, dataerreur):
    """
    Perform actions based on the provided data for the notify_information plugin.

    Parameters:
    - objectxmpp: The XMPP object representing the current agent.
    - action: The action to be performed.
    - sessionid: The session ID associated with the action.
    - data: The data containing information for the action.
    - message: The XMPP message containing the request.
    - dataerreur: Data related to any errors during the action.

    Returns:
    None
    """
    logger.debug("###################################################")
    logger.debug("call %s from %s" % (plugin, message["from"]))
    logger.debug("sessionid : %s" % sessionid)
    logger.debug("###################################################")
    if "notify" in data:
        logger.debug("notify : %s" % data["notify"])

        if data["notify"] in ["recording_case1", "recording_case2"]:
            if objectxmpp.config.agenttype in ["relayserver"]:
                # creation fichieronline dans INFOSTMP
                dirtempinfo = os.path.abspath(
                    os.path.join(
                        os.path.dirname(os.path.realpath(__file__)), "..", "INFOSTMP"
                    )
                )
                filename = os.path.join(dirtempinfo, "on_line_ars.ansible")
                file_put_contents(filename, "boolean for ansible")
