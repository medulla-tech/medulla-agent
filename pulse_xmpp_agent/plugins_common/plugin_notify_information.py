# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2016-2023 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-3.0-or-later

import os
import logging
from lib.utils import file_put_contents, set_logging_level

plugin = {"VERSION": "1.1", "VERSIONAGENT": "2.1", "NAME": "notify_information", "TYPE": "all"}  # fmt: skip

logger = logging.getLogger()
DEBUGPULSEPLUGIN = 25


@set_logging_level
def action(objectxmpp, action, sessionid, data, message, dataerreur):
    logger.debug("###################################################")
    logger.debug(f'call {plugin} from {message["from"]}')
    logger.debug(f"sessionid : {sessionid}")
    logger.debug("###################################################")
    if "notify" in data:
        logger.debug(f'notify : {data["notify"]}')

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
