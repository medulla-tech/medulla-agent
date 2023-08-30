#!/usr/bin/env python
# -*- coding: utf-8; -*-
# SPDX-FileCopyrightText: 2016-2023 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-3.0-or-later

import logging
import traceback
from lib import utils

logger = logging.getLogger()

plugin = {"VERSION": "1.0", "NAME": "unregistrer_agent", "TYPE": "relayserver"}  # fmt: skip

"""
    This plugin is used to unregister an ejabberd account of old accounts.
"""


def action(xmppobject, action, sessionid, data, msg, dataerreur):
    logger.debug(
        "---------------------------------------------------------------------"
    )
    logger.debug(plugin)
    logger.debug(
        "----------------------------------------------------------------------"
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
            res = utils.simplecommand(
                "ejabberdctl unregister %s %s" % (data["user"], data["domain"])
            )
            if res["code"] == 0:
                logger.debug(
                    "We correctly removed the account %s@%s"
                    % (data["user"], data["domain"])
                )
            else:
                logger.error(
                    "We failed to remove the account %s@%s"
                    % (data["user"], data["domain"])
                )
        except Exception as e:
            logger.error(
                "An error occured while using the unregistrer_agent plugin. We got the error %s"
                % str(e)
            )
            logger.error("We hit the backtrace \n %s" % traceback.format_exc())
    else:
        logger.error("The JID is incorrect")
