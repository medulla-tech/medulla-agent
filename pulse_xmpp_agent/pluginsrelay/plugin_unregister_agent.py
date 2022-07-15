#!/usr/bin/env python
# -*- coding: utf-8; -*-
#
# (c) 2016-2017 siveo, http://www.siveo.net
#
# This file is part of Pulse 2, http://www.siveo.net
#
# Pulse 2 is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# Pulse 2 is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Pulse 2; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
# MA 02110-1301, USA.

import logging
import traceback
from lib import utils

logger = logging.getLogger()

plugin = {"VERSION": "1.0", "NAME": "unregister_agent", "TYPE": "relayserver"}

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
                "An error occured while using the unregister_agent plugin. We got the error %s"
                % str(e)
            )
            logger.error("We hit the backtrace \n %s" % traceback.format_exc())
    else:
        logger.error("The JID is incorrect")
