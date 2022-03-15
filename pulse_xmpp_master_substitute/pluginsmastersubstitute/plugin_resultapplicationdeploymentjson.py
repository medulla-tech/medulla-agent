#!/usr/bin/python3
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
#
# file pluginsmastersubstitute/plugin_resultapplicationdeploymentjson.py

import logging
import traceback
import json
from lib.plugins.xmpp import XmppMasterDatabase

logger = logging.getLogger()


plugin = { "VERSION": "1.0", "NAME": "resultapplicationdeploymentjson", "TYPE": "substitute", } # fmt: skip


def action(xmppsub, action, sessionid, data, message, ret, dataobj):
    logger.debug("=====================================================")
    logger.debug(plugin)
    logger.debug("=====================================================")
    logger.debug(json.dumps(data, indent=4))
    try:
        if ret == 0:
            logger.debug(
                "Succes deploy on %s Package "
                ": %s Session : %s"
                % (message["from"], data["descriptor"]["info"]["name"], sessionid)
            )
            XmppMasterDatabase().delete_resources(sessionid)

        else:
            msg = "Deployment error on %s [Package " ": %s / Session : %s]" % (
                message["from"],
                data["descriptor"]["info"]["name"],
                sessionid,
            )
            logger.error(msg)

            if "status" in data and data["status"] != "":
                XmppMasterDatabase().updatedeploystate1(sessionid, data["status"])
            else:
                XmppMasterDatabase().updatedeploystate1(
                    sessionid, "ABORT PACKAGE EXECUTION ERROR"
                )
            xmppsub.xmpplog(
                msg,
                type="deploy",
                sessionname=sessionid,
                priority=-1,
                action="xmpplog",
                who="",
                how="",
                why=xmppsub.boundjid.bare,
                module="Deployment | Start | Creation",
                date=None,
                fromuser="",
                touser="",
            )
        xmppsub.sessiondeploysubstitute.clearnoevent(sessionid)
    except Exception:
        logger.error("%s" % (traceback.format_exc()))
