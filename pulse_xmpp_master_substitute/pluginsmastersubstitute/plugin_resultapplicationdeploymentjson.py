#!/usr/bin/python3
# -*- coding: utf-8; -*-
# SPDX-FileCopyrightText: 2016-2023 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-3.0-or-later

import logging
import traceback
import json
from lib.plugins.xmpp import XmppMasterDatabase

logger = logging.getLogger()
plugin = { "VERSION": "1.0", "NAME": "resultapplicationdeploymentjson", "TYPE": "substitute", }  # fmt: skip


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
