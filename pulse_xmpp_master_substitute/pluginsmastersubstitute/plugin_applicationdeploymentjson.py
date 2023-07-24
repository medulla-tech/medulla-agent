#!/usr/bin/python3
# -*- coding: utf-8; -*-
# SPDX-FileCopyrightText: 2016-2023 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-3.0-or-later
import json
import logging
import traceback

logger = logging.getLogger()
plugin = {"VERSION": "1.0", "NAME": "applicationdeploymentjson", "TYPE": "substitute"}  # fmt: skip


def action(xmppobject, action, sessionid, data, message, ret, dataobj):
    logger.debug("=====================================================")
    logger.debug("call %s from %s" % (plugin, message["from"]))
    logger.debug("=====================================================")
    try:
        if "Dtypequery" in data:
            if data["Dtypequery"] == "TED":
                logger.debug("Delete session %s" % sessionid)
                # Set deployment to done in database
                xmppobject.sessiondeploysubstitute.clear(sessionid)

                if __debug__:
                    logger.debug(
                        "_______________________RESULT DEPLOYMENT________________________"
                    )
                    logger.debug(json.dumps(data["descriptor"]))
                    logger.debug(
                        "________________________________________________________________"
                    )
            elif data["Dtypequery"] == "TE":
                # clear session
                xmppobject.sessiondeploysubstitute.clear(sessionid)
                # Set deployment to error in database
            else:
                # Update session with data
                xmppobject.sessiondeploysubstitute.sessionsetdata(sessionid, data)
        pass
    except Exception as e:
        logger.error("\n%s" % (traceback.format_exc()))
        logger.error("Error in plugin %s : %s" % (plugin["NAME"], str(e)))
