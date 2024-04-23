# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2020-2023 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-3.0-or-later

import logging
import traceback

logger = logging.getLogger()

DEBUGPULSEPLUGIN = 25
plugin = {"VERSION": "1.0", "NAME": "resultqdeploy", "TYPE": "relayserver"}  # fmt: skip


def action(objectxmpp, action, sessionid, data, message, dataerreur):
    logging.getLogger().debug("###################################################")
    logging.getLogger().debug("call %s from %s" % (plugin, message["from"]))
    logging.getLogger().debug("###################################################")
    # plugin recuperation des slots sur error
    strjidagent = str(objectxmpp.boundjid.bare)
    try:
        objectxmpp.mutex.acquire(1)
        try:
            try:
                del objectxmpp.concurrentquickdeployments[sessionid]
            except KeyError:
                logger.debug("Session %s missing" % sessionid)
            logger.debug("Deleting session id %s" % sessionid)
            objectxmpp.xmpplog(
                "Acknowledging deployment message\nFreeing quick deployment resource %s on error\n"
                "Resource status: %s/%s"
                % (
                    sessionid,
                    len(objectxmpp.concurrentquickdeployments),
                    objectxmpp.config.nbconcurrentquickdeployments,
                ),
                type="deploy",
                sessionname=sessionid,
                priority=-1,
                action="xmpplog",
                who=strjidagent,
                module="Deployment | Qdeploy | Notify",
                date=None,
                fromuser="",
            )
        except KeyError:
            logger.error("\n%s" % (traceback.format_exc()))
            pass
    finally:
        objectxmpp.mutex.release()
