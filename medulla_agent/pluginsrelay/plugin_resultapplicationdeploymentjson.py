# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2016-2023 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-3.0-or-later

import logging

logger = logging.getLogger()
DEBUGPULSEPLUGIN = 25
plugin = {"VERSION": "1.305", "NAME": "resultapplicationdeploymentjson", "TYPE": "all"}  # fmt: skip


def action(objectxmpp, action, sessionid, data, message, dataerreur):
    logger.debug("###################################################")
    logger.debug("call %s from %s" % (plugin, message["from"]))
    logger.debug("###################################################")

    if objectxmpp.session.isexist(sessionid):
        logging.getLogger().debug(
            "clear sessionid %s from %s" % (sessionid, message["from"])
        )
        objectxmpp.session.clearnoevent(sessionid)
