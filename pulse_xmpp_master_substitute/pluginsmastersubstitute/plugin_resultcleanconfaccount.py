#!/usr/bin/python3
# -*- coding: utf-8; -*-
# SPDX-FileCopyrightText: 2016-2023 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-3.0-or-later
import logging
from .utils import simplecommandstr

logger = logging.getLogger()
plugin = { "VERSION": "1.1", "NAME": "resultcleanconfaccount", "TYPE": "substitute", "FEATURE": "assessor", }  # fmt: skip


def action(xmppobject, action, sessionid, data, msg, ret, dataobj):
    logging.getLogger().debug("=====================================================")
    logging.getLogger().debug(plugin)
    logging.getLogger().debug("=====================================================")
    try:
        recipient = str(msg["from"].user)
        if data["useraccount"].startswith("conf"):
            logger.debug("Clear MUC conf account")
            cmd = "ejabberdctl unregister %s pulse" % recipient
            unregister_command = simplecommandstr(cmd)
            logger.debug(unregister_command["result"])
            logger.info(
                "The ejabberd account %s has been removed for the machine: %s"
                % (recipient, str(msg["from"].resource))
            )
    except Exception:
        pass
