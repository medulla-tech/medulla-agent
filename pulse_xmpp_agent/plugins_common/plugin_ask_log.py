# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2016-2023 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-3.0-or-later

"""
This plugin needs to call back the plugin that made the request to return the result
"""

import json
from lib import managepackage, utils
import logging
import platform
import sys

logger = logging.getLogger()

plugin = {"VERSION": "1.0", "NAME": "ask_log", "TYPE": "all"}  # fmt: skip

@utils.set_logging_level
def action(objectxmpp, action, sessionid, data, message, dataerreur):
    logging.getLogger().debug("call %s from %s" % (plugin, message["from"]))
    result = {
        "action": "result%s" % action,
        "sessionid": sessionid,
        "data": data,
        "ret": 0,
        "base64": False,
    }
    # reply data
    if "Log_agent" in data and data['Log_agent'] == True:
        if "Log_Request" in data:
            objectxmpp.Log_Request=data['Log_Request']

        if "log_context" in data:
            objectxmpp.log_context=data['log_context']

        if "log_justification" in data:
            objectxmpp.log_justification=data['log_justification']

        objectxmpp.loghandler.activate_for_seconds(180)
        logging.getLogger().debug("Relance les logs 3 minutes")
    else:
        # ici futur fonctionalite
        pass

    objectxmpp.send_message(mto=message["from"], mbody=json.dumps(result), mtype="chat")
