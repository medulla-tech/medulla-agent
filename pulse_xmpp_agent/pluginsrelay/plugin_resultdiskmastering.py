# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2022-2023 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-3.0-or-later

import logging
import json
from lib.utils import set_logging_level

plugin = {"VERSION": "0.1", "NAME": "resultdiskmastering", "TYPE": "relayserver"}  # fmt: skip

logger = logging.getLogger()


@set_logging_level
def action(objectxmpp, action, sessionid, data, message, dataerreur):
    logging.getLogger().debug("###################################################")
    logging.getLogger().debug("call %s from %s session id %s" % (plugin, message["from"], sessionid))
    logging.getLogger().debug("###################################################")

    datasend = {
        "from":objectxmpp.boundjid.bare,
        "sessionid": sessionid,
        "ret": 0,
        "base64": False,
        "agenttype": objectxmpp.config.agenttype
    }

    # Message received from davos client
    if "subaction" in data:

        # when a davos client connects to the ejabber server, it send a ping message to explicitely tell to the relay a machine has booted on davos
        # The server send back a pong message to tells davos client "I'm ready to work with you"
        if data["subaction"] == "ping":
            datasend["action"] = "pong"

    objectxmpp.send_message(mto=message["from"], mbody=json.dumps(datasend, indent=4), mtype="chat")
