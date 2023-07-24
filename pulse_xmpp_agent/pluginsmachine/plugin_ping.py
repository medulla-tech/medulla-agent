# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2022-2023 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-3.0-or-later

import logging
import json

plugin = {"VERSION": "1.1", "NAME": "ping", "TYPE": "all"}

logger = logging.getLogger()


def action(objectxmpp, action, sessionid, data, message, dataerreur):
    logging.getLogger().debug("###################################################")
    logging.getLogger().debug(
        "call %s from %s session id %s" % (plugin, message["from"], sessionid)
    )
    logging.getLogger().debug("###################################################")
    datasend = {
        "action": "pong",
        "data": {"agenttype": objectxmpp.config.agenttype},
        "sessionid": sessionid,
        "ret": 0,
        "base64": False,
    }
    objectxmpp.send_message(
        mto=message["from"], mbody=json.dumps(datasend, indent=4), mtype="chat"
    )
