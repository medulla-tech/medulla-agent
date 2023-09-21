# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2016-2023 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-3.0-or-later

import json
import traceback
import logging
from lib.utils import name_random
from lib.plugins.xmpp import XmppMasterDatabase

logger = logging.getLogger()

plugin = {"VERSION": "1.0", "NAME": "plugin_guacamole", "TYPE": "submaster"}
# plugin run guacamole


def action(xmppobject, action, sessionid, data, message, dataobj):
    logger.debug(plugin)
    try:
        relayserver = XmppMasterDatabase().getRelayServerForMachineUuid(data["uuid"])
        jidmachine = XmppMasterDatabase().getjidMachinefromuuid(data["uuid"])
        senddataplugin = {
            "action": "guacamole",
            "sessionid": name_random(5, "guacamole"),
            "data": {
                "jidmachine": jidmachine,
                "cux_id": int(data["cux_id"]),
                "cux_type": data["cux_type"],
                "uuid": data["uuid"],
            },
        }
        # xmppobject.send_message(
        # mto=relayserver["jid"],
        # mbody=json.dumps(senddataplugin, encoding="latin1"),
        # mtype="chat",
        # )
        logger.error("senddataplugin %s" % senddataplugin)

        xmppobject.send_message(
            mto=relayserver["jid"],
            mbody=json.dumps(senddataplugin, ensure_ascii=False).encode("latin1"),
            mtype="chat",
        )

    except:
        logger.error("error plugin plugin_guacamole %s" % data)
        logger.error("\n%s" % (traceback.format_exc()))
        pass
