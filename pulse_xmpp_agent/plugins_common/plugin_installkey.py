# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2016-2023 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-3.0-or-later

import os
import logging
from lib import utils

logger = logging.getLogger()
DEBUGPULSEPLUGIN = 25
plugin = { "VERSION": "4.1", "NAME": "installkey", "VERSIONAGENT": "2.0.0", "TYPE": "all", }  # fmt: skip


def action(objectxmpp, action, sessionid, data, message, dataerreur):
    logger.debug("###################################################")
    logger.debug(f'call {plugin} from {message["from"]}')
    logger.debug("###################################################")
    dataerreur = {
        "action": f"result{action}",
        "data": {"msg": f"error plugin : {action}"},
        "sessionid": sessionid,
        "ret": 255,
        "base64": False,
    }

    if objectxmpp.config.agenttype in ["machine"]:
        logger.debug("#######################################################")
        logger.debug("##############AGENT INSTALL KEY MACHINE################")
        logger.debug("#######################################################")
        if "key" not in data:
            objectxmpp.send_message_agent(message["from"], dataerreur, mtype="chat")
            return
        # Make sure user account and profile exists
        username = "pulseuser"
        result, msglog = utils.pulseuser_useraccount_mustexist(username)
        if result is False:
            logger.error(msglog)
        msg = [msglog]
        result, msglog = utils.pulseuser_profile_mustexist(username)
        if result is False:
            logger.error(msglog)
        msg.append(msglog)

        # Add the key to pulseuser account
        relayserver_pubkey = data["key"]
        result, msglog = utils.add_key_to_authorizedkeys_on_client(
            username, relayserver_pubkey
        )
        if result is False:
            logger.error(msglog)
        msg.append(msglog)

        # Send logs to logger
        if sessionid.startswith("command"):
            notify = "Notify | QuickAction"
        else:
            notify = "Deployment | Cluster | Notify"
        for line in msg:
            objectxmpp.xmpplog(
                line,
                type="deploy",
                sessionname=sessionid,
                priority=-1,
                action="xmpplog",
                who=objectxmpp.boundjid.bare,
                how="",
                why="",
                module=notify,
                date=None,
                fromuser="",
                touser="",
            )

    else:
        logger.debug("#######################################################")
        logger.debug("##############AGENT RELAY SERVER KEY MACHINE###########")
        logger.debug("#######################################################")
        # send keupub ARM TO AM
        # ARM ONLY DEBIAN
        # lit la key Public
        key = ""
        key = utils.file_get_contents(os.path.join("/", "root", ".ssh", "id_rsa.pub"))
        if key == "":
            dataerreur["data"]["msg"] = f'ARS key {dataerreur["data"]["msg"]} missing'
            objectxmpp.send_message_agent(message["from"], dataerreur, mtype="chat")
            return
        if "jidAM" not in data:
            dataerreur["data"][
                "msg"
            ] = f'Machine JID {dataerreur["data"]["msg"]} missing'
            objectxmpp.send_message_agent(message["from"], dataerreur, mtype="chat")
            return

        datasend = {
            "action": action,
            "data": {"key": key},
            "sessionid": sessionid,
            "ret": 255,
            "base64": False,
        }

        objectxmpp.send_message_agent(data["jidAM"], datasend, mtype="chat")
