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
DEBUGPULSEPLUGIN = 25
plugin = {"VERSION": "2.1", "NAME": "requestinfo", "TYPE": "all"}  # fmt: skip


@utils.set_logging_level
def action(objectxmpp, action, sessionid, data, message, dataerreur):
    logging.getLogger().debug("call %s from %s" % (plugin, message["from"]))
    result = {
        "action": "result%s" % action,
        "sessionid": sessionid,
        "data": {},
        "ret": 0,
        "base64": False,
    }

    # This plugin needs to call back the plugin that made the request to
    # return the result
    if "actionasker" in data:
        result["action"] = data["actionasker"]

    # Can tell the requester where the call was received
    if "step" in data:
        result["data"]["step"] = data["step"]

    if "actiontype" in data:
        result["data"]["actiontype"] = data["actiontype"]

    # reply data
    if "dataask" in data:
        for informations in data["dataask"]:
            if informations == "folders_packages":
                result["data"][
                    "folders_packages"
                ] = managepackage.managepackage.packagedir()
            if informations == "os":
                result["data"]["os"] = sys.platform
                result["data"]["os_version"] = platform.platform()
            if informations == "ssh_port":
                remoteservices = utils.protoandport()
                result["data"]["ssh_port"] = remoteservices["ssh"]
            if informations == "cpu_arch":
                result["data"]["cpu_arch"] = platform.machine()
            if informations == "sshd_on":
                try:
                    utils.restartsshd()
                    result["data"]["sshd_on"] = "actionstartsshd"
                except Exception:
                    pass
    if "sender" in data:
        for senderagent in data["sender"]:
            objectxmpp.send_message(
                mto=senderagent, mbody=json.dumps(result), mtype="chat"
            )

    print("message to %s" % message["from"])
    print("result \n%s" % json.dumps(result, indent=4))

    # message
    objectxmpp.send_message(mto=message["from"], mbody=json.dumps(result), mtype="chat")
