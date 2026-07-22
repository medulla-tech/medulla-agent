# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2025-2026 Medulla <medulla-tech.io>
# SPDX-License-Identifier: GPL-3.0-or-later

import json
import logging
import base64
from configparser import ConfigParser
import os

# from lib.plugins.glpi import Glpi
from lib.plugins.diskmastering import DiskMasteringDatabase

# from datetime import datetime

logger = logging.getLogger()
plugin = {"VERSION": "0.1", "NAME": "diskmastering", "TYPE": "mastersub"}


def action(xmppobject, action, sessionid, data, message, ret, dataobj):
    logger.debug("=====================================================")
    logger.debug(plugin)
    logger.debug("=====================================================")

    if "subaction" in data:

        if data["subaction"] == "workflow_done":
            try:
                DiskMasteringDatabase().set_action_status(data["sessionid"], data["action_id"], data["uuid"], "DONE")
            except Exception as e:
                logger.error(e)

        if data["subaction"] == "create_master":
            DiskMasteringDatabase().create_master(data["sessionid"], data["uuid"], data["action_id"], data["master_uuid"], data["master_fullpath"], data["master_size"])

        if data["subaction"] == "log":
            push_log(xmppobject, data)
            return

        if data["subaction"] == "askworkflow":
            if "action_id" in data:
                # Can only get non consumed action and non expired action.
                try:
                    action = DiskMasteringDatabase().get_action_details(data["action_id"], data["uuid"])
                except Exception as e:
                    logger.error(e)

                # Setup the new status WORKING for the selected action
                DiskMasteringDatabase().set_action_status(data["sessionid"], data["action_id"], data["uuid"], "WORKING")
                result = {}
                result["date_creation"] = action["date_creation"].strftime("%Y-%m-%d %H:%M:%S")
                result["date_start"] = action["date_start"].strftime("%Y-%m-%d %H:%M:%S")
                result["date_end"] = action["date_end"].strftime("%Y-%m-%d %H:%M:%S")
                result["workflow"] = {}
                result["id"]= action["id"]
                result["entity_id"]= action["entity_id"]
                # result["content"] contains the workflow
                workflow = json.loads(action["content"])
                # Modify the json
                for step in workflow:
                    if step["type"] == "script":
                        # setup the step to be hydrated
                        step["data"] = {"type":"bash", "content": "", "payload": ""}

                        # Incorporate the content into the workflow json
                        if "name" in step:
                            # Here "name" corresponds to the script id
                            try:
                                script = DiskMasteringDatabase().get_mastering_script(step["name"])
                            except Exception as e:
                                logger.error("Impossible to get the script %s"%step["name"])

                            step["data"]["type"] = script["type"]
                            step["data"]["content"] = script["content"]
                            step["data"]["payload"] = script["payload"]

                result["workflow"] = workflow

                # TODO: Need to improve this section
                # Get the AES key from the config file
                keyAES32 = ""
                xmppconf = ConfigParser()
                conffilename = "/etc/mmc/plugins/xmppmaster.ini"
                localconffilename = "/etc/mmc/plugins/xmppmaster.ini.local"
                logger.warning(os.path.isfile(conffilename))
                if os.path.isfile(conffilename):
                    xmppconf.read(conffilename)
                    if os.path.isfile(localconffilename):
                        xmppconf.read(localconffilename)

                else:
                    logger.warning(f"Config file {conffilename} not found. Please create it and add the keyAES32 parameter in the [defaultconnection] section.")

                if xmppconf.has_option("defaultconnection", "keyAES32"):
                    keyAES32 = xmppconf.get("defaultconnection", "keyAES32")


                datasend = {
                    "action":"resultaskworkflow",
                    "from":xmppobject.boundjid.bare,
                    "to": data["client_jid"],
                    "sessionid": data["sessionid"],
                    "data": {
                        "result": result,
                        "subaction": "getworkflow",
                        "keyAES32": keyAES32
                    },
                }

                xmppobject.send_message(mto=data["client_jid"], mbody=json.dumps(datasend, indent=4), mtype="chat")



def push_log(xmppobject, data):

    _logger = logger.info

    if "level" in data and data["level"] in ["debug", "info", "warning", "error", "fatal"]:
        if data["level"] == "debug":
            _logger = logger.debug
        elif data["level"] == "info":
            _logger = logger.info
        elif data["level"] == "warning":
            _logger = logger.warning
        elif data["level"] == "error":
            _logger = logger.error
        elif data["level"] == "fatal":
            _logger = logger.fatal
        _logger("%s"%data["msg"])

    if "uuid" not in data or "action_id" not in data:
        return

    try:
        DiskMasteringDatabase().push_log(data["sessionid"], data["action_id"], data["uuid"], data["msg"])
    except Exception as e:
        logger.error(e)
