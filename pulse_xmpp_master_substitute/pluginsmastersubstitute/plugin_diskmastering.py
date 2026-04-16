# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2025-2026 Medulla <medulla-tech.io>
# SPDX-License-Identifier: GPL-3.0-or-later

import json
import logging
import base64

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
            DiskMasteringDatabase().create_master(data["sessionid"], data["uuid"], data["action_id"], data["master_uuid"])

        if data["subaction"] == "log":
            push_log(xmppobject, data)
            return

        if data["subaction"] == "askworkflow":
            datasend = {
                "action":"getworkflow",
                "from":xmppobject.boundjid.bare,
                "to": data["client_jid"],
                "sessionid": data["sessionid"],
                "result": {},
            }

            if "action_id" in data:
                try:
                    result = DiskMasteringDatabase().get_action_details(data["action_id"])
                except Exception as e:
                    logger.error(e)

                # Setup the new status WORKING for the selected action
                DiskMasteringDatabase().set_action_status(data["sessionid"], data["action_id"], data["uuid"], "WORKING")

                result["date_creation"] = result["date_creation"].strftime("%Y-%m-%d %H:%M:%S")
                result["date_start"] = result["date_start"].strftime("%Y-%m-%d %H:%M:%S")
                result["date_end"] = result["date_end"].strftime("%Y-%m-%d %H:%M:%S")

                # result["content"] contains the workflow
                workflow = json.loads(result["content"])

                # Modify the json
                for step in workflow:
                    if step["type"] == "script":
                        if "id" in step:
                            script = get_mastering_script(xmppobject, step["id"])
                            step["data"] = base64.b64encode(script.encode("utf-8")).decode("utf-8")
                        else:
                            step["data"] = ""

                del(result["content"])
                result["workflow"] = workflow

                datasend = {
                    "action":"resultaskworkflow",
                    "from":xmppobject.boundjid.bare,
                    "to": data["client_jid"],
                    "sessionid": data["sessionid"],
                    "data": {
                        "result": result,
                        "subaction": "getworkflow",
                    },
                }

                xmppobject.send_message(mto=data["client_jid"], mbody=json.dumps(datasend, indent=4), mtype="chat")


def get_mastering_script(xmppobject, step):
    pass


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
