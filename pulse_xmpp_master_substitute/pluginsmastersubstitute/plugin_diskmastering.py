# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2016-2023 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-3.0-or-later

import json
import traceback
import logging
# from lib.plugins.glpi import Glpi
from lib.plugins.diskmastering import DiskMasteringDatabase
from datetime import datetime
logger = logging.getLogger()
plugin = {"VERSION": "0.1", "NAME": "diskmastering", "TYPE": "mastersub"}


def action(xmppobject, action, sessionid, data, message, ret, dataobj):
    logger.debug("=====================================================")
    logger.debug(plugin)
    logger.debug("=====================================================")

    datasend = {
        "action":"getworkflow",
        "from":xmppobject.boundjid.bare,
        "to": data["client_jid"],
        "sessionid": data["sessionid"],
        "result": {},
    }

    if "subaction" in data:
        if data["subaction"] == "askworkflow":
            if "action_id" in data:
                try:
                    result = DiskMasteringDatabase().get_action_details(data["action_id"])
                except Exception as e:
                    logger.error(e)

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
