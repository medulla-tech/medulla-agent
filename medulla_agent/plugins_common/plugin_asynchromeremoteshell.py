# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2016-2023 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-3.0-or-later

from lib import utils
import json
import traceback
import sys
import os
import logging

logger = logging.getLogger()

plugin = {"VERSION": "2.1", "NAME": "asynchromeremoteshell", "TYPE": "all"}  # fmt: skip


@utils.set_logging_level
def action(objectxmpp, action, sessionid, data, message, dataerreur):
    logger.info("###################################################")
    logger.info(f'call {plugin} from {message["from"]}')
    logger.info("###################################################")

    result = {
        "action": f"result{action}",
        "sessionid": sessionid,
        "data": {},
        "ret": 0,
        "base64": False,
    }
    try:
        obj = utils.simplecommand(data["command"])
        logger.info(f"encodage result : {sys.stdout.encoding}")

        result["ret"] = 0
        result["data"]["code"] = obj["code"]
        try:
            result["data"]["result"] = [
                x.decode("utf-8", "ignore").strip(os.linesep) for x in obj["result"]
            ]
        except Exception as e:
            logger.error("error decodage result")
            logger.error(str(e))
            result["data"]["result"] = [
                x.decode("latin-1").strip(os.linesep) for x in obj["result"]
            ]
        objectxmpp.send_message(
            mto=message["from"], mbody=json.dumps(result, indent=4), mtype="chat"
        )
    except Exception as e:
        logger.error(str(e))
        logger.error("\n%s" % (traceback.format_exc()))
        dataerreur["ret"] = -255
        dataerreur["data"]["msg"] = "Erreur commande\n %s" % data["cmd"]
        objectxmpp.send_message(
            mto=message["from"], mbody=json.dumps(dataerreur), mtype="chat"
        )
