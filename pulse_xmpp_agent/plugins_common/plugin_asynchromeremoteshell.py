# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2016-2023 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-3.0-or-later

from lib import utils
import json
import traceback
import sys
import os
import logging

plugin = {"VERSION": "2.0", "NAME": "asynchromeremoteshell", "TYPE": "all"}  # fmt: skip


def action(objectxmpp, action, sessionid, data, message, dataerreur):
    logging.getLogger().info("###################################################")
    logging.getLogger().info(f'call {plugin} from {message["from"]}')
    logging.getLogger().info("###################################################")

    result = {
        "action": f"result{action}",
        "sessionid": sessionid,
        "data": {},
        "ret": 0,
        "base64": False,
    }
    try:
        obj = utils.simplecommand(data["command"])
        logging.getLogger().info(f"encodage result : {sys.stdout.encoding}")

        result["ret"] = 0
        result["data"]["code"] = obj["code"]
        try:
            result["data"]["result"] = [
                x.decode("utf-8", "ignore").strip(os.linesep) for x in obj["result"]
            ]
        except Exception as e:
            logging.getLogger().error("error decodage result")
            logging.getLogger().error(str(e))
            result["data"]["result"] = [
                x.decode("latin-1").strip(os.linesep) for x in obj["result"]
            ]
        objectxmpp.send_message(
            mto=message["from"], mbody=json.dumps(result, indent=4), mtype="chat"
        )
    except Exception as e:
        logging.getLogger().error(str(e))
        traceback.print_exc(file=sys.stdout)
        dataerreur["ret"] = -255
        dataerreur["data"]["msg"] = "Erreur commande\n %s" % data["cmd"]
        objectxmpp.send_message(
            mto=message["from"], mbody=json.dumps(dataerreur), mtype="chat"
        )
