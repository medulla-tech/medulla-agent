# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2016-2023 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-3.0-or-later


from lib import utils
import json
import traceback
import sys
import logging

plugin = {"VERSION": "2.0", "NAME": "asynchroremoteQA", "TYPE": "all"}  # fmt: skip


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
        resultcmd = utils.shellcommandtimeout(
            utils.encode_strconsole(data["data"]["customcmd"]), 15
        ).run()
        resultcmd["result"] = [utils.decode_strconsole(x) for x in resultcmd["result"]]
        result["data"]["result"] = resultcmd
        result["data"]["data"] = data
        result["ret"] = resultcmd["code"]
        objectxmpp.send_message(
            mto=message["from"], mbody=json.dumps(result), mtype="chat"
        )
    except Exception as e:
        logging.getLogger().error(str(e))
        traceback.print_exc(file=sys.stdout)
        dataerreur["ret"] = -255
        dataerreur["data"]["msg"] = "Erreur commande\n %s" % data["data"]["customcmd"]
        objectxmpp.send_message(
            mto=message["from"], mbody=json.dumps(dataerreur), mtype="chat"
        )
