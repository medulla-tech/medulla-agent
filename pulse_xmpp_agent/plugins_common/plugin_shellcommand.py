# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2016-2023 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-3.0-or-later

from lib import utils
import json
import traceback
import sys

plugin = {"VERSION": "2.1", "NAME": "shellcommand", "TYPE": "all"}  # fmt: skip


@utils.set_logging_level
def action(objectxmpp, action, sessionid, data, message, dataerreur):
    result = {
        "action": "result%s" % action,
        "sessionid": sessionid,
        "data": {},
        "ret": 0,
        "base64": False,
    }
    try:
        obj = utils.simplecommand(utils.encode_strconsole(data["cmd"]))
        obj["result"] = [x.rstrip("\n") for x in obj["result"] if x != "\n"]
        if obj["code"] == 0:
            result["ret"] = 0
            result["data"]["result"] = "".join(obj["result"])
            result["data"]["result"] = "".join(
                [utils.decode_strconsole(x) for x in result["data"]["result"]]
            )
            print(result["data"]["result"])
            objectxmpp.send_message(
                mto=message["from"],
                mbody=json.dumps(result, sort_keys=True, indent=4),
                mtype="chat",
            )
        else:
            dataerreur["ret"] = obj["code"]
            objectxmpp.send_message(
                mto=message["from"], mbody=json.dumps(dataerreur), mtype="chat"
            )
    except Exception:
        traceback.print_exc(file=sys.stdout)
        dataerreur["ret"] = -255
        dataerreur["data"]["msg"] = "Erreur commande\n %s" % data["cmd"]
        objectxmpp.send_message(
            mto=message["from"], mbody=json.dumps(dataerreur), mtype="chat"
        )
