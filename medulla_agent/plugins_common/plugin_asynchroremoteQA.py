# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2016-2023 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-3.0-or-later


from lib import utils
import json
import traceback
import sys
import logging

logger = logging.getLogger()

plugin = {"VERSION": "2.1", "NAME": "asynchroremoteQA", "TYPE": "all"}  # fmt: skip


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
        logger.error(str(e))
        logger.error("\n%s" % (traceback.format_exc()))
        dataerreur["ret"] = -255
        dataerreur["data"]["msg"] = "Erreur commande\n %s" % data["data"]["customcmd"]
        objectxmpp.send_message(
            mto=message["from"], mbody=json.dumps(dataerreur), mtype="chat"
        )
