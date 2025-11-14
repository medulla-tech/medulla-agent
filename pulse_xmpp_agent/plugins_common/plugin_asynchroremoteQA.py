# -*- coding:Utf-8; -*
# SPDX-FileCopyrightText: 2016-2023 Siveo, http://www.siveo.net
# SPDX-FileCopyrightText: 2024-2025 Medulla, http://www.medulla-tech.io
# SPDX-License-Identifier: GPL-3.0-or-later

from lib import utils
import traceback
import logging
import base64
import json
import sys

logger = logging.getLogger()

plugin = {"VERSION": "2.2", "NAME": "asynchroremoteQA", "TYPE": "all"}  # fmt: skip

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

        # Join lines with newlines
        result_as_string = '\n'.join(resultcmd["result"])

        # Encode in base64 to preserve all special characters
        result_encoded = base64.b64encode(result_as_string.encode('utf-8')).decode('ascii')

        # Replace the list with the base64 string
        resultcmd["result"] = result_encoded

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
