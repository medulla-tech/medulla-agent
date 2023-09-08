#!/usr/bin/python
# -*- coding: utf-8; -*-
# SPDX-FileCopyrightText: 2022-2023 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-3.0-or-later

import json
import smtplib
import sys
import logging
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.utils import formatdate
import base64
import traceback
from datetime import date, datetime

# global variable
LOGFILE = "/var/lib/pulse2/script_monitoring/logfilescriptxmpp.log"
logger = logging.getLogger()
ERROR_TEST = "ERROR_MESSAGE_XMPP"  # To be analysed submon side


class DateTimeEncoder(json.JSONEncoder):
    def default(self, obj):
        return (
            obj.isoformat()
            if isinstance(obj, datetime)
            else json.JSONEncoder.default(self, obj)
        )


def action(struct):
    try:
        action = None
        if struct["mon_rules_user"]:
            action = struct["mon_rules_user"]
        elif struct["mon_rules_comment"] and "action" in struct["mon_rules_comment"]:
            action = struct["mon_rules_comment"]["action"]

        # Action is the name of the plugin call.
        # in rule it is defined in my_rules:
        # - Let in use men_rules. Example: qa_test_monitoring
        # - In 1 Strut JSON in how {"action": "qa_test_monitoring"}
        # or directly in the code template


        # action is the name of the plugin call
        send_message = {
            "action": action,
            "sessionid": struct["session_id"],
            "base64": False,
            "ret": 0,
            "data": {},
        }
        # Personal Code below
        # We write the JSON CORE call for the remote plugin

        # In the exemple code. send_message is the message sent to  the machine
        # which triggers the alert
        send_message["data"]["struct"] = struct

        # END Personal Code
        # modifies the code below if you know what you do
        if not send_message["action"]:
            logger.error("action missing")
            raise
        result = json.dumps(send_message, indent=4, cls=DateTimeEncoder)
        logger.debug(f"struct {result}")
    except:
        result = f"{traceback.format_exc()}"
        result = ERROR_TEST
    # le str json et copier dansle fichier result
    with open(struct["namefileout"], "ab") as out:
        out.write("\n-------- xmppmsg Message--------\n")
        out.write("\nMESSAGE TO MACHINE (%s)" % struct["jid"])
        out.write("\n----------------------------------------------------")
        out.write("\n%s" % result)
        out.write("\n----------------------------------------------------")
    print(result)


if __name__ == "__main__":
    # The program received the event structure as parameter (in base64)
    logging.basicConfig(
        level=logging.DEBUG,
        format="%(asctime)s %(message)s",
        filename=LOGFILE,
        filemode="a",
    )
    logger.debug("Programm starting")
    action(json.loads(base64.b64decode(sys.argv[1])))
