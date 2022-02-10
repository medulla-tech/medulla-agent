#!/usr/bin/python
# -*- coding: utf-8; -*-
#
# (c) 2022 Siveo, http://www.siveo.net/
#
# $Id$
#
# This file is part of Pulse 2, http://pulse2.mandriva.org
#
# Pulse 2 is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# Pulse 2 is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Pulse 2; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
# MA 02110-1301, USA

# file : program_xmpp_test.py

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
LOGFILE ="/var/lib/pulse2/script_monitoring/logfilescriptxmpp.log"
logger = logging.getLogger()
ERROR_TEST="ERROR_MESSAGE_XMPP" # To be analysed submon side

class DateTimeEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, datetime):
            encoded_object = obj.isoformat()
        else:
            encoded_object = json.JSONEncoder.default(self, obj)
        return encoded_object

def action(struct):
    try:
        action= None
        if struct['mon_rules_user']:
            action = struct['mon_rules_user']
        elif struct['mon_rules_comment'] and 'action' in struct['mon_rules_comment']:
            action = struct['mon_rules_comment']['action']

        # Action is the name of the plugin call.
        # in rule it is defined in my_rules:
        # - Let in use men_rules. Example: qa_test_monitoring
        # - In 1 Strut JSON in how {"action": "qa_test_monitoring"}
        # or directly in the code template

        # action = "my_plugin_appleler" # action defined directly in code if not defined in my_rules

        # action is the name of the plugin call
        send_message = { "action"   : action,
                         "sessionid" : struct['session_id'],
                         "base64"    : False,
                         "ret"       : 0,
                         "data"      : {} }
        # Personal Code below
        # We write the JSON CORE call for the remote plugin

        # In the exemple code. send_message is the message sent to  the machine
        # which triggers the alert
        send_message['data']['struct'] = struct

        # END Personal Code
        # modifies the code below if you know what you do
        if not send_message['action']
            logger.error("action missing")
            raise
        result = json.dumps(send_message, indent=4, cls=DateTimeEncoder)
        logger.debug("struct %s" % result)
    except:
        result = "%s"%(traceback.format_exc())
        result = ERROR_TEST
    # le str json et copier dansle fichier result
    with open(struct['namefileout'], "ab") as out:
        out.write("\n-------- xmppmsg Message--------\n")
        out.write("\nMESSAGE TO MACHINE (%s)" % struct['jid'])
        out.write("\n----------------------------------------------------")
        out.write("\n%s" % result)
        out.write("\n----------------------------------------------------")
    print result

if __name__ == "__main__":
    # The program received the event structure as parameter (in base64)
    logging.basicConfig(level=logging.DEBUG,
                        format='%(asctime)s %(message)s',
                        filename = LOGFILE,
                        filemode = 'a')
    logger.debug("Programm starting")
    action(json.loads(base64.b64decode(sys.argv[1])))
