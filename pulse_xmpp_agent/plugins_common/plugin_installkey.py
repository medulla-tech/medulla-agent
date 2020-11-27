# -*- coding: utf-8 -*-
#
# (c) 2016 siveo, http://www.siveo.net
#
# This file is part of Pulse 2, http://www.siveo.net
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
# MA 02110-1301, USA.
# file common/plugin_installkey.py

import sys
import os
import logging
from lib import utils
import subprocess
import uuid
import shutil

logger = logging.getLogger()
DEBUGPULSEPLUGIN = 25

plugin = { "VERSION" : "4.1", "NAME" : "installkey", "VERSIONAGENT" : "2.0.0", "TYPE" : "all" }

def action( objectxmpp, action, sessionid, data, message, dataerreur):
    logger.debug("###################################################")
    logger.debug("call %s from %s"%(plugin, message['from']))
    logger.debug("###################################################")
    dataerreur = {  "action" : "result" + action,
                    "data" : { "msg" : "error plugin : " + action
                    },
                    'sessionid': sessionid,
                    'ret': 255,
                    'base64': False
    }

    if objectxmpp.config.agenttype in ['machine']:
        logger.debug("#######################################################")
        logger.debug("##############AGENT INSTALL KEY MACHINE################")
        logger.debug("#######################################################")
        msg = []
        if 'key' not in data:
            objectxmpp.send_message_agent(message['from'], dataerreur, mtype='chat')
            return
        # Make sure user account and profile exists
        username = 'pulseuser'
        result, msglog = utils.pulseuser_useraccount_mustexist(username)
        if result is False:
            logger.error(msglog)
        msg.append(msglog)
        result, msglog = utils.pulseuser_profile_mustexist(username)
        if result is False:
            logger.error(msglog)
        msg.append(msglog)

        # Add the key to pulseuser account
        relayserver_pubkey = data['key']
        result, msglog = utils.add_key_to_authorizedkeys_on_client(username, relayserver_pubkey)
        if result is False:
            logger.error(msglog)
        msg.append(msglog)

        # Send logs to logger
        if sessionid.startswith("command"):
            notify = "Notify | QuickAction"
        else:
            notify = "Deployment | Cluster | Notify"
        for line in msg:
            xmppobject.xmpplog(line,
                               type='deploy',
                               sessionname=sessionid,
                               priority=-1,
                               action="xmpplog",
                               who= bjectxmpp.boundjid.bare,
                               how="",
                               why="",
                               module=notify,
                               date=None,
                               fromuser="",
                               touser="")

    else:
        logger.debug("#######################################################")
        logger.debug("##############AGENT RELAY SERVER KEY MACHINE###########")
        logger.debug("#######################################################")
        # send keupub ARM TO AM
        # ARM ONLY DEBIAN
        # lit la key Public
        key = ""
        key = utils.file_get_contents(os.path.join('/', 'root', '.ssh', 'id_rsa.pub'))
        if key == "":
            dataerreur['data']['msg'] = "ARS key %s missing"%dataerreur['data']['msg']
            objectxmpp.send_message_agent(message['from'], dataerreur, mtype = 'chat')
            return
        if 'jidAM' not in data:
            dataerreur['data']['msg'] = "Machine JID %s missing"%dataerreur['data']['msg']
            objectxmpp.send_message_agent(message['from'], dataerreur, mtype = 'chat')
            return

        datasend = {  "action" : action,
                    "data" : { "key" : key },
                    'sessionid': sessionid,
                    'ret': 255,
                    'base64': False
        }

        objectxmpp.send_message_agent( data['jidAM'], datasend, mtype = 'chat')
