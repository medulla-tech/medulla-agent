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
# file pulse_xmpp_master_subtitute/pluginsmastersubtitute/plugin_autoupdate.py

import base64
import json
import sys, os
import logging
import platform
from lib.utils import file_get_contents, getRandomName, data_struct_message
from lib.update_remote_agent import Update_Remote_Agent
import traceback
from sleekxmpp import jid
import types
import ConfigParser

logger = logging.getLogger()
DEBUGPULSEPLUGIN = 25

# this plugin calling to starting agent

plugin = {"VERSION" : "1.0", "NAME" : "autoupdate", "TYPE" : "subtitute"}

def action( objectxmpp, action, sessionid, data, msg, dataerreur):
    logger.debug("=====================================================")
    logger.debug("call %s from %s"%(plugin, msg['from']))
    logger.debug("=====================================================")

    compteurcallplugin = getattr(objectxmpp, "num_call%s"%action)

    if compteurcallplugin == 0:
        read_conf_remote_update(objectxmpp)
        objectxmpp.Update_Remote_Agentlist = Update_Remote_Agent(
            objectxmpp.diragentbase, objectxmpp.autoupdate)

def read_conf_remote_update(objectxmpp):
    namefichierconf = plugin['NAME'] + ".ini"
    pathfileconf = os.path.join( objectxmpp.config.pathdirconffile, namefichierconf )
    if not os.path.isfile(pathfileconf):
        logger.error("plugin %s\nConfiguration file :" \
            "\n\t%s missing" \
        "\neg conf:\n[global]\n" \
            "diragentbase = /var/lib/pulse2/xmpp_baseremoteagent/\n" \
                "autoupdate = True"%(plugin['NAME'], pathfileconf))
        logger.warning("default value for diragentbase " \
            "is /var/lib/pulse2/xmpp_baseremoteagent/"\
            "\ndefault value for autoupdate is True")
        objectxmpp.diragentbase = "/var/lib/pulse2/xmpp_baseremoteagent/"
        objectxmpp.diragentbase = True
    else:
        Config = ConfigParser.ConfigParser()
        Config.read(pathfileconf)
        if os.path.exists(pathfileconf + ".local"):
            Config.read(pathfileconf + ".local")
        if Config.has_option("global", "diragentbase"):
            objectxmpp.diragentbase = Config.get('global', 'diragentbase')
        else:
            objectxmpp.diragentbase = "/var/lib/pulse2/xmpp_baseremoteagent/"
        if Config.has_option("global", "autoupdate"):
            objectxmpp.autoupdate = Config.getboolean('global', 'autoupdate')
        else:
            objectxmpp.autoupdate = True
    objectxmpp.senddescriptormd5 = types.MethodType(senddescriptormd5, objectxmpp)
    objectxmpp.plugin_autoupdate = types.MethodType(plugin_autoupdate, objectxmpp)

def senddescriptormd5(self, to):
    """
        send the agent's figerprint descriptor in database to update the machine
        Update remote agent
    """
    datasend = {"action": "updateagent",
                "data": {'subaction': 'descriptor',
                            'descriptoragent': self.Update_Remote_Agentlist.get_md5_descriptor_agent()},
                'ret': 0,
                'sessionid': getRandomName(5, "updateagent")}
    # Send catalog of files.
    logger.debug("Send descriptor to agent [%s] for update" % to)
    self.send_message(to,
                      mbody=json.dumps(datasend),
                      mtype='chat')

def plugin_autoupdate(self, msg, data):
    # Manage update remote agent
    if self.autoupdate and 'md5agent' in data and \
        self.Update_Remote_Agentlist.get_fingerprint_agent_base() != data['md5agent']:
        if data['md5agent'].upper() != "DEV" or data['md5agent'].upper() != "DEBUG":
            # send md5 descriptor of the agent for remote update.
            self.senddescriptormd5(msg['from'])
