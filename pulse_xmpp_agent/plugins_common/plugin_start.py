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
# file  pulse_xmpp_agent/pluginsmachine/plugin_start.py

import sys, os
import logging
from lib.utils import file_get_contents
logger = logging.getLogger()
DEBUGPULSEPLUGIN = 25

plugin = {"VERSION" : "1.11", "NAME" : "start", "TYPE" : "all"}

def action( objectxmpp, action, sessionid, data, message, dataerreur):
    logger.debug("###################################################")
    logger.debug("call %s from %s"%(plugin, message['from']))
    logger.debug("###################################################")
    if objectxmpp.config.agenttype in ['machine']:
        logger.debug("#################AGENT MACHINE#####################")
        logger.debug("###################################################")
        if sys.platform.startswith('win'):
            #injection version clef de registre
            logger.debug("INJECTION KEY REGISTER VERSION")
            pathversion = os.path.join(objectxmpp.pathagent, "agentversion")
            if os.path.isfile(pathversion):
                version = file_get_contents(pathversion).replace("\n","").replace("\r","").strip()
                if len(version) < 20:
                    logger.debug("Version AGENT is " + version)
                    import _winreg
                    key = _winreg.OpenKey(_winreg.HKEY_LOCAL_MACHINE,
                                        "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Pulse Agent\\",
                                        0 ,
                                        _winreg.KEY_SET_VALUE | _winreg.KEY_WOW64_64KEY)
                    _winreg.SetValueEx ( key,
                                        'DisplayVersion'  ,
                                        0,
                                        _winreg.REG_SZ,
                                        version)
                    _winreg.CloseKey(key)
        elif sys.platform.startswith('linux') :
            pass
        elif sys.platform.startswith('darwin'):
           pass
    else:
        logger.debug("###################################################")
        logger.debug("##############AGENT RELAY SERVER###################")
        logger.debug("###################################################")
