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


#This plugin needs to call back the plugin that made the request to return the result

import json
from lib.managepackage import managepackage
import logging
import platform
import sys
from lib.utils import protoandport

logger = logging.getLogger()
DEBUGPULSEPLUGIN = 25
plugin = { "VERSION" : "1.4", "NAME" : "requestinfo", "TYPE" : "all" }

def action( objectxmpp, action, sessionid, data, message, dataerreur):
    logging.getLogger().debug("call %s from %s"%(plugin,message['from']))
    result = {
                'action': "result%s"%action,
                'sessionid': sessionid,
                'data' : {},
                'ret' : 0,
                'base64' : False }

    # This plugin needs to call back the plugin that made the request to return the result
    if 'actionasker' in data:
        result['action'] = data['actionasker']

    # Can tell the requester where the call was received
    if 'step' in data:
        result['data']['step'] = data['step']

    if 'actiontype' in data:
        result['data']['actiontype'] = data['actiontype']

    #reply data
    if 'dataask' in data:
        for informations in data['dataask']:
            if informations == "folders_packages":
                result['data']["folders_packages"] = managepackage.packagedir()
            if informations == "os":
                result['data']["os"] = sys.platform
                result['data']["os_version"] = platform.platform()
            if informations == "ssh_port":
                remoteservices = protoandport()
                result['data']["ssh_port"] = remoteservices['ssh']
            if informations == "cpu_arch":
                result['data']["cpu_arch"] = platform.machine()

    if 'sender' in data:
        for senderagent in data["sender"]:
            objectxmpp.send_message( mto=senderagent,
                             mbody=json.dumps(result),
                             mtype='chat')

    print "message to %s"%message['from']
    print "result \n%s"%json.dumps(result, indent=4)

    #message
    objectxmpp.send_message( mto=message['from'],
                             mbody=json.dumps(result),
                             mtype='chat')
