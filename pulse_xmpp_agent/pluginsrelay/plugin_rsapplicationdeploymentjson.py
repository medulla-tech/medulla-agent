# -*- coding: utf-8 -*-
#
# (c) 2016-2017 siveo, http://www.siveo.net
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

import json
import os
from lib.managepackage import managepackage
import logging


logger = logging.getLogger()
DEBUGPULSEPLUGIN = 25
plugin = {"VERSION" : "1.1", "NAME" : "rsapplicationdeploymentjson", "TYPE" : "relayserver"}



def action(objectxmpp, action, sessionid, data, message, dataerreur):
    #logging.getLogger().debug("RECV data message %s\n###############\n"%json.dumps(data, indent=4))
    logging.log(DEBUGPULSEPLUGIN,"plugin %s on %s %s from %s"% (plugin, objectxmpp.config.agenttype, message['to'], message['from']))
    datasend = {
                    'action': action,
                    'sessionid': sessionid,
                    'data' : {},
                    'ret' : 0,
                    'base64' : False
                }

    logging.getLogger().debug("#################RELAY SERVER#####################")
    logging.getLogger().debug("##############demande pacquage %s ##############"%(data['deploy']))
    logging.getLogger().debug("##################################################")
    #envoy descripteur
    try:
        descriptor =  managepackage.getdescriptorpackageuuid(data['deploy'])
    except Exception as e:
        logging.getLogger().error(str(e))
        logging.getLogger().error("plugin rsapplicationdeploymentjson Error, package [%s] uuid descriptor missing"%data['deploy'])
        descriptor = None
    if descriptor is not None:
        datasend['action'] = "applicationdeploymentjson"
        datasend['data'] = { "descriptor" : descriptor}
        datasend['data'] ['path'] = os.path.join(managepackage.packagedir(), data['deploy'])
        datasend['data'] ['packagefile'] = os.listdir(datasend['data']['path'])
        datasend['data'] ['Dtypequery'] =  "TQ"
        datasend['data'] ['Devent'] = "DEPLOYMENT START"
        datasend['data'] ['name'] = managepackage.getnamepackagefromuuidpackage(data['deploy'])
        objectxmpp.send_message(mto=message['from'],
                                mbody=json.dumps(datasend),
                                mtype='chat')
    else:
        datasend['action'] = "applicationdeploymentjson"
        datasend['data'] = { "descriptor" : "error package missing"}
        datasend['data']['deploy']=data['deploy']
        datasend['ret'] = 45
        objectxmpp.send_message( mto=message['from'],
                                 mbody=json.dumps(datasend),
                                 mtype='chat')
