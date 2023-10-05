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
from lib import managepackage
from lib.utils import file_get_contents
import logging
import configparser

logger = logging.getLogger()
DEBUGPULSEPLUGIN = 25
plugin = {"VERSION" : "2.1", "NAME" : "rsapplicationdeploymentjson", "TYPE" : "relayserver"}



def action(objectxmpp, action, sessionid, data, message, dataerreur):
    logging.log(DEBUGPULSEPLUGIN,"plugin %s on %s %s from %s"% (plugin, objectxmpp.config.agenttype, message['to'], message['from']))
    datasend = {
                    'action': action,
                    'sessionid': sessionid,
                    'data': {},
                    'ret': 0,
                    'base64': False
                }

    logging.getLogger().debug("#################RELAY SERVER#####################")
    logging.getLogger().debug("##############ask for package %s ##############"%(data['deploy']))
    try:
        descriptor =  managepackage.managepackage.getdescriptorpackageuuid(data['deploy'])
    except Exception as e:
        logging.getLogger().error(str(e))
        logging.getLogger().error("plugin rsapplicationdeploymentjson Error, package [%s] uuid descriptor missing"%data['deploy'])
        descriptor = None
    if descriptor is not None:
        datasend['action'] = "applicationdeploymentjson"
        datasend['data'] = { "descriptor" : descriptor}
        datasend['data'] ['path'] = os.path.join(managepackage.managepackage.packagedir(), data['deploy'])
        datasend['data'] ['packagefile'] = os.listdir(datasend['data']['path'])
        datasend['data'] ['Dtypequery'] =  "TQ"
        datasend['data'] ['Devent'] = "DEPLOYMENT START"
        datasend['data'] ['name'] = managepackage.managepackage.getnamepackagefromuuidpackage(data['deploy'])

        if ('localisation_server' in datasend['data']['descriptor']['info'] and datasend['data']['descriptor']['info']['localisation_server'] != ""):
            localisation_server = datasend['data']['descriptor']['info']['localisation_server']
        elif ('previous_localisation_server' in datasend['data']['descriptor']['info'] and datasend['data']['descriptor']['info']['previous_localisation_server'] != ""):
            localisation_server = datasend['data']['descriptor']['info']['previous_localisation_server']

        hashFolder = os.path.join("/var", "lib", "pulse2", "packages", "hash", localisation_server)

        config = configparser.ConfigParser()
        config.read('/etc/pulse-xmpp-agent/applicationdeploymentjson.ini.local')
        hashing_algo = config.get('parameters', 'cdn_hashing_algo')

        if os.path.exists(os.path.join(hashFolder, data['deploy'] + ".hash")):
            datasend['data']['hash'] = {'global': file_get_contents(os.path.join(hashFolder, data['deploy'] + ".hash")), 'type': hashing_algo}

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
