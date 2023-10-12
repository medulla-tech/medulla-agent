# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2016-2023 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-2.0-or-later

import json
import os
from lib import managepackage
from lib.utils import file_get_contents
import logging

logger = logging.getLogger()
DEBUGPULSEPLUGIN = 25
plugin = {"VERSION" : "2.5", "NAME" : "rsapplicationdeploymentjson", "TYPE" : "relayserver"}



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

        if hasattr(objectxmpp.config, 'cdn_hashing_algo'):
            hashing_algo = objectxmpp.config.cdn_hashing_algo
        else:
            hashing_algo = "SHA256"

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
