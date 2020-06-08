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
# file pulse_xmpp_agent/pluginsmachine/plugin_qdeploy.py

import base64
import json
import sys, os
from lib.managepackage import managepackage, search_list_of_deployment_packages
import socket
from lib.grafcetdeploy import grafcet
import logging
import pycurl
import platform
from lib.utils import simplecommandstr, \
                      simplecommand, \
                      encode_strconsole, \
                      file_get_contents, \
                      extract_file
import copy
import traceback
import time
from subprocess import STDOUT, check_output
from lib.grafcetdeploy import grafcet
if sys.platform.startswith('linux') or sys.platform.startswith('darwin'):
    import grp
    import pwd
elif sys.platform.startswith('win'):
    import win32net

import tempfile
plugin = {"VERSION" : "1.05", "NAME" : "qdeploy", "VERSIONAGENT" : "2.0.0", "TYPE" : "machine"}

logger = logging.getLogger()
DEBUGPULSEPLUGIN = 25
"""
Plugin for deploying a package
"""
def action( objectxmpp, action, sessionid, data, message, dataerreur):
    strjidagent = str(objectxmpp.boundjid.bare)
    if objectxmpp.config.agenttype in ['machine']:
        # transfert terminer libere slot
        restitution_slot_QD = { "action" : "slot_quickdeploy_count",
                                "data" : { "subaction" : "restitution" ,
                                           "sessionid" : sessionid },
                                "sessionid" : sessionid,
                                "ret" : 0 }
        objectxmpp.send_message( mto = message['from'] ,
                                 mbody = json.dumps(restitution_slot_QD),
                                 mtype = 'chat')
        # install le package
        # creation du repertoire pour mettre le package.
        logger.debug("%s"%json.dumps(data, indent=4))
        if 'namepackage' in data:
            namefolder = data['namepackage']
        elif 'descriptor' in data and 'path' in data['descriptor']:
            namefolder = os.path.basename(data['descriptor']['path'])
        elif 'descriptor' in data and 'info' in data['descriptor'] and \
                 'packageUuid' in data['descriptor']['info']:
            namefolder = data['descriptor']['info']['packageUuid']
        elif 'path'  in data:
            namefolder = os.path.basename(data['path'])
        else:
            logger.error("Error name folder")
            #to do send message de fin de deployement sur error
            return
        #creation session
        datasend = {  'action': "applicationdeploymentjson",
                      'sessionid': sessionid,
                      'data' :  data['descriptor'],
                      'ret' : 0,
                      'base64' : False}
        packagedir = os.path.join( managepackage.packagedir(), namefolder)
        logger.debug("packagedir %s"%packagedir)
        ###"filebase64":
        filetmp =  os.path.join(tempfile.gettempdir(), "%s.gz"%namefolder)
        # ecrit file gz
        logger.debug("create file %s"%filetmp)
        objectxmpp.xmpplog('<span class="log_ok">Transfer complete</span>',
                        type = 'deploy',
                        sessionname = sessionid,
                        priority = -1,
                        action = "xmpplog",
                        who = strjidagent,
                        module = "Deployment| Notify | Transfer",
                        date = None ,
                        fromuser = datasend['data']['advanced']['login'])
        with open(filetmp, 'wb') as f:
            f.write(base64.b64decode(data['filebase64']))
        if extract_file(filetmp, to_directory = managepackage.packagedir(), compresstype="gz"):
            objectxmpp.xmpplog('Package extraction successful',
                        type = 'deploy',
                        sessionname = sessionid,
                        priority = -1,
                        action = "xmpplog",
                        who = strjidagent,
                        module = "Deployment| Notify | Transfer",
                        date = None ,
                        fromuser = datasend['data']['advanced']['login'])
        else:
            objectxmpp.xmpplog('<span class="log_err">Package execution cancelled: extraction error</span>',
                    type = 'deploy',
                    sessionname = sessionid,
                    priority = -1,
                    action = "xmpplog",
                    who = strjidagent,
                    module = "Deployment| Notify | Transfer",
                    date = None ,
                    fromuser = datasend['data']['advanced']['login'])
            objectxmpp.xmpplog('DEPLOYMENT TERMINATE',
                    type = 'deploy',
                    sessionname = sessionid,
                    priority = -1,
                    action = "xmpplog",
                    who = strjidagent,
                    module = "Deployment| Notify | ABORT",
                    date = None ,
                    fromuser = datasend['data']['advanced']['login'])
            return
        if os.path.exists(filetmp):
            os.remove(filetmp)

        datasend['data']['pathpackageonmachine'] = os.path.join( managepackage.packagedir(),
                                                                 namefolder )
        # on prepare sequence en fonction de l'os.
        if not cleandescriptor(datasend['data']):
            objectxmpp.xmpplog('<span class="log_err">Descriptor error: This package is not intended for the OS of the machine. %s</span>'%sys.platform,
                        type = 'deploy',
                        sessionname = sessionid,
                        priority = -1,
                        action = "xmpplog",
                        who = strjidagent,
                        module = "Deployment| Notify | BadOS",
                        date = None ,
                        fromuser = datasend['data']['advanced']['login'])
            objectxmpp.xmpplog('DEPLOYMENT TERMINATE',
                        type = 'deploy',
                        sessionname = sessionid,
                        priority = -1,
                        action = "xmpplog",
                        who = strjidagent,
                        module = "Deployment | Notify | BadOS",
                        date = None ,
                        fromuser = datasend['data']['advanced']['login'])
            return
        logger.debug("package sequence : %s"%json.dumps(datasend, indent=4))

        objectxmpp.session.createsessiondatainfo(sessionid,
                                                 datasession =  datasend['data'],
                                                 timevalid = 180)
        try:
            initialisesequence(datasend, objectxmpp, sessionid )
        except Exception as e:
            objectxmpp.xmpplog('<span class="log_err">Error initializing grafcet %s</span>'%str(e),
                        type = 'deploy',
                        sessionname = sessionid,
                        priority = -1,
                        action = "xmpplog",
                        who = strjidagent,
                        module = "Deployment | Notify",
                        date = None ,
                        fromuser = datasend['data']['advanced']['login'])
            objectxmpp.xmpplog('DEPLOYMENT TERMINATE',
                        type = 'deploy',
                        sessionname = sessionid,
                        priority = -1,
                        action = "xmpplog",
                        who = strjidagent,
                        module = "Deployment | Notify",
                        date = None ,
                        fromuser = datasend['data']['advanced']['login'])
            return
        #grafcet(objectxmpp,datasend) #grafcet will use the session
        logger.debug("outing graphcet phase1")

def cleandescriptor(datasend):
    if sys.platform.startswith('linux'):
        try:
            del datasend['descriptor']['win']
        except KeyError:
            pass
        try:
            del datasend['descriptor']['mac']
        except KeyError:
            pass
        try:
            datasend['descriptor']['sequence'] = datasend['descriptor']['linux']['sequence']
            del datasend['descriptor']['linux']
            logger.debug("datasend is cleandescriptor %s"%json.dumps(datasend, indent=4))
        except:
            return False

    elif sys.platform.startswith('win'):
        try:
            del datasend['descriptor']['linux']
        except KeyError:
            pass
        try:
            del datasend['descriptor']['mac']
        except KeyError:
            pass
        try:
            datasend['descriptor']['sequence'] = datasend['descriptor']['win']['sequence']
            #del datasend['descriptor']['win']['sequence']
            del datasend['descriptor']['win']
        except:
            return False
    elif sys.platform.startswith('darwin'):
        try:
            del datasend['descriptor']['linux']
        except KeyError:
            pass
        try:
            del datasend['descriptor']['win']
        except KeyError:
            pass
        try:
            datasend['descriptor']['sequence'] = datasend['descriptor']['mac']['sequence']
            #del datasend['descriptor']['Macos']['sequence']
            del datasend['descriptor']['mac']
        except:
            return False
    datasend['typeos'] = sys.platform
    return True



def initialisesequence(datasend, objectxmpp, sessionid ):
    strjidagent = str(objectxmpp.boundjid.bare)
    datasend['data']['stepcurrent'] = 0 #step initial
    if not objectxmpp.session.isexist(sessionid):
        logger.debug("creation session %s"%sessionid)
        objectxmpp.session.createsessiondatainfo(sessionid,  datasession = datasend['data'], timevalid = 180)
        logger.debug("update object backtodeploy")
    logger.debug("start call grafcet (initiation)")
    objectxmpp.xmpplog('Starting package execution : %s'%datasend['data']['name'],
                        type = 'deploy',
                        sessionname = sessionid,
                        priority = -1,
                        action = "xmpplog",
                        who = strjidagent,
                        module = "Deployment| Notify | Execution | Scheduled",
                        date = None ,
                        fromuser = datasend['data']['advanced']['login'])

    logger.debug("start call grafcet (initiation)")
    if 'data' in datasend and \
                'descriptor' in datasend['data'] and \
                'path' in datasend['data'] and \
                "info" in datasend['data']['descriptor'] and \
                "launcher" in  datasend['data']['descriptor']['info']:
        try:
            id_package = os.path.basename(datasend['data']['path'])
            if id_package != "":
                name = datasend['data']['name']
                commandlauncher = base64.b64decode(datasend['data']['descriptor']['info']['launcher'])
                objectxmpp.infolauncherkiook.set_cmd_launch(id_package, commandlauncher)
                #addition correspondance name et idpackage.
                if name != "":
                    objectxmpp.infolauncherkiook.set_ref_package_for_name(name, id_package)
                    objectxmpp.xmpplog("Launcher command for kiosk [%s] - [%s] -> [%s]"%(commandlauncher, name, id_package),
                                type = 'deploy',
                                sessionname = datasend['sessionid'],
                                priority = -1,
                                action = "xmpplog",
                                who = strjidagent,
                                module = "Deployment | Kiosk",
                                date = None ,
                                fromuser = str(datasend['data']['advanced']['login']))
                else:
                    logger.warning("nanme missing for info launcher command of kiosk")
            else:
                logger.warning("id package missing for info launcher command of kiosk")
        except:
            logger.error("launcher command of kiosk")
            traceback.print_exc(file=sys.stdout)
    else:
        logger.warning("launcher command missing for kiosk")
    grafcet(objectxmpp, datasend)
    logger.debug("outing graphcet end initiation")
