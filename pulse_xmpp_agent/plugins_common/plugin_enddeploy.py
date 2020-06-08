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
# file : plugin_enddeploy.py

import logging
from lib.utils import simplecommand, encode_strconsole, _path_packagequickaction
import time

import os
import json
plugin = {"VERSION" : "1.5", "NAME" : "enddeploy",  "TYPE" : "all"}

logger = logging.getLogger()

def action( objectxmpp, action, sessionid, data, message, dataerreur):
    logging.getLogger().debug("###################################################")
    logging.getLogger().debug("call %s from %s session id %s"%( plugin, message['from'], sessionid))
    logging.getLogger().debug("###################################################")
    if objectxmpp.config.agenttype in ['relayserver']:
        try:
            objectxmpp.mutexslotquickactioncount.acquire()
            #convention 1 ban
            pathfile = _path_packagequickaction()
            filedeploy = [x for x in os.listdir(pathfile) if x.endswith("QDeploy")]
            logging.getLogger().debug("filedeploy %s"%filedeploy)
            ## remove all pool files
            for filledeployement in filedeploy:
                tabfile = filledeployement.split('@_@_@')
                idmachine = tabfile[1]
                sessionfile = tabfile[0]
                # charge fichier dans  msgstruct
                try:
                    if sessionid == sessionfile:
                        os.remove(os.path.join(pathfile, filledeployement))
                        res = simplecommand("ls %s | wc -l"%os.path.join(_path_packagequickaction(),"*.QDeploy"))
                        if res['code'] == 0:
                            nbpool = res['result']
                        else:
                            nbpool = "????"
                        objectxmpp.xmpplog( "<span class='log_err'>ABORT DEPLOYMENT CANCELLED BY USER</span>\n " \
                                            "Deleting deployment %s from queue %s : %s"%(sessionid,
                                                            str(objectxmpp.boundjid.bare),
                                                            nbpool ),
                                            type = 'deploy',
                                            sessionname = sessionid,
                                            priority = -1,
                                            action = "xmpplog",
                                            who = str(objectxmpp.boundjid.bare),
                                            module = "Deployment | Qdeploy | Notify",
                                            date = None ,
                                            fromuser = data['login'])
                        break
                except:
                    pass
        finally:
            objectxmpp.mutexslotquickactioncount.release()

        if objectxmpp.session.isexist(sessionid):
            datesession = objectxmpp.session.sessionfromsessiondata(sessionid).getdatasession()
            result = simplecommand(encode_strconsole("netstat -tpn | grep -v tcp6 | grep -v sshd | grep ssh | grep ESTABLISHED | grep '%s'"%datesession['ipmachine']))
            if result['code'] == 0:
                # termine ssh connection to AM
                for connection_ssh in result['result']:
                    parameterconnection = [ x for x in connection_ssh.split(" ") if x != ""]
                    if "ssh" in parameterconnection[6]:
                        processus = parameterconnection[6].split('/')[0]
                        logger.debug("Stopping file transfer %s [package %s] to machine %s"%( datesession['packagefile'],
                                                                                                     datesession['name'],
                                                                                                     datesession['jidmachine'].split("/")[1]))
                        objectxmpp.xmpplog( "Stopping file transfer %s [package %s] to machine %s"%( datesession['packagefile'],
                                                                                                     datesession['name'],
                                                                                                     datesession['jidmachine'].split("/")[1]),
                                            type = 'deploy',
                                            sessionname = sessionid,
                                            priority = -1,
                                            action = "xmpplog",
                                            who = objectxmpp.boundjid.bare,
                                            how = "",
                                            why = "",
                                            module = "Deployment | Transfer | Notify",
                                            date = None ,
                                            fromuser = datesession['login'],
                                            touser = "")
                        result1 = simplecommand(encode_strconsole("kill -6 %s"%processus))
                        if result1['code'] != 0:
                            logger.error(str(result1['result']))
        # add session id pour clear interdiction apres un certain momment
        objectxmpp.banterminate[sessionid] = time.time()
    # add session id pour bloquage message
    objectxmpp.ban_deploy_sessionid_list.add(sessionid)
