#!/usr/bin/env python
# -*- coding: utf-8; -*-
#
# (c) 2016-2018 siveo, http://www.siveo.net
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
#
# file pluginsrelay/plugin_slot_quickdeploy_count.py
import os
import json
import logging
import traceback
import time
from lib.utils import _path_packagequickaction
###
logger = logging.getLogger()

plugin = {"VERSION": "1.0", "NAME": "slot_quickdeploy_count", "TYPE": "relayserver"}

def action( objectxmpp, action, sessionid, data, message, dataerreur ):
    logger.debug("#################################################")
    logger.debug(plugin)
    logger.debug(json.dumps(data, indent=4))
    logger.debug("concurent deploy %s"%json.dumps(objectxmpp.concurrentquickdeployments,
                                                 indent=4))
    logger.debug("#################################################")
    strjidagent = str(objectxmpp.boundjid.bare)
    try:
        ts = time.time()
        objectxmpp.mutex.acquire(1)
        try:
            #concurrentquickdeployments list object i { numerodesession : timestamp }
            del objectxmpp.concurrentquickdeployments[sessionid]
            objectxmpp.xmpplog( "free resource quick deploy " \
                                "for (%s) %s concurent/%s"%(sessionid,
                                                            len(objectxmpp.concurrentquickdeployments),
                                                            objectxmpp.config.nbconcurrentquickdeployments),
                                type = 'deploy',
                                sessionname = sessionid,
                                priority = -1,
                                action = "xmpplog",
                                who = strjidagent,
                                module = "Deployment | Qdeploy | Notify",
                                date = None ,
                                fromuser = "")
        except KeyError:
            pass
        supp=[]
        for slot in objectxmpp.concurrentquickdeployments:
            if int(ts - objectxmpp.concurrentquickdeployments[slot]) > 400:
                # rend le slot si time est supérieur a 300
                supp.append(slot)
        for delkey in supp:
            del objectxmpp.concurrentquickdeployments[delkey]
            objectxmpp.xmpplog( "free resource QD tineout for (%s) " \
                                "%s concurent/%s \n Verify nb concurent " \
                                "deploy for size max"%(delkey,
                                                       len(objectxmpp.concurrentquickdeployments),
                                                       objectxmpp.config.nbconcurrentquickdeployments),
                                type = 'deploy',
                                sessionname = sessionid,
                                priority = -1,
                                action = "xmpplog",
                                who = strjidagent,
                                module = "Deployment | Qdeploy | Notify",
                                date = None ,
                                fromuser = "")
    finally:
        objectxmpp.mutex.release()
    nbdeploy = len(objectxmpp.concurrentquickdeployments)
    pathfile = _path_packagequickaction()
    try:
        objectxmpp.mutexslotquickactioncount.acquire()
        # charge les fichiers terminant par QDeploy
        filedeploy = [os.path.join(pathfile, x) for x in os.listdir(pathfile) if x.endswith("QDeploy")]
        if nbdeploy > 0 and \
            nbdeploy < objectxmpp.config.nbconcurrentquickdeployments and \
                len(filedeploy) > 0:
            index = 0
            while len(objectxmpp.concurrentquickdeployments) < objectxmpp.config.nbconcurrentquickdeployments:
                # lancement des déploiements en fichier.
                try:
                    pathnamefile = filedeploy[index]
                    index+=1
                    namefile = os.path.basename(pathnamefile)
                    idmachine = namefile[:-13]
                    # charge fichier dans  msgstruct
                    try:
                        with open(pathnamefile, "r") as file:
                            msgstruct = json.load(file)
                        datadata = msgstruct['data']['descriptor']
                        sessioniddata = msgstruct['sessionid']
                    except:
                        break
                    finally:
                        os.remove(pathnamefile)
                    try:
                        objectxmpp.mutex.acquire(1)
                        objectxmpp.concurrentquickdeployments[sessioniddata]=time.time()
                    finally:
                        objectxmpp.mutex.release()

                    objectxmpp.send_message( mto   = idmachine,
                                             mbody = msgstruct,
                                             mtype = 'chat')
                    objectxmpp.session.createsessiondatainfo(sessioniddata,
                                                             datasession = datadata,
                                                             timevalid = 180)
                except IndexError:
                    break
    finally:
        objectxmpp.mutexslotquickactioncount.release()
