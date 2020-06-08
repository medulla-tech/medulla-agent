# -*- coding: utf-8 -*-
#
# (c) 2004-2007 Linbox / Free&ALter Soft, http://linbox.com
# (c) 2007-2009 Mandriva, http://www.mandriva.com/
# (c) 2016 siveo, http://www.siveo.net
#
# $Id$
#
# This file is part of Pulse 2, http://pulse2.mandriva.org
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

""" declare the substitute plugin for deployments"""
# pluginsmastersubstitute/plugin_loaddeployment.py
#
import base64
import traceback
import os
import sys
import json
import logging
from lib.plugins.xmpp import XmppMasterDatabase
from lib.plugins.msc import MscDatabase
from lib.managepackage import managepackage
from lib.managesession import session
from lib.utils import getRandomName, call_plugin, name_random, name_randomplus, file_get_contents, file_put_contents
import ConfigParser
import types
import datetime
#from datetime import datetime
import random
import re
from sleekxmpp import jid
logger = logging.getLogger()


plugin = {"VERSION": "1.0", "NAME": "loaddeployment", "TYPE": "substitute"}

def action(objectxmpp, action, sessionid, data, msg, ret):
    try:
        logger.debug("=====================================================")
        logger.debug("call %s from %s"%(plugin, msg['from']))
        logger.debug("=====================================================")
        compteurcallplugin = getattr(objectxmpp, "num_call%s"%action)

        if compteurcallplugin == 0:
            read_conf_loaddeployment(objectxmpp)
        ## must list plugin substitute for deploy
        ### wakeonlan, wakeonlangroup, deploysyncthing, resultenddeploy,
        # ___________________ code  _____________________

        # _______________________________________________
    except Exception as e:
        logger.error("machine info %s\n%s" % (str(e),traceback.format_exc()))

def scheduledeploy(self):
    """
        # Set to pause the folders already shared into the ars.
        # Clean the syncthing deployments.
        # Search all the syncthing deployment done
        # and clean into the network and the machines
    """
    # Firstly we replace the current rule by a new one.
    # 2 transfers done limit the ARS bandwidth.
    # Be aware of the new's deploy creation, its remove the limite rate.
    # TODO
    # If 1 package is in pending state, then the limit rate is removed.
    ###########################################################################
    msg=[]
    list_ars_syncthing_pause =  XmppMasterDatabase().get_ars_for_pausing_syncthing(2)
    for arssyncthing in list_ars_syncthing_pause:
        datasend = {  "action" : "deploysyncthing",
                        "sessionid" : name_random(5, "pausesyncthing"),
                        "data" : {  "subaction" : "pausefolder",
                                    "folder" : arssyncthing[2]}
                    }
        listars = arssyncthing[1].split(",")
        for arssyncthing in listars:
            self.send_message(  mto=arssyncthing,
                                mbody=json.dumps(datasend),
                                mtype='chat')
    try:
        deploys_to_clean = XmppMasterDatabase().get_syncthing_deploy_to_clean()
        if type(deploys_to_clean) is list:
            for deploydata in deploys_to_clean:
                ars = XmppMasterDatabase().get_list_ars_from_cluster(deploydata['numcluster'])
                datasend = {"action" : "deploysyncthing",
                            "sessionid" : name_random(5, "cleansyncthing"),
                            "data" : {  "subaction" : "cleandeploy",
                                        "iddeploy" : deploydata['directory_tmp'],
                                        "jidmachines" : deploydata['jidmachines'],
                                        "jidrelays" : deploydata['jidrelays'] } }
                for relay in ars:
                    self.send_message(  mto=relay['jid'],
                                        mbody=json.dumps(datasend),
                                        mtype='chat')
                XmppMasterDatabase().refresh_syncthing_deploy_clean(deploydata['id'])
    except Exception:
        pass
    listobjnoexist = []
    listobjsupp = []
    #search deploy to rumming
    resultdeploymachine = MscDatabase().deployxmpp()

    for deployobject in resultdeploymachine:
        # creation deployment
        UUID = deployobject['UUID']
        resultpresence = XmppMasterDatabase().getPresenceExistuuids(UUID)
        if resultpresence[UUID][1] == 0:
            sessiondeployementless = name_random(5, "missingagent")
            listobjnoexist.append(deployobject)
            # incrition dans deploiement cette machine sans agent
            XmppMasterDatabase().adddeploy(deployobject['commandid'],
                                            deployobject['name'],
                                            deployobject['name'],
                                            deployobject['name'],
                                            UUID,
                                            deployobject['login'],
                                            "ABORT MISSING AGENT",
                                            sessiondeployementless,
                                            user=deployobject['login'],
                                            login=deployobject['login'],
                                            title=deployobject['title'],
                                            group_uuid=deployobject['GUID'],
                                            startcmd=deployobject['start_date'],
                                            endcmd=deployobject['end_date'],
                                            macadress=deployobject['mac'],
                                            result = "",
                                            syncthing = 0)

            msg.append("<span class='log_err'>Agent missing on machine %s. " \
                        "Deployment impossible : GLPI ID is %s</span>"%(deployobject['name'],
                                                                            UUID))
            msg.append("Action : Check that the machine "\
                "agent is working, or install the agent on the"\
                    " machine %s (%s) if it is missing."%(deployobject['name'],
                                                                    UUID))
            for logmsg in msg:
                self.xmpplog(logmsg,
                            type='deploy',
                            sessionname=sessiondeployementless,
                            priority=-1,
                            action="xmpplog",
                            why=self.boundjid.bare,
                            module="Deployment | Start | Creation",
                            date=None,
                            fromuser=deployobject['login'])
            continue

        if datetime.datetime.now() < deployobject['start_date']:
            deployobject['wol'] = 2 #
        else:
            if resultpresence[UUID][0] == 1:
                # If a machine is present, add deployment in deploy list to manage.
                deployobject['wol'] = 0
            else:
                deployobject['wol'] = 1
        try:
            self.machineDeploy[UUID].append(deployobject)
        except:
            #creation list deployement
            self.machineDeploy[UUID] = []
            self.machineDeploy[UUID].append(deployobject)

    listobjsupp = []
    nbdeploy=len(self.machineDeploy)
    for deployuuid in self.machineDeploy:
        try:
            deployobject = self.machineDeploy[deployuuid].pop(0)
            listobjsupp.append(deployuuid)
            logging.debug("send deploy on machine %s package %s" %
                            (deployuuid, deployobject['pakkageid']))
            self.applicationdeployjsonUuidMachineAndUuidPackage(deployuuid,
                                                                deployobject['pakkageid'],
                                                                deployobject['commandid'],
                                                                deployobject['login'],
                                                                30,
                                                                encodebase64=False,
                                                                start_date=deployobject['start_date'],
                                                                end_date=deployobject['end_date'],
                                                                title=deployobject['title'],
                                                                macadress=deployobject['mac'],
                                                                GUID=deployobject['GUID'],
                                                                nbdeploy=nbdeploy,
                                                                wol=deployobject['wol'])
        except Exception:
            listobjsupp.append(deployuuid)
        if deployobject['wol'] == 1:
            listmacadress = [x.strip() for x in deployobject['mac'].split("||")]
            for macadressdata in listmacadress:
                self._addsetwol(self.wolglobal_set, macadressdata)
    self.wolglobal_set.discard("")
    if len(self.wolglobal_set):
        self._sendwolgroup(self.wolglobal_set)
    self.wolglobal_set.clear()
    for objsupp in listobjsupp:
        try:
            del self.machineDeploy[objsupp]
        except Exception:
            pass


def scheduledeployrecoveryjob(self):
    msglog=[]
    wol_set = set()
    try:
        # machine ecart temps de deploiement terminer met status a ABORT ON TIMEOUT
        result = XmppMasterDatabase().Timeouterrordeploy()
        for machine in result:
            hostnamemachine=machine['jidmachine'].split('@')[0][:-4]
            msglog.append("<span class='log_err'>Deployment timed out on machine %s</span>"%hostnamemachine)
            msglog.append("<span class='log_err'>Machine is no longer available</span>")
        for logmsg in msglog:
            self.xmpplog(logmsg,
                        type='deploy',
                        sessionname=machine['sessionid'],
                        priority=-1,
                        action="xmpplog",
                        why=self.boundjid.bare,
                        module="Deployment | Start | Creation",
                        date=None,
                        fromuser=machine['login'])
        msglog=[]
        #########################################################################
        machines_scheduled_deploy = XmppMasterDatabase().search_machines_from_state("DEPLOY TASK SCHEDULED")
        for machine in machines_scheduled_deploy:
            ##datetime_startcmd = datetime.strptime(machine['startcmd'], '%Y-%m-%d %H:%M:%S')
            ##datetime_endcmd = datetime.strptime(machine['startcmd'], '%Y-%m-%d %H:%M:%S')
            UUID = machine['inventoryuuid']

            resultpresence = XmppMasterDatabase().getPresenceExistuuids(UUID)
            if resultpresence[UUID][1] == 0:
                # la machine n'est plus dans la table machine
                ### voir le message a afficher.
                # cas on 1 deployement est cheduler.
                # et la machine n'existe plus. soit son uuid GLPI a changer, ou elle a ete suprimer. la machine n'existe plus.
                msglog.append("<span class='log_err'>Machine %s disappeared "\
                    "during deployment. GLPI ID: %s</span>"%(machine['jidmachine'], UUID))
                XmppMasterDatabase().update_state_deploy(machine['id'], "ABORT MACHINE DISAPPEARED")
            elif resultpresence[UUID][0] == 1:
                XmppMasterDatabase().update_state_deploy(machine['id'], "WAITING MACHINE ONLINE")
            else:
                XmppMasterDatabase().update_state_deploy(machine['id'], "WOL 3")
        for logmsg in msglog:
            self.xmpplog(logmsg,
                        type='deploy',
                        sessionname=machine['sessionid'],
                        priority=-1,
                        action="xmpplog",
                        why=self.boundjid.bare,
                        module="Deployment | Start | Creation",
                        date=None,
                        fromuser=machine['login'])
        msglog=[]
        ###########################################################################
        machines_wol3 = XmppMasterDatabase().search_machines_from_state("WOL 3")
        for machine in machines_wol3:
            XmppMasterDatabase().update_state_deploy(machine['id'], "WAITING MACHINE ONLINE")
            hostnamemachine=machine['jidmachine'].split('@')[0][:-4]
            msglog.append("Waiting for machine %s to be online"%hostnamemachine)
        for logmsg in msglog:
            self.xmpplog(logmsg,
                        type='deploy',
                        sessionname=machine['sessionid'],
                        priority=-1,
                        action="xmpplog",
                        why=self.boundjid.bare,
                        module="Deployment | Start | Creation",
                        date=None,
                        fromuser=machine['login'])
        msglog=[]
        ###########################################################################
        machines_wol2 = XmppMasterDatabase().search_machines_from_state("WOL 2")
        for machine in machines_wol2:
            if XmppMasterDatabase().getPresenceuuid(machine['inventoryuuid']):
                # recu presence machine.
                XmppMasterDatabase().update_state_deploy(machine['id'], "WAITING MACHINE ONLINE")
                continue
            XmppMasterDatabase().update_state_deploy(machine['id'], "WOL 3")
            hostnamemachine=machine['jidmachine'].split('@')[0][:-4]
            self._addsetwol(wol_set, machine['macadress'])
            msglog.append("Third WOL sent to machine %s"%hostnamemachine)
        for logmsg in msglog:
            self.xmpplog(logmsg,
                        type='deploy',
                        sessionname=machine['sessionid'],
                        priority=-1,
                        action="xmpplog",
                        why=self.boundjid.bare,
                        module="Deployment | Start | Creation",
                        date=None,
                        fromuser=machine['login'])
        msglog=[]
        ###########################################################################
        machines_wol1 = XmppMasterDatabase().search_machines_from_state("WOL 1")
        for machine in machines_wol1:
            if XmppMasterDatabase().getPresenceuuid(machine['inventoryuuid']):
                # recu presence machine.
                XmppMasterDatabase().update_state_deploy(machine['id'], "WAITING MACHINE ONLINE")
                continue
            XmppMasterDatabase().update_state_deploy(machine['id'], "WOL 2")
            hostnamemachine=machine['jidmachine'].split('@')[0][:-4]
            self._addsetwol(wol_set, machine['macadress'])
            #self.sendwol(machine['macadress'], hostnamemachine)

            msglog.append("Second WOL sent to machine %s"%hostnamemachine)
        for logmsg in msglog:
            self.xmpplog(logmsg,
                        type='deploy',
                        sessionname=machine['sessionid'],
                        priority=-1,
                        action="xmpplog",
                        why=self.boundjid.bare,
                        module="Deployment | Start | Creation",
                        date=None,
                        fromuser=machine['login'])
        msglog=[]
        ###########################################################################
        #relance machine off_line to on_line
        machines_waitting_online = XmppMasterDatabase().search_machines_from_state("WAITING MACHINE ONLINE")
        #### on verify si il y a des machines online dans cet ensemble
        for machine in machines_waitting_online:
            #machine WAITING MACHINE ONLINE presente ?
            data = json.loads(machine['result'])
            if XmppMasterDatabase().getPresenceuuid(machine['inventoryuuid']):
                hostnamemachine=machine['jidmachine'].split('@')[0][:-4]
                msg="Machine %s online. Starting deployment"%hostnamemachine
                self.xmpplog(msg,
                            type='deploy',
                            sessionname=machine['sessionid'],
                            priority=-1,
                            action="xmpplog",
                            why=self.boundjid.bare,
                            module="Deployment | Start | Creation",
                            date=None,
                            fromuser=machine['login'])
                XmppMasterDatabase().update_state_deploy(int(machine['id']), "DEPLOYMENT START")
                #"relance deployement on machine online"
                # il faut verifier qu'il y ai 1 groupe deja en syncthing.alors seulement on peut decoder de l'incorporer
                if data['advanced']['grp'] is not None and \
                    'syncthing' in data['advanced'] and \
                        data['advanced']['syncthing'] == 1 and \
                            XmppMasterDatabase().nbsyncthingdeploy(machine['group_uuid'],
                                                                    machine['command']) > 2:
                    msg =  "Starting peer deployment on machine %s" % machine['jidmachine']
                    self.xmpplog(msg,
                                type='deploy',
                                sessionname=machine['sessionid'],
                                priority=-1,
                                action="xmpplog",
                                why=self.boundjid.bare,
                                module="Deployment | Start | Creation",
                                date=None,
                                fromuser=data['login'])
                    XmppMasterDatabase().updatedeploytosyncthing(machine['sessionid'])
                    # call plugin master syncthing
                    ###initialisation deployement syncthing
                    self.callpluginsubstitute("deploysyncthing",
                                                data,
                                                sessionid = machine['sessionid'])
                    self.syncthingdeploy()
                else:
                    datasession = self.session.sessiongetdata(machine['sessionid'])
                    msglog.append("Starting deployment on machine %s from ARS %s" %(machine['jidmachine'],
                                                                            machine['jid_relay']))

                    command = {'action': "applicationdeploymentjson",
                            'base64': False,
                            'sessionid': machine['sessionid'],
                            'data': data}

                    self.send_message(mto= machine['jid_relay'],
                                    mbody=json.dumps(command),
                                    mtype='chat')
                    for logmsg in msglog:
                        self.xmpplog(logmsg,
                                    type='deploy',
                                    sessionname=machine['sessionid'],
                                    priority=-1,
                                    action="xmpplog",
                                    why=self.boundjid.bare,
                                    module="Deployment | Start | Creation",
                                    date=None,
                                    fromuser=machine['login'])
                    msglog=[]
                    if 'syncthing' in data['advanced'] and \
                        data['advanced']['syncthing'] == 1:
                        self.xmpplog("<span class='log_warn'>There are not enough " \
                                        "machines to deploy in peer mode</span>",
                                type='deploy',
                                sessionname=machine['sessionid'],
                                priority=-1,
                                action="xmpplog",
                                why=self.boundjid.bare,
                                module="Deployment | Start | Creation",
                                date=None,
                                fromuser=data['login'])
    except Exception:
        logger.error("%s"%(traceback.format_exc()))
    finally:
        #send wols
        wol_set.discard("")
        if len(wol_set):
            self._sendwolgroup(wol_set)

def applicationdeployjsonUuidMachineAndUuidPackage(self,
                                                    uuidmachine,
                                                    uuidpackage,
                                                    idcommand,
                                                    login,
                                                    time,
                                                    encodebase64=False,
                                                    start_date=None,
                                                    end_date=None,
                                                    macadress=None,
                                                    GUID=None,
                                                    title=None,
                                                    nbdeploy=-1,
                                                    wol=0):
    sessiondeployementless = name_random(5, "arsdeploy")
    msg=[]
    name = managepackage.getnamepackagefromuuidpackage(uuidpackage)
    if name is not None:
        return self.applicationdeployjsonuuid(str(uuidmachine),
                                                str(name),
                                                idcommand,
                                                login,
                                                time,
                                                start_date=start_date,
                                                end_date=end_date,
                                                macadress=macadress,
                                                GUID=GUID,
                                                title=title,
                                                nbdeploy=nbdeploy,
                                                wol=wol)
    else:
        XmppMasterDatabase().adddeploy( idcommand,
                                        "%s____"%uuidmachine,
                                        "package %s"%uuidpackage,
                                        "error_name_package____",
                                        uuidmachine,
                                        title,
                                        "ABORT PACKAGE IDENTIFIER MISSING",
                                        sessiondeployementless,
                                        user=login,
                                        login=login,
                                        title=title,
                                        group_uuid=GUID,
                                        startcmd=start_date,
                                        endcmd=end_date,
                                        macadress=macadress,
                                        result = "",
                                        syncthing = 0)
        msg.append("<span class='log_err'>Package identifier misssing for %s</span>"%uuidpackage)
        msg.append("Action : Check the package %s"%(uuidpackage))
        for logmsg in msg:
            self.xmpplog(logmsg,
                            type='deploy',
                            sessionname=sessiondeployementless,
                            priority=-1,
                            action="xmpplog",
                            why=self.boundjid.bare,
                            module="Deployment | Start | Creation",
                            date=None,
                            fromuser=login)
        logger.warn('%s package name missing'%uuidpackage)
        return False

def applicationdeployjsonuuid(self,
                                uuidmachine,
                                name,
                                idcommand,
                                login,
                                time,
                                encodebase64=False,
                                uuidpackage="",
                                start_date=None,
                                end_date=None,
                                title=None,
                                macadress=None,
                                GUID=None,
                                nbdeploy=-1,
                                wol=0):
    try:
        sessiondeployementless = name_random(5, "arsdeploy")
        msg=[]
        # search group deploy and jid machine
        objmachine = XmppMasterDatabase().getGuacamoleRelayServerMachineUuid(uuidmachine, None)
        jidrelay = objmachine['groupdeploy']
        jidmachine = objmachine['jid']
        keysyncthing = objmachine['keysyncthing']
        if jidmachine != None and jidmachine != "" and jidrelay != None and jidrelay != "":
            # il y a 1 ARS pour le deploiement
            # on regarde si celui-ci est up dans la table machine
            ARSsearch = XmppMasterDatabase().getMachinefromjid(jidrelay)
            if ARSsearch['enabled'] == 0:
                msg.append("<span class='log_err'>ARS %s for deployment is down.</span>"%jidrelay)
                msg.append("Action : Either restart it or rerun the configurator "\
                            "on the machine %s to use another ARS"%(name))
                msg.append("Searching alternative ARS for deployment")
                # il faut recherche si on trouve 1 alternative. dans le cluster
                # on cherche 1 ars disponible et up dans son cluster.
                cluster = XmppMasterDatabase().clusterlistars(enabled=None)
                trouver = False
                for  i in range(1, len(cluster)+1):
                    nbars = len(cluster[i]['listarscluster'])
                    if jidrelay in cluster[i]['listarscluster']:
                        if nbars < 2:
                            msg.append("<span class='log_err'>No alternative ARS found</span>")
                            msg.append("Action : Either restart it or rerun the configurator "\
                                        "on the machine %s to use another ARS"%(name))
                            XmppMasterDatabase().adddeploy(idcommand,
                                                            jidmachine,
                                                            jidrelay,
                                                            name,
                                                            uuidmachine,
                                                            title,
                                                            "ABORT RELAY DOWN",
                                                            sessiondeployementless,
                                                            user=login,
                                                            login=login,
                                                            title=title,
                                                            group_uuid=GUID,
                                                            startcmd=start_date,
                                                            endcmd=end_date,
                                                            macadress=macadress,
                                                            result = "",
                                                            syncthing = 0)
                            for logmsg in msg:
                                self.xmpplog(logmsg,
                                            type='deploy',
                                            sessionname=sessiondeployementless,
                                            priority=-1,
                                            action="xmpplog",
                                            why=self.boundjid.bare,
                                            module="Deployment | Start | Creation",
                                            fromuser=login)
                            logger.error("deploy %s error on machine %s ARS down" % (name, uuidmachine))
                            return False
                        else:
                            cluster[i]['listarscluster'].remove(jidrelay)
                            nbars = len(cluster[i]['listarscluster'])
                            nbint = random.randint(0, nbars-1)
                            arsalternative = cluster[i]['listarscluster'][nbint]

                            msg.append("<span class='log_err'>ARS %s for deployment is "\
                                        "down. Use alternative ARS for deployment %s. ARS "\
                                            " %s must be restarted</span>"%(jidrelay,arsalternative,jidrelay) )
                            jidrelay = arsalternative
                            ARSsearch = XmppMasterDatabase().getMachinefromjid(jidrelay)
                            if ARSsearch['enabled'] == 1:
                                trouver = True
                                break

                if not trouver:
                    sessiondeployementless = name_random(5, "missinggroupdeploy")
                    XmppMasterDatabase().adddeploy(idcommand,
                                                    jidmachine,
                                                    jidrelay,
                                                    name,
                                                    uuidmachine,
                                                    title,
                                                    "ABORT ALTERNATIVE RELAYS DOWN",
                                                    sessiondeployementless,
                                                    user=login,
                                                    login=login,
                                                    title=title,
                                                    group_uuid=GUID,
                                                    startcmd=start_date,
                                                    endcmd=end_date,
                                                    macadress=macadress,
                                                    result = "",
                                                    syncthing = 0)
                    msg.append("<span class='log_err'>Alternative ARS Down</span>")
                    msg.append("Action : check ARS cluster.")
                    for logmsg in msg:
                        self.xmpplog(logmsg,
                                    type='deploy',
                                    sessionname=sessiondeployementless,
                                    priority=-1,
                                    action="xmpplog",
                                    why=self.boundjid.bare,
                                    module="Deployment | Start | Creation",
                                    fromuser=login)
                    logger.error("deploy error cluster ARS")
                    return False
            else:
                trouver = True
            #run deploiement
            return self.applicationdeploymentjson(jidrelay,
                                                    jidmachine,
                                                    idcommand,
                                                    login,
                                                    name,
                                                    time,
                                                    encodebase64=False,
                                                    uuidmachine=uuidmachine,
                                                    start_date=start_date,
                                                    end_date=end_date,
                                                    title=title,
                                                    macadress=macadress,
                                                    GUID=GUID,
                                                    keysyncthing = keysyncthing,
                                                    nbdeploy=nbdeploy,
                                                    wol=wol,
                                                    msg=msg)
        else:
            sessiondeployementless = name_random(5, "missinggroupdeploy")
            XmppMasterDatabase().adddeploy(idcommand,
                                            jidmachine,
                                            jidrelay,
                                            name,
                                            uuidmachine,
                                            title,
                                            "ABORT INFO RELAY MISSING",
                                            sessiondeployementless,
                                            user=login,
                                            login=login,
                                            title=title,
                                            group_uuid=GUID,
                                            startcmd=start_date,
                                            endcmd=end_date,
                                            macadress=macadress,
                                            result = "",
                                            syncthing = 0)
            msg.append("<span class='log_err'>ARS for deployment is missing for machine %s </span>"%uuidmachine)
            msg.append("Action : The configurator must be restarted on the machine.")
            for logmsg in msg:
                self.xmpplog(logmsg,
                            type='deploy',
                            sessionname=sessiondeployementless,
                            priority=-1,
                            action="xmpplog",
                            why=self.boundjid.bare,
                            module="Deployment | Start | Creation",
                            fromuser=login)
            logger.error("deploy %s error on machine %s" % (name, uuidmachine))
            return False
    except:
        logger.error("%s" % (traceback.format_exc()))
        logger.error("deploy %s error on machine %s" % (name, uuidmachine))
        XmppMasterDatabase().adddeploy( idcommand,
                                        jidmachine,
                                        jidrelay,
                                        name,
                                        uuidmachine,
                                        title,
                                        "ERROR UNKNOWN ERROR",
                                        sessiondeployementless,
                                        user=login,
                                        login=login,
                                        title=title,
                                        group_uuid=GUID,
                                        startcmd=start_date,
                                        endcmd=end_date,
                                        macadress=macadress,
                                        result = "",
                                        syncthing = 0)
        msg.append("<span class='log_err'>Error creating deployment on machine %s "\
                "[%s]</span>"%(name, uuidmachine))
        for logmsg in msg:
            self.xmpplog(logmsg,
                        type='deploy',
                        sessionname=sessiondeployementless,
                        priority=-1,
                        action="xmpplog",
                        why=self.boundjid.bare,
                        module="Deployment | Start | Creation",
                        fromuser=login)
        return False



def applicationdeploymentjson(self,
                                jidrelay,
                                jidmachine,
                                idcommand,
                                login,
                                name,
                                time,
                                encodebase64=False,
                                uuidmachine="",
                                start_date=None,
                                end_date=None,
                                title=None,
                                macadress=None,
                                GUID=None,
                                keysyncthing = "",
                                nbdeploy=-1,
                                wol=0,
                                msg=[]):
    """ For a deployment
    1st action: synchronizes the previous package name
    The package is already on the machine and also in relay server.
    """
    sessiondeployementless = name_random(5, "arsdeploy")
    if managepackage.getversionpackagename(name) is None:
        logger.error("deploy %s error package name version missing" % (name))
        msg.append("<span class='log_err'>Package name or version missing for %s</span>"%(name))
        msg.append("Action : check the package %s"%name)
        XmppMasterDatabase().adddeploy(idcommand,
                                        jidmachine,
                                        jidrelay,
                                        name,
                                        uuidmachine,
                                        title,
                                        "ABORT PACKAGE VERSION MISSING",
                                        sessiondeployementless,
                                        user=login,
                                        login=login,
                                        title=title,
                                        group_uuid=GUID,
                                        startcmd=start_date,
                                        endcmd=end_date,
                                        macadress=macadress,
                                        result = "",
                                        syncthing = 0)
        for logmsg in msg:
            self.xmpplog(logmsg,
                        type='deploy',
                        sessionname=sessiondeployementless,
                        priority=-1,
                        action="xmpplog",
                        why=self.boundjid.bare,
                        module="Deployment | Start | Creation",
                        fromuser=login)
        return False
    # Name the event
    path = managepackage.getpathpackagename(name)
    if path is None:
        msg.append("<span class='log_err'>Package name missing in package %s</span>"%(name))
        msg.append("Action : check the package %s"%(name))
        XmppMasterDatabase().adddeploy(idcommand,
                                        jidmachine,
                                        jidrelay,
                                        name,
                                        uuidmachine,
                                        title,
                                        "ABORT PACKAGE NAME MISSING",
                                        sessiondeployementless,
                                        user=login,
                                        login=login,
                                        title=title,
                                        group_uuid=GUID,
                                        startcmd=start_date,
                                        endcmd=end_date,
                                        macadress=macadress,
                                        result = "",
                                        syncthing = 0)
        for logmsg in msg:
            self.xmpplog(logmsg,
                        type='deploy',
                        sessionname=sessiondeployementless,
                        priority=-1,
                        action="xmpplog",
                        why=self.boundjid.bare,
                        module="Deployment | Start | Creation",
                        fromuser=login)
        logger.error("package Name missing (%s)" % (name))
        return False
    descript = managepackage.loadjsonfile(os.path.join(path, 'xmppdeploy.json'))

    self.parsexmppjsonfile(os.path.join(path, 'xmppdeploy.json'))
    if descript is None:
        XmppMasterDatabase().adddeploy(idcommand,
                                        jidmachine,
                                        jidrelay,
                                        name,
                                        uuidmachine,
                                        title,
                                        "ABORT DESCRIPTOR MISSING",
                                        sessiondeployementless,
                                        user=login,
                                        login=login,
                                        title=title,
                                        group_uuid=GUID,
                                        startcmd=start_date,
                                        endcmd=end_date,
                                        macadress=macadress,
                                        result = "",
                                        syncthing = 0)
        msg.append("<span class='log_err'>Descriptor xmppdeploy.json " \
                    "missing for %s [%s]</span>"%(name, uuidmachine))
        msg.append("Action : Find out why xmppdeploy.json file is missing.")
        for logmsg in msg:
            self.xmpplog(logmsg,
                        type='deploy',
                        sessionname=sessiondeployementless,
                        priority=-1,
                        action="xmpplog",
                        why=self.boundjid.bare,
                        module="Deployment | Start | Creation",
                        fromuser=login)
        logger.error("deploy %s on %s  error : xmppdeploy.json missing" % (name, uuidmachine))
        return False
    objdeployadvanced = XmppMasterDatabase().datacmddeploy(idcommand)

    if jidmachine != None and jidmachine != "" and jidrelay != None and jidrelay != "":
        userjid=jid.JID(jidrelay).user
        iprelay = XmppMasterDatabase().ipserverARS(userjid)[0]
        ippackageserver =   XmppMasterDatabase().ippackageserver(userjid)[0]
        portpackageserver = XmppMasterDatabase().portpackageserver(userjid)[0]
    else:
        iprelay = ""
        ippackageserver =   ""
        portpackageserver = ""
        wol = 3
    data = {"name": name,
            "login": login,
            "idcmd": idcommand,
            "advanced": objdeployadvanced,
            "stardate" : self.totimestamp(start_date),
            "enddate" : self.totimestamp(end_date),
            'methodetransfert': 'pushrsync',
            "path": path,
            "packagefile": os.listdir(path),
            "jidrelay": jidrelay,
            "jidmachine": jidmachine,
            "jidmaster": self.boundjid.bare,
            "iprelay":  iprelay,
            "ippackageserver": ippackageserver,
            "portpackageserver":  portpackageserver,
            "ipmachine": XmppMasterDatabase().ipfromjid(jidmachine, None)[0],
            "ipmaster": self.config.Server,
            "Dtypequery": "TQ",
            "Devent": "DEPLOYMENT START",
            "uuid": uuidmachine,
            "descriptor": descript,
            "transfert": True,
            "nbdeploy" : nbdeploy
            }
    #TODO on verify dans la table syncthing machine
    # si il n'y a pas un partage syncthing en cour pour cette machine
    # si c'est la cas on ignore cette machine car deja en deploy.
    #res = XmppMasterDatabase().deploy_machine_partage_exist( jidmachine,
                                    #descript['info']['packageUuid'])
    #if len(res) > 0:
        #print "il existe 1 deployement de ce package [%s]"\
            #"sur la machine [%s]"%(descript['info']['packageUuid'],
                                    #jidmachine)
        #logger.debug("il existe 1 deployement de ce package [%s]"\
            #"sur la machine [%s]"%(descript['info']['packageUuid'],
                                    #jidmachine))
        #return

    # todo rattacher 1 deployement d'un package d'une machine si partage syncthing sur cluster existe deja pour d'autre machines.
    # res = XmppMasterDatabase().getnumcluster_for_ars(jidrelay)

    ###### ici on peut savoir si c'est 1 groupe et si syncthing est demande
    if wol == 3:
        state="GROUP DEPLOY MISSING"
        data['wol'] = 2
        data['mac'] = macadress #use macadress for WOL
        sessionid = self.createsessionfordeploydiffered(data)
        result = json.dumps(data, indent = 4)
        msg.append("Machine %s is ready for deployment" % jidmachine)
    if wol == 2:
        state="DEPLOY TASK SCHEDULED"
        data['wol'] = 2
        data['mac'] = macadress #use macadress for WOL
        sessionid = self.createsessionfordeploydiffered(data)
        result = json.dumps(data, indent = 4)
        msg.append("Machine %s is ready for deployment" % jidmachine)
    elif wol == 1:
        state = "WOL 1"
        data['wol'] = 1
        data['mac'] = macadress #use macadress for WOL
        sessionid = self.createsessionfordeploydiffered(data)
        result = json.dumps(data, indent = 4)
        msg.append("Machine %s online" % jidmachine)
        msg.append("First WOL sent to machine %s" % uuidmachine)
    else:
        state = "DEPLOYMENT START"
        data['wol'] = 0
        #data['advanced']['syncthing'] = 1
        if data['advanced']['grp'] != None and \
            'syncthing' in data['advanced'] and \
            data['advanced']['syncthing'] == 1 and \
                nbdeploy > 2:
            # deploiement avec syncthing
            # call plugin preparesyncthing on master or assesseur master
            # addition session
            # send deploy descriptor to machine
            sessionid = self.send_session_command( jidmachine,
                                                "deploysyncthing",
                                                data,
                                                datasession=None,
                                                encodebase64=False,
                                                prefix = "command")
            #state = "DEPLOYMENT SYNCTHING"
            result = json.dumps(data, indent = 4)
            msg.append("Starting peer deployment on machine %s" % jidmachine)
        else:
            msg.append("Starting deployment on machine %s from ARS %s" % (jidmachine,jidrelay))
            if data['advanced']['syncthing'] == 1:
                msg.append("<span class='log_warn'>There are not enough machines " \
                            "to deploy in peer mode</span>")

            data['advanced']['syncthing'] = 0
            result = None
            sessionid = self.send_session_command(jidrelay,
                                                "applicationdeploymentjson",
                                                data,
                                                datasession=None,
                                                encodebase64=False,
                                                prefix = "command")
    if wol >= 1:
        avacedpara = 0
    else:
        avacedpara = data['advanced']['syncthing']
    for msglog in msg:
        self.xmpplog(msglog,
                    type='deploy',
                    sessionname=sessionid,
                    priority=-1,
                    action="xmpplog",
                    why=self.boundjid.bare,
                    module="Deployment | Start | Creation",
                    date=None,
                    fromuser=data['login'])
    XmppMasterDatabase().adddeploy(idcommand,
                                    jidmachine,
                                    jidrelay,
                                    jidmachine,
                                    uuidmachine,
                                    descript['info']['name'],
                                    state,
                                    sessionid,
                                    user="",
                                    login=login,
                                    title=title,
                                    group_uuid=GUID,
                                    startcmd=start_date,
                                    endcmd=end_date,
                                    macadress=macadress,
                                    result = result,
                                    syncthing = avacedpara)
    if data['advanced']['syncthing'] == 0:
        XmppMasterDatabase().addcluster_resources(jidmachine,
                                                    jidrelay,
                                                    jidmachine,
                                                    sessionid,
                                                    login=login,
                                                    startcmd = start_date,
                                                    endcmd = end_date)
    self.syncthingdeploy()
    return sessionid

def totimestamp(self, dt, epoch=datetime.datetime(1970,1,1)):
    td = dt - epoch
    # return td.total_seconds()
    return (td.microseconds + (td.seconds + td.days * 86400) * 10**6) / 10**6

def syncthingdeploy(self):
    #nanlyse la table deploy et recupere les deployement syncthing.
    iddeploylist = XmppMasterDatabase().deploysyncthingxmpp()
    if len(iddeploylist)!= 0:
        for iddeploy in iddeploylist:
            # les tables sont create
            # maintenant on appelle le plugin master de syncthing
            data = { "subaction" : "initialisation",
                        "iddeploy" : iddeploy }
            self.callpluginsubstitute("deploysyncthing",
                                            data,
                                            sessionid = name_randomplus(25,
                                            pref="deploysyncthing"))

def callpluginsubstitute(self, plugin, data, sessionid=None):
    if sessionid == None:
        sessionid = getRandomName(5, plugin)
    msg = {}
    msg['from'] = self.boundjid.bare
    msg['body'] = json.dumps({'action': plugin,
                                'ret': 0,
                                'sessionid': sessionid,
                                'data': data})
    self.directcallplugin(msg)

def directcallplugin(self, msg):
    try:
        dataobj = json.loads(msg['body'])
        if dataobj.has_key('action') and dataobj['action'] != "" and dataobj.has_key('data'):
            if dataobj.has_key('base64') and \
                ((isinstance(dataobj['base64'], bool) and dataobj['base64'] is True) or
                    (isinstance(dataobj['base64'], str) and dataobj['base64'].lower() == 'true')):
                mydata = json.loads(base64.b64decode(dataobj['data']))
            else:
                mydata = dataobj['data']
            if not dataobj.has_key('sessionid'):
                dataobj['sessionid'] = "absent"
            if not 'ret' in dataobj:
                dataobj['ret'] = 0
            try:
                logging.debug("Calling plugin %s from  %s" % (dataobj['action'], msg['from']))
                msg['body'] = dataobj
                del dataobj['data']
                dataerreur={ "action" : "result" + dataobj['action'],
                     "data" : { "msg" : "error plugin : " + dataobj['action']},
                     'sessionid' : dataobj['sessionid'],
                     'ret' : 255,
                     'base64' : False}
                module = "%s/plugin_%s.py"%(self.modulepath, dataobj['action'])
                call_plugin(module,
                            self,
                            dataobj['action'],
                            dataobj['sessionid'],
                            mydata,
                            msg,
                            dataerreur)
            except TypeError:
                logging.error("TypeError: executing plugin %s %s" %
                                (dataobj['action'], sys.exc_info()[0]))
                logger.error("%s"%(traceback.format_exc()))

            except Exception as e:
                logging.error("Executing plugin (%s) %s %s" % (msg['from'], dataobj['action'], str(e)))
                logger.error("%s"%(traceback.format_exc()))

    except Exception as e:
        logging.error("Message structure %s   %s " % (msg, str(e)))
        logger.error("%s"%(traceback.format_exc()))

def send_session_command(self, jid, action, data={}, datasession=None, encodebase64=False, time=20, eventthread=None, prefix=None):
    if prefix is None:
        prefix = "command"
    if datasession == None:
        datasession = {}
    command = {'action': action,
                'base64': encodebase64,
                'sessionid': name_randomplus(25, pref=prefix),
                'data': ''
                }
    if encodebase64:
        command['data'] = base64.b64encode(json.dumps(data))
    else:
        command['data'] = data

    datasession['data'] = data
    datasession['callbackcommand'] = "commandend"
    self.sessiondeploysubstitute.createsessiondatainfo(command['sessionid'],
                                        datasession=data,
                                        timevalid=time,
                                        eventend=eventthread)
    if action is not None:
        logging.debug("Send command and creation session")
        if jid == self.boundjid.bare:
            self.callpluginsubstitute(action,
                                        data,
                                        sessionid = command['sessionid'])
        else:
            self.send_message(mto=jid,
                            mbody=json.dumps(command),
                            mtype='chat')
    else:
        logging.debug("creation session")
    return command['sessionid']

def parsexmppjsonfile(self, path):
    ### puts the words False in lowercase.
    datastr = file_get_contents(path)
    datastr = re.sub(r"(?i) *: *false", " : false", datastr)
    datastr = re.sub(r"(?i) *: *true", " : true", datastr)
    file_put_contents(path, datastr)

def _chunklist(self, listseq, nb = 5000):
    nbinlist, rest = divmod(len(listseq), nb)
    avg = len(listseq) / float(nbinlist + 1)
    result = []
    endlist = 0.0
    while endlist < len(listseq):
        result.append(listseq[int(endlist):int(endlist + avg)])
        endlist += avg
    return result

def _sendwolgroup(self, listorset, nb = 5000):
    # on sinde la liste en liste de 5000 mac address maximum
    try:
        listforsplit = self._chunklist(list(listorset), nb)
        listorset.clear()
        for listsend in listforsplit:
            self.callpluginsubstitute('wakeonlangroup',
                                        {'macadress': list(listsend)})
    except Exception:
        logger.error("%s"%(traceback.format_exc()))

def _addsetwol( self, setdata, macadress):
    listmacadress = [x.strip() for x in macadress.split("||")]
    for macadressdata in listmacadress:
        setdata.add(macadressdata)

def handlemanagesession(self):
    self.sessiondeploysubstitute.decrementesessiondatainfo()

def garbagedeploy(self):
    MscDatabase().xmppstage_statecurrent_xmpp()
    XmppMasterDatabase().update_status_deploy_end()

def createsessionfordeploydiffered(self, data):
    sessionid = name_randomplus(25, "command")
    #Calculate maximum duration of a session
    timeseconde = data['enddate'] - data['stardate']
    self.sessiondeploysubstitute.createsessiondatainfo(sessionid,
                                        datasession=data,
                                        timevalid=timeseconde,
                                        eventend=None)
    return sessionid

def read_conf_loaddeployment(objectxmpp):
    # dictionary used for deploy

    objectxmpp.wolglobal_set = set() #use group wol

    # initialise session object
    objectxmpp.sessiondeploysubstitute = session("sessiondeploysubstitute")
    objectxmpp.machineDeploy = {}

    logger.debug("Initialisation plugin :% s "%plugin["NAME"])
    namefichierconf = plugin['NAME'] + ".ini"
    pathfileconf = os.path.join( objectxmpp.config.pathdirconffile, namefichierconf )

    if not os.path.isfile(pathfileconf):
        deployment_end_timeout = 300
        deployment_scan_interval = 30
        wol_interval = 60
        session_check_interval = 15
    else:
        Config = ConfigParser.ConfigParser()
        Config.read(pathfileconf)
        if Config.has_option("parameters", "wol_interval"):
            objectxmpp.wol_interval =  Config.getint('parameters', 'wol_interval')
        else:
            objectxmpp.wol_interval = 60

        if Config.has_option("parameters", "deployment_scan_interval"):
            objectxmpp.deployment_scan_interval =  Config.getint('parameters', 'deployment_scan_interval')
        else:
            objectxmpp.deployment_scan_interval = 30

        if Config.has_option("parameters", "deployment_end_timeout"):
            objectxmpp.deployment_end_timeout =  Config.getint('parameters', 'deployment_end_timeout')
        else:
            objectxmpp.deployment_end_timeout = 300

        if Config.has_option("parameters", "session_check_interval"):
            objectxmpp.session_check_interval =  Config.getint('parameters', 'session_check_interval')
        else:
            objectxmpp.session_check_interval = 15

    # initialisation des object for deployement

    objectxmpp.applicationdeployjsonUuidMachineAndUuidPackage = types.MethodType(applicationdeployjsonUuidMachineAndUuidPackage, objectxmpp)

    objectxmpp.applicationdeployjsonuuid = types.MethodType(applicationdeployjsonuuid, objectxmpp)
    objectxmpp.applicationdeploymentjson = types.MethodType(applicationdeploymentjson, objectxmpp)

    #objectxmpp.affichelog = types.MethodType(affichelog, objectxmpp)

    objectxmpp._chunklist = types.MethodType(_chunklist, objectxmpp)
    objectxmpp._sendwolgroup = types.MethodType(_sendwolgroup, objectxmpp)
    objectxmpp._addsetwol = types.MethodType(_addsetwol, objectxmpp)

    objectxmpp.syncthingdeploy = types.MethodType(syncthingdeploy, objectxmpp)

    objectxmpp.callpluginsubstitute = types.MethodType(callpluginsubstitute, objectxmpp)

    objectxmpp.directcallplugin = types.MethodType(directcallplugin, objectxmpp)

    objectxmpp.createsessionfordeploydiffered = types.MethodType(createsessionfordeploydiffered, objectxmpp)

    objectxmpp.send_session_command = types.MethodType(send_session_command, objectxmpp)

    objectxmpp.totimestamp = types.MethodType(totimestamp, objectxmpp)
    objectxmpp.parsexmppjsonfile = types.MethodType(parsexmppjsonfile, objectxmpp)

    ## declaration function scheduledeploy in object xmpp
    objectxmpp.scheduledeploy = types.MethodType(scheduledeploy, objectxmpp)
    ## schedule function scheduledeploy
    objectxmpp.schedule('check_and_process_deployment',
                    objectxmpp.deployment_scan_interval,
                    objectxmpp.scheduledeploy,
                    repeat=True)

    ## declaration function scheduledeployrecoveryjob in object xmpp
    objectxmpp.scheduledeployrecoveryjob = types.MethodType(scheduledeployrecoveryjob, objectxmpp)
    objectxmpp.schedule('wol_interval',
                        objectxmpp.wol_interval,
                        objectxmpp.scheduledeployrecoveryjob,
                        repeat=True)

    ## declaration function garbagedeploy in object xmpp
    objectxmpp.garbagedeploy = types.MethodType(garbagedeploy, objectxmpp)
    objectxmpp.schedule('deployment_end_timeout',
                        objectxmpp.deployment_end_timeout,
                        objectxmpp.garbagedeploy,
                        repeat=True)

    ## declaration function handlemanagesession in object xmpp
    objectxmpp.handlemanagesession = types.MethodType(handlemanagesession, objectxmpp)
    objectxmpp.schedule('session check',
                        objectxmpp.session_check_interval,
                        objectxmpp.handlemanagesession,
                        repeat=True)
