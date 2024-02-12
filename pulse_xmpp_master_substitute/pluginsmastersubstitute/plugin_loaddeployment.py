# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2004-2007 Linbox / Free&ALter Soft, http://linbox.com
# SPDX-FileCopyrightText: 2007-2009 Mandriva, http://www.mandriva.com/
# SPDX-FileCopyrightText: 2016-2023 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-2.0-or-later

""" declare the substitute plugin for deployments"""
import base64
import shutil
import traceback
import os
import sys
import json
import logging
import hashlib
from lib.plugins.xmpp import XmppMasterDatabase
from lib.plugins.msc import MscDatabase
from lib.managepackage import managepackage
from lib.managesession import session, clean_session
from lib.utils import getRandomName, call_plugin, name_random, name_randomplus, file_get_contents, file_put_contents
import ConfigParser
import types
import datetime
import random
import re
from sleekxmpp import jid
import time
import threading

logger = logging.getLogger()

plugin = {"VERSION": "1.4", "NAME": "loaddeployment", "TYPE": "substitute"}

def action(objectxmpp, action, sessionid, data, msg, ret):
    try:
        logger.debug("=====================================================")
        logger.debug("call %s from %s" % (plugin, msg['from']))
        logger.debug("=====================================================")
        compteurcallplugin = getattr(objectxmpp, "num_call%s"%action)

        if compteurcallplugin == 0:
            read_conf_loaddeployment(objectxmpp)
            objectxmpp.process_load_deployment_on=True
        # must list plugin substitute for deploy
        # wakeonlan, wakeonlangroup, deploysyncthing, resultenddeploy,
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

    nb_machine_select_for_deploy_cycle = 0
    datetimenow = datetime.datetime.now()
    startfunc = time.time()
    if not self.process_load_deployment_on:
        logger.warning("We cannot start a new deployment cyle. The previous one is still running.")
        return
    else:
        logger.debug("We start a new deployment cycle of %s computers. Next check in %s seconds" % (self.deployment_nbr_mach_cycle,
                                                                                                    self.deployment_scan_interval))
    try:
        self.process_load_deployment_on = False
        msg = []
        try:
            self.mycompteurcallplugin+=1
            if not self.mycompteurcallplugin % 6:
                list_ars_syncthing_pause = XmppMasterDatabase().get_ars_for_pausing_syncthing()
                for arssyncthing in list_ars_syncthing_pause:
                    datasend = {"action": "deploysyncthing",
                                "sessionid": name_random(5, "pausesyncthing"),
                                "data": {"subaction": "pausefolder",
                                         "folder": arssyncthing[2]}
                                }
                    listars = arssyncthing[1].split(",")
                    for arssyncthing in listars:
                        self.send_message(mto=arssyncthing,
                                        mbody=json.dumps(datasend),
                                        mtype='chat')
                deploys_to_clean = XmppMasterDatabase().get_syncthing_deploy_to_clean()
                if type(deploys_to_clean) is list:
                    for deploydata in deploys_to_clean:
                        ars = XmppMasterDatabase().get_list_ars_from_cluster(deploydata['numcluster'])
                        datasend = {"action": "deploysyncthing",
                                    "sessionid": name_random(5, "cleansyncthing"),
                                    "data": {"subaction": "cleandeploy",
                                             "iddeploy": deploydata['directory_tmp'],
                                             "jidmachines": deploydata['jidmachines'],
                                             "jidrelays": deploydata['jidrelays']}}
                        for relay in ars:
                            self.send_message(mto=relay['jid'],
                                            mbody=json.dumps(datasend),
                                            mtype='chat')
                        XmppMasterDatabase().refresh_syncthing_deploy_clean(deploydata['id'])
        except AttributeError:
            self.mycompteurcallplugin = 0
        except Exception:
            logger.error("We hit the backtrace: \n %s" % (traceback.format_exc()))
        listobjsupp = []
        try:
            # Searching for deployements to start
            logger.debug("Waiting for lock for substitute %s" % (self.boundjid.user))
            nb_machine_select_for_deploy_cycle, resultdeploymachine = MscDatabase().deployxmpp(limitnbr=self.deployment_nbr_mach_cycle,textindicator=self.boundjid.bare)
            logger.debug("Unlock substitute %s" % (self.boundjid.user))
        except Exception as error_while_deploy:
            logger.error("We encountered the following error while trying to deploy: \n %s" % error_while_deploy)
            logger.error("We hit the backtrace: \n %s" % (traceback.format_exc()))
            logger.debug("Unlock substitute %s" % (self.boundjid.user))
            return
        except Exception as e:
            logger.error("We hit the backtrace \n %s" % (traceback.format_exc()))
            logger.debug("Unlock substitute %s" % (self.boundjid.user))
            return
        if nb_machine_select_for_deploy_cycle == 0:
            return

        uuidlist = []
        for deployobject in resultdeploymachine:
            uuidlist.append(deployobject['UUID'])
        resultpresence = XmppMasterDatabase().getPresenceExistuuids(uuidlist)


        for deployobject in resultdeploymachine:
            # creation deployment
            UUID = deployobject['UUID']
            UUIDSTR = UUID.replace('UUID', "")
            re_search = []
            hostname = deployobject['name'].split(".", 1)[0]

            if resultpresence[UUID][1] == 0:
                # There is no GLPI UUID
                re_search = XmppMasterDatabase().getMachinedeployexistonHostname(hostname)
                if self.recover_glpi_identifier_from_name and len(re_search) == 1:
                    update_result = XmppMasterDatabase().update_uuid_inventory(re_search[0]['id'], UUID)
                    if update_result is not None:
                        if update_result.rowcount > 0:
                            logger.info("update uuid inventory %s for machine %s" % (UUID, hostname))
                    resultpresence[UUID][1] = 1
                    reloadresultpresence_uuid = XmppMasterDatabase().getPresenceExistuuids(UUID)
                    resultpresence[UUID] = reloadresultpresence_uuid[UUID]
                    self.xmpplog("Attaching GLPI identifier [%s] in xmppmaster machine [%s]" % (UUID, hostname),
                                type='deploy',
                                sessionname="no_session",
                                priority=-1,
                                action="xmpplog",
                                why=self.boundjid.bare,
                                module="Deployment | Start | Creation| Notify",
                                date=None,
                                fromuser=deployobject['login'])

            if resultpresence[UUID][1] == 0:
                if re_search:
                    msg.append( "<span class='log_err'>Consolidation GLPI XMPP ERROR for machine %s. " \
                                "Deployment impossible : GLPI ID is %s</span>" % (deployobject['name'],
                                                                                    UUIDSTR))
                    for mach in re_search:
                        msg.append( "<span> Action : Please check"\
                            " that mac address or serial is/are properly"\
                                " imported in GLPI: serial (%s) or macs(%s)</span>"% (mach['serial'],
                                                                                    mach['macs']))
                    MSG_ERROR = "ABORT INCONSISTENT GLPI INFORMATION"
                    sessiondeployementless = name_random(5, "glpixmppconsolidationerror")
                else:
                    MSG_ERROR = "ABORT MISSING AGENT"
                    sessiondeployementless = name_random(5, "missingagent")
                    msg.append( "<span class='log_err'>Agent missing on machine %s. " \
                                "Deployment impossible : GLPI ID is %s</span>" % (deployobject['name'],
                                                                                    UUIDSTR))
                    msg.append( "Action : Check that the machine "\
                                "agent is working, or install the agent on the"\
                                " machine %s (%s) if it is missing." % (deployobject['name'],
                                                                        UUIDSTR))

                    logging.warning("No machine found on hostname. You must verify consolidation GLPI with xmpp")
                    logging.warning("INFO\nGLPI : name %s uuid %s " % (deployobject['name'],
                                                                    deployobject['UUID']))
                    logging.warning("INFO\nXMPP : No machine found for %s" % (deployobject['name']))

                # We add a fake entry in the database for the machine w/o agent
                deployobject['name'] = deployobject['name'].split('.')[0]
                XmppMasterDatabase().adddeploy(deployobject['commandid'],
                                            deployobject['name'],
                                            deployobject['name'],
                                            deployobject['name'],
                                            UUID,
                                            deployobject['login'],
                                            MSG_ERROR,
                                            sessiondeployementless,
                                            user=deployobject['login'],
                                            login=deployobject['login'],
                                            title=deployobject['title'],
                                            group_uuid=deployobject['GUID'],
                                            startcmd=deployobject['start_date'],
                                            endcmd=deployobject['end_date'],
                                            macadress=deployobject['mac'],
                                            result="",
                                            syncthing=0)


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


            if datetimenow < deployobject['start_date']:
                deployobject['wol'] = 2
            else:
                if resultpresence[UUID][0] == 1:
                    # If a machine is present, add deployment in deploy list to manage.
                    deployobject['wol'] = 0
                else:
                    deployobject['wol'] = 1
            try:
                self.machineDeploy[UUID].append(deployobject)
            except:
                # creation list deployement
                self.machineDeploy[UUID] = []
                self.machineDeploy[UUID].append(deployobject)

        listobjsupp = []
        nbdeploy=len(self.machineDeploy)
        for deployuuid in self.machineDeploy:
            try:
                deployobject = self.machineDeploy[deployuuid].pop(0)
                listobjsupp.append(deployuuid)
                logging.debug("Sending deployment on machine %s package %s" % (deployuuid,
                                                                        deployobject['pakkageid']))

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
                logger.error("%s" % (traceback.format_exc()))
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
        self.syncthingdeploy()
    except Exception:
        logger.error("%s" % (traceback.format_exc()))
    finally:
        self.process_load_deployment_on = True
        if nb_machine_select_for_deploy_cycle:
            timef = time.time()-startfunc
            logger.info("scheduledeploy : mach %s time %s t/m %s" % (nb_machine_select_for_deploy_cycle,
                                                                    timef,
                                                                    (timef/nb_machine_select_for_deploy_cycle) \
                                                                    if nb_machine_select_for_deploy_cycle else "--" ))

def scheduledeployrecoveryjob(self):
    msglog = []
    wol_set = set()
    try:
        # We set the deploiement as ABORT ON TIMEOUT as the deploy launch window is over.
        result = XmppMasterDatabase().Timeouterrordeploy()
        for machine in result:
            msglog = []
            machine_hostname = machine['jidmachine'].split('@')[0][:-4]
            msglog.append("<span class='log_err'>Deployment timed out on machine %s</span>" % machine_hostname)
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

        machines_scheduled_deploy = XmppMasterDatabase().search_machines_from_state("DEPLOY TASK SCHEDULED")
        for machine in machines_scheduled_deploy:
            msglog = []
            # datetime_startcmd = datetime.strptime(machine['startcmd'], '%Y-%m-%d %H:%M:%S')
            # datetime_endcmd = datetime.strptime(machine['startcmd'], '%Y-%m-%d %H:%M:%S')
            UUID = machine['inventoryuuid']

            resultpresence = XmppMasterDatabase().getPresenceExistuuids(UUID)
            if resultpresence[UUID][1] == 0:
                # la machine n'est plus dans la table machine
                # voir le message a afficher.
                # cas on 1 deployement est cheduler.
                # et la machine n'existe plus. soit son uuid GLPI a changer, ou elle a ete suprimer. la machine n'existe plus.
                msglog.append("<span class='log_err'>Machine %s disappeared "\
                              "during deployment. GLPI ID: %s</span>" % (machine['jidmachine'], UUID))
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

        # Plan with blocked deployments again
        XmppMasterDatabase().restart_blocked_deployments()
        msglog = []
        # We search all the machines that was offline (deploy with state WAITING MACHINE ONLINE)
        machines_waiting_online = XmppMasterDatabase().search_machines_from_state("WAITING MACHINE ONLINE")
        # We check which machines of machines_waiting_online are now online
        for machine in machines_waiting_online:
            logger.debug("Restarting the deployment %s currently in machines_waiting_online state" % machine["sessionid"])
            # ----------------- contrainte slopt partiel-----------------------
            res = MscDatabase().test_deploy_in_partiel_slot( machine['title'])
            if not res:
                # machine avec contrainte slot partiel on est pas dans le slot
                continue
            # -----------------------------------------------------------------
            try:
                data = json.loads(machine['result'])
                if XmppMasterDatabase().getPresenceuuid(machine['inventoryuuid']):
                    machine_hostname=machine['jidmachine'].split('@')[0][:-4]
                    msg = "Machine %s is online. Starting the deployment" % machine_hostname
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
                    # We restart to deploy on online machines
                    # We need to check if there is a syncthing group. Then we can decide to add it.
                    if 'grp' in data['advanced'] and data['advanced']['grp'] is not None and \
                        'syncthing' in data['advanced'] and \
                            data['advanced']['syncthing'] == 1 and \
                                XmppMasterDatabase().nbsyncthingdeploy(machine['group_uuid'],
                                                                    machine['command']) > 2:
                        msg = "Starting peer deployment on machine %s" % machine['jidmachine']
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
                        self.callpluginsubstitute("deploysyncthing",
                                                data,
                                                sessionid=machine['sessionid'])
                    else:
                        datasession = self.sessiondeploysubstitute.sessiongetdata(machine['sessionid'])
                        msglog.append("Starting deployment on machine %s from ARS %s" % (machine['jidmachine'],
                                                                                         machine['jid_relay']))
                        # lance deployment to ars
                        try:
                            if 'jidmachine' in data and data['jidmachine'] != "" :
                                checkChangedJID =  XmppMasterDatabase().update_jid_if_changed(data['jidmachine'] )
                                if checkChangedJID:
                                    if checkChangedJID[0]['jid'] != data['jidmachine']:
                                        logging.warning("Machine JID changed since creation of deployment")
                                        logging.warning("Machine JID %s -> %s"%(data['jidmachine'],checkChangedJID[0]['jid'] ))
                                        logging.warning("Relay server JID %s -> %s"%(data['jidrelay'],checkChangedJID[0]['groupdeploy'] ))
                                        msglog.append("jid machine changed : replace jid mach from %s to %s" % (data['jidmachine'], checkChangedJID[0]['jid']))
                                        msglog.append("replace jid ars from %s to %s" % (data['jidrelay'], checkChangedJID[0]['groupdeploy'] ))
                                        data['jidmachine'] =  checkChangedJID[0]['jid']
                                        data['jidrelay'] =  checkChangedJID[0]['groupdeploy']
                                        XmppMasterDatabase().replace_jid_mach_ars_in_deploy(data['jidmachine'],
                                                                                            data['jidrelay'],
                                                                                            data['title'])

                        except Exception as e:
                            logger.error("%s" % (traceback.format_exc()))
                            logging.error("Error checking for JID changes")

                        command = {'action': "applicationdeploymentjson",
                                   'base64': False,
                                   'sessionid': machine['sessionid'],
                                   'data': data}
                        self.send_message(mto=machine['jid_relay'],
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
                        msglog = []
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
            except:
                if 'sessionid' in machine:
                    XmppMasterDatabase().replaydeploysessionid( machine['sessionid'], force_redeploy=self.force_redeploy, reschedule=self.reschedule)

        msglog = []

        machines_wol3 = XmppMasterDatabase().search_machines_from_state("WOL 3")
        for machine in machines_wol3:
            msglog = []
            XmppMasterDatabase().update_state_deploy(machine['id'], "WAITING MACHINE ONLINE")
            machine_hostname = machine['jidmachine'].split('@')[0][:-4]
            msglog.append("Waiting for machine %s to be online" % machine_hostname)
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

        msglog = []
        machines_wol2 = XmppMasterDatabase().search_machines_from_state("WOL 2")
        for machine in machines_wol2:
            msglog = []
            if XmppMasterDatabase().getPresenceuuid(machine['inventoryuuid']):
                XmppMasterDatabase().update_state_deploy(machine['id'], "WAITING MACHINE ONLINE")
                continue
            XmppMasterDatabase().update_state_deploy(machine['id'], "WOL 3")
            machine_hostname = machine['jidmachine'].split('@')[0][:-4]
            self._addsetwol(wol_set, machine['macadress'])
            msglog.append("Third WOL sent to machine %s" % machine_hostname)
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
        msglog = []

        machines_wol1 = XmppMasterDatabase().search_machines_from_state("WOL 1")
        for machine in machines_wol1:
            msglog = []
            if XmppMasterDatabase().getPresenceuuid(machine['inventoryuuid']):
                XmppMasterDatabase().update_state_deploy(machine['id'], "WAITING MACHINE ONLINE")
                continue
            XmppMasterDatabase().update_state_deploy(machine['id'], "WOL 2")
            machine_hostname=machine['jidmachine'].split('@')[0][:-4]
            self._addsetwol(wol_set, machine['macadress'])

            msglog.append("Second WOL sent to machine %s" % machine_hostname)
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
    except Exception:
        logger.error("%s" % (traceback.format_exc()))
    finally:
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
    deploymenttype="deploy"
    if "-@upd@-" in title:
        sessiondeployementless = name_random(5, "arsdeployupdate")
        deploymenttype="update"
        prefixcommanddeploy="update"
    else:
        sessiondeployementless = name_random(5, "command")
        prefixcommanddeploy="command"
    msg = []
    name = uuidpackage
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
        XmppMasterDatabase().adddeploy(idcommand,
                                       "%s____" % uuidmachine,
                                       "package %s" % uuidpackage,
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
                                       result="",
                                       syncthing=0)
        msg.append("<span class='log_err'>Package identifier misssing for %s</span>" % uuidpackage)
        msg.append("Action: Check the package %s" % (uuidpackage))
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
        logger.warn('%s package name missing' % uuidpackage)
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
        deploymenttype="deploy"
        if "-@upd@-" in title:
            sessiondeployementless = name_random(5, "arsdeployupdate")
            deploymenttype="update"
            prefixcommanddeploy="update"
        else:
            sessiondeployementless = name_random(5, "command")
            prefixcommanddeploy="command"
        msg = []
        # search group deploy and jid machine
        objmachine = XmppMasterDatabase().getGuacamoleRelayServerMachineUuid(uuidmachine, None)
        if 'error' in objmachine and objmachine['error'] == "MultipleResultsFound" :
            logger.warn('getGuacamoleRelayServerMachineUuid %s' % objmachine['error'])
            dupplicate_machines = XmppMasterDatabase().get_machine_with_dupplicate_uuidinventory(uuidmachine, None)
            logger.warn('get_machine_with_dupplicate_uuidinventory %s' % dupplicate_machines)
            grparray = []
            jidarray = []
            keysyncthingarray = []

            for machine in dupplicate_machines:
                grparray.append(machine['groupdeploy'])
                jidarray.append(machine['jid'])
                keysyncthingarray.append(machine['keysyncthing'])

            grparray = list(set(grparray))
            jidarray = list(set(jidarray))
            keysyncthingarray = list(set(keysyncthingarray))
            jidrelay = ",".join(grparray)
            jidmachine = ",".join(jidarray)
            keysyncthing = ",".join(keysyncthingarray)
            raise Exception("MultipleResultsFound")

        jidrelay = objmachine['groupdeploy']
        jidmachine = objmachine['jid']
        keysyncthing = objmachine['keysyncthing']
        if jidmachine is not None and jidmachine != "" and jidrelay is not None and jidrelay != "":
            # There is an ARS for the deploiement.
            # We check if this ARS is online in the machine table.
            ARSsearch = XmppMasterDatabase().getMachinefromjid(jidrelay)
            if ARSsearch['enabled'] == 0:
                msg.append("<span class='log_err'>ARS %s for deployment is down.</span>" % jidrelay)
                msg.append("Action : Either restart it or rerun the configurator "\
                            "on the machine %s to use another ARS" % (name))
                msg.append("Searching alternative ARS for deployment")
                # We need to check if there is an alternative in the cluster.
                # We check 1 available and online ARS in its cluster
                cluster = XmppMasterDatabase().clusterlistars(enabled=None)
                Found = False
                for i in range(1, len(cluster) + 1):
                    nbars = len(cluster[i]['listarscluster'])
                    if jidrelay in cluster[i]['listarscluster']:
                        if nbars < 2:
                            msg.append("<span class='log_err'>No alternative ARS found</span>")
                            msg.append("Action : Either restart it or rerun the configurator "\
                                       "on the machine %s to use another ARS" % (name))
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
                                                           result="",
                                                           syncthing=0)
                            for logmsg in msg:
                                self.xmpplog(logmsg,
                                             type='deploy',
                                             sessionname=sessiondeployementless,
                                             priority=-1,
                                             action="xmpplog",
                                             why=self.boundjid.bare,
                                             module="Deployment | Start | Creation",
                                             fromuser=login)
                            logger.error("Deployment %s encountered an error on machine %s: ARS down" % (name, uuidmachine))
                            return False
                        else:
                            cluster[i]['listarscluster'].remove(jidrelay)
                            nbars = len(cluster[i]['listarscluster'])
                            nbint = random.randint(0, nbars-1)
                            arsalternative = cluster[i]['listarscluster'][nbint]

                            msg.append("<span class='log_err'>ARS %s for deployment is "
                                       "down. Use alternative ARS for deployment %s. ARS "
                                       " %s must be restarted</span>" % (jidrelay, arsalternative, jidrelay))
                            jidrelay = arsalternative
                            ARSsearch = XmppMasterDatabase().getMachinefromjid(jidrelay)
                            if ARSsearch['enabled'] == 1:
                                Found = True
                                break

                if not Found:
                    sessiondeployementless = name_random(5, "command")
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
                                                   result="",
                                                   syncthing=0)
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
                    logger.error("Deployment error: ARS cluster unavailable")
                    return False
            else:
                Found = True
            # Run deploiement
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
                                                  keysyncthing=keysyncthing,
                                                  nbdeploy=nbdeploy,
                                                  wol=wol,
                                                  msg=msg)
        else:
            sessiondeployementless = name_random(5, "command")
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
                                           result="",
                                           syncthing=0)
            msg.append("<span class='log_err'>ARS for deployment is missing for machine %s </span>" % uuidmachine)
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
            logger.error("The deploiement %s failed on %s" % (name, uuidmachine))
            return False
    except Exception as e:
        logger.error("We encountered the error: %s" % (str(e)))
        logger.error("We hit the backtrace: \n %s" % (traceback.format_exc()))
        logger.error("The deploiement %s failed on %s" % (name, uuidmachine))

        if str(e) == "MultipleResultsFound":
            statusmsg = "ABORT DUPLICATE MACHINES"
        else:
            statusmsg = "ERROR UNKNOWN ERROR"


        XmppMasterDatabase().adddeploy(idcommand,
                                       jidmachine,
                                       jidrelay,
                                       name,
                                       uuidmachine,
                                       title,
                                       statusmsg,
                                       sessiondeployementless,
                                       user=login,
                                       login=login,
                                       title=title,
                                       group_uuid=GUID,
                                       startcmd=start_date,
                                       endcmd=end_date,
                                       macadress=macadress,
                                       result="",
                                       syncthing=0)
        msg.append("<span class='log_err'>Error creating deployment on machine[ %s ] "\
                   "[%s] package[%s]</span>" % (jidmachine, uuidmachine,name))
        if str(e) == "MultipleResultsFound":
            msg.append("<span class='log_err'>The following machines " \
                "(%s) have the same GLPI ID: %s</span>" % (jidmachine,
                                                           uuidmachine ))
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

def generate_hash(path, package_id, hash_type, packages, keyAES32):
    source = "/var/lib/pulse2/packages/sharing/" + path + "/" + package_id
    dest = "/var/lib/pulse2/packages/hash/" + path + "/" + package_id
    BLOCK_SIZE = 65535
    
    if os.path.exists(dest):
        shutil.rmtree(dest)

    if os.path.exists(dest + ".hash"):
        os.remove(dest + ".hash")

    try:
        file_hash = hashlib.new(hash_type)
    except:
        logging.error("Wrong hash type")

    if not os.path.exists(dest):
        os.makedirs(dest)

    source_file = os.listdir(source)

    for file_package in sorted(source_file):
        with open(os.path.join(source, file_package), "rb") as _file:
            try:
                file_hash = hashlib.new(hash_type)
            except:
                logging.error("Wrong hash type")
            file_block = _file.read(BLOCK_SIZE) # Read from the file. Take in the amount declared above
            while len(file_block) > 0: # While there is still data being read from the file
                file_hash.update(file_block) # Update the hash
                file_block = _file.read(BLOCK_SIZE) # Read the next block from the file

        try:
            with open((os.path.join(dest, file_package)) + ".hash", 'wb') as _file:
                _file.write(file_hash.hexdigest())
        except:
            logging.error("Error writing the hash for %s" % file_package)

    #FOREACH FILES IN DEST IN ALPHA ORDER AND ADD KEY AES32, CONCAT AND HASH
    content = ""

    salt = keyAES32
    filelist = os.listdir(dest)
    for file_package in sorted(filelist):
        with open(os.path.join(dest, file_package), "rb") as infile:
            content += infile.read()

    content += salt
    try:
        file_hash = hashlib.new(hash_type)
    except:
        logging.error("Wrong hash type")
    file_hash.update(content)
    content = file_hash.hexdigest()

    with open("%s.hash" % dest, 'wb') as outfile:
        outfile.write(content)

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
                              keysyncthing="",
                              nbdeploy=-1,
                              wol=0,
                              msg=[]):
    """ For a deployment
    1st action: synchronizes the previous package name
    The package is already on the machine and also in relay server.
    """

    logger.debug("PARAMETER jidrelay (%s)" % (jidrelay))
    logger.debug("PARAMETER jidmachine (%s)" % (jidmachine))
    logger.debug("PARAMETER idcommand (%s)" % (idcommand))
    logger.debug("PARAMETER login (%s)" % (login))
    logger.debug("PARAMETER name (%s)" % (name))
    logger.debug("PARAMETER time (%s)" % (time))
    logger.debug("PARAMETER encodebase64 (%s)" % (encodebase64))
    logger.debug("PARAMETER uuidmachine (%s)" % (uuidmachine))
    logger.debug("PARAMETER start_date (%s)" % (start_date))
    logger.debug("PARAMETER end_date (%s)" % (end_date))
    logger.debug("PARAMETER title (%s)" % (title))
    logger.debug("PARAMETER macadress (%s)" % (macadress))
    logger.debug("PARAMETER GUID (%s)" % (GUID))
    logger.debug("PARAMETER keysyncthing (%s)" % (keysyncthing))
    logger.debug("PARAMETER nbdeploy (%s)" % (nbdeploy))
    logger.debug("PARAMETER wol (%s)" % (wol))
    logger.debug("PARAMETER msg (%s)" % (msg))

    deploymenttype="deploy"
    if "-@upd@-" in title:
        sessiondeployementless = name_random(5, "arsdeployupdate")
        deploymenttype="update"
        prefixcommanddeploy="update"
    else:
        sessiondeployementless = name_random(5, "command")
        prefixcommanddeploy="command"

    if managepackage.getversionpackageuuid(name) is None:
        logger.error("Deployment error package name or version missing for %s" % (name))
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
                                       result="",
                                       syncthing=0)
        for logmsg in msg:
            self.xmpplog(logmsg,
                         type=deploymenttype,
                         sessionname=sessiondeployementless,
                         priority=-1,
                         action="xmpplog",
                         why=self.boundjid.bare,
                         module="Deployment | Start | Creation",
                         fromuser=login)
        return False
    # Name the event
    path = managepackage.getpathpackagebyuuid(name)
    if path is None:
        msg.append("<span class='log_err'>Package name missing in package %s</span>" % (name))
        msg.append("Action : check the package %s" % (name))
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
                                       result="",
                                       syncthing=0)
        for logmsg in msg:
            self.xmpplog(logmsg,
                         type=deploymenttype,
                         sessionname=sessiondeployementless,
                         priority=-1,
                         action="xmpplog",
                         why=self.boundjid.bare,
                         module="Deployment | Start | Creation",
                         fromuser=login)
        logger.error("package Name missing (%s)" % (name))
        return False
    descript = managepackage.loadjsonfile(os.path.join(path, 'xmppdeploy.json'))

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
                                       result="",
                                       syncthing=0)
        msg.append("<span class='log_err'>Descriptor xmppdeploy.json " \
                    "missing for %s [%s]</span>" % (name, uuidmachine))
        msg.append("Action : Find out why xmppdeploy.json file is missing.")
        for logmsg in msg:
            self.xmpplog(logmsg,
                         type=deploymenttype,
                         sessionname=sessiondeployementless,
                         priority=-1,
                         action="xmpplog",
                         why=self.boundjid.bare,
                         module="Deployment | Start | Creation",
                         fromuser=login)
        logger.error("Deployment %s on %s  error : xmppdeploy.json missing" % (name, uuidmachine))
        return False
    objdeployadvanced = XmppMasterDatabase().datacmddeploy(idcommand)

    if not objdeployadvanced:
        logger.error("The line has_login_command for the idcommand %s is missing" % idcommand)
        logger.error("To solve this, please remove the group, and recreate it")

    if jidmachine is not None and jidmachine != "" and jidrelay is not None and jidrelay != "":
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
    # TODO on verify dans la table syncthing machine
    # si il n'y a pas un partage syncthing en cour pour cette machine
    # si c'est la cas on ignore cette machine car deja en deploy.
    # res = XmppMasterDatabase().deploy_machine_partage_exist( jidmachine,
    # descript['info']['packageUuid'])
    # if len(res) > 0:
    # print "il existe 1 deployement de ce package [%s]"\
    # sur la machine [%s]"%(descript['info']['packageUuid'],
    # jidmachine)
    # logger.debug("il existe 1 deployement de ce package [%s]"\
    # sur la machine [%s]"%(descript['info']['packageUuid'],
    # jidmachine))
    # return

    # TODO: rattacher 1 deployement d'un package d'une machine si partage syncthing sur cluster existe deja pour d'autre machines.
    # res = XmppMasterDatabase().getnumcluster_for_ars(jidrelay)

    # ici on peut savoir si c'est 1 groupe et si syncthing est demande
    if wol == 3:
        state="GROUP DEPLOY MISSING"
        data['wol'] = 2
        data['mac'] = macadress  # use macadress for WOL
        sessionid = self.createsessionfordeploydiffered(data, prefixcommanddeploy)
        result = json.dumps(data, indent=4)
        msg.append("Machine %s is ready for deployment" % jidmachine)
    if wol == 2:
        state="DEPLOY TASK SCHEDULED"
        data['wol'] = 2
        data['mac'] = macadress  # use macadress for WOL
        sessionid = self.createsessionfordeploydiffered(data, prefixcommanddeploy)
        result = json.dumps(data, indent=4)
        msg.append("Machine %s is ready for deployment" % jidmachine)
    elif wol == 1:
        state = "WOL 1"
        data['wol'] = 1
        data['mac'] = macadress  # use macadress for WOL
        sessionid = self.createsessionfordeploydiffered(data, prefixcommanddeploy)
        result = json.dumps(data, indent=4)
        msg.append("First WOL sent to machine %s" % uuidmachine)
        msg.append("Ping machine %s" % jidmachine)
        pingdata=json.dumps({'action': "ping",
                                'ret': 0,
                                'sessionid': name_random(5, "ping"),
                                'data': {"ping" : True}})
        self.send_message(mto=jidmachine, mbody=pingdata, mtype='chat')
    else:
        state = "DEPLOYMENT START"
        data['wol'] = 0
        # data['advanced']['syncthing'] = 1
        if data['advanced'] and \
            data['advanced']['grp'] is not None and \
            'syncthing' in data['advanced'] and \
            data['advanced']['syncthing'] == 1 and \
                nbdeploy > 2:
            # deploiement avec syncthing
            # call plugin preparesyncthing on master or assesseur master
            # addition session
            # send deploy descriptor to machine
            sessionid = self.send_session_command(jidmachine,
                                                  "deploysyncthing",
                                                  data,
                                                  datasession=None,
                                                  encodebase64=False,
                                                  prefix=prefixcommanddeploy)
            # state = "DEPLOYMENT SYNCTHING"
            result = json.dumps(data, indent=4)
            msg.append("Starting peer deployment on machine %s" % jidmachine)
        else:
            msg.append("Starting deployment on machine %s from ARS %s" % (jidmachine,jidrelay))
            if data['advanced'] and data['advanced']['syncthing'] == 1:
                msg.append("<span class='log_warn'>There are not enough machines " \
                           "to deploy in peer mode</span>")

            data['advanced']['syncthing'] = 0
            result = None

            if self.send_hash is True:
                try:
                    self.mutexdeploy.acquire()
                    if data['name'] in self.hastable:
                        if (self.hastable[data['name']] + 10) > time:
                            del self.hastable[data['name']]
                    if not data['name'] in self.hastable:
                        
                        if ('localisation_server' in data['descriptor']['info'] and data['descriptor']['info']['localisation_server'] != ""):
                            localisation_server = data['descriptor']['info']['localisation_server']
                        elif ('previous_localisation_server' in data['descriptor']['info'] and data['descriptor']['info']['previous_localisation_server'] != ""):
                            localisation_server = data['descriptor']['info']['previous_localisation_server']
                        else:
                            localisation_server = "global"

                        dest_not_hash = "/var/lib/pulse2/packages/sharing/" + localisation_server + "/" + data['name']
                        dest = "/var/lib/pulse2/packages/hash/" + localisation_server + "/" + data['name']

                        if not os.path.exists(dest_not_hash):
                            XmppMasterDatabase().adddeploy(idcommand,
                                       jidmachine,
                                       jidrelay,
                                       name,
                                       uuidmachine,
                                       title,
                                       "ABORT DESCRIPTOR INFO MISSING",
                                       sessiondeployementless,
                                       user=login,
                                       login=login,
                                       title=title,
                                       group_uuid=GUID,
                                       startcmd=start_date,
                                       endcmd=end_date,
                                       macadress=macadress,
                                       result="",
                                       syncthing=0)
                            msg.append("<span class='log_err'>Destination package not find, localisation server must be missing in descriptor for %s [%s]</span>" % (name, uuidmachine))
                            logger.error("Deployment %s on %s error : destination package not find, localisation server must be missing in descriptor " % (name, uuidmachine))
                            return False

                        need_hash = False
                        counter_no_hash = 0
                        counter_hash = 0

                        for file_not_hashed in os.listdir(dest_not_hash):
                            counter_no_hash += 1

                        if not os.path.exists(dest):
                            need_hash = True
                        else:
                            if len(os.listdir(dest)) == 0:
                                need_hash = True
                            else:
                                filelist = os.listdir(dest)
                                for file_package in filelist:
                                    file_package_no_hash = file_package.replace('.hash','')
                                    counter_hash += 1
                                    if counter_hash == counter_no_hash:
                                        if os.path.getmtime(dest + "/" + file_package) < os.path.getmtime(dest_not_hash + "/" + file_package_no_hash):
                                            need_hash = True
                            if counter_hash != counter_no_hash:
                                need_hash = True

                        if need_hash == True:
                            generate_hash(localisation_server, data['name'], self.hashing_algo, data['packagefile'], self.keyAES32)
                        self.hastable[data['name']]= time
                except Exception:
                    logger.error("%s" % (traceback.format_exc()))
                finally:
                    self.mutexdeploy.release()
                content = ""
                try:
                    with open(dest + ".hash", "rb") as infile:
                        content += infile.read()
                        data['hash'] = {}
                        data['hash']['global'] = content
                        data['hash']['type'] = self.hashing_algo

                except Exception as e:
                    logger.error("Pulse is configured to check integrity of packages but the hashes have not been generated")
                    logger.error(str(e))
                    msg.append("<span class='log_err'>Pulse is configured to check integrity of packages but the hashes have not been generated</span>")
                    sessiondeployementless = name_random(5, "hashmissing")
                    sessionid = sessiondeployementless
                    state = 'ERROR HASH MISSING'

            if state != 'ERROR HASH MISSING':
                sessionid = self.send_session_command(jidrelay,
                                                        "applicationdeploymentjson",
                                                        data,
                                                        datasession=None,
                                                        encodebase64=False,
                                                        prefix=prefixcommanddeploy)

    if wol >= 1:
        advancedparameter_syncthing = 0
    else:
        advancedparameter_syncthing = data['advanced']['syncthing']
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
                                   result=result,
                                   syncthing=advancedparameter_syncthing)
    if 'syncthing' not in  data['advanced'] or data['advanced']['syncthing'] == 0:
        XmppMasterDatabase().addcluster_resources(jidmachine,
                                                  jidrelay,
                                                  jidmachine,
                                                  sessionid,
                                                  login=login,
                                                  startcmd=start_date,
                                                  endcmd=end_date)
    return sessionid

def totimestamp(self, dt, epoch=datetime.datetime(1970,1,1)):
    td = dt - epoch
    # return td.total_seconds()
    return (td.microseconds + (td.seconds + td.days * 86400) * 10**6) / 10**6

def syncthingdeploy(self):
    iddeploylist = XmppMasterDatabase().deploysyncthingxmpp()
    if len(iddeploylist) != 0:
        for iddeploy in iddeploylist:
            logging.debug("We correctly initialized the synching deployment for the group: %s" % iddeploy)
            # The tables are created.
            # We now call the syncthing master plugin
            data = {"subaction": "initialisation",
                    "iddeploy": iddeploy}
            self.callpluginsubstitute("deploysyncthing",
                                      data,
                                      sessionid=name_randomplus(25,
                                                                pref="deploysyncthing"))
    else:
        logging.debug("This is not a syncthing deployment, so we did not initialize it.")

def callpluginsubstitute(self, plugin, data, sessionid=None):
    if sessionid is None:
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
            if 'ret' not in dataobj:
                dataobj['ret'] = 0
            try:
                logging.debug("Calling plugin %s from  %s" % (dataobj['action'], msg['from']))
                msg['body'] = dataobj
                del dataobj['data']
                dataerreur={"action": "result" + dataobj['action'],
                            "data": {"msg": "error plugin : " + dataobj['action']},
                            'sessionid': dataobj['sessionid'],
                            'ret': 255,
                            'base64': False}
                module = "%s/plugin_%s.py" % (self.modulepath, dataobj['action'])
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
                logger.error("%s" % (traceback.format_exc()))

            except Exception as e:
                logging.error("Executing plugin (%s) %s %s" % (msg['from'], dataobj['action'], str(e)))
                logger.error("%s" % (traceback.format_exc()))

    except Exception as e:
        logging.error("Message structure %s   %s " % (msg, str(e)))
        logger.error("%s" % (traceback.format_exc()))

def send_session_command(self, jid, action, data={}, datasession=None, encodebase64=False, time=20, eventthread=None, prefix=None):
    if prefix is None:
        prefix = "command"
    if datasession is None:
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
                                      sessionid=command['sessionid'])
        else:
            self.send_message(mto=jid,
                              mbody=json.dumps(command),
                              mtype='chat')
    else:
        logging.debug("creation session")
    return command['sessionid']

def _chunklist(self, listseq, nb=5000):
    nbinlist, rest = divmod(len(listseq), nb)
    avg = len(listseq) / float(nbinlist + 1)
    result = []
    endlist = 0.0
    while endlist < len(listseq):
        result.append(listseq[int(endlist): int(endlist + avg)])
        endlist += avg
    return result

def _sendwolgroup(self, listorset, nb=5000):
    # on scinde la liste en liste de 5000 mac address maximum
    try:
        listforsplit = self._chunklist(list(listorset), nb)
        listorset.clear()
        for listsend in listforsplit:
            self.callpluginsubstitute('wakeonlangroup',
                                      {'macadress': list(listsend)})
    except Exception:
        logger.error("%s" % (traceback.format_exc()))

def _addsetwol( self, setdata, macadress):
    listmacadress = [x.strip() for x in macadress.split("||")]
    for macadressdata in listmacadress:
        setdata.add(macadressdata)

def handlemanagesession(self):
    self.sessiondeploysubstitute.decrementesessiondatainfo()

def garbagedeploy(self):
    MscDatabase().xmppstage_statecurrent_xmpp()
    XmppMasterDatabase().update_status_deploy_end()

def createsessionfordeploydiffered(self, data, prefix="command"):
    sessionid = name_randomplus(25, prefix)
    # Calculate maximum duration of a session
    timeseconde = data['enddate'] - data['stardate']
    self.sessiondeploysubstitute.createsessiondatainfo(sessionid,
                                                       datasession=data,
                                                       timevalid=timeseconde,
                                                       eventend=None)
    return sessionid

def read_conf_loaddeployment(objectxmpp):
    # dictionary used for deploy

    objectxmpp.mutexdeploy = threading.Lock()
    objectxmpp.hastable = {}

    objectxmpp.wolglobal_set = set()  # use group wol
    #clean old folder session
    foldersession = os.path.abspath(os.path.join(os.path.dirname(os.path.realpath(__file__)),'..', "sessiondeploysubstitute"))
    clean_session(foldersession)
    # initialise session object
    objectxmpp.sessiondeploysubstitute = session("sessiondeploysubstitute")
    objectxmpp.machineDeploy = {}

    logger.debug("Initialisation plugin :% s " % plugin["NAME"])
    namefichierconf = plugin['NAME'] + ".ini"
    pathfileconf = os.path.join( objectxmpp.config.pathdirconffile, namefichierconf )

    if not os.path.isfile(pathfileconf):
        objectxmpp.deployment_end_timeout = 300
        objectxmpp.deployment_scan_interval = 10
        objectxmpp.deployment_nbr_mach_cycle = 100
        objectxmpp.wol_interval = 60
        objectxmpp.session_check_interval = 15
        objectxmpp.recover_glpi_identifier_from_name = False
        objectxmpp.force_redeploy = 1
        objectxmpp.reschedule = 0
        objectxmpp.send_hash = False
        objectxmpp.hashing_algo = "sha256"
        objectxmpp.keyAES32 = "abcdefghijklnmopqrstuvwxyz012345"
    else:
        Config = ConfigParser.ConfigParser()
        Config.read(pathfileconf)

        if os.path.exists(pathfileconf + ".local"):
            Config.read(pathfileconf + ".local")

        if Config.has_option("parameters", "wol_interval"):
            objectxmpp.wol_interval =  Config.getint('parameters', 'wol_interval')
        else:
            objectxmpp.wol_interval = 60

        if Config.has_option("parameters", "deployment_scan_interval"):
            objectxmpp.deployment_scan_interval =  Config.getint('parameters', 'deployment_scan_interval')
        else:
            objectxmpp.deployment_scan_interval = 10

        if Config.has_option("parameters", "deployment_nbr_mach_cycle"):
            objectxmpp.deployment_nbr_mach_cycle =  Config.getint('parameters', 'deployment_nbr_mach_cycle')
        else:
            objectxmpp.deployment_nbr_mach_cycle = 100

        if Config.has_option("parameters", "deployment_end_timeout"):
            objectxmpp.deployment_end_timeout =  Config.getint('parameters', 'deployment_end_timeout')
        else:
            objectxmpp.deployment_end_timeout = 300

        if Config.has_option("parameters", "session_check_interval"):
            objectxmpp.session_check_interval =  Config.getint('parameters', 'session_check_interval')
        else:
            objectxmpp.session_check_interval = 15

        if Config.has_option("parameters", "recover_glpi_identifier_from_name"):
            objectxmpp.recover_glpi_identifier_from_name =  Config.getboolean('parameters', 'recover_glpi_identifier_from_name')
        else:
            objectxmpp.recover_glpi_identifier_from_name = False

        if Config.has_option("parameters", "force_redeploy"):
            objectxmpp.force_redeploy =  Config.getboolean('parameters', 'force_redeploy')
        else:
            objectxmpp.force_redeploy = 1

        if Config.has_option("parameters", "reschedule"):
            objectxmpp.reschedule =  Config.getboolean('parameters', 'reschedule')
        else:
            objectxmpp.reschedule = 0

        if Config.has_option("parameters", "send_hash"):
            objectxmpp.send_hash =  Config.getboolean('parameters', 'send_hash')
        else:
            objectxmpp.send_hash = False

        if Config.has_option("parameters", "hashing_algo"):
            objectxmpp.hashing_algo =  Config.get('parameters', 'hashing_algo')
        else:
            objectxmpp.hashing_algo = "sha256"

        if Config.has_option("parameters", "keyAES32"):
            objectxmpp.keyAES32 =  Config.get('parameters', 'keyAES32')
        else:
            objectxmpp.keyAES32 = "abcdefghijklnmopqrstuvwxyz012345"

    # initialisation des object for deployement

    objectxmpp.applicationdeployjsonUuidMachineAndUuidPackage = types.MethodType(applicationdeployjsonUuidMachineAndUuidPackage, objectxmpp)

    objectxmpp.applicationdeployjsonuuid = types.MethodType(applicationdeployjsonuuid, objectxmpp)
    objectxmpp.applicationdeploymentjson = types.MethodType(applicationdeploymentjson, objectxmpp)


    objectxmpp._chunklist = types.MethodType(_chunklist, objectxmpp)
    objectxmpp._sendwolgroup = types.MethodType(_sendwolgroup, objectxmpp)
    objectxmpp._addsetwol = types.MethodType(_addsetwol, objectxmpp)

    objectxmpp.syncthingdeploy = types.MethodType(syncthingdeploy, objectxmpp)

    objectxmpp.callpluginsubstitute = types.MethodType(callpluginsubstitute, objectxmpp)

    objectxmpp.directcallplugin = types.MethodType(directcallplugin, objectxmpp)

    objectxmpp.createsessionfordeploydiffered = types.MethodType(createsessionfordeploydiffered, objectxmpp)

    objectxmpp.send_session_command = types.MethodType(send_session_command, objectxmpp)

    objectxmpp.totimestamp = types.MethodType(totimestamp, objectxmpp)

    # declaration function scheduledeploy in object xmpp
    objectxmpp.scheduledeploy = types.MethodType(scheduledeploy, objectxmpp)
    # schedule function scheduledeploy
    objectxmpp.schedule('check_and_process_deployment',
                        objectxmpp.deployment_scan_interval,
                        objectxmpp.scheduledeploy,
                        repeat=True)

    # declaration function scheduledeployrecoveryjob in object xmpp
    objectxmpp.scheduledeployrecoveryjob = types.MethodType(scheduledeployrecoveryjob, objectxmpp)
    objectxmpp.schedule('wol_interval',
                        objectxmpp.wol_interval,
                        objectxmpp.scheduledeployrecoveryjob,
                        repeat=True)

    # declaration function garbagedeploy in object xmpp
    objectxmpp.garbagedeploy = types.MethodType(garbagedeploy, objectxmpp)
    objectxmpp.schedule('deployment_end_timeout',
                        objectxmpp.deployment_end_timeout,
                        objectxmpp.garbagedeploy,
                        repeat=True)

    # declaration function handlemanagesession in object xmpp
    objectxmpp.handlemanagesession = types.MethodType(handlemanagesession, objectxmpp)
    objectxmpp.schedule('session check',
                        objectxmpp.session_check_interval,
                        objectxmpp.handlemanagesession,
                        repeat=True)
