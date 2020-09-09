#!/usr/bin/env python
# -*- coding: utf-8; -*-
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
# file /pulse_xmpp_agent/agentxmpp.py

import sys
import os
import logging
import traceback
import sleekxmpp
import platform
import base64
import json
import time
import threading
import shutil
import subprocess
import psutil
import random
import hashlib
from lib.reverseport import reverse_port_ssh
from lib.agentconffile import conffilename
from lib.update_remote_agent import Update_Remote_Agent
from lib.xmppiq import dispach_iq_command
from lib.networkinfo import networkagentinfo,\
                            organizationbymachine,\
                            organizationbyuser
from lib.configuration import confParameter,\
                              nextalternativeclusterconnection,\
                              changeconnection
from lib.managesession import session
from lib.managefifo import fifodeploy
from lib.managedeployscheduler import manageschedulerdeploy
from lib.utils import   DEBUGPULSE, getIpXmppInterface, refreshfingerprint,\
                        getRandomName, load_back_to_deploy, cleanbacktodeploy,\
                        call_plugin, subnetnetwork,\
                        createfingerprintnetwork, isWinUserAdmin,\
                        isMacOsUserAdmin, check_exist_ip_port, ipfromdns,\
                        shutdown_command, reboot_command, vnc_set_permission,\
                        save_count_start, test_kiosk_presence, file_get_contents,\
                        isBase64, connection_established, file_put_contents, \
                        simplecommand, testagentconf, \
                        Setdirectorytempinfo, setgetcountcycle, setgetrestart, \
                        protodef, geolocalisation_agent
from lib.manage_xmppbrowsing import xmppbrowsing
from lib.manage_event import manage_event
from lib.manage_process import mannageprocess, process_on_end_send_message_xmpp
from lib.syncthingapirest import syncthing, syncthingprogram, iddevice, conf_ars_deploy
from lib.manage_scheduler import manage_scheduler
from lib.logcolor import  add_coloring_to_emit_ansi, add_coloring_to_emit_windows
from lib.manageRSAsigned import MsgsignedRSA, installpublickey
from lib.managepackage import managepackage

from optparse import OptionParser
from multiprocessing import Queue, Process, Event
from multiprocessing.managers import SyncManager
import multiprocessing
from modulefinder import ModuleFinder

from sleekxmpp.xmlstream import handler, matcher
from sleekxmpp.exceptions import IqError, IqTimeout
from sleekxmpp.xmlstream.stanzabase import ET
from sleekxmpp import jid

if sys.platform.startswith('win'):
    import win32api
    import win32con
    import win32pipe
    import win32file
else:
    import signal

from lib.server_kiosk import process_tcp_serveur, manage_kiosk_message, process_serverPipe

sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), "lib"))

logger = logging.getLogger()

signalint = False

if sys.version_info < (3, 0):
    reload(sys)
    sys.setdefaultencoding('utf8')
else:
    raw_input = input

class QueueManager(SyncManager):
    pass

class MUCBot(sleekxmpp.ClientXMPP):
    def __init__(self,
                 conf,
                 queue_recv_tcp_to_xmpp,
                 queueout,
                 eventkilltcp,
                 eventkillpipe):
        logging.log(DEBUGPULSE, "start machine  %s Type %s" % (conf.jidagent,
                                                               conf.agenttype))
        # create mutex
        self.mutex = threading.Lock()
        self.mutexslotquickactioncount = threading.Lock()
        self.eventkilltcp = eventkilltcp
        self.eventkillpipe = eventkillpipe
        self.queue_recv_tcp_to_xmpp = queue_recv_tcp_to_xmpp
        self.queueout = queueout

        self.concurrentquickdeployments = {}

        # create dir for descriptor syncthing deploy
        self.dirsyncthing =  os.path.join(os.path.dirname(os.path.realpath(__file__)),
                                          "syncthingdescriptor")
        if not os.path.isdir(self.dirsyncthing):
            os.makedirs(self.dirsyncthing, 0755)
        logger.info("start machine1  %s Type %s" % (conf.jidagent,
                                                    conf.agenttype))
        sleekxmpp.ClientXMPP.__init__(self, jid.JID(conf.jidagent),
                                      conf.passwordconnection)
        laps_time_update_plugin = 3600
        laps_time_action_extern = 60
        laps_time_handlemanagesession = 20
        laps_time_check_established_connection = 900
        logging.warning("check connexion xmpp %ss" % laps_time_check_established_connection)
        self.back_to_deploy = {}
        self.config = conf
        # creation object session ##########
        self.session = session(self.config.agenttype)
        # CREATE MANAGE SCHEDULER##############
        logging.debug("### CREATION MANAGER PLUGINSCHULING ##########")
        self.manage_scheduler = manage_scheduler(self)
        logging.debug("##############################################")
        # Definition path directory plugin
        namelibplugins = "pluginsmachine"
        if self.config.agenttype in ['relayserver']:
            namelibplugins = "pluginsrelay"
        self.modulepath = os.path.abspath(\
                os.path.join(os.path.dirname(os.path.realpath(__file__)),
                             namelibplugins))
        # totalise les sessions persistence de 10 secondes
        self.sessionaccumulator = {}
        self.charge_apparente_cluster = {}

        self.laps_time_networkMonitor = self.config.detectiontime
        logging.warning("laps time network changing %s" % self.laps_time_networkMonitor)
        # self.quitserverkiosk = False
        # self.quitserverpipe  = True
        # Update agent from MAster#############################
        self.pathagent = os.path.join(os.path.dirname(os.path.realpath(__file__)))
        self.img_agent = os.path.join(os.path.dirname(os.path.realpath(__file__)),
                                      "img_agent")
        if os.path.isdir(self.img_agent):
            logging.warning('deleting directory %s' % self.img_agent)
            try:
                shutil.rmtree(self.img_agent)
            except Exception as e:
                logging.error('Cannot delete the directory %s : %s' % (self.img_agent, str(e)))

        self.Update_Remote_Agentlist = Update_Remote_Agent(self.pathagent, True )
        self.descriptorimage = Update_Remote_Agent(self.img_agent)
        self.descriptor_master = None
        if len(self.descriptorimage.get_md5_descriptor_agent()['program_agent']) == 0:
            # copy agent vers remote agent.
            if sys.platform.startswith('win'):
                for fichier in self.Update_Remote_Agentlist.get_md5_descriptor_agent()['program_agent']:
                    if not os.path.isfile(os.path.join(self.img_agent, fichier)):
                        os.system('copy %s %s' % (os.path.join(self.pathagent, fichier), os.path.join(self.img_agent, fichier)))
                if not os.path.isfile(os.path.join(self.img_agent,'agentversion' )):
                    os.system('copy %s %s' % (os.path.join(self.pathagent, 'agentversion'), os.path.join(self.img_agent, 'agentversion')))
                for fichier in self.Update_Remote_Agentlist.get_md5_descriptor_agent()['lib_agent']:
                    if not os.path.isfile(os.path.join(self.img_agent,"lib", fichier)):
                        os.system('copy %s %s' % (os.path.join(self.pathagent, "lib", fichier), os.path.join(self.img_agent, "lib", fichier)))
                for fichier in self.Update_Remote_Agentlist.get_md5_descriptor_agent()['script_agent']:
                    if not os.path.isfile(os.path.join(self.img_agent, "script", fichier)):
                        os.system('copy %s %s' % (os.path.join(self.pathagent, "script", fichier), os.path.join(self.img_agent, "script", fichier)))
            elif sys.platform.startswith('linux') or sys.platform.startswith('darwin'):
                os.system('cp -u %s/*.py %s' % (self.pathagent, self.img_agent))
                os.system('cp -u %s/script/* %s/script/' % (self.pathagent, self.img_agent))
                os.system('cp -u %s/lib/*.py %s/lib/' % (self.pathagent, self.img_agent))
                os.system('cp -u %s/agentversion %s/agentversion' % (self.pathagent, self.img_agent))
            else:
                logger.error("The copy has failed")
        self.descriptorimage = Update_Remote_Agent(self.img_agent)
        if self.config.updating != 1:
            logging.warning("remote updating disable")
        if self.descriptorimage.get_fingerprint_agent_base() != self.Update_Remote_Agentlist.get_fingerprint_agent_base():
            self.agentupdating = True
            logging.warning("Agent installed is different from agent on master.")
        # END Update agent from Master#############################
        if self.config.agenttype in ['relayserver']:
            self.managefifo = fifodeploy()
            self.levelcharge = {}
            self.levelcharge['machinelist'] = []
            self.levelcharge['charge'] = 0
            # supprime les reverses ssh inutile
            self.manage_persistence_reverse_ssh = reverse_port_ssh()
        self.jidclusterlistrelayservers = {}
        self.machinerelayserver = []
        self.nicklistchatroomcommand = {}
        self.jidchatroomcommand = jid.JID(self.config.jidchatroomcommand)
        self.agentcommand = jid.JID(self.config.agentcommand)

        if not testagentconf(self.config.agenttype):
            # We remove the fingerprint file
            pathfingerprint = os.path.join( Setdirectorytempinfo(),
                                            'fingerprintconf')
            logger.error("configuration error del figerprint %s"%pathfingerprint)
            if os.path.isfile(pathfingerprint):
                os.remove(pathfingerprint)
                logger.error("configuration error del figerprint %s"%pathfingerprint)
        self.agentsiveo = self.config.jidagentsiveo

        self.agentmaster = jid.JID("master@pulse")

        if not hasattr(self.config, 'sub_subscribe'):
            self.sub_subscribe = self.agentmaster
        else:
            if isinstance(self.config.sub_subscribe, list) and\
                len(self.config.sub_subscribe) > 0:
                self.sub_subscribe = jid.JID(self.config.sub_subscribe[0])
            else:
                self.sub_subscribe = jid.JID(self.config.sub_subscribe)

        if not hasattr(self.config, 'sub_logger'):
            self.sub_logger = self.agentmaster
        else:
            if isinstance(self.config.sub_logger, list) and\
                len(self.config.sub_logger) > 0:
                self.sub_logger = jid.JID(self.config.sub_logger[0])
            else:
                self.sub_logger = jid.JID(self.config.sub_logger)

        if self.sub_subscribe.bare == "":
            self.sub_subscribe = self.agentmaster

        if not hasattr(self.config, 'sub_inventory'):
            self.sub_inventory = self.agentmaster
        else:
            if isinstance(self.config.sub_inventory, list) and\
                len(self.config.sub_inventory) > 0:
                self.sub_inventory = jid.JID(self.config.sub_inventory[0])
            else:
                self.sub_inventory = jid.JID(self.config.sub_inventory)
        if self.sub_inventory.bare == "":
            self.sub_inventory = self.agentmaster

        if not hasattr(self.config, 'sub_registration'):
            self.sub_registration = self.agentmaster
        else:
            if isinstance(self.config.sub_registration, list) and\
                len(self.config.sub_registration) > 0:
                self.sub_registration = jid.JID(self.config.sub_registration[0])
            else:
                self.sub_registration = jid.JID(self.config.sub_registration)
        if self.sub_registration.bare == "":
            self.sub_registration = self.agentmaster

        if not hasattr(self.config, 'sub_monitoring'):
            self.sub_monitoring = self.agentmaster
        else:
            if isinstance(self.config.sub_monitoring, list) and\
                len(self.config.sub_monitoring) > 0:
                self.sub_monitoring = jid.JID(self.config.sub_monitoring[0])
            else:
                self.sub_monitoring = jid.JID(self.config.sub_monitoring)
        if self.sub_monitoring.bare == "":
            self.sub_monitoring = self.agentmaster

        if sys.platform.startswith('linux'):
            if self.config.agenttype in ['relayserver']:
                self.fichierconfsyncthing = os.path.join(self.config.syncthing_home, 'config.xml')
                conf_ars_deploy(self.config.syncthing_port,
                                configfile=self.fichierconfsyncthing,
                                name="pulse")
            else:
                self.fichierconfsyncthing = os.path.join(os.path.expanduser('~pulseuser'),
                                                         ".config",
                                                         "syncthing",
                                                         "config.xml")
            self.tmpfile = "/tmp/confsyncting.txt"
        elif sys.platform.startswith('win'):
            self.fichierconfsyncthing = "%s\\pulse\\etc\\syncthing\\config.xml"%os.environ['programfiles']
            self.tmpfile = "%s\\Pulse\\tmp\\confsyncting.txt"%os.environ['programfiles']
        elif sys.platform.startswith('darwin'):
            self.fichierconfsyncthing = os.path.join("/opt",
                                                "Pulse",
                                                "etc",
                                                "syncthing",
                                                "config.xml")
            self.tmpfile = "/tmp/confsyncting.txt"
        try:
            hostnameiddevice = None
            if self.boundjid.domain == "pulse":
                hostnameiddevice = "pulse"
            self.deviceid = iddevice(configfile=self.fichierconfsyncthing, hostname=hostnameiddevice)
        except Exception:
            pass

        if self.config.agenttype in ['relayserver']:
            # We remove the start sessions of the agent.
            # As long as the Relayserver Agent isn't started, the sesion queues
            # where the deploy has failed are not useful
            self.session.clearallfilesession()
        self.reversessh = None
        self.reversesshmanage = {}
        self.signalinfo = {}
        self.queue_read_event_from_command = Queue()
        self.xmppbrowsingpath = xmppbrowsing(defaultdir=self.config.defaultdir,
                                             rootfilesystem=self.config.rootfilesystem,
                                             objectxmpp=self)
        self.ban_deploy_sessionid_list = set() # List id sessions that are banned
        self.lapstimebansessionid = 900     # ban session id 900 secondes
        self.banterminate = { } # used for clear id session banned
        self.schedule('removeban', 30, self.remove_sessionid_in_ban_deploy_sessionid_list, repeat=True)
        self.Deploybasesched = manageschedulerdeploy()
        self.eventkiosk = manage_kiosk_message(self.queue_recv_tcp_to_xmpp, self)
        self.eventmanage = manage_event(self.queue_read_event_from_command, self)
        self.mannageprocess = mannageprocess(self.queue_read_event_from_command)
        self.process_on_end_send_message_xmpp = process_on_end_send_message_xmpp(self.queue_read_event_from_command)
        self.schedule('check established connection',
                      laps_time_check_established_connection,
                      self.established_connection,
                      repeat=True)
        if self.config.agenttype in ['relayserver']:
            #scheduled task that calls the slot plugin for sending the quick deployments that have not been processed.
            self.schedule('Quick deployment load',
                        15,
                        self.QDeployfile,
                        repeat=True)

        if not hasattr(self.config, 'geolocalisation'):
            self.config.geolocalisation = True
        if not hasattr(self.config, 'request_type'):
            self.config.request_type = "public"

        self.geodata = None
        if  self.config.geolocalisation:
            self.geodata = geolocalisation_agent(typeuser = self.config.request_type,
                                                geolocalisation=self.config.geolocalisation,
                                                ip_public=self.config.public_ip,
                                                strlistgeoserveur=self.config.geoservers    )

            self.config.public_ip = self.geodata.get_ip_public()
        if self.config.public_ip == "" or self.config.public_ip == None:
            self.config.public_ip = None

        self.md5reseau = refreshfingerprint()
        self.schedule('schedulerfunction',
                      10 ,
                      self.schedulerfunction,
                      repeat=True)
        self.schedule('update plugin',
                      laps_time_update_plugin,
                      self.update_plugin,
                      repeat=True)
        if not sys.platform.startswith('win'):
            if self.config.netchanging == 1:
                logging.warning("Network Changing enable")
                self.schedule('check network',
                            self.laps_time_networkMonitor,
                            self.networkMonitor,
                            repeat=True)
            else:
                logging.warning("Network Changing disable")
        self.schedule('check AGENT INSTALL', 350,
                      self.checkinstallagent,
                      repeat=True)
        self.schedule('manage session',
                      laps_time_handlemanagesession,
                      self.handlemanagesession,
                      repeat=True)
        if self.config.agenttype in ['relayserver']:
            self.schedule('reloaddeploy',
                          15,
                          self.reloaddeploy,
                          repeat=True)

            # ######################Update remote agent#########################
            self.diragentbase = os.path.join('/',
                                             'var',
                                             'lib',
                                             'pulse2',
                                             'xmpp_baseremoteagent')
            self.Update_Remote_Agentlist = Update_Remote_Agent(
                self.diragentbase, True)
            # ######################Update remote agent#########################

        # we make sure that the temp for the inventories is greater than or equal to 1 hour.
        # if the time for the inventories is 0, it is left at 0.
        # this deactive cycle inventory
        if self.config.inventory_interval != 0:
            if self.config.inventory_interval < 3600:
                self.config.inventory_interval = 3600
                logging.warning("chang minimun time cyclic inventory : 3600")
                logging.warning("we make sure that the time for "\
                    " the inventories is greater than or equal to 1 hour.")
            self.schedule('event inventory',
                          self.config.inventory_interval,
                          self.handleinventory,
                          repeat=True)
        else:
            logging.warning("not enable cyclic inventory")

        #self.schedule('queueinfo', 10 , self.queueinfo, repeat=True)
        if self.config.agenttype not in ['relayserver']:
            self.schedule('session reload',
                          15,
                          self.reloadsesssion,
                          repeat=False)

        self.schedule('reprise_evenement',
                      10,
                      self.handlereprise_evenement,
                      repeat=True)

        self.add_event_handler("register", self.register, threaded=True)
        self.add_event_handler("session_start", self.start)
        self.add_event_handler('message', self.message, threaded=True)
        self.add_event_handler("signalsessioneventrestart",
                               self.signalsessioneventrestart)
        self.add_event_handler("loginfotomaster", self.loginfotomaster)

        self.add_event_handler('changed_status', self.changed_status)

        self.add_event_handler('presence_unavailable', self.presence_unavailable)
        self.add_event_handler('presence_available', self.presence_available)

        self.add_event_handler('presence_subscribe', self.presence_subscribe)
        self.add_event_handler('presence_subscribed', self.presence_subscribed)

        self.add_event_handler('presence_unsubscribe', self.presence_unsubscribe)
        self.add_event_handler('presence_unsubscribed', self.presence_unsubscribed)

        self.add_event_handler('changed_subscription', self.changed_subscription)

        self.RSA = MsgsignedRSA(self.config.agenttype)
        logger.info("VERSION AGENT IS %s"%self.version_agent())
        #### manage information extern for Agent RS(relayserver only dont working on windows.)
        ##################
        if  self.config.agenttype in ['relayserver']:
            from lib.manage_info_command import manage_infoconsole
            self.qin = Queue(10)
            self.qoutARS = Queue(10)
            QueueManager.register('json_to_ARS' , self.setinARS)
            QueueManager.register('json_from_ARS', self.getoutARS)
            QueueManager.register('size_nb_msg_ARS' , self.sizeoutARS)
            #queue_in, queue_out, objectxmpp
            self.commandinfoconsole = manage_infoconsole(self.qin, self.qoutARS, self)
            self.managerQueue = QueueManager(("", self.config.parametersscriptconnection['port']),
                                            authkey = self.config.passwordconnection)
            self.managerQueue.start()

        if sys.platform.startswith('win'):
            result = win32api.SetConsoleCtrlHandler(self._CtrlHandler, 1)
            if result == 0:
                logging.log(DEBUGPULSE,'Could not SetConsoleCtrlHandler (error %r)' %
                             win32api.GetLastError())
            else:
                logging.log(DEBUGPULSE,'Set handler for console events.')
                self.is_set = True
        elif sys.platform.startswith('linux') :
            signal.signal(signal.SIGINT, self.signal_handler)
        elif sys.platform.startswith('darwin'):
            signal.signal(signal.SIGINT, self.signal_handler)

        self.register_handler(handler.Callback(
                                    'CustomXEP Handler',
                                    matcher.MatchXPath('{%s}iq/{%s}query' % (self.default_ns,
                                                                             "custom_xep")),
                                    self._handle_custom_iq))
        self.schedule('execcmdfile',
                      laps_time_action_extern,
                      self.execcmdfile,
                      repeat=True)

        self.schedule('initsyncthing',
                      15,
                      self.initialise_syncthing,
                      repeat=False)

    def QDeployfile(self):
        sessioniddata = getRandomName(6, "Qdeployfile")
        dataerreur={"action": "resultqdeploy",
                    "sessionid" : sessioniddata,
                    "ret" : 255,
                    "base64" : False,
                    "data": {"msg" : "Deployment error"}
                }
        transfertdeploy = {
            'action': "slot_quickdeploy_count",
            "sessionid" : sessioniddata,
            'data': { "subaction" : "deployfile"},
            'ret': 0,
            'base64': False }

        msg = {'from': self.boundjid.bare,
                "to" : self.boundjid.bare,
                'type': 'chat' }
        call_plugin(transfertdeploy["action"],
                    self,
                    transfertdeploy["action"],
                    transfertdeploy['sessionid'],
                    transfertdeploy['data'],
                    msg,
                    dataerreur)

    ###############################################################
    # syncthing function
    ###############################################################
    # syncthing function
    def is_exist_folder_id(self, idfolder, config):
        for folder in config['folders']:
            if folder['id'] == idfolder:
                return True
        return False

    def add_folder_dict_if_not_exist_id(self, dictaddfolder, config):
        if not self.is_exist_folder_id(dictaddfolder['id'], config):
            config['folders'].append(dictaddfolder)
            return True
        return False

    def add_device_in_folder_if_not_exist(self,
                                          folderid,
                                          keydevice,
                                          config,
                                          introducedBy = ""):
        result = False
        for folder in config['folders']:
            if folderid == folder['id']:
                #folder trouve
                for device in folder['devices']:
                    if device['deviceID'] == keydevice:
                        #device existe
                        result = False
                new_device = {"deviceID": keydevice,
                                "introducedBy": introducedBy}
                folder['devices'].append(new_device)
                result =  True
        return result

    def is_exist_device_in_config(self, keydevicesyncthing, config):
        for device in config['devices']:
            if device['deviceID'] == keydevicesyncthing:
                return True
        return False

    def add_device_syncthing( self,
                            keydevicesyncthing,
                            namerelay,
                            config,
                            introducer = False,
                            autoAcceptFolders=False,
                            address = ["dynamic"]):
        # test si device existe
        for device in config['devices']:
            if device['deviceID'] == keydevicesyncthing:
                result = False
        logger.debug("add device syncthing %s"%keydevicesyncthing)
        dsyncthing_tmp = self.syncthing.create_template_struct_device(namerelay,
                                                            str(keydevicesyncthing),
                                                            introducer = introducer,
                                                            autoAcceptFolders=autoAcceptFolders,
                                                            address = address)

        logger.debug("add device [%s]syncthing to ars %s\n%s"%(keydevicesyncthing,
                                                                namerelay,
                                                                json.dumps(dsyncthing_tmp,
                                                                            indent = 4)))

        config['devices'].append(dsyncthing_tmp)
        return dsyncthing_tmp

    def clean_pendingFolders_ignoredFolders_in_devices(self, config):
        for device in config['devices']:
            if "pendingFolders" in device:
                del device["pendingFolders"]
            if "ignoredFolders" in device:
                del device["ignoredFolders"]

    def pendingdevice_accept(self, config):
        modif=False
        if 'pendingDevices' in config and \
            len(config['pendingDevices']) != 0:
            #print "device trouve"
            for pendingdevice in config['pendingDevices']:
                logger.info("pendingdevice %s"%pendingdevice)
                # exist device?
                if not self.is_exist_device_in_config(pendingdevice['deviceID'], config):
                    # add device
                    if pendingdevice['name'] == "":
                        continue
                    self.add_device_syncthing( pendingdevice['deviceID'],
                                                pendingdevice['name'],
                                                config,
                                                introducer = False,
                                                autoAcceptFolders=False,
                                                address = ["dynamic"])
                    modif = True
                else:
                    pass
        #self.clean_pending(config)
        return modif

    def synchro_synthing(self):
        if not self.config.syncthing_on:
            return
        self.syncthingreconfigure = False;
        logger.info("synchro_synthing")
        # update syncthing
        if self.config.agenttype in ['relayserver']:
            self.clean_old_partage_syncting()
        try:
            config = self.syncthing.get_config() # content all config
            # logger.debug("\n%s"%(json.dumps(config, indent=4 )))
        except:
            #logger.error("\n%s"%(traceback.format_exc()))
            return
        if len(config) == 0:
            return
        if len(config['pendingDevices']) > 0:
            if self.pendingdevice_accept(config):
                self.syncthingreconfigure = True;
            config['pendingDevices']=[]
            #self.syncthing.reload_config(config=config)
            #config = self.syncthing.get_config() # content all config
        if 'remoteIgnoredDevices' in config:
            config['remoteIgnoredDevices'] = []

        #pas de pathfolder definie. warning.
        defaultFolderPath =  config['options']['defaultFolderPath']


        if 'defaultFolderPath' in config['options']:
            for de in  config['devices']:
                if 'pendingFolders' in de and len(de['pendingFolders']) > 0:
                    #add folder
                    for devicefolder in de['pendingFolders']:
                        path_folder = os.path.join(defaultFolderPath,devicefolder['id'])
                        newfolder = self.syncthing.\
                                create_template_struct_folder(devicefolder['label'],
                                                              path_folder,
                                                              id=devicefolder['id'])
                        logging.debug("add shared folder %s"%path_folder)
                        logger.info("add device in folder %s"%devicefolder['id'])
                        self.add_folder_dict_if_not_exist_id(newfolder, config)
                        self.add_device_in_folder_if_not_exist( devicefolder['id'],
                                                                de['deviceID'],
                                                                config)
                        self.syncthingreconfigure = True;
            if self.syncthingreconfigure:
                self.syncthing.post_config(config)
                time.sleep(3)
                self.syncthing.post_restart()
                time.sleep(1)
                self.syncthing.reload_config()
            else:
                self.syncthing.validate_chang_config()

    def clean_old_descriptor_syncting(self, pathdescriptor):
        duration = 3
        onlyfiles = [os.path.join(pathdescriptor, f) \
            for f in os.listdir(pathdescriptor) if os.path.isfile(os.path.join(pathdescriptor, f))]
        timestampnew = time.time()
        for f in onlyfiles:
            if ((timestampnew - os.stat(f).st_mtime) / 3600) > duration:
                os.remove(f)

    def clean_old_partage_syncting(self):
        """
        This function helps to clean old syncthing shares.
        A share ends after 3 hours ( duration variable )
        """
        try:
            self.syncthing
        except Exception:
            return
        duration = 3.
        syncthingroot = self.getsyncthingroot()
        if not os.path.exists(syncthingroot):
            os.makedirs(syncthingroot)
        sharefolder = [x for x in os.listdir(syncthingroot)]
        listflo=[]
        for folder in sharefolder:
            folderpart = os.path.join(syncthingroot, folder)
            exist = self.syncthing.is_exist_folder_id(folder)
            if not exist:
                # If there is no shared folder, we remove the useless files from the share
                # listflo.append(folderpart)
                pass
            if ((time.time() - os.stat(folderpart).st_mtime) / 3600) > duration:
                if exist:
                    # Shares older from 3 hours must be deleted
                    # self.syncthing.del_folder(folder)
                    self.syncthing.delete_folder_pulse_deploy(folder, reload = False)
                    listflo.append(folderpart)
        self.syncthing.validate_chang_config()
        for deletedfolder in listflo:
            if os.path.isdir(deletedfolder):
                try:
                    logger.debug("Removing the shared folder %s" % deletedfolder)
                    shutil.rmtree(deletedfolder)
                except OSError:
                    logger.error("Error while removing the shared folder %s" % (deletedfolder))
                    logger.error("\n%s" % (traceback.format_exc()))

    def getsyncthingroot(self):
        syncthingroot = ""
        if self.config.agenttype in ['relayserver']:
            return self.config.syncthing_share
        else:
            if sys.platform.startswith('win'):
                syncthingroot = "%s\\pulse\\var\\syncthing"%os.environ['programfiles']
            elif sys.platform.startswith('linux'):
                syncthingroot = os.path.join(os.path.expanduser('~pulseuser'), "syncthing")
            elif sys.platform.startswith('darwin'):
                syncthingroot = os.path.join("/opt",
                                            "Pulse",
                                            "var",
                                            "syncthing")
        return syncthingroot

    def scan_syncthing_deploy(self):
        if not self.config.syncthing_on:
            return
        self.clean_old_partage_syncting()
        self.clean_old_descriptor_syncting(self.dirsyncthing)
        listfilearssyncthing =  [os.path.join(self.dirsyncthing, x) \
            for x in os.listdir(self.dirsyncthing) if x.endswith("ars")]

        # get the root for the sync folders
        syncthingroot = self.getsyncthingroot()

        for filears in listfilearssyncthing:
            try:
                syncthingtojson = managepackage.loadjsonfile(filears)
            except:
                syncthingtojson = None

            if syncthingtojson != None:
                namesearch = os.path.join( syncthingroot ,
                                           syncthingtojson['objpartage']['repertoiredeploy'])
                #verify le contenue de namesearch
                if os.path.isdir(namesearch):
                    logging.debug("deploy transfert syncthing : %s"%namesearch)
                    # Get the deploy json
                    filedeploy = os.path.join("%s.descriptor"%filears[:-4])
                    deploytojson = managepackage.loadjsonfile(filedeploy)
                    # Now we have :
                    #   - the .ars file root in filears
                    #   - it's json in syncthingtojson
                    #   - the .descriptor file root in filedeploy
                    #   - it's json in deploytojson
                    #
                    # We need to copy the content of namesearch into the tmp package dirl
                    packagedir = managepackage.packagedir()
                    logging.warning(packagedir)
                    for dirname in os.listdir(namesearch):
                        if dirname != ".stfolder":
                            #clean the dest package to be sure
                            try:
                                shutil.rmtree(os.path.join(packagedir,dirname))
                                logging.debug("clean package before copy %s" % (os.path.join(packagedir, dirname)))
                            except OSError:
                                pass
                            try:
                                self.xmpplog("Transfer complete on machine %s\n " \
                                    "Start Deployement"%self.boundjid.bare,
                                            type='deploy',
                                            sessionname= syncthingtojson["sessionid"],
                                            priority=-1,
                                            action="xmpplog",
                                            who="",
                                            how="",
                                            why=self.boundjid.bare,
                                            module="Deployment | Syncthing",
                                            date=None,
                                            fromuser="",
                                            touser="")
                                shutil.copytree(os.path.join(namesearch, dirname), os.path.join(packagedir, dirname))

                                logging.debug("copy %s to %s" % (os.path.join(namesearch, dirname), os.path.join(packagedir, dirname)))
                                try:
                                    logging.debug("Delete %s" % filears)
                                    os.remove(filears)
                                except Exception:
                                    logging.warning("%s no exist" % filears)
                                try:
                                    logging.debug("delete %s" % filedeploy)
                                    os.remove(filedeploy)
                                except Exception:
                                    logging.warning("%s does no exist" % filedeploy)

                                dataerreur={
                                    "action": "resultapplicationdeploymentjson",
                                    "sessionid": syncthingtojson['sessionid'],
                                    "ret": 255,
                                    "base64": False,
                                    "data": {"msg": "error deployement"}
                                }

                                transfertdeploy = {
                                    'action': "applicationdeploymentjson",
                                    'sessionid': syncthingtojson['sessionid'],
                                    'data': deploytojson,
                                    'ret': 0,
                                    'base64': False}
                                msg = {'from': syncthingtojson['objpartage']['cluster']['elected'],
                                       "to": self.boundjid.bare,
                                       'type': 'chat'}
                                logging.debug("call  applicationdeploymentjson")
                                logging.debug("%s " % json.dumps(transfertdeploy, indent=4))
                                call_plugin(transfertdeploy["action"],
                                            self,
                                            transfertdeploy["action"],
                                            transfertdeploy['sessionid'],
                                            transfertdeploy['data'],
                                            msg,
                                            dataerreur)
                                logging.warning("SEND MASTER")
                                datasend={ 'action': "deploysyncthing",
                                           'sessionid': syncthingtojson['sessionid'],
                                           'data': {"subaction": "counttransfertterminate",
                                                    "iddeploybase": syncthingtojson['objpartage']["syncthing_deploy_group"]},
                                           'ret': 0,
                                           'base64': False}
                                strr = json.dumps(datasend)
                                logging.warning("SEND MASTER %s : " % strr)
                                logging.error("send to master")
                                logging.error("%s " % strr)

                                self.send_message(mto=self.agentmaster,
                                                  mbody=strr,
                                                  mtype='chat')
                            except Exception:
                                logging.error("The package's copy %s to %s failed" % (dirname, packagedir))
                                logger.error("\n%s" % (traceback.format_exc()))
                else:
                    # we look if we have informations about the transfert
                    # print self.syncthing.get_db_status(syncthingtojson['id_deploy'])
                    logging.debug("Recherche la completion de transfert %s" % namesearch)
                    result = self.syncthing.get_db_completion(syncthingtojson['objpartage']['repertoiredeploy'],
                                                              self.syncthing.device_id)
                    if 'syncthing_deploy_group' in syncthingtojson['objpartage'] and len(self.syncthing.device_id) > 40:
                        if 'completion' in result and result['completion'] != 0:
                            datasend = {'action': "deploysyncthing",
                                        'sessionid': syncthingtojson['sessionid'],
                                        'data': {"subaction": "completion",
                                                 "iddeploybase": syncthingtojson['objpartage']["syncthing_deploy_group"],
                                                 "completion": result['completion'],
                                                 "jidfull": self.boundjid.full},
                                        'ret': 0,
                                        'base64': False}
                            strr = json.dumps(datasend)
                            self.send_message(mto=syncthingtojson['objpartage']["agentdeploy"],
                                              mbody=strr,
                                              mtype='chat')
            else:
                # todo supprimer le fichier ars et descriptor.
                # signaler l'erreur de decodage du fichier json.
                logger.error("\n%s" % (traceback.format_exc()))
                pass

    # end syncthing function

    def execcmdfile(self):
        """
           lit fichier avec demande de commande
        """
        fileextern = os.path.join(os.path.dirname(os.path.realpath(__file__)), "cmdexterne")
        if os.path.isfile(fileextern):
            aa = file_get_contents(fileextern).strip()
            logging.info("cmd externe : %s " % aa)
            if aa.startswith('inventory'):
                logging.info("send inventory")
                self.handleinventory()
            os.remove(fileextern)

    def version_agent(self):
        pathversion = os.path.join(self.pathagent, "agentversion")
        if os.path.isfile(pathversion):
            self.versionagent = file_get_contents(pathversion).replace("\n","").replace("\r","").strip()
        else :
            self.versionagent = 0.0
        return self.versionagent

    def iqsendpulse(self, to, datain, timeout):
        # send iq synchronous message
        if type(datain) == dict or type(datain) == list:
            try:
                data = json.dumps(datain)
            except Exception as e:
                logging.error("iqsendpulse : encode json : %s" % str(e))
                return '{"err" : "%s"}' % str(e).replace('"', "'")
        elif type(datain) == unicode:
            data = str(datain)
        else:
            data = datain
        try:
            data = data.encode("base64")
        except Exception as e:
            logging.error("iqsendpulse : encode base64 : %s" % str(e))
            return '{"err" : "%s"}' % str(e).replace('"', "'")
        try:
            iq = self.make_iq_get(queryxmlns='custom_xep', ito=to)
            itemXML = ET.Element('{%s}data' % data)
            for child in iq.xml:
                if child.tag.endswith('query'):
                    child.append(itemXML)
            try:
                result = iq.send(timeout=timeout)
                if result['type'] == 'result':
                    for child in result.xml:
                        if child.tag.endswith('query'):
                            for z in child:
                                if z.tag.endswith('data'):
                                    # decode result
                                    # TODO : Replace print by log
                                    #print z.tag[1:-5]
                                    return base64.b64decode(z.tag[1:-5])
                                    try:
                                        data = base64.b64decode(z.tag[1:-5])
                                        # TODO : Replace print by log
                                        #print "RECEIVED data"
                                        #print data
                                        return data
                                    except Exception as e:
                                        logging.error("iqsendpulse : %s" % str(e))
                                        logger.error("\n%s"%(traceback.format_exc()))
                                        return '{"err" : "%s"}' % str(e).replace('"', "'")
                                    return "{}"
            except IqError as e:
                err_resp = e.iq
                logging.error("iqsendpulse : Iq error %s" % str(err_resp).replace('"', "'"))
                logger.error("\n%s" % (traceback.format_exc()))
                return '{"err" : "%s"}' % str(err_resp).replace('"', "'")

            except IqTimeout:
                logging.error("iqsendpulse : Timeout Error")
                return '{"err" : "Timeout Error"}'
        except Exception as e:
            logging.error("iqsendpulse : error %s" % str(e).replace('"', "'"))
            logger.error("\n%s" % (traceback.format_exc()))
            return '{"err" : "%s"}' % str(e).replace('"', "'")
        return "{}"

    def handle_client_connection(self, client_socket):
        """
        this function handles the message received from kiosk or watching syncting service
        the function must provide a response to an acknowledgment kiosk or a result
        Args:
            client_socket: socket for exchanges between AM and Kiosk

        Returns:
            no return value
        """
        try:
            # request the recv message
            recv_msg_from_kiosk = client_socket.recv(4096)
            if len(recv_msg_from_kiosk) != 0:
                print 'Received {}'.format(recv_msg_from_kiosk)
                datasend = {'action': "resultkiosk",
                            "sessionid": getRandomName(6, "kioskGrub"),
                            "ret": 0,
                            "base64": False,
                            'data': {}}
                msg = str(recv_msg_from_kiosk.decode("utf-8", 'ignore'))
                ##############
                if isBase64(msg):
                    msg = base64.b64decode(msg)
                try:
                    result = json.loads(msg)
                except ValueError as e:
                    logger.error('Message socket is not json correct : %s' % (str(e)))
                    return
                if 'uuid' in result:
                    datasend['data']['uuid'] = result['uuid']
                if 'utcdatetime' in result:
                    datasend['data']['utcdatetime'] = result['utcdatetime']
                if 'action' in result:
                    if result['action'] == "kioskinterface":
                        #start kiosk ask initialization
                        datasend['data']['subaction'] =  result['subaction']
                        datasend['data']['userlist'] = list(set([users[0]  for users in psutil.users()]))
                        datasend['data']['ouuser'] = organizationbyuser(datasend['data']['userlist'])
                        datasend['data']['oumachine'] = organizationbymachine()
                    elif result['action'] == 'kioskinterfaceInstall':
                        datasend['data']['subaction'] =  'install'
                    elif result['action'] == 'kioskinterfaceLaunch':
                        datasend['data']['subaction'] =  'launch'
                    elif result['action'] == 'kioskinterfaceDelete':
                        datasend['data']['subaction'] =  'delete'
                    elif result['action'] == 'kioskinterfaceUpdate':
                        datasend['data']['subaction'] =  'update'
                    elif result['action'] == 'kioskLog':
                        if 'message' in result and result['message'] != "":
                            self.xmpplog(
                                        result['message'],
                                        type = 'noset',
                                        sessionname = '',
                                        priority = 0,
                                        action = "xmpplog",
                                        who = self.boundjid.bare,
                                        how = "Planned",
                                        why = "",
                                        module = "Kiosk | Notify",
                                        fromuser = "",
                                        touser = "")
                            if 'type' in result:
                                if result['type'] == "info":
                                    logging.getLogger().info(result['message'])
                                elif result['type'] == "warning":
                                    logging.getLogger().warning(result['message'])
                    elif result['action'] == "notifysyncthing":
                        datasend['action'] = "notifysyncthing"
                        datasend['sessionid'] = getRandomName(6, "syncthing")
                        datasend['data'] = result['data']
                    else:
                        #bad action
                        logging.getLogger().warning("this action is not taken into account : %s"%result['action'])
                        return
                    #call plugin on master
                    self.send_message_to_master(datasend)
        except Exception as e:
            logging.error("message to kiosk server : %s" % str(e))
            logger.error("\n%s"%(traceback.format_exc()))
        finally:
            client_socket.close()

    def established_connection(self):
        """ check connection xmppmaster """
        if not connection_established(self.config.Port):
            logger.info("RESTART AGENT lost Connection")
            self.restartBot()

    def reloaddeploy(self):
        for sessionidban in self.ban_deploy_sessionid_list:
            self.managefifo.delsessionfifo(sessionidban)

        list_session_terminate_fifo = self.managefifo.checking_deploy_slot_outdoor()

        for sessionid in list_session_terminate_fifo:
            # on supprime cette session des fifo
            # le deploiement est treminée pour cette session.
            self.managefifo.delsessionfifo(sessionid )
            logging.warning("stop deploy session %s "\
                "(deployment slot has passed)"%sessionid)
            self.xmpplog('<span class="log_err">Deployment error in fifo : '\
                         'timed out (sessionid %s)</span>' % (sessionid),
                         type='deploy',
                         sessionname=sessionid,
                         priority=-1,
                         action="xmpplog",
                         who=self.boundjid.bare,
                         how="",
                         why="",
                         module="Deployment | Download | Transfert | Notify | Error",
                         date=None,
                         fromuser=self.boundjid.bare,
                         touser="")
            self.xmpplog('DEPLOYMENT TERMINATE',
                         type='deploy',
                         sessionname=sessionid,
                         priority=-1,
                         action="xmpplog",
                         who=self.boundjid.bare,
                         how="",
                         why="",
                         module="Deployment | Error | Terminate | Notify",
                         date=None,
                         fromuser=self.boundjid.bare,
                         touser="")
        if len(list_session_terminate_fifo) > 0:
            dataerreur = {"action": "resultcluster",
                          "data": {"msg": "error plugin : plugin"
                               },
                          'sessionid': list_session_terminate_fifo[0],
                          'ret': 255,
                          'base64': False
            }
            ###send "envoi message pour signaler ressource level"
            msg = { "from" : self.boundjid.bare,
                    "to" : self.boundjid.bare,
                    "type" : "chat" }
            call_plugin("cluster",
                        self,
                        "cluster",
                        list_session_terminate_fifo[0],
                        {"subaction" : "refresh"},
                        msg,
                        dataerreur)

        if self.managefifo.getcount() != 0:
            logger.debug("FIFO DEPLOY %s level charge %s"\
                " concurent deploy max %s"%(self.managefifo.getcount(),
                                            self.levelcharge['charge'],
                                            self.config.concurrentdeployments))

            if self.levelcharge['charge'] < self.config.concurrentdeployments:
                nbresource = self.config.concurrentdeployments - self.levelcharge['charge']
                logger.debug("Possible Slot deploy %s"%nbresource)
                for Slot in range(nbresource):
                    if self.managefifo.getcount() != 0:
                        data = self.managefifo.getfifo()
                        datasend = { "action": data['action'],
                                "sessionid" : data['sessionid'],
                                "ret" : 0,
                                "base64" : False
                            }
                        del data['action']
                        del data['sessionid']
                        datasend['data'] = data
                        self.send_message(  mto = self.boundjid.bare,
                                        mbody = json.dumps(datasend),
                                        mtype = 'chat')

    def _handle_custom_iq(self, iq):
        if iq['type'] == 'get':
            for child in iq.xml:
                if child.tag.endswith('query'):
                    for z in child:
                        data = z.tag[1:-5]
                        try:
                            data = base64.b64decode(data)
                        except Exception as e:
                            logging.error("_handle_custom_iq : decode base64 : %s"%str(e))
                            logger.error("\n%s"%(traceback.format_exc()))
                            return
                        try:
                            # traitement de la function
                            # result json str
                            result = dispach_iq_command(self, data)
                            try:
                                result = result.encode("base64")
                            except Exception as e:
                                logging.error("_handle_custom_iq : encode base64 : %s"%str(e))
                                logger.error("\n%s"%(traceback.format_exc()))
                                return ""
                        except Exception as e:
                            logging.error("_handle_custom_iq : error function : %s"%str(e))
                            logger.error("\n%s"%(traceback.format_exc()))
                            return
            #retourn result iq get
            for child in iq.xml:
                if child.tag.endswith('query'):
                    for z in child:
                        z.tag = '{%s}data' % result
            iq['to'] = iq['from']
            iq.reply(clear=False)
            iq.send()
        elif iq['type'] == 'set':
            pass
        else:
            pass

    ########################################################
    ################## manage levelcharge ##################
    def checklevelcharge(self, ressource = 0):
        self.levelcharge['charge'] = self.levelcharge['charge'] + ressource
        if self.levelcharge['charge'] < 0 :
            self.levelcharge['charge'] = 0
        return self.levelcharge['charge']

    def getlevelmachinelist(self, jidmachine = ""):
        return self.levelcharge['machinelist']

    def addmachineinlevelmachinelist(self, jidmachine):
        self.levelcharge['machinelist'].append(jidmachine)
        self.levelcharge['charge'] = len(self.levelcharge['machinelist'])

    def delmachineinlevelmachinelist(self, jidmachine):
        for index, elt in enumerate(self.levelcharge['machinelist'][:]):
            if elt == jidmachine:
                del self.levelcharge['machinelist'][index]
                #self.checklevelcharge(ressource = -1)
        self.levelcharge['charge'] = len(self.levelcharge['machinelist'])
    ########################################################

    def signal_handler(self, signal, frame):
        logging.log(DEBUGPULSE, "CTRL-C EVENT")
        global signalint
        signalint = True
        msgevt={
                    "action": "evtfrommachine",
                    "sessionid" : getRandomName(6, "eventwin"),
                    "ret" : 0,
                    "base64" : False,
                    'data': { 'machine': self.boundjid.jid,
                               'event'   : "CTRL_C_EVENT" }
                    }
        self.send_message_subcripted_agent(msgevt)
        time.sleep(2)
        self.quit_application( wait=3)

    def send_message_subcripted_agent(self , msg):
        self.send_message(  mbody = json.dumps(msg),
                            mto = self.sub_subscribe,
                            mtype ='chat')

    def send_message_to_master(self , msg):
        self.send_message(  mbody = json.dumps(msg),
                            mto = '%s/MASTER'%self.agentmaster,
                            mtype ='chat')

    def _CtrlHandler(self, evt):
        """## todo intercep message in console program
        win32con.WM_QUERYENDSESSION win32con.WM_POWERBROADCAS(PBT_APMSUSPEND
        """
        global signalint
        if sys.platform.startswith('win'):
            msgevt={
                    "action": "evtfrommachine",
                    "sessionid" : getRandomName(6, "eventwin"),
                    "ret" : 0,
                    "base64" : False,
                    'data': { 'machine': self.boundjid.jid }
                    }
            if evt == win32con.CTRL_SHUTDOWN_EVENT:
                msgevt['data']['event'] = "SHUTDOWN_EVENT"
                self.send_message_to_master(msgevt)
                logging.log(DEBUGPULSE, "CTRL_SHUTDOWN EVENT")
                signalint = True
                return True
            elif evt == win32con.CTRL_LOGOFF_EVENT:
                msgevt['data']['event'] = "LOGOFF_EVENT"
                self.send_message_to_master(msgevt)
                logging.log(DEBUGPULSE, "CTRL_LOGOFF EVENT")
                return True
            elif evt == win32con.CTRL_BREAK_EVENT:
                msgevt['data']['event'] = "BREAK_EVENT"
                self.send_message_to_master(msgevt)
                logging.log(DEBUGPULSE, "CTRL_BREAK EVENT")
                return True
            elif evt == win32con.CTRL_CLOSE_EVENT:
                msgevt['data']['event'] = "CLOSE_EVENT"
                self.send_message_to_master(msgevt)
                logging.log(DEBUGPULSE, "CTRL_CLOSE EVENT")
                return True
            elif evt == win32con.CTRL_C_EVENT:
                msgevt['data']['event'] = "CTRL_C_EVENT"
                self.send_message_to_master(msgevt)
                logging.log(DEBUGPULSE, "CTRL-C EVENT")
                signalint = True
                self.quit_application( wait=3)
                return True
            else:
                return False
        else:
            pass

    def __sizeout(self, q):
        return q.qsize()

    def sizeoutARS(self):
        return self.__sizeout(self.qoutARS)

    def __setin(self, data , q):
        self.qin.put(data)

    def setinARS(self, data):
        self.__setin(data , self.qoutARS)

    def __getout(self, timeq, q):
        try:
            valeur = q.get(True, timeq)
        except Exception:
            valeur=""
        return valeur

    def getoutARS(self, timeq=10):
        return self.__getout(timeq, self.qoutARS)

    def gestioneventconsole(self, event, q):
        try:
            dataobj = json.loads(event)
        except Exception as e:
            logging.error("bad struct jsopn Message console %s : %s " %(event, str(e)))
            q.put("bad struct jsopn Message console %s : %s " %(event, str(e)))
        listaction = [] # cette liste contient les function directement appelable depuis console.
        #check action in message
        if 'action' in dataobj:
            if 'sessionid' not in dataobj:
                dataobj['sessionid'] = getRandomName(6, dataobj["action"])
            if dataobj["action"] in listaction:
                #call fubnction agent direct
                func = getattr(self, dataobj["action"])
                if "params_by_val" in dataobj and "params_by_name" not in dataobj:
                    func(*dataobj["params_by_val"])
                elif "params_by_val" in dataobj and "params_by_name" in dataobj:
                    func(*dataobj["params_by_val"], **dataobj["params_by_name"])
                elif "params_by_name" in dataobj and "params_by_val" not in dataobj:
                    func( **dataobj["params_by_name"])
                else :
                    func()
            else:
                #call plugin
                dataerreur = { "action" : "result" + dataobj["action"],
                               "data" : { "msg" : "error plugin : "+ dataobj["action"]
                               },
                               'sessionid': dataobj['sessionid'],
                               'ret': 255,
                               'base64': False
                }
                msg = {'from': 'console', "to" : self.boundjid.bare, 'type': 'chat' }
                if 'data' not in dataobj:
                    dataobj['data'] = {}
                call_plugin(dataobj["action"],
                    self,
                    dataobj["action"],
                    dataobj['sessionid'],
                    dataobj['data'],
                    msg,
                    dataerreur)
        else:
            logging.error("action missing in json Message console %s" %(dataobj))
            q.put("action missing in jsopn Message console %s" %(dataobj))
            return
    ##################

    def remove_sessionid_in_ban_deploy_sessionid_list(self):
        """
            this function remove sessionid banned
        """
        # renove if timestamp is 10000 millis seconds.
        d = time.time()
        for sessionidban, timeban in self.banterminate.items():
            if (d - self.banterminate[sessionidban]) > 60:
                del self.banterminate[sessionidban]
                try:
                    self.ban_deploy_sessionid_list.remove(sessionidban)
                except Exception as e:
                    logger.warning(str(e))

    def schedulerfunction(self):
        self.manage_scheduler.process_on_event()

    def presence_subscribe(self, presence):
        logger.info("**********   presence_subscribe %s %s"%(presence['from'],presence['type'] ))

    def presence_subscribed(self, presence):
        logger.info("**********   presence_subscribed %s %s"%(presence['from'],presence['type'] ))

    def changed_subscription(self, presence):
        logger.info("**********   changed_subscription %s %s"%(presence['from'],presence['type'] ))

    def presence_unavailable(self, presence):
        logger.info("**********   presence_unavailable %s %s"%(presence['from'],presence['type'] ))

    def presence_available(self, presence):
        logger.info("**********   presence_available %s %s"%(presence['from'],presence['type'] ))
        self.unsubscribe_agent()

    def presence_unsubscribe(self, presence):
        logger.info("**********   presence_unsubscribe %s %s"%(presence['from'],presence['type'] ))

    def presence_unsubscribed(self, presence):
        logger.info("**********   presence_unsubscribed %s %s"%(presence['from'],presence['type'] ))
        self.get_roster()

    def changed_status(self, presence):
        """
            This function is a xmpp handler used to follow the signal
            from ejabberd when the state of an affiliated agent changes.
        """
        frommsg = jid.JID(presence['from'])
        if frommsg.bare == self.boundjid.bare:
            logger.debug( "Message self calling not processed")
            return
        if frommsg.bare == self.sub_subscribe and presence['type'] == 'available':
            self.update_plugin()

    def unsubscribe_agent(self):
        keyroster = str(self.boundjid.bare)
        if keyroster in self.roster:
            for t in self.roster[keyroster]:
                if t == self.boundjid.bare or t in [self.sub_subscribe]:
                    continue
                logger.info("unsubscribe %s"%self.sub_subscribe)
                self.send_presence ( pto = t, ptype = 'unsubscribe' )
                #self.del_roster_item(t)
                self.update_roster(t, subscription='remove')

    def start(self, event):
        self.get_roster()
        self.send_presence()
        logger.info("subscribe to %s agent"%self.sub_subscribe.user)
        self.send_presence ( pto = self.sub_subscribe, ptype = 'subscribe' )
        self.unsubscribe_agent()
        self.ipconnection = self.config.Server

        if  self.config.agenttype in ['relayserver']:
            try:
                if self.config.public_ip_relayserver != "":
                    logging.log(DEBUGPULSE,"Attribution ip public by configuration for ipconnexion: [%s]"%self.config.public_ip_relayserver)
                    self.ipconnection = self.config.public_ip_relayserver
            except Exception:
                pass

        self.config.ipxmpp = getIpXmppInterface(self.config.Server, self.config.Port)

        self.agentrelayserverrefdeploy = self.config.jidchatroomcommand.split('@')[0][3:]
        logging.log(DEBUGPULSE,"Roster agent \n%s"%self.client_roster)

        self.xmpplog("Starting %s agent" % self.config.agenttype,
                    type = 'info',
                    sessionname = "",
                    priority = -1,
                    action = "xmpplog",
                    who = self.boundjid.bare,
                    how = "",
                    why = "",
                    date = None ,
                    fromuser = self.boundjid.bare,
                    touser = "")
        #notify master conf error in AM
        dataerrornotify = {
                            'to': self.boundjid.bare,
                            'action': "notify",
                            "sessionid" : getRandomName(6, "notify"),
                            'data': { 'msg': "",
                                       'type': 'error'
                                      },
                            'ret': 0,
                            'base64': False
                    }

        if not os.path.isdir(self.config.defaultdir):
            dataerrornotify['data']['msg'] =  "Configurateur error browserfile on machine %s: defaultdir %s does not exit\n"%(self.boundjid.bare, self.config.defaultdir)
            self.send_message(  mto = self.agentmaster,
                                mbody = json.dumps(dataerrornotify),
                                mtype = 'chat')

        if not os.path.isdir(self.config.rootfilesystem):
            dataerrornotify['data']['msg'] += "Configurateur error browserfile on machine %s: rootfilesystem %s does not exit"%(self.boundjid.bare, self.config.rootfilesystem)
        #send notify
        if dataerrornotify['data']['msg'] !="":
            self.send_message(  mto = self.agentmaster,
                                    mbody = json.dumps(dataerrornotify),
                                    mtype = 'chat')
        #call plugin start
        startparameter={
            "action": "start",
            "sessionid" : getRandomName(6, "start"),
            "ret" : 0,
            "base64" : False,
            "data" : {}}
        dataerreur={ "action" : "result" + startparameter["action"],
                     "data" : { "msg" : "error plugin : "+ startparameter["action"]},
                     'sessionid': startparameter['sessionid'],
                     'ret': 255,
                     'base64': False}
        msg = {'from': self.boundjid.bare, "to" : self.boundjid.bare, 'type': 'chat' }
        if 'data' not in startparameter:
            startparameter['data'] = {}
        call_plugin(startparameter["action"],
                    self,
                    startparameter["action"],
                    startparameter['sessionid'],
                    startparameter['data'],
                    msg,
                    dataerreur)



    def initialise_syncthing(self):
        logger.info("____________________________________________")
        logger.info("___________ INITIALISE SYNCTHING ___________")
        logger.info("____________________________________________")
        try:
            self.config.syncthing_on
        except NameError:
            self.config.syncthing_on = False

        ################################### initialise syncthing ###################################
        if self.config.syncthing_on:
            if self.config.agenttype not in ['relayserver']:
                self.schedule('scan_syncthing_deploy', 55, self.scan_syncthing_deploy, repeat=True)
            self.schedule('synchro_synthing', 60, self.synchro_synthing, repeat=True)
            if logger.level <= 10:
                console = False
                browser = True
            self.Ctrlsyncthingprogram = syncthingprogram(agenttype=self.config.agenttype)
            self.Ctrlsyncthingprogram.restart_syncthing()

            try:
                logging.debug("initialisation syncthing file conf : %s port %s" % (self.fichierconfsyncthing,
                                                                                   self.config.syncthing_gui_port))
                self.syncthing = syncthing(configfile=self.fichierconfsyncthing, port=self.config.syncthing_gui_port)
                if logger.level <= 10:
                    self.syncthing.save_conf_to_file(self.tmpfile)
                else:
                    try:
                        os.remove(self.tmpfile)
                    except OSError:
                        pass
            except Exception as e:
                logging.error("syncthing initialisation : %s" % str(e))
                logger.error("\n%s"%(traceback.format_exc()))
                logging.error("functioning of the degraded agent. impossible to use syncthing")
            #self.syncthing = syncthing(configfile = fichierconfsyncthing)
        ################################### syncthing ###################################

    def send_message_agent( self,
                            mto,
                            mbody,
                            msubject=None,
                            mtype=None,
                            mhtml=None,
                            mfrom=None,
                            mnick=None):
        if mto != "console":
            print "send command %s"%json.dumps(mbody)
            self.send_message(  mto,
                                json.dumps(mbody),
                                msubject,
                                mtype,
                                mhtml,
                                mfrom,
                                mnick)
        else :
            if self.config.agenttype in ['relayserver']:
                q = self.qoutARS
            else:
                q = self.qoutAM
            if q.full():
                #vide queue
                while not q.empty():
                    q.get()
            else:
                try :
                    q.put(json.dumps(mbody), True, 10)
                except Exception:
                    print "put in queue impossible"

    def logtopulse(self, text, type = 'noset', sessionname = '', priority = 0, who =""):
        if who == "":
            who = self.boundjid.bare
        msgbody = {}
        data = {'log': 'xmpplog',
                'action': 'xmpplog',
                'text': text,
                'type':type,
                'sessionid':sessionname,
                'session':sessionname,
                'priority':priority,
                'who':who}
        msgbody['data'] = data
        msgbody['action'] = 'xmpplog'
        msgbody['sessionid'] = sessionname
        msgbody['session'] = sessionname
        self.send_message(  mto = self.sub_logger,
                            mbody=json.dumps(msgbody),
                            mtype='chat')

    def xmpplog(self,
                text,
                type = 'noset',
                sessionname = '',
                priority = 0,
                action = "xmpplog",
                who = "",
                how = "",
                why = "",
                module = "",
                date = None ,
                fromuser = "",
                touser = ""):
        if sessionname == "":
            sessionname = getRandomName(6, "logagent")
        if who == "":
            who = self.boundjid.bare
        msgbody = {}
        data = {'log': 'xmpplog',
                'text': text,
                'type': type,
                'sessionid': sessionname,
                'priority': priority,
                'action': action ,
                'who': who,
                'how': how,
                'why': why,
                'module': module,
                'date': None ,
                'fromuser': fromuser,
                'touser': touser}
        msgbody['data'] = data
        msgbody['action'] = 'xmpplog'
        msgbody['sessionid'] = sessionname
        self.send_message(  mto = self.sub_logger,
                            mbody=json.dumps(msgbody),
                            mtype='chat')

    def handleinventory(self, forced = "forced", sessionid = None):
        msg={ 'from': "master@pulse/MASTER",
              'to': self.boundjid.bare
            }
        datasend = {"forced" : "forced"}
        if forced == "forced" or forced is True:
            datasend = {"forced" : "forced"}
        else:
            datasend = {"forced" : "noforced" }
        if sessionid == None:
            sessionid = getRandomName(6, "inventory")
        dataerreur = {}
        dataerreur['action'] = "resultinventory"
        dataerreur['data']= datasend
        dataerreur['data']['msg'] = "ERROR : inventory"
        dataerreur['sessionid'] = sessionid
        dataerreur['ret'] = 255
        dataerreur['base64'] = False

        self.xmpplog("Sending inventory from agent"\
                     " %s (Interval : %s)"%( self.boundjid.bare,
                                            self.config.inventory_interval),
                                            type = 'noset',
                                            sessionname = '',
                                            priority = 0,
                                            action = "xmpplog",
                                            who = self.boundjid.bare,
                                            how = "Planned",
                                            why = "",
                                            module = "Inventory | Inventory reception | Planned",
                                            fromuser = "",
                                            touser = "")
        call_plugin("inventory",
                    self,
                    "inventory",
                    sessionid,
                    datasend,
                    msg,
                    dataerreur)

    def update_plugin(self):
        # Send plugin and machine informations to Master
        dataobj  = self.seachInfoMachine()
        logging.log(DEBUGPULSE,"SEND REGISTRATION XMPP to %s \n%s"%(self.sub_registration,
                                                                    json.dumps(dataobj,
                                                                               indent=4)))

        setgetcountcycle()
        self.send_message(  mto=self.sub_registration,
                            mbody = json.dumps(dataobj),
                            mtype = 'chat')


    def reloadsesssion(self):
        # reloadsesssion only for machine
        # retrieve existing sessions
        if not self.session.loadsessions():
            return
        logging.log(DEBUGPULSE,"RELOAD SESSION DEPLOY")
        try:
            # load back to deploy after read session
            self.back_to_deploy = load_back_to_deploy()
            logging.log(DEBUGPULSE,"RELOAD DEPENDENCY MANAGER")
        except IOError:
            self.back_to_deploy = {}
        cleanbacktodeploy(self)
        for i in self.session.sessiondata:
            logging.log(DEBUGPULSE,"DEPLOYMENT AFTER RESTART OU RESTART BOT")
            msg={
                'from': self.boundjid.bare,
                'to': self.boundjid.bare
            }
            call_plugin( i.datasession['action'],
                        self,
                        i.datasession['action'],
                        i.datasession['sessionid'],
                        i.datasession['data'],
                        msg,
                        {}
            )

    def loginfotomaster(self, msgdata):
        logstruct={
                    "action": "infolog",
                    "sessionid" : getRandomName(6, "xmpplog"),
                    "ret" : 0,
                    "base64" : False,
                    "msg":  msgdata }
        try:
            self.send_message(  mbody = json.dumps(logstruct),
                                mto = '%s/MASTER'%self.agentmaster,
                                mtype ='chat')
        except Exception as e:
            logging.error("message log to '%s/MASTER': %s " %  ( self.agentmaster,str(e)))
            logger.error("\n%s"%(traceback.format_exc()))
            return

    def handlereprise_evenement(self):
        #self.eventTEVENT = [i for i in self.eventTEVENT if self.session.isexist(i['sessionid'])]
        #appelle plugins en local sur un evenement
        self.eventmanage.manage_event_loop()

    def signalsessioneventrestart(self,result):
        pass

    def handlemanagesession(self):
        self.session.decrementesessiondatainfo()

    def networkMonitor(self):
        try:
            logging.log(DEBUGPULSE,"network monitor time  "\
                "%ss %s!" % (self.laps_time_networkMonitor,
                             self.boundjid.user))
            md5ctl = createfingerprintnetwork()
            force_reconfiguration = os.path.join(os.path.dirname(os.path.realpath(__file__)), "action_force_reconfiguration")
            if self.md5reseau != md5ctl or os.path.isfile(force_reconfiguration):
                if not os.path.isfile(force_reconfiguration):
                    refreshfingerprint()
                    logging.log(DEBUGPULSE,"by network changed. The reconfiguration of the agent [%s] will be executed." % self.boundjid.user)
                else:
                    logging.log(DEBUGPULSE,"by request. The reconfiguration of the agent [%s] will be executed." % self.boundjid.user)
                    os.remove(force_reconfiguration)
                #### execution de convigurateur.
                #### timeout 5 minutes.
                namefilebool = os.path.join(os.path.dirname(os.path.realpath(__file__)), "BOOLCONNECTOR")
                nameprogconnection = os.path.join(os.path.dirname(os.path.realpath(__file__)), "connectionagent.py")
                if os.path.isfile(namefilebool):
                    os.remove(namefilebool)

                connectionagentArgs = ['python', nameprogconnection, '-t', 'machine']
                subprocess.call(connectionagentArgs)

                for i in range(15):
                    if os.path.isfile(namefilebool):
                        break
                    time.sleep(2)
                logging.log(DEBUGPULSE,"RESTART AGENT [%s] for new configuration" % self.boundjid.user)
                self.restartBot()
        except Exception as e:
            logging.error(" %s " %(str(e)))
            logger.error("\n%s"%(traceback.format_exc()))

    def reinstall_agent(self):
        file_put_contents(os.path.join(self.pathagent, "BOOL_UPDATE_AGENT"),
                        "use file boolean update. enable verify update.")
        logger.debug("RE_INSTALL AGENT VERSION %s to %s"%(file_get_contents(os.path.join(self.img_agent,
                                                                                        "agentversion")),
                                                        self.boundjid.bare ))
        agentversion = os.path.join(self.pathagent, "agentversion")
        versiondata = file_get_contents(os.path.join(self.img_agent, "agentversion")).replace("\n","").replace("\r","").strip()

        try:
            os.remove(os.path.join(self.pathagent, "BOOL_UPDATE_AGENT"))
        except OSError:
            pass

        replycatorcmd = "python %s" % (os.path.join(self.pathagent, "replicator.py"))
        logger.debug("cmd : %s" % (replycatorcmd))
        result = simplecommand(replycatorcmd)
        if result['code'] == 0:
            logger.warning("the agent is already installed for version  %s"%(versiondata))
        elif result['code'] == 1:
            logger.info("installed success agent version %s"%(versiondata))
        elif result['code'] == 120:
            logger.error("installed default agent version %s (rollback previous version.). We will not switch to new agent."%(versiondata))
        elif result['code'] == 121:
            logger.warning("installed success agent version %s (unable to update the version in the registry.)"%(versiondata))
        elif result['code'] == 122:
            logger.warning("Some python modules needed for running lib are missing. We will not switch to new agent)")
        elif result['code'] == 5:
            logger.warning("mode replicator non permit dans pluging, ni installation agent. We will not switch to new agent.")
        else:
            logger.error("installed agent version %s (indefinie operation). We will not switch to new agent."%(versiondata))
            logger.error("return code is : %s"%(result['code']))

    def checkinstallagent(self):
        # verify si boollean existe.
        if self.config.updating == 1:
            if os.path.isfile(os.path.join(self.pathagent, "BOOL_UPDATE_AGENT")):
                if self.descriptor_master is not None:
                    Update_Remote_Agenttest = Update_Remote_Agent(self.pathagent, True )
                    Update_Remote_Img   = Update_Remote_Agent(self.img_agent, True )
                    logger.debug("Fingerprint of Remote Agenttest: %s" % Update_Remote_Agenttest.get_fingerprint_agent_base() )
                    logger.debug("Fingerprint of Remote Image: %s" % Update_Remote_Img.get_fingerprint_agent_base() )
                    logger.debug("Fingerprint of Master Image: %s" % self.descriptor_master['fingerprint'] )
                    if Update_Remote_Agenttest.get_fingerprint_agent_base() != Update_Remote_Img.get_fingerprint_agent_base() and \
                    Update_Remote_Img.get_fingerprint_agent_base() ==  self.descriptor_master['fingerprint']:
                        self.reinstall_agent()
                else:
                    logger.warning("ask update but descriptor_agent base missing.")

    def restartBot(self, wait=10):
        logging.log(DEBUGPULSE,"RESTART BOOT")
        setgetrestart(1)
        logging.log(DEBUGPULSE,"restart xmpp agent %s!" % self.boundjid.user)
        self.disconnect(wait=wait)

    def quit_application(self, wait=2):
        logging.log(DEBUGPULSE,"Quit Application")
        setgetrestart(0)
        self.disconnect(wait=wait)

    def register(self, iq):
        """ This function is called for automatic registation """
        resp = self.Iq()
        resp['type'] = 'set'
        resp['register']['username'] = self.boundjid.user
        resp['register']['password'] = self.password
        try:
            resp.send(now=True)
            logging.info("Account created for %s!" % self.boundjid)
        except IqError as e:
            if e.iq['error']['code'] == "409":
                logging.info("Could not register account: User already exists")
            else:
                logging.error("Could not register account: %s" %\
                        e.iq['error']['text'])
        except IqTimeout:
            logging.error("No response from server.")
            logger.error("\n%s"%(traceback.format_exc()))
            self.disconnect()

    def filtre_message(self, msg):
        pass

    def message(self, msg):
        possibleclient = ['master',
                          self.agentcommand.user,
                          self.boundjid.user,
                          'log',
                          self.jidchatroomcommand.user] + self.agentsiveo
        possibleclient=[str(x) for x in possibleclient]
        if not msg['type'] == "chat":
            return
        try :
            dataobj = json.loads(msg['body'])

        except Exception as e:
            logging.error("bad struct Message %s %s " %(msg, str(e)))
            dataerreur={
                    "action": "resultmsginfoerror",
                    "sessionid" : "",
                    "ret" : 255,
                    "base64" : False,
                    "data": {"msg" : "ERROR : Message structure"}
        }
            self.send_message(  mto=msg['from'],
                                        mbody=json.dumps(dataerreur),
                                        mtype='chat')
            logger.error("\n%s"%(traceback.format_exc()))
            return

        if not str(msg['from'].user) in possibleclient:
            if not('sessionid' in  dataobj and self.session.isexist(dataobj['sessionid'])):
                #les messages venant d'une machine sont filtré sauf si une session message existe dans le gestionnaire de session.
                if  self.config.ordreallagent:
                    logging.warning("filtre message from %s eg possible client" % (msg['from'].bare))
                    return

        dataerreur={
                    "action": "resultmsginfoerror",
                    "sessionid" : "",
                    "ret" : 255,
                    "base64" : False,
                    "data": {"msg" : ""}
        }

        if 'action' not in dataobj:
            logging.error("warning message action missing %s"%(msg))
            return

        if dataobj['action'] == "restarfrommaster":
            reboot_command()

        if dataobj['action'] == "shutdownfrommaster":
            msg = "\"Shutdown from administrator\""
            time = 15 # default 15 seconde
            if 'time' in dataobj['data'] and dataobj['data']['time'] != 0:
                time = dataobj['data']['time']
            if 'msg' in dataobj['data'] and dataobj['data']['msg'] != "":
                msg = '"' + dataobj['data']['msg'] + '"'

            shutdown_command(time, msg)
            return

        if dataobj['action'] == "vncchangepermsfrommaster":
            askpermission = 1
            if 'askpermission' in dataobj['data'] and dataobj['data']['askpermission'] == '0':
                askpermission = 0

            vnc_set_permission(askpermission)

        if dataobj['action'] == "installkeymaster":
            # note install publickeymaster
            self.masterpublickey = installpublickey("master", dataobj['keypublicbase64'] )
            return

        if dataobj['action'] ==  "resultmsginfoerror":
            logging.warning("filtre message from %s for action %s" % (msg['from'].bare,dataobj['action']))
            return
        try :
            if dataobj.has_key('action') and dataobj['action'] != "" and dataobj.has_key('data'):
                if dataobj.has_key('base64') and \
                    ((isinstance(dataobj['base64'],bool) and dataobj['base64'] is True) or
                    (isinstance(dataobj['base64'],str) and dataobj['base64'].lower()=='true')):
                    # data in base 64
                    mydata = json.loads(base64.b64decode(dataobj['data']))
                else:
                    mydata = dataobj['data']

                if not dataobj.has_key('sessionid'):
                    dataobj['sessionid']= getRandomName(6, "xmpp")
                    logging.warning("sessionid missing in message from %s : attributed sessionid %s " % (msg['from'],
                                                                                                         dataobj['sessionid']))
                else:
                    if dataobj['sessionid'] in self.ban_deploy_sessionid_list:
                        ## abort deploy if msg session id is banny
                        logging.info("ABORT DEPLOYMENT CANCELLED BY USER Sesion %s"%dataobj['sessionid'])
                        self.xmpplog("<span class='log_err'>ABORT DEPLOYMENT CANCELLED BY USER</span>",
                                    type = 'deploy',
                                    sessionname = dataobj['sessionid'],
                                    priority = -1,
                                    action = "xmpplog",
                                    who = self.boundjid.bare,
                                    how = "",
                                    why = "",
                                    module = "Deployment | Banned",
                                    date = None ,
                                    fromuser = "MASTER",
                                    touser = "")
                        return

                del dataobj['data']
                # traitement TEVENT
                # TEVENT event sended by remote machine ou RS
                # message adresse au gestionnaire evenement
                if 'Dtypequery' in mydata and mydata['Dtypequery'] == 'TEVENT' and self.session.isexist(dataobj['sessionid']):
                    mydata['Dtypequery'] = 'TR'
                    datacontinue = {
                            'to': self.boundjid.bare,
                            'action': dataobj['action'],
                            'sessionid': dataobj['sessionid'],
                            'data': dict(self.session.sessionfromsessiondata(dataobj['sessionid']).datasession.items() + mydata.items()),
                            'ret': 0,
                            'base64': False
                    }
                    #add Tevent gestion event
                    self.eventmanage.addevent(datacontinue)
                    return
                try:
                    msg['body'] = dataobj
                    logging.info("call plugin %s from %s" % (dataobj['action'],msg['from'].user))
                    call_plugin(dataobj['action'],
                                self,
                                dataobj['action'],
                                dataobj['sessionid'],
                                mydata,
                                msg,
                                dataerreur
                                )
                except TypeError:
                    if dataobj['action'] != "resultmsginfoerror":
                        dataerreur['data']['msg'] = "ERROR : plugin %s Missing"%dataobj['action']
                        dataerreur['action'] = "result%s"%dataobj['action']
                        self.send_message(  mto=msg['from'],
                                            mbody=json.dumps(dataerreur),
                                            mtype='chat')
                    logging.error("TypeError execution plugin %s : [ERROR : plugin Missing] %s" %(dataobj['action'],
                                                                                                  sys.exc_info()[0]))
                    logger.error("\n%s"%(traceback.format_exc()))

                except Exception as e:
                    logging.error("execution plugin [%s]  : %s " % (dataobj['action'],str(e)))
                    if dataobj['action'].startswith('result'):
                        return
                    if dataobj['action'] != "resultmsginfoerror":
                        dataerreur['data']['msg'] = "ERROR : plugin execution %s"%dataobj['action']
                        dataerreur['action'] = "result%s"%dataobj['action']
                        self.send_message(  mto=msg['from'],
                                            mbody=json.dumps(dataerreur),
                                            mtype='chat')
                    logger.error("\n%s"%(traceback.format_exc()))
            else:
                if 'data' not in dataobj:
                    msgerr = "data section missing;  msg : %s"%(msg['body'])
                if 'action' in dataobj:
                    act = dataobj['action']
                else:
                    act = ""
                dataerreur['data']['msg'] = "ERROR : Action ignored : %s\n " \
                    "structure msg\n%s"%(act, msgerr)
                self.send_message(  mto=msg['from'],
                                        mbody=json.dumps(dataerreur),
                                        mtype='chat')
        except Exception as e:
            logging.error("bad struct Message %s %s " %(msg, str(e)))
            dataerreur['data']['msg'] = "ERROR : Message structure"
            self.send_message(  mto=msg['from'],
                                        mbody=json.dumps(dataerreur),
                                        mtype='chat')
            logger.error("\n%s"%(traceback.format_exc()))

    def seachInfoMachine(self):
        er = networkagentinfo("master", "infomachine")
        er.messagejson['info'] = self.config.information
        #send key public agent
        er.messagejson['publickey'] =  self.RSA.loadkeypublictobase64()
        #send if master public key public is missing
        er.messagejson['is_masterpublickey'] = self.RSA.isPublicKey("master")
        for t in er.messagejson['listipinfo']:
            # search network info used for xmpp
            if t['ipaddress'] == self.config.ipxmpp:
                xmppmask = t['mask']
                try:
                    xmppbroadcast = t['broadcast']
                except :
                    xmppbroadcast = ""
                xmppdhcp = t['dhcp']
                xmppdhcpserver = t['dhcpserver']
                xmppgateway = t['gateway']
                xmppmacaddress = t['macaddress']
                xmppmacnotshortened = t['macnotshortened']
                portconnection = self.config.Port
                break
        try:
            subnetreseauxmpp =  subnetnetwork(self.config.ipxmpp, xmppmask)
        except Exception:
            logreception = """
Imposible calculate subnetnetwork verify the configuration of %s [%s]
Check if ip [%s] is correct:
check if interface exist with ip %s

Warning Configuration machine %s
[connection]
server = It must be expressed in ip notation.

server = 127.0.0.1  correct
server = localhost in not correct
AGENT %s ERROR TERMINATE"""%(self.boundjid.bare,
                             er.messagejson['info']['hostname'],
                             self.config.ipxmpp,
                             self.config.ipxmpp,
                             er.messagejson['info']['hostname'],
                             self.boundjid.bare)
            self.loginfotomaster(logreception)
            sys.exit(0)

        if self.config.public_ip == None:
            self.config.public_ip = self.config.ipxmpp
        remoteservice = protodef()
        # if regcomplet = True then register agent reconfigure complet of agent
        self.regcomplet = remoteservice.boolchangerproto # || condition de reconf complet
        dataobj = {
            'action': 'infomachine',
            'from': self.config.jidagent,
            'compress': False,
            'deployment': self.config.jidchatroomcommand,
            'who'    : "%s/%s"%(self.config.jidchatroomcommand,self.config.NickName),
            'machine': self.config.NickName,
            'platform': platform.platform(),
            'completedatamachine': base64.b64encode(json.dumps(er.messagejson)),
            'plugin': {},
            'pluginscheduled': {},
            'versionagent': self.version_agent(),
            'portxmpp': self.config.Port,
            'serverxmpp': self.config.Server,
            'agenttype': self.config.agenttype,
            'baseurlguacamole': self.config.baseurlguacamole,
            'subnetxmpp':subnetreseauxmpp,
            'xmppip': self.config.ipxmpp,
            'xmppmask': xmppmask,
            'xmppbroadcast': xmppbroadcast,
            'xmppdhcp': xmppdhcp,
            'xmppdhcpserver': xmppdhcpserver,
            'xmppgateway': xmppgateway,
            'xmppmacaddress': xmppmacaddress,
            'xmppmacnotshortened': xmppmacnotshortened,
            'ipconnection':self.ipconnection,
            'portconnection':portconnection,
            'classutil': self.config.classutil,
            'ippublic': self.config.public_ip,
            'geolocalisation': {},
            'remoteservice': remoteservice.proto,
            'regcomplet': self.regcomplet,
            'packageserver': self.config.packageserver,
            'adorgbymachine': base64.b64encode(organizationbymachine()),
            'adorgbyuser': '',
            'kiosk_presence': test_kiosk_presence(),
            'countstart': save_count_start(),
            'keysyncthing': self.deviceid
        }
        try:
            dataobj['md5_conf_monitoring'] = ""
            # self.monitoring_agent_config_file
            if self.config.agenttype not in ['relayserver'] and \
                hasattr(self.config, 'monitoring_agent_config_file') and \
                    self.config.monitoring_agent_config_file != "" and \
                        os.path.exists(self.config.monitoring_agent_config_file):
                            dataobj['md5_conf_monitoring'] =  hashlib.md5(file_get_contents(self.config.monitoring_agent_config_file)).hexdigest()
        except AttributeError:
            logging.warning('conf file monitoring missing')
        except Exception as e:
            logging.error('%s error on file config monitoring'%str(e))
        if self.config.agenttype in ['relayserver']:
            try:
                dataobj['syncthing_port'] = self.config.syncthing_port
            except Exception:
                pass
        if self.geodata is not None:
            dataobj['geolocalisation'] = self.geodata.localisation
        else:
            logging.warning('geolocalisation not defined')
        try:
            if  self.config.agenttype in ['relayserver']:
                dataobj["moderelayserver"] = self.config.moderelayserver
                if dataobj['moderelayserver'] == "dynamic":
                    dataobj['packageserver']['public_ip'] = self.config.ipxmpp
        except Exception:
            dataobj["moderelayserver"] = "static"
        ###################Update agent from MAster#############################
        if self.config.updating == 1:
            dataobj['md5agent'] = Update_Remote_Agent(self.pathagent, True ).get_fingerprint_agent_base()
        ###################End Update agent from MAster#############################
        #todo determination lastusersession to review
        lastusersession = ""
        userlist = list(set([users[0]  for users in psutil.users()]))
        if len(userlist) > 0:
            lastusersession = userlist[0]
        if lastusersession != "":
            dataobj['adorgbyuser'] = base64.b64encode(organizationbyuser(lastusersession))

        dataobj['lastusersession'] = lastusersession
        sys.path.append(self.config.pathplugins)
        for element in os.listdir(self.config.pathplugins):
            if element.endswith('.py') and element.startswith('plugin_'):
                try:
                    mod = __import__(element[:-3])
                    reload(mod)
                    module = __import__(element[:-3]).plugin
                    dataobj['plugin'][module['NAME']] = module['VERSION']
                except Exception as e:
                    logger.error("error loading plugin %s : %s\verify plugin %s"%(element,
                                                                                  str(e),
                                                                                  element))
        #add list scheduler plugins
        dataobj['pluginscheduled'] = self.loadPluginschedulerList()
        #persistence info machine
        self.infomain = dataobj
        self.dataplugininstall = {"plu" : dataobj['plugin'],
                                  "schedule" : dataobj['pluginscheduled'] }
        return dataobj

    def loadPluginschedulerList(self):
        logger.debug("Verify base plugin scheduler")
        plugindataseach = {}
        for element in os.listdir(self.config.pathpluginsscheduled):
            if element.endswith('.py') and element.startswith('scheduling_'):
                f = open(os.path.join(self.config.pathpluginsscheduled,element),'r')
                lignes  = f.readlines()
                f.close()
                for ligne in lignes:
                    if 'VERSION' in ligne and 'NAME' in ligne:
                        l=ligne.split("=")
                        plugin = eval(l[1])
                        plugindataseach[plugin['NAME']] = plugin['VERSION']
                        break
        return plugindataseach

    def module_needed(self):
        finder = ModuleFinder()
        newdescriptorimage = Update_Remote_Agent(self.img_agent)
        for file in newdescriptorimage.get_md5_descriptor_agent()['program_agent']:
            finder.run_script(os.path.join(self.img_agent, file))
            for name, mod in finder.modules.iteritems():
                try:
                    __import__(name.split('.', 1)[0])
                except ImportError:
                    logging.warning('The following python module needs to be installed first: %s'%(name))
                    return True
        for file in newdescriptorimage.get_md5_descriptor_agent()['lib_agent']:
            finder.run_script(os.path.join(self.img_agent, "lib", file))
            for name, mod in finder.modules.iteritems():
                try:
                    __import__(name.split('.', 1)[0])
                except ImportError:
                    logging.warning('The following python module needs to be installed first: %s'%(name))
                    return True
        return False

def createDaemon(optstypemachine, optsconsoledebug, optsdeamon, tglevellog, tglogfile):
    """
        This function create a service/Daemon that will execute a det. task
    """
    try:
        if sys.platform.startswith('win'):
            p = multiprocessing.Process(name='xmppagent',target=doTask, args=(optstypemachine, optsconsoledebug, optsdeamon, tglevellog, tglogfile,))
            p.daemon = True
            p.start()
            p.join()
        else:
            # Store the Fork PID
            pid = os.fork()
            if pid > 0:
                print 'PID: %d' % pid
                os._exit(0)
            doTask(optstypemachine, optsconsoledebug, optsdeamon, tglevellog, tglogfile)
    except OSError, error:
        logging.error("Unable to fork. Error: %d (%s)" % (error.errno, error.strerror))
        logging.error("\n%s"%(traceback.format_exc()))
        os._exit(1)

def tgconf(optstypemachine):
    tg = confParameter(optstypemachine)

    if optstypemachine.lower() in ["machine"]:
        tg.pathplugins = os.path.join(os.path.dirname(os.path.realpath(__file__)), "pluginsmachine")
        tg.pathpluginsscheduled = os.path.join(os.path.dirname(os.path.realpath(__file__)), "descriptor_scheduler_machine")
    else:
        tg.pathplugins = os.path.join(os.path.dirname(os.path.realpath(__file__)), "pluginsrelay")
        tg.pathpluginsscheduled = os.path.join(os.path.dirname(os.path.realpath(__file__)), "descriptor_scheduler_relay")

    while True:
        if tg.Server == "" or tg.Port == "":
            logger.error("Error config ; Parameter Connection missing")
            sys.exit(1)
        if ipfromdns(tg.Server) != "" and check_exist_ip_port(ipfromdns(tg.Server), tg.Port):
            break
        logging.log(DEBUGPULSE,"Unable to connect. (%s : %s) on xmpp server."\
            " Check that %s can be resolved"%(tg.Server,
                                              tg.Port,
                                              tg.Server))
        logging.log(DEBUGPULSE,"verify a information ip or dns for connection AM")
        if ipfromdns(tg.Server) == "" :
            logging.log(DEBUGPULSE, "not resolution adresse : %s "%tg.Server)
        time.sleep(2)
    return tg

def doTask( optstypemachine, optsconsoledebug, optsdeamon, tglevellog, tglogfile):
    processes = []
    queue_recv_tcp_to_xmpp = Queue()
    queueout= Queue()
    #event inter process
    eventkilltcp = Event()
    eventkillpipe = Event()
    file_put_contents(os.path.join(os.path.dirname(os.path.realpath(__file__)),
                                   "pidagent"),
                      "%s"%os.getpid())
    if sys.platform.startswith('win'):
        try:
            result = subprocess.check_output(["icacls",
                                    os.path.join(os.path.dirname(os.path.realpath(__file__)), "pidagent"),
                                    "/setowner",
                                    "pulse",
                                    "/t"], stderr=subprocess.STDOUT)
        except subprocess.CalledProcessError as e:
            pass
    global signalint
    if platform.system()=='Windows':
        # Windows does not support ANSI escapes and we are using API calls to set the console color
        logging.StreamHandler.emit = add_coloring_to_emit_windows(logging.StreamHandler.emit)
    else:
        # all non-Windows platforms are supporting ANSI escapes so we use them
        logging.StreamHandler.emit = add_coloring_to_emit_ansi(logging.StreamHandler.emit)
    # format log more informations
    format = '%(asctime)s - %(levelname)s - %(message)s'
    # more information log
    # format ='[%(name)s : %(funcName)s : %(lineno)d] - %(levelname)s - %(message)s'
    if not optsdeamon :
        if optsconsoledebug :
            logging.basicConfig(level = logging.DEBUG, format=format)
        else:
            logging.basicConfig( level = tglevellog,
                                 format = format,
                                 filename = tglogfile,
                                 filemode = 'a')
    else:
        logging.basicConfig( level = tglevellog,
                             format = format,
                             filename = tglogfile,
                             filemode = 'a')
    if optstypemachine.lower() in ["machine"]:
        sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)),
                                     "pluginsmachine"))
    else:
        sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)),
                                     "pluginsrelay"))

    #### start xmpp process
    p = Process(target=process_xmpp_agent,
                name="xmppagent",
                args=(optstypemachine, optsconsoledebug,
                                       optsdeamon,
                                       tglevellog,
                                       tglogfile,
                                       queue_recv_tcp_to_xmpp,
                                       queueout,
                                       eventkilltcp,
                                       eventkillpipe))
    processes.append(p)
    p.start()

    p = Process(target=process_tcp_serveur, args=(14000,
                                                  optstypemachine,
                                                  optsconsoledebug,
                                                  optsdeamon,
                                                  tglevellog,
                                                  tglogfile,
                                                  queue_recv_tcp_to_xmpp,
                                                  queueout,
                                                  eventkilltcp))
    processes.append(p)
    p.start()

    if sys.platform.startswith('win'):
        logger.debug("_______________________________________________________")
        logger.info("__________ INSTALL SERVER PIPE NAMED WINDOWS __________")
        logger.debug("_______________________________________________________")
        #using event eventkillpipe for signal stop thread
        p = Process(target=process_serverPipe,
                    args=(optstypemachine,
                          optsconsoledebug,
                          optsdeamon,
                          tglevellog,
                          tglogfile,
                          queue_recv_tcp_to_xmpp,
                          queueout,
                          eventkillpipe))
        processes.append(p)
        p.start()


    # completing process
    try:
        for p in processes:
            p.join()
    except KeyboardInterrupt:
        logging.error("TERMINATE PROGRAMM ON CTRL+C")
        os._exit(1)
    except Exception as e:
        logging.error("TERMINATE PROGRAMM ON ERROR : %s"%str(e))
    logging.debug("END PROGRAMM")

class process_xmpp_agent():

    def __init__(self,
                 optstypemachine,
                 optsconsoledebug,
                 optsdeamon,
                 tglevellog,
                 tglogfile,
                 queue_recv_tcp_to_xmpp,
                 queueout,
                 eventkilltcp,
                 eventkillpipe):
        if platform.system()=='Windows':
            # Windows does not support ANSI escapes and we are using API calls to set the console color
            logging.StreamHandler.emit = add_coloring_to_emit_windows(logging.StreamHandler.emit)
        else:
            # all non-Windows platforms are supporting ANSI escapes so we use them
            logging.StreamHandler.emit = add_coloring_to_emit_ansi(logging.StreamHandler.emit)
        # format log more informations
        format = '%(asctime)s - %(levelname)s - %(message)s'
        # more information log
        # format ='[%(name)s : %(funcName)s : %(lineno)d] - %(levelname)s - %(message)s'
        if not optsdeamon :
            if optsconsoledebug :
                logging.basicConfig(level = logging.DEBUG, format=format)
            else:
                logging.basicConfig( level = tglevellog,
                                     format = format,
                                     filename = tglogfile,
                                     filemode = 'a')
        else:
            logging.basicConfig( level = tglevellog,
                                 format = format,
                                 filename = tglogfile,
                                 filemode = 'a')
        self.logger = logging.getLogger()

        self.logger.debug("____________________________________________________________")
        self.logger.debug("_______________ INITIALISATION XMPP AGENT ________________")
        self.logger.debug("____________________________________________________________")
        setgetcountcycle()
        while True:
            setgetrestart()
            logging.log(DEBUGPULSE,"WHILE RESTART VARIABLE %s"%setgetrestart(-1))
            tg = tgconf(optstypemachine)
            xmpp = MUCBot(tg,
                          queue_recv_tcp_to_xmpp,
                          queueout,
                          eventkilltcp,
                          eventkillpipe)

            xmpp.auto_reconnect = False
            xmpp.register_plugin('xep_0030') # Service Discovery
            xmpp.register_plugin('xep_0045') # Multi-User Chat
            xmpp.register_plugin('xep_0004') # Data Forms
            xmpp.register_plugin('xep_0050') # Adhoc Commands
            xmpp.register_plugin('xep_0199', {'keepalive': True,
                                              'frequency': 600,
                                              'interval': 600,
                                              'timeout': 500  })
            xmpp.register_plugin('xep_0077') # In-band Registration
            xmpp['xep_0077'].force_registration = True

            #tg = tgconf(optstypemachine)
            #xmpp.config.__dict__.update(tg.__dict__)
            # Connect to the XMPP server and start processing XMPP stanzas.address=(args.host, args.port)
            if xmpp.config.agenttype in ['relayserver']:
                attempt = True
            else:
                attempt = False
            logging.log(DEBUGPULSE,"connect to %s"%ipfromdns(tg.Server))
            logging.log(DEBUGPULSE,"connect to port %s"%tg.Port)
            time.sleep(5)
            if xmpp.connect(address=(ipfromdns(tg.Server),tg.Port), reattempt=attempt):
                xmpp.process(block=True)
                logging.log(DEBUGPULSE,"terminate infocommand")
                logging.log(DEBUGPULSE,"event for quit loop server tcpserver for kiosk")
                logging.log(DEBUGPULSE,"RESTART %s"%setgetrestart(-1))
                logging.log(DEBUGPULSE,"RESTART VARIABLE %s"%setgetrestart(-1))
                time.sleep(2)
            else:
                logging.log(DEBUGPULSE,"Unable to connect. search alternative")
                setgetrestart(0)
                logging.log(DEBUGPULSE,"RESTART VARIABLE %s"%setgetrestart(-1))
                time.sleep(2)
            if signalint:
                logging.log(DEBUGPULSE,"bye bye Agent CTRL-C")
                try:
                    xmpp.eventkilltcp.set()
                    xmpp.eventkillpipe.set()
                except Exception:
                    pass
                time.sleep(1)
                break
            if xmpp.config.agenttype in ['relayserver']:
                terminateserver(xmpp)

            if setgetrestart(-1) == 0:
                logging.log(DEBUGPULSE,"not restart")
                # verify if signal stop
                # verify if alternative connection
                if os.path.isfile(conffilename("cluster")):
                    # il y a une configuration alternative
                    logging.log(DEBUGPULSE,"analyse alternative alternative connection")
                    logging.log(DEBUGPULSE,"file %s"%conffilename("cluster"))
                    logging.log(DEBUGPULSE, "alternative configuration")
                    setgetcountcycle(1)
                    try:
                        timealternatifars = random.randint(*xmpp.config.timealternatif)
                        logging.log(DEBUGPULSE,"waiting %s for reconection alternatif ARS"%timealternatifars)
                        time.sleep(timealternatifars)
                        newparametersconnect = nextalternativeclusterconnection(conffilename("cluster"))

                        changeconnection( conffilename(xmpp.config.agenttype),
                                        newparametersconnect[2],
                                        newparametersconnect[1],
                                        newparametersconnect[0],
                                        newparametersconnect[3])
                        if newparametersconnect[5] < setgetcountcycle(-1):
                            # if plus d'un cycle fait on relance le configurateur
                            setgetcountcycle()
                            logging.log(DEBUGPULSE,"run subprocess connectionagent on cycle alternatif terminate")
                            nameprogconnection = os.path.join(os.path.dirname(os.path.realpath(__file__)), "connectionagent.py")
                            args = ['python', nameprogconnection, '-t', 'machine']
                            subprocess.call(args)
                            time.sleep(10)
                    except Exception:
                        logging.log(40," ERROR analyse alternative connection")
                        logging.log(40," Check file %s"%conffilename(xmpp.config.agenttype))
        terminateserver(xmpp)

def terminateserver(xmpp):
    #event for quit loop server tcpserver for kiosk
    logging.log(DEBUGPULSE,"terminateserver")
    if  xmpp.config.agenttype in ['relayserver']:
        xmpp.qin.put("quit")
    xmpp.queue_read_event_from_command.put("quit")

    if  xmpp.config.agenttype in ['relayserver']:
        xmpp.managerQueue.shutdown()
    #termine server kiosk
    xmpp.eventkiosk.quit()
    xmpp.eventkilltcp.set()
    xmpp.eventkillpipe.set()
    if sys.platform.startswith('win'):
        try:
            # on debloque le pipe
            fileHandle = win32file.CreateFile("\\\\.\\pipe\\interfacechang",
                            win32file.GENERIC_READ | win32file.GENERIC_WRITE,
                            0, None,
                            win32file.OPEN_EXISTING,
                            0, None)
            win32file.WriteFile(fileHandle, "terminate")
            fileHandle.Close()
        except Exception as e:
            logger.error("\n%s"%(traceback.format_exc()))
            pass
    logging.log(DEBUGPULSE,"wait 2s end thread event loop")
    logging.log(DEBUGPULSE,"terminate manage data sharing")
    time.sleep(2)
    logging.log(DEBUGPULSE,"terminate scheduler")
    xmpp.scheduler.quit()
    logging.log(DEBUGPULSE,"Waiting to stop kiosk server")
    logging.log(DEBUGPULSE,"QUIT")
    logging.log(DEBUGPULSE,"bye bye Agent")
    os._exit(0)


if __name__ == '__main__':
    if sys.platform.startswith('linux') and  os.getuid() != 0:
        print "Agent must be running as root"
        sys.exit(0)
    elif sys.platform.startswith('win') and isWinUserAdmin() ==0 :
        print "Pulse agent must be running as Administrator"
        sys.exit(0)
    elif sys.platform.startswith('darwin') and not isMacOsUserAdmin():
        print "Pulse agent must be running as root"
        sys.exit(0)
    optp = OptionParser()
    optp.add_option("-d", "--deamon",action="store_true",
                 dest="deamon", default=False,
                  help="deamonize process")
    optp.add_option("-t", "--type",
                dest="typemachine", default=False,
                help="Type machine : machine or relayserver")
    optp.add_option("-c", "--consoledebug",action="store_true",
                dest="consoledebug", default = False,
                  help="console debug")

    opts, args = optp.parse_args()
    tg = confParameter(opts.typemachine)
    # termine ssh reverse
    if sys.platform.startswith('win'):
        searchreversesshprocess = os.path.join(os.environ["ProgramFiles"], "Pulse", "bin")
        for f in [ os.path.join(os.environ["ProgramFiles"], "Pulse", "bin", x) \
                    for x in os.listdir(searchreversesshprocess) if x[-4:]== ".pid"]:
            pid= file_get_contents(f).strip(" \n\r\t")
            cmd = "taskkill /F /PID %s"%str(pid)
            logger.info(cmd)
            simplecommand(cmd)
            os.remove(f)

    if not opts.deamon :
        doTask(opts.typemachine, opts.consoledebug, opts.deamon, tg.levellog, tg.logfile)
    else:
        createDaemon(opts.typemachine, opts.consoledebug, opts.deamon, tg.levellog, tg.logfile)
