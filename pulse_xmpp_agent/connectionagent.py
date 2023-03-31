#!/usr/bin/env python
# -*- coding: utf-8; -*-
# SPDX-FileCopyrightText: 2016-2023 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-2.0-or-later

import shutil
import sys
import os
import logging
import sleekxmpp
import platform
import subprocess
import base64
import time
import json
import re
from sleekxmpp import jid
import traceback
from sleekxmpp.exceptions import IqError, IqTimeout
from lib.networkinfo import networkagentinfo, organizationbymachine,\
    organizationbyuser, powershellgetlastuser
from lib.configuration import  confParameter, changeconnection,\
    alternativeclusterconnection, nextalternativeclusterconnection,\
        substitutelist, changeconfigurationsubtitute
from lib.agentconffile import conffilename, conffilenametmp, rotation_file
from lib.utils import DEBUGPULSE, getIpXmppInterface,\
        subnetnetwork, check_exist_ip_port, ipfromdns,\
            isWinUserAdmin, isMacOsUserAdmin, file_put_contents, \
                      getRandomName, AESCipher, refreshfingerprintconf, \
                        geolocalisation_agent, \
                        serialnumbermachine, offline_search_kb

from optparse import OptionParser

from threading import Timer
from lib.logcolor import  add_coloring_to_emit_ansi, add_coloring_to_emit_windows
from lib.syncthingapirest import syncthing, syncthingprogram, iddevice
# Additionnal path for library and plugins
pathbase = os.path.abspath(os.curdir)
pathplugins = os.path.join(pathbase, "pluginsmachine")
pathplugins_relay = os.path.join(pathbase, "pluginsrelay")
sys.path.append(pathplugins)

sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), "lib"))

logger = logging.getLogger()


if sys.version_info < (3, 0):
    reload(sys)
    sys.setdefaultencoding('utf8')
else:
    raw_input = input

class MUCBot(sleekxmpp.ClientXMPP):
    def __init__(self,conf):#jid, password, room, nick):
        self.agent_machine_name= conf.jidagent
        newjidconf = conf.jidagent.split("@")
        resourcejid=newjidconf[1].split("/")
        resourcejid[0]=conf.confdomain
        newjidconf[0] = getRandomName(10,"conf")
        self.HostNameSystem = platform.node().split('.')[0]
        conf.jidagent = f"{newjidconf[0]}@{resourcejid[0]}/{self.HostNameSystem}"
        self.agentmaster =jid.JID("master@pulse")
        self.session = ""
        logger.info(f"start machine {conf.jidagent} Type {conf.agenttype}")

        sleekxmpp.ClientXMPP.__init__(self, conf.jidagent, conf.confpassword)
        self.config = conf

        # Create tmp config file
        namefileconfiguration = conffilename(self.config.agenttype)
        namefileconfigurationtmp = conffilenametmp(self.config.agenttype)
        shutil.copyfile(namefileconfiguration, namefileconfigurationtmp)

        # Update level log for sleekxmpp
        handler_sleekxmpp = logging.getLogger('sleekxmpp')
        handler_sleekxmpp.setLevel(self.config.log_level_sleekxmpp)

        if not hasattr(self.config, 'geoservers'):
            self.geoservers = "ifconfig.co, if.siveo.net"

        self.ippublic = None
        self.geodata = None
        if self.config.geolocalisation:
            self.geodata = geolocalisation_agent(typeuser = 'nomade',
                                                 geolocalisation=self.config.geolocalisation,
                                                 ip_public=None,
                                                 strlistgeoserveur=self.config.geoservers)

            self.ippublic = self.geodata.get_ip_public()

        if self.ippublic == "" or self.ippublic is None:
            self.ippublic = None

        if not hasattr(self.config, 'sub_assessor'):
            self.sub_assessor = self.agentmaster
        elif isinstance(self.config.sub_assessor, list) and\
                    len(self.config.sub_assessor) > 0:
            self.sub_assessor = jid.JID(self.config.sub_assessor[0])
        else:
            self.sub_assessor = jid.JID(self.config.sub_assessor)
        if self.sub_assessor.bare == "":
            self.sub_assessor = self.agentmaster

        self.xmpplog(
            f"Starting configurator on machine {conf.jidagent}. Assessor : {self.sub_assessor}",
            type='conf',
            priority=-1,
            action="xmpplog",
            who=self.HostNameSystem,
            module="Configuration",
            date=None,
            fromuser=self.boundjid.bare,
            touser="",
        )

        #self.config.masterchatroom="%s/MASTER"%self.config.confjidchatroom

        self.add_event_handler("register", self.register, threaded=True)
        self.add_event_handler("session_start", self.start)
        self.add_event_handler('message', self.message)
        try:
            self.config.syncthing_on
        except NameError:
            self.config.syncthing_on = False

        if self.config.syncthing_on:
            logger.info("---initialisation syncthing---")
            self.deviceid=""
            # initialise syncthing
            if logger.level <= 10:
                console = False
                browser = True

            if sys.platform.startswith('linux'):
                # if self.config.agenttype in ['relayserver']:
                # self.fichierconfsyncthing = "/var/lib/syncthing/.config/syncthing/config.xml"
                # else:
                self.fichierconfsyncthing = os.path.join(os.path.expanduser('~pulseuser'),
                                                        ".config","syncthing","config.xml")

                tmpfile = "/tmp/confsyncting.txt"
            elif sys.platform.startswith('win'):
                self.fichierconfsyncthing = "%s\\pulse\\etc\\syncthing\\config.xml"%os.environ['programfiles']
                tmpfile = "%s\\Pulse\\tmp\\confsyncting.txt"%os.environ['programfiles']
            elif sys.platform.startswith('darwin'):
                self.fichierconfsyncthing = os.path.join("/opt", "Pulse",
                                                    "etc", "syncthing", "config.xml")
                tmpfile = "/tmp/confsyncting.txt"

            # Before reinitialisation we remove the config.xml file
            try:
                os.remove(self.fichierconfsyncthing)
            except :
                pass
            self.Ctrlsyncthingprogram = syncthingprogram(agenttype=self.config.agenttype)
            self.Ctrlsyncthingprogram.restart_syncthing()
            time.sleep(4)
            try:
                self.syncthing = syncthing(configfile = self.fichierconfsyncthing)
                if logger.level <= 10:
                    self.syncthing.save_conf_to_file(tmpfile)
                else:
                    try:
                        os.remove(tmpfile)
                    except :
                        pass
                time.sleep(1)
                if os.path.isfile(self.fichierconfsyncthing):
                    try:
                        self.deviceid = iddevice(configfile=self.fichierconfsyncthing)
                    except Exception:
                        pass

                logger.debug(f"device local syncthing : [{self.deviceid}]")
            except Exception as e:
                logger.error(
                    f"The initialisation of syncthing failed. We got the error {str(e)}"
                )
                informationerror = traceback.format_exc()
                logger.error("\n%s" % informationerror)
                logger.error("Syncthing is not functionnal. Using the degraded mode")
                confsyncthing = {"action": "resultconfsyncthing",
                                "sessionid" : getRandomName(6, "confsyncthing"),
                                "ret" : 255,
                                "data":  { 'errorsyncthingconf': informationerror}}
                self.send_message(mto =  self.sub_assessor,
                                    mbody = json.dumps(confsyncthing),
                                    mtype = 'chat')
    # syncthing

    def start(self, event):
        self.get_roster()
        self.send_presence()

        self.config.ipxmpp = getIpXmppInterface(self.config.confserver, self.config.confport)
        self.infos_machine_assessor()

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
        if touser == "":
            touser = self.boundjid.bare
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
        msgbody = {'data': data, 'action': 'xmpplog', 'sessionid': sessionname}
        if not hasattr(self.config, 'sub_logger'):
            self.sub_logger = self.agentmaster
        elif isinstance(self.config.sub_logger, list) and\
                len(self.config.sub_logger) > 0:
            self.sub_logger = jid.JID(self.config.sub_logger[0])
        else:
            self.sub_logger = jid.JID(self.config.sub_logger)
        self.send_message(  mto = self.sub_logger,
                            mbody=json.dumps(msgbody),
                            mtype='chat')


    def register(self, iq):
        """ This function is called for automatic registration"""
        resp = self.Iq()
        resp['type'] = 'set'
        resp['register']['username'] = self.boundjid.user
        resp['register']['password'] = self.password
        try:
            resp.send(now=True)
            logging.info(f"Account created for {self.boundjid}")
        except IqError as e:
            if e.iq['error']['code'] == "409":
                logging.debug(
                    f"Could not register account {resp['register']['username']} : User already exists"
                )
            else:
                logging.debug(
                    f"Could not register account {resp['register']['username']} : {e.iq['error']['text']}"
                )
        except IqTimeout:
            logging.error("No response from server.")
            self.disconnect()

    def adddevicesyncthing(self, keydevicesyncthing, namerelay, address = ["dynamic"]):
        resource = jid.JID(namerelay).user[2:]
        if jid.JID(namerelay).bare == "rspulse@pulse":
            resource = "pulse"
        if resource=="":
            resource = namerelay
        if not self.is_exist_device_in_config(keydevicesyncthing):
            logger.debug(
                f"add device syncthing name : {namerelay} key: {keydevicesyncthing}"
            )
            dsyncthing_tmp = self.syncthing.\
                    create_template_struct_device( resource,
                                               str(keydevicesyncthing),
                                               introducer = True,
                                               autoAcceptFolders=True,
                                               address = address)
            logger.debug("add device [%s]syncthing to ars %s\n%s"%(keydevicesyncthing,
                                                                 namerelay,
                                                                 json.dumps(dsyncthing_tmp,
                                                                            indent = 4)))
            self.syncthing.config['devices'].append(dsyncthing_tmp)
        else:
            # Change conf for introducer and autoAcceptFolders
            for dev in self.syncthing.config['devices']:
                if dev['name'] == namerelay or dev['deviceID'] == keydevicesyncthing:
                    dev["introducer"] = True
                    dev["autoAcceptFolders"] = True
                if dev['name'] == jid.JID(namerelay).resource:
                    dev['name'] = "pulse"
                dev['addresses'] = address
                logger.debug("Device [%s] syncthing to ars %s\n%s"%( dev['deviceID'],
                                                                    dev['name'],
                                                                    json.dumps( dev,
                                                                                indent = 4)))

    def is_exist_device_in_config(self, keydevicesyncthing):
        return any(
            device['deviceID'] == keydevicesyncthing
            for device in self.syncthing.devices
        )

    def is_format_key_device(self, keydevicesyncthing):
        if len(str(keydevicesyncthing)) != 63:
            logger.warning("The size of the syncthing key is incorrect.")
        listtest = keydevicesyncthing.split("-")
        if len(listtest) != 8:
            logger.error("group key diff of 8")
            return False
        for z in listtest:
            if len(z) != 7:
                logger.error("size group key diff of 7")
                return False
            index = 1 + 1
        return True

    def message(self, msg):
        if msg['body']=="This room is not anonymous" or msg['subject']=="Welcome!":
            return
        try :
            data = json.loads(msg['body'])
        except Exception:
            return

        if self.session == data['sessionid'] and \
                data['action'] == "resultconnectionconf":
            if data['ret'] == 0:
                fromagent = str(msg['from'].bare)
                if fromagent == self.sub_assessor:
                    #resultconnectionconf
                    logging.info("Resultat data : %s"%json.dumps(data,
                                                                indent=4,
                                                                sort_keys=True))
                    if len(data['data']) == 0 :
                        logging.error("Verify table cluster : has_cluster_ars")
                        sys.exit(0)
                    logging.info("Start relay server agent configuration\n%s"%json.dumps(data['data'],
                                                                                        indent=4,
                                                                                        sort_keys=True))
                    logging.log(DEBUGPULSE, "write new config")

                    if self.config.syncthing_on:
                        try:
                            if "syncthing" in data:
                                self.syncthing.config['options']['globalAnnounceServers'] = [data["syncthing"]]
                                self.syncthing.config['options']['relaysEnabled'] = False
                                self.syncthing.config['options']['localAnnounceEnabled'] = False
                                self.syncthing.del_folder("default")
                                if sys.platform.startswith('win'):
                                    defaultFolderPath = "%s\\pulse\\var\\syncthing"%os.environ['programfiles']
                                elif sys.platform.startswith('linux'):
                                    defaultFolderPath = os.path.join(os.path.expanduser('~pulseuser'),
                                                                    "syncthing")
                                elif sys.platform.startswith('darwin'):
                                    defaultFolderPath = os.path.join("/",
                                                                    "Library",
                                                                    "Application Support",
                                                                    "Pulse",
                                                                    "var", "syncthing")
                                if not os.path.exists(defaultFolderPath):
                                    os.mkdir(defaultFolderPath)
                                    os.chmod(defaultFolderPath, 0o777)
                                self.syncthing.config['options']['defaultFolderPath'] = defaultFolderPath

                            if self.deviceid != "":
                                if len(data['data'][0]) >= 7:
                                    for x in data['data']:
                                        if self.is_format_key_device(str(x[5])):
                                            self.adddevicesyncthing(
                                                str(x[5]),
                                                str(x[2]),
                                                address=[f"tcp4://{x[0]}:{x[6]}"],
                                            )
                                logger.debug(f"synchro config {self.syncthing.is_config_sync()}")
                                logging.log(DEBUGPULSE, "New syncthing configuration written")
                                self.syncthing.validate_chang_config()
                                time.sleep(2)
                                filesyncthing = os.path.join(os.path.dirname(os.path.realpath(__file__)),
                                            "baseconfigsyncthing.xml")
                                logging.log(DEBUGPULSE, "copy configuration syncthing")
                                shutil.copyfile(self.fichierconfsyncthing, filesyncthing)
                                logger.debug("%s"%json.dumps(self.syncthing.config, indent =4))
                                if logging.getLogger().level == logging.DEBUG:
                                    dataconf = json.dumps(self.syncthing.config, indent =4)
                                else:
                                    dataconf = 're-setup syncthing ok'

                                confsyncthing = { "action": "resultconfsyncthing",
                                                "sessionid" : getRandomName(6, "confsyncthing"),
                                                "ret" : 0,
                                                "base64" : False,
                                                "data":  { 'syncthingconf': 're-setup syncthing ok\n%s'%dataconf}}

                                self.send_message(mto =  msg['from'],
                                                mbody = json.dumps(confsyncthing),
                                                mtype = 'chat')
                        except Exception:
                            confsyncthing = {
                                "action": "resultconfsyncthing",
                                "sessionid": getRandomName(6, "confsyncthing"),
                                "ret": 255,
                                "data": {
                                    'errorsyncthingconf': f"{traceback.format_exc()}"
                                },
                            }
                            self.send_message(mto =  msg['from'],
                                                mbody = json.dumps(confsyncthing),
                                                mtype = 'chat')
                    try:
                        if "substitute" in data:
                            logger.debug("substitute information")
                            changeconfigurationsubtitute(conffilenametmp(opts.typemachine),
                                                         data['substitute'])
                    except Exception as e:
                        logger.error("change configuration subtitute ko")

                    try:
                        changeconnection(conffilenametmp(opts.typemachine),
                                        data['data'][0][1],
                                        data['data'][0][0],
                                        data['data'][0][2],
                                        data['data'][0][3])
                        try:
                            #write alternative configuration
                            alternativeclusterconnection(conffilenametmp("cluster"),
                                                         data['data'])
                            alternativeclusterconnection(conffilename("cluster"),
                                                         data['data'])
                            #go to next ARS
                            nextalternativeclusterconnection(conffilenametmp("cluster"))

                            namefileconfiguration = conffilename(self.config.agenttype)
                            namefileconfigurationtmp = conffilenametmp(self.config.agenttype)
                            logger.debug("rotate configuration")
                            rotation_file(namefileconfiguration)
                            logger.debug("write new configuration")
                            shutil.move(namefileconfigurationtmp,namefileconfiguration)
                            logger.debug("make finger print conf file")
                            refreshfingerprintconf(opts.typemachine)
                        except Exception as configuration_error:
                            logger.error("An error occured while modifying the configuration")
                            logger.error(f"We obtained the error {configuration_error}")
                            logger.error(f"We hit the backtrace {traceback.format_exc()} ")

                    except Exception:
                        # We failed to read the configuration file. Trying with the old version for compatibility.
                        try:
                            logger.debug("old configuration structure")
                            changeconnection(conffilenametmp(opts.typemachine),
                                        data['data'][1],
                                        data['data'][0],
                                        data['data'][2],
                                        data['data'][3])
                        except Exception as configuration_error:
                            logger.error("An error occured while modifying the configuration in old format.")
                            logger.error(f"We obtained the error {configuration_error}")
                            logger.error(f"The data variable contains the value: {data}")
                            logger.error(f"We hit the backtrace {traceback.format_exc()} ")
            else:
                logging.error("The configuration failed.")
                logging.error(
                    f"The AES key may be invalid. On this machine, this is configured to use the key {self.config.keyAES32}"
                )
                logging.error("Please check on the server on the /etc/pulse-xmpp-agent-substitute/assessor_agent.ini.local")
            self.disconnect(wait=5)

    def terminate(self):
        self.disconnect()

    def muc_message(self, msg):
        pass

    def infosubstitute(self):
        return substitutelist().parameterssubtitute()

    def infos_machine_assessor(self):
        #envoi information
        dataobj=self.seachInfoMachine()
        self.session = getRandomName(10,"session")
        dataobj['sessionid'] = self.session
        dataobj['base64'] = False
        dataobj['action'] = "assessor_agent"
        dataobj['substitute'] = self.infosubstitute()
        msginfo={
            'action': "assessor_agent",
            'base64': False,
            'sessionid': self.session,
            'data': dataobj,
            'ret': 0
            }
        self.config.keyAES32 = [str(x.strip()) \
            for x in re.split(r'[;,:@\(\)\[\]\|\s]\s*', self.config.keyAES32) \
                if x.strip() != "" and len(x) == 32][0]
        cipher = AESCipher(self.config.keyAES32)
        msginfo['data']['codechaine'] = cipher.encrypt(str(self.boundjid))

        #----------------------------------
        print "affiche object"
        print json.dumps(dataobj, indent = 4)
        #----------------------------------
        self.send_message(mto = self.sub_assessor,
                            mbody = json.dumps(msginfo),
                            mtype = 'chat')

    def seachInfoMachine(self):
        er = networkagentinfo("config","inforegle")
        er.messagejson['info'] = self.config.information
        for t in er.messagejson['listipinfo']:
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
                break

        subnetreseauxmpp =  subnetnetwork(self.config.ipxmpp, xmppmask)
        BOOLFILECOMPLETREGISTRATION = os.path.join(os.path.dirname(os.path.realpath(__file__)),
                                                                   "BOOLFILECOMPLETREGISTRATION")
        self.FullRegistration = False
        if os.path.exists(BOOLFILECOMPLETREGISTRATION):
            self.FullRegistration = True
            os.remove(BOOLFILECOMPLETREGISTRATION)
        dataobj = {
            'action': 'connectionconf',
            'from': self.config.jidagent,
            'compress': False,
            'deployment': self.config.jidchatroomcommand,
            'who': f"{self.config.jidchatroomcommand}/{self.config.NickName}",
            'machine': self.config.NickName,
            'platform': platform.platform(),
            'completedatamachine': base64.b64encode(json.dumps(er.messagejson)),
            'plugin': {},
            'portxmpp': self.config.Port,
            'serverxmpp': self.config.Server,
            'agenttype': self.config.agenttype,
            'baseurlguacamole': self.config.baseurlguacamole,
            'subnetxmpp': subnetreseauxmpp,
            'xmppip': self.config.ipxmpp,
            'xmppmask': xmppmask,
            'xmppbroadcast': xmppbroadcast,
            'xmppdhcp': xmppdhcp,
            'xmppdhcpserver': xmppdhcpserver,
            'xmppgateway': xmppgateway,
            'xmppmacaddress': xmppmacaddress,
            'xmppmacnotshortened': xmppmacnotshortened,
            'classutil': self.config.classutil,
            'ippublic': self.ippublic,
            'geolocalisation': {},
            'adorgbymachine': base64.b64encode(organizationbymachine()),
            'adorgbyuser': '',
            'agent_machine_name': self.agent_machine_name,
            'uuid_serial_machine': serialnumbermachine(),
            'regcomplet': self.FullRegistration,
            'system_info': offline_search_kb().search_system_info_reg(),
        }
        if self.geodata is not None:
            dataobj['geolocalisation'] = self.geodata.localisation
        else:
            logging.warning('geolocalisation disabled')
        lastusersession = powershellgetlastuser()
        if lastusersession == "":
            try:
                lastusersession = os.environ['USERNAME']
            except KeyError as e:
                lastusersession = ""
                logging.error(str(e))
        if lastusersession != "":
            dataobj['adorgbyuser'] = base64.b64encode(organizationbyuser(lastusersession))
        return dataobj

def createDaemon(optstypemachine, optsconsoledebug, optsdeamon, tglevellog, tglogfile):
    """
        This function create a service/Daemon that will execute a det. task
    """
    try:
        if sys.platform.startswith('win'):
            import multiprocessing
            p = multiprocessing.Process(name='xmppagent',
                                        target=doTask,
                                        args=(optstypemachine,
                                              optsconsoledebug,
                                              optsdeamon,
                                              tglevellog,
                                              tglogfile,))
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
        traceback.print_exc(file=sys.stdout)
        os._exit(1)


def doTask( optstypemachine, optsconsoledebug, optsdeamon, tglevellog, tglogfile):
    file_put_contents(os.path.join(os.path.dirname(os.path.realpath(__file__)),
                                   "INFOSTMP",
                                   "pidconnection"), "%s"%os.getpid())
    if sys.platform.startswith('win'):
        try:
            result = subprocess.check_output(["icacls",
                                    os.path.join(os.path.dirname(os.path.realpath(__file__)),
                                                 "INFOSTMP",
                                                 "pidconnection"),
                                    "/setowner",
                                    "pulse",
                                    "/t"], stderr=subprocess.STDOUT)
        except subprocess.CalledProcessError as e:
            pass

    if platform.system()=='Windows':
        # Windows does not support ANSI escapes and we are using API calls to set the console color
        logging.StreamHandler.emit = add_coloring_to_emit_windows(logging.StreamHandler.emit)
    else:
        # all non-Windows platforms are supporting ANSI escapes so we use them
        logging.StreamHandler.emit = add_coloring_to_emit_ansi(logging.StreamHandler.emit)
    # format log more informations
    format = '%(asctime)s - %(levelname)s - (CONF)%(message)s'
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
        sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), "pluginsmachine"))
    else:
        sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), "pluginsrelay"))
    # Setup the command line arguments.
    tg = confParameter(optstypemachine)

    if optstypemachine.lower() in ["machine"]:
        tg.pathplugins = os.path.join(os.path.dirname(os.path.realpath(__file__)), "pluginsmachine")
    else:
        tg.pathplugins = os.path.join(os.path.dirname(os.path.realpath(__file__)),
                                      "pluginsrelay")

    while True:
        if not tg.confserver.strip():
            tg = confParameter(optstypemachine)

        if ipfromdns(tg.confserver) != "" and \
            check_exist_ip_port(ipfromdns(tg.confserver), tg.confport):
            break
        logging.error("The connector failed.")
        logging.error("Unable to connect to %s:%s." %(tg.confserver,
                                                      tg.confport))
        if ipfromdns(tg.confserver) == "" :
            logging.log(DEBUGPULSE, "We cannot contact: %s " % tg.confserver)

        time.sleep(2)


    if tg.agenttype != "relayserver":
        xmpp = MUCBot(tg)
        xmpp.register_plugin('xep_0030') # Service Discovery
        xmpp.register_plugin('xep_0045') # Multi-User Chat
        xmpp.register_plugin('xep_0004') # Data Forms
        xmpp.register_plugin('xep_0050') # Adhoc Commands
        xmpp.register_plugin('xep_0199', {'keepalive': True,
                                          'frequency':600,
                                          'interval': 600,
                                          'timeout': 500  })
        xmpp.register_plugin('xep_0077') # In-band Registration
        xmpp['xep_0077'].force_registration = True

        # Connect to the XMPP server and start processing XMPP
        if xmpp.connect(address=(ipfromdns(tg.confserver),tg.confport)):
            t = Timer(300, xmpp.terminate)
            t.start()
            xmpp.process(block=True)
            t.cancel()
            logging.log(DEBUGPULSE,"bye bye connecteur")
            namefilebool = os.path.join(os.path.dirname(os.path.realpath(__file__)),
                                        "BOOLCONNECTOR")
            fichier= open(namefilebool,"w")
            fichier.close()
        else:
            logging.log(DEBUGPULSE,"Unable to connect to %s" % tg.confserver)
    else:
        logging.log(DEBUGPULSE,"Warning: A relay server holds a Static "\
            "configuration. Do not run configurator agent on relay servers.")

if __name__ == '__main__':
    if sys.platform.startswith('linux') and  os.getuid() != 0:
        logging.error("Agent must be running as root")
        sys.exit(0)
    elif sys.platform.startswith('win') and isWinUserAdmin() == 0 :
        logging.error("Medulla agent must be running as Administrator")
        sys.exit(0)
    elif sys.platform.startswith('darwin') and not isMacOsUserAdmin():
        logging.error("Medulla agent must be running as root")
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

    if not opts.deamon :
        doTask(opts.typemachine, opts.consoledebug, opts.deamon, tg.levellog, tg.logfile)
    else:
        createDaemon(opts.typemachine, opts.consoledebug, opts.deamon, tg.levellog, tg.logfile)
