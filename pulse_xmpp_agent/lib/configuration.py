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
#
# file : lib/configuration.py
#
import netifaces
import json
import sys
import platform
import os
import logging
import ConfigParser
import utils
import random
from agentconffile import conffilename
from sleekxmpp import jid
from agentconffile import directoryconffile
from utils import ipfromdns
import re

logger = logging.getLogger()

def changeconfigurationsubtitute(conffile, confsubtitute):
    """
    This function allow to modify the machine agent to use substitute by default

    Args:
    conffile: the configuration file to modify
    confsubtitute: the substitute to add in the configuration file

    """
    Config = ConfigParser.ConfigParser()
    Config.read(conffile)
    if not Config.has_section('substitute'):
        Config.add_section('substitute')
    for t in confsubtitute['conflist']:
        Config.set('substitute', t, ",".join(confsubtitute[t]))
    logger.info("write parameter subtitute")
    with open(conffile, 'w') as configfile:
        Config.write(configfile)

def changeconnection(conffile, port, ipserver, jidrelayserver, baseurlguacamole):
    """
        This function allow to modify default configuration.

        Args:
        conffile: the configuration file to modify
        port: the new port to use ( section connection )
        ipserver:  the new IP of the main server ( section connection )
        jidrelayserver: the new jid of the relayserver ( section global )
        baseurlguacamole: the url used for guacamole ( section type )
    """
    Config = ConfigParser.ConfigParser()
    Config.read(conffile)
    domain = jid.JID(jidrelayserver).domain
    if not Config.has_option("configuration_server", "confdomain"):
        logger.warning("confdomain parameter missing in configuration_server")
        logger.warning("parameters confdomain in configuration_server initialiastion value\"pulse\"")
        Config.set(
            'configuration_server',
            'confdomain',
            "pulse")
    Config.set('chat', 'domain', domain)
    Config.set('connection', 'port', str(port))
    Config.set('connection', 'server', ipfromdns(str(ipserver)))
    Config.set('global', 'relayserver_agent', str(jidrelayserver))
    Config.set('type', 'guacamole_baseurl', str(baseurlguacamole))
    with open(conffile, 'w') as configfile:
        Config.write(configfile)

def alternativeclusterconnection(conffile, data):
    """
    This function allow to add a alternative cluster.
    Args:
        conffile: the configuration file in which we add the alternative cluster
        data: the informations about the cluster
    """
    # todo del of list the ars without ip
    #for arsdataconection in data:
        #if ipfromdns(str(arsdataconection[0])) != "" and check_exist_ip_port(ipfromdns(str(arsdataconection[0])), str(arsdataconection[1])):
            #print ipfromdns(str(arsdataconection[0]))
    with open(conffile, 'w') as configfile:
        if len(data) != 0:
            listalternative = [str(x[2]) for x in data]
            nb_alternativeserver =  len(listalternative)
            configfile.write("[alternativelist]" + os.linesep)
            configfile.write("listars = %s%s"%(",".join(listalternative), os.linesep))
            configfile.write("nbserver = %s%s"%(nb_alternativeserver, os.linesep))
            configfile.write("nextserver = 1%s"%os.linesep)
            for arsdataconection in data:
                configfile.write("[%s]%s"%(str(arsdataconection[2]),os.linesep))
                configfile.write("port = %s%s"%(str(arsdataconection[1]),os.linesep))
                configfile.write("server = %s%s"%(ipfromdns(str(str(arsdataconection[0]))),os.linesep))
                configfile.write("guacamole_baseurl = %s%s"%(str(arsdataconection[3]),
                                                             os.linesep))
        else:
            if os.path.isfile(conffile):
                os.unlink(conffile)

def nextalternativeclusterconnection(conffile):
    """
    This function allow to add more alternative clusters

    Args:
        conffile: the configuration file to modify
    """
    if not os.path.isfile(conffile):
        return []

    Config = ConfigParser.ConfigParser()
    Config.read(conffile)

    nextserver          = Config.getint('alternativelist', 'nextserver')
    nbserver            = Config.getint('alternativelist', 'nbserver')
    listalternative     = Config.get('alternativelist', 'listars').split(",")

    serverjid = listalternative[nextserver-1]

    port              = Config.get(serverjid, 'port')
    server            = Config.get(serverjid, 'server')
    guacamole_baseurl = Config.get(serverjid, 'guacamole_baseurl')
    try:
        domain = str(serverjid).split("@")[1].split("/")[0]
    except:
        domain = str(serverjid)
    nextserver = nextserver + 1
    if nextserver > nbserver:
        nextserver = 1

    Config.set('alternativelist', 'nextserver', nextserver)

    # Writing our configuration file to 'example.cfg'
    with open(conffile, 'wb') as configfile:
        Config.write(configfile)

    return [serverjid, server, port, guacamole_baseurl, domain, nbserver]


# Singleton/SingletonDecorator.py
class SingletonDecorator:
    def __init__(self, klass):
        self.klass = klass
        self.instance = None

    def __call__(self, *args, **kwds):
        if self.instance == None:
            self.instance = self.klass(*args, **kwds)
        return self.instance


def infos_network_packageserver():
    """
    This function allow to determine the port and the IP of the package Server.

    Returns:
        the port and the public IP of the packageserver
    """

    namefileconfig = os.path.join(
        'etc',
        'mmc',
        'pulse2',
        'package-server',
        'package-server.ini')
    namefileconfiglocal = os.path.join(
        'etc',
        'mmc',
        'pulse2',
        'package-server',
        'package-server.ini.local')
    public_ip = ipfromdns(
        loadparameters(
            namefileconfiglocal,
            "main",
            "public_ip"))
    if public_ip == "":
        public_ip = ipfromdns(
            loadparameters(
                namefileconfig,
                "main",
                "public_ip"))
    port = loadparameters(namefileconfiglocal, "main", "port")
    if port == "":
        port = loadparameters(namefileconfig, "main", "port")
    return {'port': port, 'public_ip': public_ip}


def loadparameters(namefile, group, key):
    """
    This function allow to obtain the parameters from group and key

    Args:
        namefile: The configuration file where are stored the informations
        group:    The group in the config file
        key:      The key where is stored the needed information

    Returns:
        the Value defined by the group/key couple.
    """

    Config = ConfigParser.ConfigParser()
    Config.read(namefile)
    value = ""
    if Config.has_option("group", "key"):
        value = Config.get('group', 'key')
    return value

class substitutelist:
    def __init__(self):
        Config = ConfigParser.ConfigParser()
        namefileconfig = conffilename('machine')
        Config.read(namefileconfig)
        if os.path.exists(namefileconfig + ".local"):
            Config.read(namefileconfig + ".local")
        #################substitute####################

        self.sub_inventory = ["master@pulse"]
        self.sub_subscribe = ["master@pulse"]
        self.sub_registration = ["master@pulse"]
        self.sub_assessor = ["master@pulse"]
        self.sub_logger = ["log@pulse", "master@pulse"]
        self.sub_monitoring = ["master@pulse"]

        if Config.has_option('substitute', 'subscription'):
            sub_subscribelocal = Config.get('substitute', 'subscription')
            self.sub_subscribe = [x.strip() for x in sub_subscribelocal.split(",")]

        if Config.has_option('substitute', 'inventory'):
            sub_inventorylocal = Config.get('substitute', 'inventory')
            self.sub_inventory = [x.strip() for x in sub_inventorylocal.split(",")]

        if Config.has_option('substitute', 'registration'):
            sub_registrationlocal = Config.get('substitute', 'registration')
            self.sub_registration = [x.strip() for x in sub_registrationlocal.split(",")]

        if Config.has_option('substitute', 'assessor'):
            sub_assessorlocal = Config.get('substitute', 'assessor')
            self.sub_assessor = [x.strip() for x in sub_assessorlocal.split(",")]

        if Config.has_option('substitute', 'logger'):
            sub_loggerlocal = Config.get('substitute', 'logger')
            self.sub_logger = [x.strip() for x in sub_loggerlocal.split(",")]

        if Config.has_option('substitute', 'monitoring'):
            sub_monitoringlocal = Config.get('substitute', 'monitoring')
            self.sub_monitoring = [x.strip() for x in sub_monitoringlocal.split(",")]

    def parameterssubtitute(self):
        conflist = []
        data={ 'subscription': self.sub_subscribe,
               'inventory': self.sub_inventory,
               'registration': self.sub_registration,
               'assessor': self.sub_assessor,
               'logger': self.sub_logger,
               'monitoring': self.sub_monitoring}
        for t in data:
            #if len(data[t]) == 1 and data[t][0] == "master@pulse": continue
            conflist.append(t)
        data['conflist'] = conflist
        return data

class confParameter:
    def __init__(self, typeconf='machine'):
        Config = ConfigParser.ConfigParser()
        namefileconfig = conffilename(typeconf)
        Config.read(namefileconfig)
        if os.path.exists(namefileconfig + ".local"):
            Config.read(namefileconfig + ".local")
        self.packageserver = {}
        self.Port = Config.get('connection', 'port')
        self.Server = ipfromdns(Config.get('connection', 'server'))
        self.passwordconnection = Config.get('connection', 'password')
        self.nameplugindir = os.path.dirname(namefileconfig)

        #parameters AM and kiosk tcp server
        self.am_local_port = 8765
        self.kiosk_local_port = 8766
        if Config.has_option('kiosk', 'am_local_port'):
            self.am_local_port = Config.getint('kiosk', 'am_local_port')
        if Config.has_option('kiosk', 'kiosk_local_port'):
            self.kiosk_local_port = Config.getint('kiosk', 'kiosk_local_port')

        self.sub_inventory = ["master@pulse"]
        self.sub_subscribe = ["master@pulse"]
        self.sub_registration = ["master@pulse"]
        self.sub_assessor = ["master@pulse"]
        self.sub_monitoring= ["master@pulse"]
        self.sub_logger = ["log@pulse", "master@pulse"]

        if Config.has_option('substitute', 'subscription'):
            sub_subscribelocal = Config.get('substitute', 'subscription')
            self.sub_subscribe = [x.strip() for x in sub_subscribelocal.split(",")]

        if Config.has_option('substitute', 'inventory'):
            sub_inventorylocal = Config.get('substitute', 'inventory')
            self.sub_inventory = [x.strip() for x in sub_inventorylocal.split(",")]

        if Config.has_option('substitute', 'registration'):
            sub_registrationlocal = Config.get('substitute', 'registration')
            self.sub_registration = [x.strip() for x in sub_registrationlocal.split(",")]

        if Config.has_option('substitute', 'monitoring'):
            sub_monitoringlocal = Config.get('substitute', 'monitoring')
            self.sub_monitoring = [x.strip() for x in sub_monitoringlocal.split(",")]

        if Config.has_option('substitute', 'assessor'):
            sub_assessorlocal = Config.get('substitute', 'assessor')
            self.sub_assessor = [x.strip() for x in sub_assessorlocal.split(",")]

        if Config.has_option('substitute', 'logger'):
            sub_loggerlocal = Config.get('substitute', 'logger')
            self.sub_logger = [x.strip() for x in sub_loggerlocal.split(",")]

        try:
            self.agenttype = Config.get('type', 'agent_type')
        except BaseException:
            self.agenttype = "machine"

        # syncthing true or fale
        self.syncthing_on = True
        if self.agenttype == "relayserver":
            self.syncthing_share = "/var/lib/syncthing-depl/depl_share"
            self.syncthing_home = "/var/lib/syncthing-depl/.config/syncthing"

            self.syncthing_port = 23000
            if Config.has_option('syncthing-deploy', 'syncthing_port'):
                self.syncthing_port = Config.getint('syncthing-deploy', 'syncthing_port')

            self.syncthing_gui_port = 8385
            if Config.has_option('syncthing-deploy', 'syncthing_gui_port'):
                self.syncthing_gui_port = Config.getint('syncthing-deploy', 'syncthing_gui_port')

            if Config.has_option('syncthing-deploy', 'syncthing_share'):
                self.syncthing_share = Config.get('syncthing-deploy', 'syncthing_share')
        else:
            self.syncthing_home = "/var/lib/pulse2/.config/syncthing"
            self.syncthing_gui_port = 8384
            if Config.has_option('syncthing', 'activation'):
                self.syncthing_on = Config.getboolean('syncthing', 'activation')
            else:
                self.syncthing_on = True
        if Config.has_option('syncthing-deploy', 'syncthing_home'):
            self.syncthing_home = Config.get('syncthing-deploy', 'syncthing_home')

        logger.info('activation syncthing %s'%self.syncthing_on)
        # SYNCTHING #################

        self.moderelayserver = "static"
        if Config.has_option("type", "moderelayserver"):
            self.moderelayserver = Config.get('type', 'moderelayserver')
        logger.info('moderelayserver %s'%self.moderelayserver)

        if Config.has_option("updateagent", "updating"):
            self.updating = Config.getint('updateagent', 'updating')
        else:
            self.updating = 1
        logger.info('updating %s'%self.updating)

        if Config.has_option("networkstatus", "netchanging"):
            self.netchanging = Config.getint('networkstatus', 'netchanging')
        else:
            self.netchanging = 1
        logger.info('netchanging %s'%self.netchanging)

        if Config.has_option("networkstatus", "detectiontime"):
            self.detectiontime = Config.getint('networkstatus', 'detectiontime')
        else:
            self.detectiontime = 300
        logger.info('detection time for networkstatus%s'%self.detectiontime)

        self.parametersscriptconnection = {}

        if self.agenttype == "relayserver":
            self.concurrentdeployments = 10
            if Config.has_option("global", "concurrentdeployments"):
                try:
                    self.concurrentdeployments = Config.getint('global',
                                                               'concurrentdeployments')
                except Exception as e :
                    logger.warning(
                        "parameter [global]  concurrentdeployments :(%s)" %str(e))
                    logger.warning(
                        "parameter [global]  concurrentdeployments"\
                            " : parameter set to 10")

            if self.concurrentdeployments < 1:
                logger.warning(
                        "parameter [global]  concurrentdeployments "\
                            " : parameter must be greater than or equal to 1")
                logger.warning(
                        "parameter [global]  concurrentdeployments "\
                            ": parameter set to 10")
                self.concurrentdeployments = 10

            if Config.has_option("connection", "portARSscript"):
                self.parametersscriptconnection['port'] = Config.get(
                    'connection', 'portARSscript')
            else:
                self.parametersscriptconnection['port'] = 5001
        else:
            if Config.has_option("connection", "portAMscript"):
                self.parametersscriptconnection['port'] = Config.get(
                    'connection', 'portAMscript')
            else:
                self.parametersscriptconnection['port'] = 5000
        #######configuration browserfile#######
        if sys.platform.startswith('win'):
            self.defaultdir = os.path.join(os.environ["TEMP"])
            self.rootfilesystem = os.path.join(os.environ["TEMP"])
        elif sys.platform.startswith('darwin'):
            self.defaultdir = os.path.join("/opt", "Pulse", "tmp")
            self.rootfilesystem = os.path.join("/opt", "Pulse", "tmp")
        else:
            self.defaultdir = os.path.join("/", "tmp")
            self.rootfilesystem = os.path.join("/", "tmp")

        if Config.has_option("browserfile", "defaultdir"):
            self.defaultdir = Config.get('browserfile', 'defaultdir')
        if Config.has_option("browserfile", "rootfilesystem"):
            self.rootfilesystem = Config.get('browserfile', 'rootfilesystem')
        if self.rootfilesystem[-1] == '\\':
            self.rootfilesystem = self.rootfilesystem[:-1]
        if self.rootfilesystem[-1] == "/" and len(self.rootfilesystem) > 1:
            self.rootfilesystem = self.rootfilesystem[:-1]
        if self.defaultdir[-1] == '\\' or self.defaultdir[-1] == "/":
            self.defaultdir = self.defaultdir[:-1]
        self.listexclude = ""
        if Config.has_option("browserfile", "listexclude"):
        # listexclude=/usr,/etc,/var,/lib,/boot,/run,/proc,/lib64,
        # /bin,/sbin,/dev,/lost+found,/media,/mnt,/opt,/root,/srv,/sys,/vagrant
            self.listexclude = Config.get('browserfile', 'listexclude')
        self.excludelist = [x.strip() for x in self.listexclude.split(",")
                            if x.strip() != ""]
        #######end configuration browserfile#######
        if self.agenttype == "relayserver":
            packageserver = infos_network_packageserver()
            if packageserver["public_ip"] == '':
                self.packageserver["public_ip"] = self.Server
            if packageserver["port"] == '':
                self.packageserver["port"] = 9990
            else:
                self.packageserver["port"] = int(packageserver["port"])
        self.public_ip = ""
        self.public_ip_relayserver = ""
        self.geoservers = "ifconfig.co, if.siveo.net"
        self.geolocalisation = True

        if Config.has_option("type", "public_ip"):
            self.public_ip = Config.get('type', 'public_ip')

        if self.agenttype == "relayserver":
            if Config.has_option("type", "request_type"):
                self.request_type = Config.get('type', 'request_type')
                if self.request_type.lower() == "public" and Config.has_option("type",
                                                                               "public_ip"):
                    self.public_ip_relayserver = ipfromdns(
                        Config.get('type', 'public_ip'))
                    self.packageserver["public_ip"] = self.public_ip_relayserver
        else:
            if Config.has_option("type", "request_type"):
                self.request_type = Config.get('type', 'request_type')
            else:
                self.request_type = "public"
        if Config.has_option("type", "geolocalisation"):
            self.geolocalisation = Config.getboolean("type", "geolocalisation")

        if Config.has_option("type", "geoservers"):
            self.geoserversstr = Config.get("type", "geoservers")

        pluginlist = Config.get('plugin', 'pluginlist').split(",")
        # par convention :
        # la liste des plugins definie dans la section plugin avec la clef pluginlist
        # donne les fichiers .ini a chargé.
        # les fichiers ini des plugins doivent comporter une session parameters.
        # les clef representeront aussi par convention le nom des variables
        # utilisable dans le plugins.
        if Config.has_option("plugin", "pluginlist"):
            pluginlist = Config.get('plugin', 'pluginlist').split(",")
            pluginlist = [x.strip() for x in pluginlist]
            for z in pluginlist:
                namefile = "%s.ini" % os.path.join(self.nameplugindir, z)
                if os.path.isfile(namefile):
                    liststuple = self.loadparametersplugins(namefile)
                    for keyparameter, valueparameter in liststuple:
                        setattr(self, keyparameter, valueparameter)
                else:
                    logger.warning(
                        "parameter File plugin %s : missing" %
                        self.nameplugindir)
                    #self.nameplugindir=""
        try:
            self.agentcommand = Config.get('global', 'relayserver_agent')
        except BaseException:
            self.agentcommand = ""

        if self.agenttype == "relayserver":
            if Config.has_option("global", "diragentbase"):
                self.diragentbase = Config.get('global', 'diragentbase')
            else:
                self.diragentbase = "/var/lib/pulse2/xmpp_baseremoteagent/"


        jidsufixetempinfo = os.path.join(os.path.dirname(os.path.realpath(__file__)),
                                         "INFOSTMP",
                                         "JIDSUFFIXE")
        jidsufixe=''
        if os.path.exists(jidsufixetempinfo):
            jidsufixe = utils.file_get_contents(jidsufixetempinfo)[:3]
        else:
            jidsufixe = utils.getRandomName(3)
            utils.file_put_contents(jidsufixetempinfo, jidsufixe)
        ressource = utils.name_jid()
        #########chatroom############
        #self.jidchatroommaster = "master@%s" % Config.get('chatroom', 'server')
        #self.jidchatroomlog = "log@%s" % Config.get('chatroom', 'server')
        ## Deployment chatroom
        #self.passwordconnexionmuc = Config.get('chatroom', 'password')
        self.NickName = "%s.%s" % (platform.node(), jidsufixe)
        ########chat#############
        # The jidagent must be the smallest value in the list of mac addresses
        self.chatserver = Config.get('chat', 'domain')
        # Smallest mac address
        nameuser = self.NickName

        if Config.has_option("jid_01", "jidname"):
            self.jidagent = Config.get('jid_01', 'jidname')
            nameuser = jid.JID(self.jidagent).user
        self.jidagent = "%s@%s/%s" % (nameuser,
                                      Config.get(
                                          'chat',
                                          'domain'),
                                      ressource)
        try:
            self.nbrotfile = Config.getint('global', 'nb_rot_file')
        except BaseException:
            self.nbrotfile = 6
        if self.nbrotfile < 1:
            self.nbrotfile = 1
        try:
            self.compress = Config.get('global', 'compress')
        except BaseException:
            self.compress = "no"
        self.compress = self.compress.lower()
        if self.compress not in ["zip", "gzip", "bz2","No"]:
            self.compress = "no"
        defaultnamelogfile = "xmpp-agent-machine.log"  
        if self.agenttype == "relayserver":
            defaultnamelogfile = "xmpp-agent-relay.log"  
        try:
            self.logfile = Config.get('global', 'logfile')
        except BaseException:
            if sys.platform.startswith('win'):
                self.logfile = os.path.join(
                    os.environ["ProgramFiles"],
                                "Pulse",
                                "var",
                                "log",
                                defaultnamelogfile)
            elif sys.platform.startswith('darwin'):
                self.logfile = os.path.join(
                    "/opt",
                    "Pulse",
                    "var",
                    "log",
                    defaultnamelogfile)
            else:
                self.logfile = os.path.join(
                    "/", "var", "log", "pulse", defaultnamelogfile)

        # information configuration dynamique
        if Config.has_option("configuration_server", "confserver"):
            self.confserver = Config.get('configuration_server', 'confserver')
        if Config.has_option("configuration_server", "confport"):
            self.confport = Config.get('configuration_server', 'confport')
        if Config.has_option("configuration_server", "confpassword"):
            self.confpassword = Config.get(
                'configuration_server', 'confpassword')
        if Config.has_option("configuration_server", "keyAES32"):
            self.keyAES32 = Config.get('configuration_server', 'keyAES32')
        else:
            self.keyAES32 = "abcdefghijklnmopqrstuvwxyz012345"

        try:
            self.baseurlguacamole = Config.get('type', 'guacamole_baseurl')
        except BaseException:
            self.baseurlguacamole = ""

        if self.agenttype == "machine":
            try:
                timeal = Config.get('global', 'alternativetimedelta')
                self.timealternatif = [int(x) for x in
                                       re.split(r'[a-zA-Z;,\[\(\]\)\{\}\:\=\+\*\\\?\/\#\+\.\&\-\$\|\s]\s*',
                                                timeal)
                                       if x.strip()!=""][:2]
                self.timealternatif.sort()
                if len(self.timealternatif) < 2:
                    raise
                else:
                    if self.timealternatif[0] < 2:
                        self.timealternatif[0] = 2
                    if self.timealternatif[1] > 30:
                        self.timealternatif[1] = 30
            except Exception:
                self.timealternatif=[2,30]
                logger.warning('default [Global] parameter "alternativetimedelta" is %s'%self.timealternatif)
            logger.info('[Global] Parameter "alternativetimedelta" is %s'%self.timealternatif)

        try:
            self.debug = Config.get('global', 'log_level')
        except BaseException:
            self.debug = 'NOTSET'
        self.debug = self.debug.upper()

        if Config.has_option("configuration_server", "confdomain"):
            self.confdomain = Config.get('configuration_server', 'confdomain')
        else:
            self.confdomain = "pulse"

        if self.debug == 'CRITICAL':
            self.levellog = 50
        elif self.debug == 'ERROR':
            self.levellog = 40
        elif self.debug == 'WARNING':
            self.levellog = 30
        elif self.debug == 'INFO':
            self.levellog = 20
        elif self.debug == 'DEBUG':
            self.levellog = 10
        elif self.debug == 'NOTSET':
            self.levellog = 0
        elif self.debug == "LOG" or self.debug == "DEBUGPULSE":
            self.levellog = 25
        else:
            self.levellog = 0o2

        try:
            self.classutil = Config.get('global', 'agent_space')
        except BaseException:
            self.classutil = "both"

        try:
            jidagentsiveo = Config.get('global', 'allow_order')
            self.jidagentsiveo = [jid.JID(x.strip()).user for x in jidagentsiveo.split(",")]
        except BaseException:
            self.jidagentsiveo = ["agentsiveo"]

        try:
            self.ordreallagent = Config.getboolean('global', 'inter_agent')
        except BaseException:
            self.ordreallagent = False

        if self.agenttype == "relayserver":
            self.jidchatroomcommand = self.jidagent
        else:
            self.jidchatroomcommand = str(self.agentcommand)

        self.max_size_stanza_xmpp = 1048576
        if Config.has_option("quick_deploy", "max_size_stanza_xmpp"):
            self.max_size_stanza_xmpp = Config.getint("quick_deploy",
                                                    "max_size_stanza_xmpp")

        self.nbconcurrentquickdeployments = 10
        if Config.has_option("quick_deploy", "concurrentdeployments"):
            self.nbconcurrentquickdeployments = Config.getint("quick_deploy",
                                                    "concurrentdeployments")
        # we make sure that the temp for the
        # inventories is greater than or equal to 1 hour.
        # if the time for the inventories is 0, it is left at 0.
        # this deactive cycle inventory
        self.inventory_interval = 0
        if Config.has_option("inventory", "inventory_interval"):
            self.inventory_interval = Config.getint("inventory",
                                                    "inventory_interval")
            if self.inventory_interval !=0 and self.inventory_interval < 3600:
                self.inventory_interval = 36000

        # configuration monitoring
        if self.agenttype == "machine":
            if Config.has_option("monitoring", "monitoring_agent_config_file"):
                self.monitoring_agent_config_file = Config.get("monitoring",
                                                        "monitoring_agent_config_file")
            else:
                # Config file not found
                self.monitoring_agent_config_file = ""

        self.information = {}
        self.PlatformSystem = platform.platform()
        self.information['platform'] = self.PlatformSystem
        self.OperatingSystem = platform.system()
        self.information['os'] = self.OperatingSystem
        self.UnameSystem = platform.uname()
        self.information['uname'] = self.UnameSystem
        self.HostNameSystem = platform.node()
        self.information['hostname'] = self.HostNameSystem
        self.OsReleaseNumber = platform.release()
        self.information['osrelease'] = self.OsReleaseNumber
        self.DetailedVersion = platform.version()
        self.information['version'] = self.DetailedVersion
        self.HardwareType = platform.machine()
        self.information['hardtype'] = self.HardwareType
        self.ProcessorIdentifier = platform.processor()
        self.information['processor'] = self.ProcessorIdentifier
        self.Architecture = platform.architecture()
        self.information['archi'] = self.Architecture

        # Http fileviewer server parameters
        self.paths = []
        self.names = []
        self.extensions = []
        self.date_format = '%Y-%m-%d %H:%M:%S'

        if Config.has_option('fileviewer', 'sources'):
            self.paths = Config.get('fileviewer', 'sources').split(';')

        # The size_paths drive the final size of paths, names and extensions parameters
        size_paths = len(self.paths)

        if Config.has_option('fileviewer', 'names'):
            # Get names from ini file
            self.names = Config.get('fileviewer', 'names').split(';')

        # If some names are missing, complete display names associated to each paths
        count = 0
        while count < size_paths:
            try:
                self.names[count]
            except IndexError:
                # The displayed names are in lowercase
                self.names.append(os.path.basename(self.paths[count]).lower())
            finally:
                count += 1

        # Get available extensions
        if Config.has_option('fileviewer', 'extensions'):
            self.extensions = Config.get('fileviewer', 'extensions').split(';')

        # If some extensions group are missing, complete the list for each paths
        count = 0
        while count < size_paths:
            try:
                self.extensions[count]
            except IndexError:
                self.extensions.append([])
            finally:
                count += 1

        count = 0
        while count < size_paths:
            if type(self.extensions[count]) is list:
                self.extensions[count] = self.extensions[count]
            else:
                self.extensions[count] = self.extensions[count].split(',')
            count += 1

        if Config.has_option('fileviewer', 'date_format'):
            self.date_format = Config.get('fileviewer', 'date_format')


    def loadparametersplugins(self, namefile):
        Config = ConfigParser.ConfigParser()
        Config.read(namefile)
        if os.path.isfile(namefile+".local"):
            Config.read(namefile+".local")
        return Config.items("parameters")

    def getRandomName(self, nb, pref=""):
        """
        This function create a random name with only letters

        Returns:
            A random name ( letters only )

        """
        a = "abcdefghijklnmopqrstuvwxyz"
        d = pref
        for t in range(nb):
            d = d + a[random.randint(0, 25)]
        return d

    def getRandomNameID(self, nb, pref=""):
        """
        This function create a random name with only numbers

        Returns:
            A Random number
        """
        a = "0123456789"
        d = pref
        for t in range(nb):
            d = d + a[random.randint(0, 9)]
        return d

    def get_local_ip_addresses(self):
        """
        This function permit to obtain all the local addresses from all the interfaces.

        Returns:
            a list of the IP addresses
        """
        ip_addresses = list()
        interfaces = netifaces.interfaces()
        for i in interfaces:
            if i == 'lo':
                continue
            iface = netifaces.ifaddresses(i).get(netifaces.AF_INET)
            if iface:
                for j in iface:
                    addr = j['addr']
                    if addr != '127.0.0.1':
                        ip_addresses.append(addr)
        return ip_addresses

    def mac_for_ip(self, ip):
        """
        This function permit ti have mac addresses from the IP address

        Return:
            A list of MACs for interfaces that have given IP,
            None if not found
        """
        for i in netifaces.interfaces():
            addrs = netifaces.ifaddresses(i)
            try:
                if_mac = addrs[netifaces.AF_LINK][0]['addr']
                if_ip = addrs[netifaces.AF_INET][0]['addr']
            except BaseException:
                # IndexError, KeyError: #ignore ifaces that dont have MAC or IP
                if_mac = if_ip = None
            if if_ip == ip:
                return if_mac
        return None

    def __str__(self):
        return str(self.__dict__)

    def jsonobj(self):
        return json.dumps(self.re)


def listMacAdressMacOs():
    """
    This function return the mac address on MAC OS

    Return:
        it returns the mac address of the MacOS machine
    """
    lst = {}
    ifconfig = os.popen('/sbin/ifconfig').readlines()
    for line in ifconfig:
        if line.startswith(' ') or line.startswith(
                "\t") and "ether" not in line:
            pass
        else:
            if "ether" not in line:
                ll = line.strip().split(':')[0]
            else:
                lst[ll] = line.split('ether')[1].strip()
    return lst


def listMacAdressWinOs():
    """
    This function return the mac address on MS Windows

    Return:
        it returns the mac address of the windows machine.
    """
    lst = {}
    i = 0
    ifconfig = os.popen('ipconfig /all').readlines()
    for line in ifconfig:
        if line.strip() == "":
            continue
        if "phy" in line.lower() or not (line.startswith("\t") or line.startswith(' ')):
            if "phy" not in line.lower():
                ll = line.split(' ')[0].strip() + "%d" % i
            else:
                lst[ll] = line.split(':')[1].strip()
                i = i + 1
    return lst


def listMacAdressLinuxOs():
    """
    This function return the mac address on GNU/Linux

    Returns:
        it returns the mac address of the linux machine
    """
    lst = {}
    ifconfig = os.popen('/sbin/ifconfig').readlines()
    for line in ifconfig:
        if 'hwaddr' in line.lower():
            t = line.strip().split(' ')
            lst[t[0]] = t[-1]
    return lst


def setconfigfile(listdataconfiguration):
    """
        This function changes, adds or deletes config option in configuration file

        eg list data configuration
            ["add","agentconf","global","log_level","DEBUG"]
            or
            ["del","agentconf","global","log_level"]
        Args:
            listdataconfiguration:   A list of configuration files
        Returns:
            bool: False if the is less than 2 config files and config folder does not exist
    TODO: Finish this documentation
    """
    if len (listdataconfiguration) > 1 and directoryconffile() is not None:
        fileofconf = os.path.join(directoryconffile(), listdataconfiguration[1])
    else:
        return False
    if listdataconfiguration[0].lower() == "add":
        if len(listdataconfiguration) != 5:
            return False
        if listdataconfiguration[2] != "" and listdataconfiguration[3] != "" and listdataconfiguration[4] != "":
            fileconf = ConfigParser.ConfigParser()
            fileconf.read(fileofconf)
            # test si section existe.
            if not listdataconfiguration[2] in fileconf.sections():
                fileconf.add_section(listdataconfiguration[2])
            fileconf.set(listdataconfiguration[2], listdataconfiguration[3], listdataconfiguration[4])
            with open(fileofconf, 'w') as configfile:
                fileconf.write(configfile)
            return True
        else:
            return False
    elif listdataconfiguration[0].lower() == "del":
        if len(listdataconfiguration) < 4:
            return False
        fileconf = ConfigParser.ConfigParser()
        fileconf.read(fileofconf)
        if listdataconfiguration[2] != "" and fileconf.has_section(listdataconfiguration[2]):
            if len(fileconf.options(listdataconfiguration[2])) == 0:
                fileconf.remove_section(listdataconfiguration[2])
                with open(fileofconf, 'w') as configfile:
                    fileconf.write(configfile)
                return True
            if listdataconfiguration[3] != "" and fileconf.has_option(listdataconfiguration[2], listdataconfiguration[3]):
                fileconf.remove_option(listdataconfiguration[2], listdataconfiguration[3])
                if len(fileconf.options(listdataconfiguration[2])) == 0:
                    fileconf.remove_section(listdataconfiguration[2])
                with open(fileofconf, 'w') as configfile:
                    fileconf.write(configfile)
                return True
            else:
                return False
        else:
            return False
    else:
        return False
