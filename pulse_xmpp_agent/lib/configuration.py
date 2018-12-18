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


def changeconnection(conffile, port, ipserver, jid, baseurlguacamole):
    Config = ConfigParser.ConfigParser()
    Config.read(conffile)
    if not Config.has_option("configuration_server", "confdomain"):
        Config.set(
            'configuration_server',
            'confdomain',
            Config.get(
                'chat',
                'domain'))
    Config.set('connection', 'port', str(port))
    Config.set('connection', 'server', ipfromdns(str(ipserver)))
    Config.set('global', 'relayserver_agent', str(jid))
    Config.set('type', 'guacamole_baseurl', str(baseurlguacamole))
    try:
        domain = str(jid).split("@")[1].split("/")[0]
    except BaseException:
        domain = str(jid)
    Config.set('chat', 'domain', domain)
    with open(conffile, 'w') as configfile:
        Config.write(configfile)

def alternativeclusterconnection(conffile, data):
    # todo del of list the ars without ip 
    #for arsdataconection in data:
        #if ipfromdns(str(arsdataconection[0])) != "" and check_exist_ip_port(ipfromdns(str(arsdataconection[0])), str(arsdataconection[1])):
            #print ipfromdns(str(arsdataconection[0]))
    with open(conffile, 'w') as configfile:
        if len(data) != 0:
            listalternative = [str(x[2]) for x in data]
            nb_alternativeserver =  len(listalternative)
            print ",".join(listalternative)
            configfile.write("[alternativelist]" + os.linesep)
            configfile.write("listars = %s%s"%(",".join(listalternative), os.linesep))
            configfile.write("nbserver = %s%s"%(nb_alternativeserver, os.linesep))
            configfile.write("nextserver = 1%s"%os.linesep)
            for arsdataconection in data:
                configfile.write("[%s]%s"%(str(arsdataconection[2]),os.linesep))
                configfile.write("port = %s%s"%(str(arsdataconection[1]),os.linesep))
                configfile.write("server = %s%s"%(ipfromdns(str(str(arsdataconection[0]))),os.linesep))
                configfile.write("guacamole_baseurl = %s%s"%(str(arsdataconection[3]),os.linesep))
        else:
            if os.path.isfile(conffile):
                os.unlink(conffile)

def nextalternativeclusterconnection(conffile):
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

    return [ serverjid, server, port, guacamole_baseurl, domain ]


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
    Config = ConfigParser.ConfigParser()
    Config.read(namefile)
    value = ""
    if Config.has_option("group", "key"):
        value = Config.get('group', 'key')
    return value


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

        try:
            self.agenttype = Config.get('type', 'agent_type')
        except BaseException:
            self.agenttype = "machine"

        self.moderelayserver = "static"
        if Config.has_option("type", "moderelayserver"):
            self.moderelayserver = Config.get('type', 'moderelayserver')

        if Config.has_option("updateagent", "updating"):
            self.updating = Config.getint('updateagent', 'updating')
        else:
            self.updating = 1

        ##parameter for deploy default timeout
        if Config.has_option("default_timeout", "parameters"):
            self.default_timeout = Config.getint('default_timeout', 'parameters')
        else:
            self.default_timeout = 800

        if Config.has_option("networkstatus", "netchanging"):
            self.netchanging = Config.getint('networkstatus', 'netchanging')
        else:
            self.netchanging = 1
        if Config.has_option("networkstatus", "detectiontime"):
            self.detectiontime = Config.getint('networkstatus', 'detectiontime')
        else:
            self.detectiontime = 300

        self.parametersscriptconnection = {}

        if self.agenttype == "relayserver":
            self.concurrentdeployments = 10
            if Config.has_option("global", "concurrentdeployments"):
                try:
                    self.concurrentdeployments = Config.getint('global', 'concurrentdeployments')
                except Exception as e :
                    logging.getLogger().warning(
                        "parameter [global]  concurrentdeployments :(%s)" %str(e))
                    logging.getLogger().warning(
                        "parameter [global]  concurrentdeployments : parameter set to 10")

            if self.concurrentdeployments < 1:
                logging.getLogger().warning(
                        "parameter [global]  concurrentdeployments  : parameter must be greater than or equal to 1")
                logging.getLogger().warning(
                        "parameter [global]  concurrentdeployments : parameter set to 10")
                self.concurrentdeployments = 10

            #PUSH METHOD TRANSFERT
            self.pushmethod="scp"
            if Config.has_option("global", "pushmethod"):
                try:
                    self.pushmethod = Config.get('global', 'pushmethod')
                except Exception as e :
                    logging.getLogger().warning(
                        "parameter [global]  pushmethod :(%s)" %str(e))
                    logging.getLogger().warning(
                        "parameter [global]  pushmethod : parameter set to scp")
                    self.pushmethod="scp"
            if not self.pushmethod in ["rsync", "scp"]:
                self.pushmethod="scp"

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
            self.defaultdir     = os.path.join(os.environ["TEMP"])
            self.rootfilesystem = os.path.join(os.environ["TEMP"])
        elif sys.platform.startswith('darwin'):
            self.defaultdir     = os.path.join("/", "tmp")
            self.rootfilesystem = os.path.join("/", "tmp")
        else:
            self.defaultdir     = os.path.join("/", "tmp")
            self.rootfilesystem = os.path.join("/", "tmp")
        if Config.has_option("browserfile", "defaultdir"):
            self.defaultdir = Config.get('browserfile', 'defaultdir')
        if Config.has_option("browserfile", "rootfilesystem"):
            self.rootfilesystem = Config.get('browserfile', 'rootfilesystem')
        if self.rootfilesystem[-1] == '\\' or self.rootfilesystem[-1] == "/":
            self.rootfilesystem = self.rootfilesystem[:-1]
        if self.defaultdir[-1] == '\\' or self.defaultdir[-1] == "/":
            self.defaultdir = self.defaultdir[:-1]
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
        if self.agenttype == "relayserver":
            if Config.has_option("type", "request_type"):
                self.request_type = Config.get('type', 'request_type')
                if self.request_type.lower() == "public" and Config.has_option("type", "public_ip"):
                    self.public_ip_relayserver = ipfromdns(
                        Config.get('type', 'public_ip'))
                    self.packageserver["public_ip"] = self.public_ip_relayserver
        pluginlist = Config.get('plugin', 'pluginlist').split(",")
        # par convention :
        # la liste des plugins definie dans la section plugin avec la clef pluginlist
        # donne les fichiers .ini a chargé.
        # les fichiers ini des plugins doivent comporter une session parameters.
        # les clef representeront aussi par convention le nom des variables
        # utilisable dans le plugins.
        # Si un fichier de configuration .ini a un fichier de meme nom suffixé de .local, 
        # alors le .local est appliqué aprés le .ini 
        if Config.has_option("plugin", "pluginlist"):
            pluginlist = Config.get('plugin', 'pluginlist').split(",")
            pluginlist = [x.strip() for x in pluginlist]
            for z in pluginlist:
                namefile = "%s.ini" % os.path.join(self.nameplugindir, z)
                namefilelocal = "%s.ini.local" % os.path.join(self.nameplugindir, z)
                if os.path.isfile(namefile):
                    liststuple = self.loadparametersplugins(namefile)
                    for keyparameter, valueparameter in liststuple:
                        setattr(self, keyparameter, valueparameter)
                    if os.path.isfile(namefilelocal):
                        liststuple = self.loadparametersplugins(namefilelocal)
                        for keyparameter, valueparameter in liststuple:
                            setattr(self, keyparameter, valueparameter)
                else:
                    logging.getLogger().warning(
                        "parameter File plugin %s : missing" %
                        self.nameplugindir)
                    self.nameplugindir=""

        try:
            self.agentcommand = Config.get('global', 'relayserver_agent')
        except BaseException:
            self.agentcommand = ""
        #########chatroom############
        self.jidchatroommaster = "master@%s" % Config.get('chatroom', 'server')
        self.jidchatroomlog = "log@%s" % Config.get('chatroom', 'server')
        # Deployment chatroom
        self.passwordconnexionmuc = Config.get('chatroom', 'password')
        self.NickName = "%s_%s" % (platform.node(), utils.getRandomName(2))
        ########chat#############
        # The jidagent must be the smallest value in the list of mac addresses
        self.chatserver = Config.get('chat', 'domain')
        # Smallest mac address
        nameuser = utils.name_jid()

        if Config.has_option("jid_01", "jidname"):
            self.jidagent = Config.get('jid_01', 'jidname')
            nameuser = jid.JID(self.jidagent).user
        self.jidagent = "%s@%s/%s" % (nameuser,
                                      Config.get(
                                          'chat',
                                          'domain'),
                                      platform.node())
        try:
            self.logfile = Config.get('global', 'logfile')
        except BaseException:
            if sys.platform.startswith('win'):
                self.logfile = os.path.join(
                    os.environ["ProgramFiles"], "Pulse", "var", "log", "xmpp-agent.log")
            elif sys.platform.startswith('darwin'):
                self.logfile = os.path.join(
                    "/",
                    "Library",
                    "Application Support",
                    "Pulse",
                    "var",
                    "log",
                    "xmpp-agent.log")
            else:
                self.logfile = os.path.join(
                    "/", "var", "log", "pulse", "xmpp-agent.log")

        # information configuration dynamique
        if Config.has_option("configuration_server", "confserver"):
            self.confserver = Config.get('configuration_server', 'confserver')
        if Config.has_option("configuration_server", "confport"):
            self.confport = Config.get('configuration_server', 'confport')
        if Config.has_option("configuration_server", "confpassword"):
            self.confpassword = Config.get(
                'configuration_server', 'confpassword')
        if Config.has_option("configuration_server", "confmuc_domain"):
            try:
                self.confjidchatroom = "%s@%s" % (Config.get(
                    'configuration_server',
                    'confmuc_chatroom'),
                    Config.get(
                    'configuration_server',
                    'confmuc_domain'))
            except BaseException:
                self.confjidchatroom = "%s@%s" % ("configmaster", Config.get(
                    'configuration_server', 'confmuc_domain'))
        if Config.has_option("configuration_server", "confmuc_password"):
            self.confpasswordmuc = Config.get(
                'configuration_server', 'confmuc_password')

        try:
            self.baseurlguacamole = Config.get('type', 'guacamole_baseurl')
        except BaseException:
            self.baseurlguacamole = ""

        try:
            self.debug = Config.get('global', 'log_level')
        except BaseException:
            self.debug = 'NOTSET'
        self.debug = self.debug.upper()

        # use [chat) domain for first connection if not  [configuration_server] [confdomain]
        # agent connection add [configuration_server] [confdomain]
        if Config.has_option("configuration_server", "confdomain"):
            self.confdomain = Config.get('configuration_server', 'confdomain')
        else:
            self.confdomain = self.chatserver

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
            self.jidagentsiveo = "%s@%s" % (Config.get(
                'global', 'allow_order'), Config.get('chat', 'domain'))
        except BaseException:
            self.jidagentsiveo = "%s@%s" % (
                "agentsiveo", Config.get('chat', 'domain'))

        try:
            self.ordreallagent = Config.getboolean('global', 'inter_agent')
        except BaseException:
            self.ordreallagent = False

        if self.agenttype == "relayserver":
            self.jidchatroomcommand = self.jidagent
        else:
            self.relayserverdeploy = jid.JID(self.agentcommand)
            self.jidchatroomcommand = str(self.agentcommand)

        # we make sure that the temp for the inventories is greater than or equal to 1 hour.
        # if the time for the inventories is 0, it is left at 0. 
        # this deactive cycle inventory
        self.inventory_interval = 0
        if Config.has_option("inventory", "inventory_interval"):
            self.inventory_interval = Config.getint("inventory", "inventory_interval")
            if self.inventory_interval !=0 and self.inventory_interval < 3600:
                self.inventory_interval = 36000

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

    def loadparametersplugins(self, namefile):
        Config = ConfigParser.ConfigParser()
        Config.read(namefile)
        return Config.items("parameters")

    def getRandomName(self, nb, pref=""):
        a = "abcdefghijklnmopqrstuvwxyz"
        d = pref
        for t in range(nb):
            d = d + a[random.randint(0, 25)]
        return d

    def getRandomNameID(self, nb, pref=""):
        a = "0123456789"
        d = pref
        for t in range(nb):
            d = d + a[random.randint(0, 9)]
        return d

    def get_local_ip_addresses(self):
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
        'Returns a list of MACs for interfaces that have given IP, returns None if not found'
        for i in netifaces.interfaces():
            addrs = netifaces.ifaddresses(i)
            try:
                if_mac = addrs[netifaces.AF_LINK][0]['addr']
                if_ip = addrs[netifaces.AF_INET][0]['addr']
            except BaseException:  # IndexError, KeyError: #ignore ifaces that dont have MAC or IP
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
    :returns: it returns the mac address of the MacOS machine
    :rtype: dictionnary
    """
    lst = {}
    ifconfig = os.popen('/sbin/ifconfig').readlines()
    for line in ifconfig:
        if line.startswith(' ') or line.startswith(
                "\t") and not "ether" in line:
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
    :returns: it returns the mac address of the windows machine
    :rtype: dictionnary
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
    :returns: it returns the mac address of the linux machine
    :rtype: dictionnary
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
        :returns: it return False or True
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
