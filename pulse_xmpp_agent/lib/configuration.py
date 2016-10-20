#!/usr/bin/env python
# -*- coding: utf-8 -*-
import netifaces
import json
import subprocess
import sys
import platform
import os
import sys,os
import logging
import ConfigParser
import utils
from  agentconffile import conffilename
from sleekxmpp import jid


def changeconnection(conffile, port, ipserver, jid, baseurlguacamole):
    Config = ConfigParser.ConfigParser()
    Config.read(conffile)
    Config.set('connection', 'port'  , str(port) )
    Config.set('connection', 'server', str(ipserver))
    Config.set('global', 'relayserver_agent', str(jid))
    Config.set('type', 'guacamole_baseurl', str(baseurlguacamole))
    with open(conffile, 'w') as configfile:
        Config.write(configfile)

# Singleton/SingletonDecorator.py
class SingletonDecorator:
    def __init__(self,klass):
        self.klass = klass
        self.instance = None
    def __call__(self,*args,**kwds):
        if self.instance == None:
            self.instance = self.klass(*args,**kwds)
        return self.instance

class parametreconf:
    def __init__(self,typeconf='machine'):
        Config = ConfigParser.ConfigParser()
        namefileconfig = conffilename(typeconf)
        Config.read(namefileconfig)
        self.Port = Config.get('connection', 'port')
        self.Server = Config.get('connection', 'server')
        self.passwordconnection = Config.get('connection', 'password')
        self.nameplugindir = os.path.dirname(namefileconfig)
        try:
            self.agenttype = Config.get('type', 'agent_type')
        except:
            self.agenttype = "machine"

        pluginlist = Config.get('plugin', 'pluginlist').split(",")
        #par convention :
                #la liste des plugins definie dans la section plugin avec la clef pluginlist
                # donne les fichiers .ini a chargé.
                #les fichiers ini des plugins doivent comporter une session parameters.
                # les clef representeront aussi par convention le nom des variables utilisable dans le plugins.
        if Config.has_option("plugin", "pluginlist"):
            pluginlist = Config.get('plugin', 'pluginlist').split(",")
            pluginlist = [x.strip() for x in pluginlist ]
            for z in pluginlist:
                namefile = "%s.ini"%os.path.join(self.nameplugindir,z)
                if os.path.isfile(namefile):
                    liststuple = self.loadparametersplugins(namefile)
                    for keyparameter, valueparameter in liststuple:
                        #locals()[keyparameter] = valueparameter
                        setattr(self, keyparameter,valueparameter)
                else:
                    logging.getLogger().warning("parameter File pluging %s : missing"%self.nameplugindir)

        try:
            self.agentcommand = Config.get('global', 'relayserver_agent')
        except:
            self.agentcommand=""
        #########chatroom############
        #jidchatroommaster
        #jidchatroomlog
        #jidchatroomcommand
        self.jidchatroommaster="master@%s"%Config.get('chatroom', 'server')
        self.jidchatroomlog="log@%s"%Config.get('chatroom', 'server')
        #chatroom de deploiement
        self.passwordconnexionmuc=Config.get('chatroom', 'password')
        self.NickName="%s_%s"%(platform.node(),utils.name_random(2))
        ########chat#############
        # le jidagent doit être la plus petite valeur de la liste des macs.
        self.chatserver=Config.get('chat', 'domain')
        # plus petite mac adress
        nameuser = utils.name_jid()

        if  Config.has_option("jid_01", "jidname"):
            self.jidagent = Config.get('jid_01', 'jidname')
            nameuser = jid.JID(self.jidagent).user
        self.jidagent="%s@%s/%s"%(nameuser,Config.get('chat', 'domain'),platform.node())
        # jid hostname
        #self.jidagent="%s@%s/%s"%(platform.node(),Config.get('chat', 'server'),platform.node())
        try:
            self.logfile = Config.get('global', 'logfile')
        except:
            if sys.platform.startswith('win'):
                self.logfile = os.path.join(os.environ["ProgramFiles"], "Pulse", "var", "log", "xmpp-agent.log")
            elif sys.platform.startswith('darwin'):
                self.logfile = os.path.join("/", "Library", "Application Support", "Pulse", "var", "log", "xmpp-agent.log")
            else:
               self.logfile = os.path.join("/", "var", "log" , "pulse", "xmpp-agent.log")

        #information configuration dynamique
        if Config.has_option("configuration_server", "confserver"):
            self.confserver = Config.get('configuration_server', 'confserver')
        if Config.has_option("configuration_server", "confport"):
            self.confport   = Config.get('configuration_server', 'confport')
        if Config.has_option("configuration_server", "confpassword"):
            self.confpassword = Config.get('configuration_server', 'confpassword')
        if  Config.has_option("configuration_server", "confmuc_domain"):
            try:
                self.confjidchatroom ="%s@%s"%(Config.get('configuration_server', 'confmuc_chatroom'),Config.get('configuration_server', 'confmuc_domain'))
            except:
                self.confjidchatroom ="%s@%s"%("configmaster",Config.get('configuration_server', 'confmuc_domain'))
        if  Config.has_option("configuration_server", "confmuc_password"):
            self.confpasswordmuc = Config.get('configuration_server', 'confmuc_password')

        try:
            self.baseurlguacamole = Config.get('type', 'guacamole_baseurl')
        except:
            self.baseurlguacamole = ""

        self.version_agent = Config.get('version', 'version_agent')

        try:
            self.debug = Config.get('global', 'log_level')
        except:
            self.debug = 'NOTSET'
        self.debug = self.debug.upper()

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
            self.levellog= 0
        elif self.debug == "LOG" or self.debug == "DEBUGPULSE":
            self.levellog = 25
        else :
            self.levellog= 02

        try:
            self.classutil = Config.get('global', 'agent_space')
        except:
            self.classutil = "both"

        try:
            self.jidagentsiveo = "%s@%s"%(Config.get('global', 'allow_order'),Config.get('chat', 'domain'))
        except:
            self.jidagentsiveo = "%s@%s"%("agentsiveo",Config.get('chat', 'domain'))

        try:
            self.ordreallagent = Config.getboolean('global', 'inter_agent')
        except:
            self.ordreallagent = False

        if self.agenttype == "relayserver":
            self.jidchatroomcommand="muc%s@%s"%(nameuser,Config.get('chatroom', 'server'))
            self.relayserverdeploy = ""
        else:
            self.relayserverdeploy = jid.JID(self.agentcommand)
            self.jidchatroomcommand = "muc%s@%s"%(self.relayserverdeploy.user,Config.get('chatroom', 'server'))



        self.information={}
        self.PlateformSystem=platform.platform()
        self.information['plateform']=self.PlateformSystem
        self.OperatingSystem=platform.system()
        self.information['os']=self.OperatingSystem
        self.UnameSystem = platform.uname()
        self.information['uname']=self.UnameSystem
        self.HostNameSystem =platform.node()
        self.information['hostname']=self.HostNameSystem
        self.OsReleaseNumber=platform.release()
        self.information['osrelease']=self.OsReleaseNumber
        self.DetailedVersion=platform.version()
        self.information['version']=self.DetailedVersion
        self.HardwareType=platform.machine()
        self.information['hardtype']=self.HardwareType
        self.ProcessorIdentifier=platform.processor()
        self.information['processor']=self.ProcessorIdentifier
        self.Architecture=platform.architecture()
        self.information['archi']=self.Architecture

    def loadparametersplugins(self,namefile):
        Config = ConfigParser.ConfigParser()
        Config.read(namefile)
        return Config.items("parameters")

    def name_random(self, nb, pref=""):
        a="abcdefghijklnmopqrstuvwxyz"
        d=pref
        for t in range(nb):
            d=d+a[random.randint(0,25)]
        return d

    def name_randomID(self, nb, pref=""):
        a="0123456789"
        d=pref
        for t in range(nb):
            d=d+a[random.randint(0,9)]
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
            except:# IndexError, KeyError: #ignore ifaces that dont have MAC or IP
                if_mac = if_ip = None
            if if_ip == ip:
                return if_mac
        return None

    def listMacAdressOs(self):
        lst = {}
        a = self.get_local_ip_addresses()
        for t in a:
            lst[t] = self.mac_for_ip(t)
        return lst

    def __str__(self):
        return str(self.__dict__)

    def jsonobj(self):
        return json.dumps(self.re)

def listMacAdressMacOs():
    lst={}
    ifconfig = os.popen('/sbin/ifconfig').readlines()
    for ligne in ifconfig:
        if ligne.startswith(' ') or ligne.startswith("\t") and not "ether" in ligne:
            pass
        else:
            if "ether" not in ligne:
                ll=ligne.strip().split(':')[0]
            else :
                lst[ll]=ligne.split('ether')[1].strip()
    return lst

def listMacAdressWinOs():
    lst={}
    i=0
    ifconfig = os.popen('ipconfig /all').readlines()
    for ligne in ifconfig:
        if ligne.strip()=="":
            continue
        if "phy"  in ligne.lower()  or not (ligne.startswith("\t") or ligne.startswith(' ')) :
            if "phy" not in ligne.lower():
                ll=ligne.split(' ')[0].strip()+"%d"%i
            else :
                lst[ll]=ligne.split(':')[1].strip()
                i=i+1
    return lst

def listMacAdressLinuxOs():
    lst={}
    ifconfig = os.popen('/sbin/ifconfig').readlines()
    for ligne in ifconfig:
        if 'hwaddr' in ligne.lower():
            t = ligne.strip().split(' ')
            lst[t[0]]=t[-1]
    return lst
