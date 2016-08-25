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


def changeconnection(conffile, port,ipserver,jid,guacamole_baseurl):
    Config = ConfigParser.ConfigParser()
    Config.read(conffile)
    Config.set('connection', 'port'  , str(port) )
    Config.set('connection', 'server', str(ipserver))
    Config.set('global', 'relayserver_agent', str(jid))
    Config.set('type', 'guacamole_baseurl', str(guacamole_baseurl))
    with open(conffile, 'wb') as configfile:
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

@SingletonDecorator
class parametreconf:
    def __init__(self,typeconf='machine'):
        Config = ConfigParser.ConfigParser()
        Config.read(conffilename(typeconf))
        self.Port= Config.get('connection', 'port')
        self.Server= Config.get('connection', 'server')
        self.passwordconnection=Config.get('connection', 'password')

        try:
            self.agent_type = Config.get('type', 'agent_type')
        except:
            self.agent_type = "machine"

        try:
            self.relayserver_agent = Config.get('global', 'relayserver_agent')
        except:
            self.relayserver_agent=""
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
        self.chatdomain=Config.get('chat', 'domain')
        # plus petite mac adress
        nameuser = utils.name_jid()

        if  Config.has_option("jid_01", "jidname"):
            self.jidagent = Config.get('jid_01', 'jidname')
            nameuser = jid.JID(self.jidagent).user

        self.jidagent="%s@%s/%s"%(nameuser,Config.get('chat', 'domain'),platform.node())
        # jid hostname
        #self.jidagent="%s@%s/%s"%(platform.node(),Config.get('chat', 'server'),platform.node())
        platform.node()
        self.logfile = Config.get('global', 'logfile')

        #information configuration dynamique
        self.confserver = Config.get('configuration_server', 'confserver')
        self.confport   = Config.get('configuration_server', 'confport')
        self.confpassword = Config.get('configuration_server', 'confpassword')
        self.confjidchatroom ="%s@%s"%(Config.get('configuration_server', 'confmuc_chatroom'),Config.get('configuration_server', 'confmuc_domain'))
        self.confmuc_password = Config.get('configuration_server', 'confmuc_password')

        try:
            self.guacamole_baseurl = Config.get('type', 'guacamole_baseurl')
        except:
            self.guacamole_baseurl = ""

        self.version_agent = Config.get('version', 'version_agent')

        try:
            self.log_level = Config.get('global', 'log_level')
        except:
            self.log_level = logging.NOTSET


        try:
            self.agent_space = Config.get('global', 'agent_space')
        except:
            self.agent_space = "both"

        self.jidagentsiveo = "%s@%s"%(Config.get('global', 'allow_order'),Config.get('chat', 'domain'))
        self.ordreallagent = Config.getboolean('global', 'inter_agent')
        self.showinfomaster = Config.getboolean('master', 'showinfo')
        self.showplugins = Config.getboolean('master', 'showplugins')


        if self.agent_type == "relayserver":
            self.jidchatroomcommand="muc%s@%s"%(nameuser,Config.get('chatroom', 'server'))
            self.relayserverdeploy = ""
        else:
            self.relayserverdeploy = jid.JID(self.relayserver_agent)
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
