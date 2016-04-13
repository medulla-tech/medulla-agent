/**
 * (c) 2016 Siveo, http://http://www.siveo.net
 *
 * $Id$
 *
 * This file is part of Pulse .
 *
 * Pulse is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * Pulse is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Pulse.  If not, see <http://www.gnu.org/licenses/>.
 */
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
from  fichierdecomf import fileconf

class parametreconf:
    def __init__(self,typeconf='agent'):
        Config = ConfigParser.ConfigParser()
        Config.read(fileconf)
        self.Port= Config.get('connection', 'port')
        self.Server= Config.get('connection', 'server')
        self.passwordconnection=Config.get('connection', 'password')
        self.jidchannelmaster="master@%s"%Config.get('channel', 'server')
        self.jidchannellog="log@%s"%Config.get('channel', 'server')
        self.jidchannelcommand="command@%s"%Config.get('channel', 'server')
        self.passwordconnexionmuc=Config.get('channel', 'password')
        self.NickName="%s_%s"%(platform.node(),utils.name_random(2))
        self.chatserver=Config.get('chat', 'server')
        self.jidagent="%s@%s/%s"%(utils.name_jid(),Config.get('chat', 'server'),platform.node())
        platform.node()
        self.logfile = Config.get('global', 'logfile')
        
        try:
            self.agenttype = Config.get('type', 'agenttype')
        except:
            self.agenttype = "machine"
        try:
            self.baseurlguacamole = Config.get('type', 'baseurlguacamole')
        except:
            self.baseurlguacamole = ""

        self.version_agent = Config.get('version', 'version_agent')

        try:
            self.debug = Config.get('global', 'debug')
        except:
            self.debug = logging.NOTSET 
        self.jidagentsiveo = "%s@%s"%(Config.get('global', 'ordre'),Config.get('chat', 'server'))
        self.ordreallagent = Config.getboolean('global', 'inter_agent')
        self.showinfomaster = Config.getboolean('master', 'showinfo')
        self.showplugins = Config.getboolean('master', 'showplugins')
        try:
            self.host = Config.get('mysql', 'host')
            self.user = Config.get('mysql', 'user')
            self.password = Config.get('mysql', 'password')
            self.database = Config.get('mysql', 'database')
            self.sgbd = True
            self.inventory = Config.get('inventorypulse', 'inventory')
        except:
            self.sgbd = False
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
        return str(self.re)

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
