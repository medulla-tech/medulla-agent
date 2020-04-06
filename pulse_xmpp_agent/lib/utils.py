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

# file : pulse_xmpp_agent/lib/utils.py

import netifaces
import json
import subprocess
import threading
import sys
import os
import logging
import random
import re
import traceback
from pprint import pprint
import hashlib
import base64
import urllib
import urllib2
import pickle
from agentconffile import conffilename
import ConfigParser
import socket
import psutil
import time
from datetime import datetime
import imp

from Crypto import Random
from Crypto.Cipher import AES

logger = logging.getLogger()

DEBUGPULSE = 25


if sys.platform.startswith('win'):
    import wmi
    import pythoncom
    import _winreg as wr
    #import win32net
    #import win32netcon
    #import win32api
    import win32security
    import ntsecuritycon
    import win32net
    import win32com.client
    from win32com.client import GetObject

def Setdirectorytempinfo():
    """
    This functions create a temporary directory.

    Returns:
    path directory INFO Temporaly and key RSA
    """
    dirtempinfo = os.path.join(
        os.path.dirname(
            os.path.realpath(__file__)),
        "INFOSTMP")
    if not os.path.exists(dirtempinfo):
        os.makedirs(dirtempinfo, mode=0o007)
    return dirtempinfo


def cleanbacktodeploy(objectxmpp):
    delsession = [
        session for session in objectxmpp.back_to_deploy if not objectxmpp.session.isexist(session)]
    for session in delsession:
        del (objectxmpp.back_to_deploy[session])
    if len(delsession) != 0:
        logging.log(DEBUGPULSE, "Clear dependency : %s" % delsession)
        save_back_to_deploy(objectxmpp.back_to_deploy)


def networkinfoexist():
    filenetworkinfo = os.path.join(
        Setdirectorytempinfo(),
        'fingerprintnetwork')
    if os.path.exists(filenetworkinfo):
        return True
    return False

def save_count_start():
    filecount = os.path.join(Setdirectorytempinfo(), 'countstart')
    if not os.path.exists(filecount):
        file_put_contents(filecount, "1")
        return  1
    countstart = file_get_contents(filecount)
    try:
        if countstart != "":
            countstart = int(countstart.strip())
            countstart +=1
        else:
            countstart = 1
    except ValueError:
        countstart = 1
    file_put_contents(filecount, str(countstart))
    return countstart


def save_back_to_deploy(obj):
    fileback_to_deploy = os.path.join(Setdirectorytempinfo(), 'back_to_deploy')
    save_obj(obj, fileback_to_deploy)


def load_back_to_deploy():
    fileback_to_deploy = os.path.join(Setdirectorytempinfo(), 'back_to_deploy')
    return load_obj(fileback_to_deploy)


def listback_to_deploy(objectxmpp):
    if len(objectxmpp.back_to_deploy) != 0:
        print "list session pris en compte back_to_deploy"
        for u in objectxmpp.back_to_deploy:
            print u


def testagentconf(typeconf):
    if typeconf == "relayserver":
        return True
    Config = ConfigParser.ConfigParser()
    namefileconfig = conffilename(typeconf)
    Config.read(namefileconfig)
    if Config.has_option("type", "guacamole_baseurl")\
            and Config.has_option('connection', 'port')\
            and Config.has_option('connection', 'server')\
            and Config.has_option('global', 'relayserver_agent')\
            and Config.get('type', 'guacamole_baseurl') != ""\
            and Config.get('connection', 'port') != ""\
            and Config.get('connection', 'server') != ""\
            and Config.get('global', 'relayserver_agent') != "":
        return True
    return False


def createfingerprintnetwork():
    md5network = ""
    if sys.platform.startswith('win'):
        obj = simplecommandstr("ipconfig")
        md5network = hashlib.md5(obj['result']).hexdigest()
    elif sys.platform.startswith('linux'):
        obj = simplecommandstr("LANG=C ifconfig | egrep '.*(inet|HWaddr).*' | grep -v inet6")
        md5network = hashlib.md5(obj['result']).hexdigest()
    elif sys.platform.startswith('darwin'):
        obj = simplecommandstr("ipconfig")
        md5network = hashlib.md5(obj['result']).hexdigest()
    return md5network


def createfingerprintconf(typeconf):
    namefileconfig = conffilename(typeconf)
    return hashlib.md5(file_get_contents(namefileconfig)).hexdigest()


def confinfoexist():
    filenetworkinfo = os.path.join(Setdirectorytempinfo(), 'fingerprintconf')
    if os.path.exists(filenetworkinfo):
        return True
    return False


def confchanged(typeconf):
    if confinfoexist():
        fingerprintconf = file_get_contents(
            os.path.join(
                Setdirectorytempinfo(),
                'fingerprintconf'))
        newfingerprintconf = createfingerprintconf(typeconf)
        if newfingerprintconf == fingerprintconf:
            return False
    return True


def refreshfingerprintconf(typeconf):
    fp = createfingerprintconf(typeconf)
    file_put_contents(
        os.path.join(
            Setdirectorytempinfo(),
            'fingerprintconf'),
        fp)
    return fp


def networkchanged():
    if networkinfoexist():
        fingerprintnetwork = file_get_contents(os.path.join(
            Setdirectorytempinfo(), 'fingerprintnetwork'))
        newfingerprint = createfingerprintnetwork()
        if fingerprintnetwork == newfingerprint:
            return False
    else:
        return True


def refreshfingerprint():
    fp = createfingerprintnetwork()
    file_put_contents(
        os.path.join(
            Setdirectorytempinfo(),
            'fingerprintnetwork'),
        fp)
    return fp


def file_get_contents(filename, use_include_path=0,
                      context=None, offset=-1, maxlen=-1):
    if (filename.find('://') > 0):
        ret = urllib2.urlopen(filename).read()
        if (offset > 0):
            ret = ret[offset:]
        if (maxlen > 0):
            ret = ret[:maxlen]
        return ret
    else:
        fp = open(filename, 'rb')
        try:
            if (offset > 0):
                fp.seek(offset)
            ret = fp.read(maxlen)
            return ret
        finally:
            fp.close()


def file_put_contents(filename, data):
    if not os.path.exists(os.path.dirname(filename)):
        os.makedirs(os.path.dirname(filename))
    f = open(filename, 'w')
    f.write(data)
    f.close()


def file_put_contents_w_a(filename, data, option = "w"):
    if not os.path.exists(os.path.dirname(filename)):
        os.makedirs(os.path.dirname(filename))
    if option == "a" or  option == "w":
        f = open( filename, option )
        f.write(data)
        f.close()


def save_obj(obj, name):
    """
    funct save serialised object
    """
    with open(name + '.pkl', 'wb') as f:
        pickle.dump(obj, f, pickle.HIGHEST_PROTOCOL)


def load_obj(name):
    """
    function load serialized object
    """
    with open(name + '.pkl', 'rb') as f:
        return pickle.load(f)


def getCurrentWorkingDirectory():
    return os.path.abspath(os.getcwd())


def getScriptPath():
    return os.path.abspath(os.path.join(
        getCurrentWorkingDirectory(), "script"))


def getPluginsPath():
    return os.path.abspath(os.path.join(
        getCurrentWorkingDirectory(), "plugins"))


def getLibPath():
    return os.path.abspath(os.path.join(getCurrentWorkingDirectory(), "lib"))


def getPerlScriptPath(name):
    return os.path.abspath(os.path.join(
        getCurrentWorkingDirectory(), "script", "perl", name))


def showJSONData(jsondata):
    pp = pprint.PrettyPrinter(indent=4)
    pp.pprint(jsondata)


class StreamToLogger(object):
    """
    Fake file-like stream object that redirects writes to a logger instance.
    """

    def __init__(self, logger, debug=logging.INFO):
        self.logger = logger
        self.debug = debug
        self.linebuf = ''

    def write(self, buf):
        for line in buf.rstrip().splitlines():
            self.logger.log(self.debug, line.rstrip())

# windows


def get_connection_name_from_guid(iface_guids):
    iface_names = ['(unknown)' for i in range(len(iface_guids))]
    reg = wr.ConnectRegistry(None, wr.HKEY_LOCAL_MACHINE)
    reg_key = wr.OpenKey(
        reg,
        r'SYSTEM\CurrentControlSet\Control\Network\{4d36e972-e325-11ce-bfc1-08002be10318}')
    for i in range(len(iface_guids)):
        try:
            reg_subkey = wr.OpenKey(reg_key, iface_guids[i] + r'\Connection')
            iface_names[i] = wr.QueryValueEx(reg_subkey, 'Name')[0]
        except BaseException:
            pass
    return iface_names


def isWinUserAdmin():
    if os.name == 'nt':
        import ctypes
        # WARNING: requires Windows XP SP2 or higher!
        try:
            return ctypes.windll.shell32.IsUserAnAdmin()
        except BaseException:
            traceback.print_exc()
            print "Admin check failed, assuming not an admin."
            return False
    elif os.name == 'posix':
        # Check for root on Posix
        return os.getuid() == 0
    else:
        raise RuntimeError(
            "Unsupported operating system for this module: %s" %
            (os.name,))


def isMacOsUserAdmin():
    # pour linux "cat /etc/shadow")
    obj = simplecommand("cat /etc/master.passwd")
    if int(obj['code']) == 0:
        return True
    else:
        return False


#listplugins = ['.'.join(fn.split('.')[:-1]) for fn in os.listdir(getPluginsPath) if fn.endswith(".py") and fn != "__init__.py"]
def getRandomName(nb, pref=""):
    a = "abcdefghijklnmopqrstuvwxyz0123456789"
    d = pref
    for t in range(nb):
        d = d + a[random.randint(0, 35)]
    return d


def md5(fname):
    hash = hashlib.md5()
    with open(fname, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash.update(chunk)
    return hash.hexdigest()


def loadModule(filename):
    if filename == '':
        raise RuntimeError, 'Empty filename cannot be loaded'
    searchPath, file = os.path.split(filename)
    if not searchPath in sys.path:
        sys.path.append(searchPath)
        sys.path.append(os.path.normpath(searchPath+"/../"))
    moduleName, ext = os.path.splitext(file)
    fp, pathName, description = imp.find_module(moduleName, [searchPath,])
    try:
        module = imp.load_module(moduleName, fp, pathName, description)
    finally:
        if fp:
            fp.close()
    return module

def call_plugin(name, *args, **kwargs):
    nameplugin = os.path.join(args[0].modulepath, "plugin_%s"%args[1])
    #add compteur appel plugins
    count = 0
    try:
        count = getattr(args[0], "num_call%s"%args[1])
    except AttributeError:
        count = 0
        setattr(args[0], "num_call%s"%args[1], count)
    pluginaction = loadModule(nameplugin)
    pluginaction.action(*args, **kwargs)
    setattr(args[0], "num_call%s"%args[1], count + 1)

#def load_plugin(name):
    #mod = __import__("plugin_%s" % name)
    #return mod


#def call_plugin(name, *args, **kwargs):
    #pluginaction = load_plugin(name)
    #pluginaction.action(*args, **kwargs)


def getshortenedmacaddress():
    listmacadress = {}
    for nbsearchmac in range(20):
        for i in netifaces.interfaces():
            addrs = netifaces.ifaddresses(i)
            try:
                if_mac = reduction_mac(addrs[netifaces.AF_LINK][0]['addr'])
                addrs[netifaces.AF_INET][0]['addr']
                address = int(if_mac, 16)
                if address != 0:
                    listmacadress[address] = if_mac
            except BaseException:
                pass
        if len(listmacadress) > 0:
            break
        else:
            time.sleep(1)
    return listmacadress


def getMacAdressList():
    listmacadress = []
    for interfacenet in netifaces.interfaces():
        try:
            macadress = netifaces.ifaddresses(
                interfacenet)[netifaces.AF_LINK][0]['addr']
            if macadress != "00:00:00:00:00:00":
                listmacadress.append(macadress)
        except BaseException:
            pass
    return listmacadress


def getIPAdressList():
    ip_list = []
    for interface in netifaces.interfaces():
        try:
            for link in netifaces.ifaddresses(interface)[netifaces.AF_INET]:
                if link['addr'] != '127.0.0.1':
                    ip_list.append(link['addr'])
        except BaseException:
            pass
    return ip_list


def MacAdressToIp(ip):
    'Returns a MAC for interfaces that have given IP, returns None if not found'
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


def name_jid():
    shortmacaddress = getshortenedmacaddress()
    sorted_macaddress = sorted(shortmacaddress.keys())
    return shortmacaddress[sorted_macaddress[0]]


def reduction_mac(mac):
    mac = mac.lower()
    mac = mac.replace(":", "")
    mac = mac.replace("-", "")
    mac = mac.replace(" ", "")
    #mac = mac.replace("/","")
    return mac


def is_valid_ipv4(ip):
    """Validates IPv4 addresses.
    """
    pattern = re.compile(r"""
        ^
        (?:
          # Dotted variants:
          (?:
            # Decimal 1-255 (no leading 0's)
            [3-9]\d?|2(?:5[0-5]|[0-4]?\d)?|1\d{0,2}
          |
            0x0*[0-9a-f]{1,2}  # Hexadecimal 0x0 - 0xFF (possible leading 0's)
          |
            0+[1-3]?[0-7]{0,2} # Octal 0 - 0377 (possible leading 0's)
          )
          (?:                  # Repeat 0-3 times, separated by a dot
            \.
            (?:
              [3-9]\d?|2(?:5[0-5]|[0-4]?\d)?|1\d{0,2}
            |
              0x0*[0-9a-f]{1,2}
            |
              0+[1-3]?[0-7]{0,2}
            )
          ){0,3}
        |
          0x0*[0-9a-f]{1,8}    # Hexadecimal notation, 0x0 - 0xffffffff
        |
          0+[0-3]?[0-7]{0,10}  # Octal notation, 0 - 037777777777
        |
          # Decimal notation, 1-4294967295:
          429496729[0-5]|42949672[0-8]\d|4294967[01]\d\d|429496[0-6]\d{3}|
          42949[0-5]\d{4}|4294[0-8]\d{5}|429[0-3]\d{6}|42[0-8]\d{7}|
          4[01]\d{8}|[1-3]\d{0,9}|[4-9]\d{0,8}
        )
        $
    """, re.VERBOSE | re.IGNORECASE)
    return pattern.match(ip) is not None


def is_valid_ipv6(ip):
    """Validates IPv6 addresses.
    """
    pattern = re.compile(r"""
        ^
        \s*                         # Leading whitespace
        (?!.*::.*::)                # Only a single whildcard allowed
        (?:(?!:)|:(?=:))            # Colon iff it would be part of a wildcard
        (?:                         # Repeat 6 times:
            [0-9a-f]{0,4}           #   A group of at most four hexadecimal digits
            (?:(?<=::)|(?<!::):)    #   Colon unless preceeded by wildcard
        ){6}                        #
        (?:                         # Either
            [0-9a-f]{0,4}           #   Another group
            (?:(?<=::)|(?<!::):)    #   Colon unless preceeded by wildcard
            [0-9a-f]{0,4}           #   Last group
            (?: (?<=::)             #   Colon iff preceeded by exacly one colon
             |  (?<!:)              #
             |  (?<=:) (?<!::) :    #
             )                      # OR
         |                          #   A v4 address with NO leading zeros
            (?:25[0-4]|2[0-4]\d|1\d\d|[1-9]?\d)
            (?: \.
                (?:25[0-4]|2[0-4]\d|1\d\d|[1-9]?\d)
            ){3}
        )
        \s*                         # Trailing whitespace
        $
    """, re.VERBOSE | re.IGNORECASE | re.DOTALL)
    return pattern.match(ip) is not None


def typelinux():
    """
        This function is used to tell which init system is used on the server.
        :return: Return the used init system between init.d or systemd
    """
    p = subprocess.Popen('cat /proc/1/comm',
                         shell=True,
                         stdout=subprocess.PIPE,
                         stderr=subprocess.STDOUT)
    result = p.stdout.readlines()
    #code_result = p.wait()
    system = result[0].rstrip('\n')
    """renvoi la liste des ip gateway en fonction de l'interface linux"""
    return system


def isprogramme(name):
    obj = {}
    p = subprocess.Popen("which %s" % (name),
                         shell=True,
                         stdout=subprocess.PIPE,
                         stderr=subprocess.STDOUT)
    result = p.stdout.readlines()
    obj['code'] = p.wait()
    obj['result'] = result
    if obj['result'] != "":
        return True
    else:
        return False


def simplecommand(cmd):
    obj = {}
    p = subprocess.Popen(cmd,
                         shell=True,
                         stdout=subprocess.PIPE,
                         stderr=subprocess.STDOUT)
    result = p.stdout.readlines()
    obj['code'] = p.wait()
    obj['result'] = result
    return obj


def simplecommandstr(cmd):
    obj = {}
    p = subprocess.Popen(cmd,
                         shell=True,
                         stdout=subprocess.PIPE,
                         stderr=subprocess.STDOUT)
    result = p.stdout.readlines()
    obj['code'] = p.wait()
    obj['result'] = "\n".join(result)
    return obj

def windowspath(namescript):
    if sys.platform.startswith('win'):
        return '"' + namescript + '"'
    else:
        return namescript

def powerschellscriptps1(namescript):
    namescript = windowspath(namescript)
    print "powershell -ExecutionPolicy Bypass -File  %s"%namescript
    obj = simplecommandstr(encode_strconsole("powershell -ExecutionPolicy Bypass -File %s"%namescript))
    return obj


class shellcommandtimeout(object):
    def __init__(self, cmd, timeout=15):
        self.process = None
        self.obj = {}
        self.obj['timeout'] = timeout
        self.obj['cmd'] = cmd
        self.obj['result']="result undefined"
        self.obj['code'] = 255
        self.obj['separateurline'] = os.linesep

    def run(self):
        def target():
            # print 'Thread started'
            self.process = subprocess.Popen(self.obj['cmd'],
                                            shell=True,
                                            stdout=subprocess.PIPE,
                                            stderr=subprocess.STDOUT)
            self.obj['result'] = self.process.stdout.readlines()
            self.obj['code'] = self.process.wait()
            self.process.communicate()
            # print 'Thread finished'
        thread = threading.Thread(target=target)
        thread.start()

        thread.join(self.obj['timeout'])
        if thread.is_alive():
            print 'Terminating process'
            print "timeout %s" % self.obj['timeout']
            #self.codereturn = -255
            #self.result = "error tineour"
            self.process.terminate()
            thread.join()

        #self.result = self.process.stdout.readlines()
        self.obj['codereturn'] = self.process.returncode

        if self.obj['codereturn'] == -15:
            self.result = "error tineout"

        return self.obj


def servicelinuxinit(name, action):
    obj = {}
    p = subprocess.Popen("/etc/init.d/%s %s" % (name, action),
                         shell=True,
                         stdout=subprocess.PIPE,
                         stderr=subprocess.STDOUT)
    result = p.stdout.readlines()
    obj['code'] = p.wait()
    obj['result'] = result
    return obj

# restart service


def service(name, action):  # start | stop | restart | reload
    obj = {}
    if sys.platform.startswith('linux'):
        system = ""
        p = subprocess.Popen('cat /proc/1/comm',
                             shell=True,
                             stdout=subprocess.PIPE,
                             stderr=subprocess.STDOUT)
        result = p.stdout.readlines()
        #code_result = p.wait()
        system = result[0].rstrip('\n')
        if system == "init":
            p = subprocess.Popen("/etc/init.d/%s %s" % (name, action),
                                 shell=True,
                                 stdout=subprocess.PIPE,
                                 stderr=subprocess.STDOUT)
            result = p.stdout.readlines()
            obj['code'] = p.wait()
            obj['result'] = result
        elif system == "systemd":
            p = subprocess.Popen("systemctl %s %s" % (action, name),
                                 shell=True,
                                 stdout=subprocess.PIPE,
                                 stderr=subprocess.STDOUT)
            result = p.stdout.readlines()
            obj['code'] = p.wait()
            obj['result'] = result
    elif sys.platform.startswith('win'):
        pythoncom.CoInitialize()
        try:
            wmi_obj = wmi.WMI()
            wmi_sql = "select * from Win32_Service Where Name ='%s'" % name
            wmi_out = wmi_obj.query(wmi_sql)
        finally:
            pythoncom.CoUninitialize()
        for dev in wmi_out:
            print dev.Caption
        pass
    elif sys.platform.startswith('darwin'):
        pass
    return obj


def listservice():
    pythoncom.CoInitialize()
    try:
        wmi_obj = wmi.WMI()
        wmi_sql = "select * from Win32_Service"  # Where Name ='Alerter'"
        wmi_out = wmi_obj.query(wmi_sql)
    finally:
        pythoncom.CoUninitialize()
    for dev in wmi_out:
        print dev.Caption
        print dev.DisplayName


def joint_compteAD(domain, password, login, group):
    # https://msdn.microsoft.com/en-us/library/windows/desktop/aa392154%28v=vs.85%29.aspx
    pythoncom.CoInitialize()
    try:
        c = wmi.WMI()
        for computer in c.Win32_ComputerSystem():
            if computer.PartOfDomain:
                print computer.Domain  # DOMCD
                print computer.SystemStartupOptions
                computer.JoinDomainOrWorkGroup(
                    domain, password, login, group, 3)
    finally:
        pythoncom.CoUninitialize()


def windowsservice(name, action):
    pythoncom.CoInitialize()
    try:
        wmi_obj = wmi.WMI()
        wmi_sql = "select * from Win32_Service Where Name ='%s'" % name
        print wmi_sql
        wmi_out = wmi_obj.query(wmi_sql)
    finally:
        pythoncom.CoUninitialize()
    print len(wmi_out)
    for dev in wmi_out:
        print dev.caption
        if action.lower() == "start":
            dev.StartService()
        elif action.lower() == "stop":
            print dev.Name
            dev.StopService()
        elif action.lower() == "restart":
            dev.StopService()
            dev.StartService()
        else:
            pass


def methodservice():
    import pythoncom
    import wmi
    pythoncom.CoInitialize()
    try:
        c = wmi.WMI()
        for method in c.Win32_Service._methods:
            print method
    finally:
        pythoncom.CoUninitialize()


def file_get_content(path):
    inputFile = open(path, 'r')  # Open test.txt file in read mode
    content = inputFile.read()
    inputFile.close()
    return content


def file_put_content(filename, contents, mode="w"):
    fh = open(filename, mode)
    fh.write(contents)
    fh.close()

# windows
# def listusergroup():
    #import wmi
    #c = wmi.WMI()
    # for group in c.Win32_Group():
    # print group.Caption
    # for user in group.associators("Win32_GroupUser"):
    # print "  ", user.Caption

# decorateur pour simplifier les plugins


def pluginprocess(func):
    def wrapper(objetxmpp, action, sessionid, data, message, dataerreur):
        resultaction = "result%s" % action
        result = {}
        result['action'] = resultaction
        result['ret'] = 0
        result['sessionid'] = sessionid
        result['base64'] = False
        result['data'] = {}
        dataerreur['action'] = resultaction
        dataerreur['data']['msg'] = "ERROR : %s" % action
        dataerreur['sessionid'] = sessionid
        try:
            response = func(
                objetxmpp,
                action,
                sessionid,
                data,
                message,
                dataerreur,
                result)
            # encode  result['data'] si besoin
            # print result
            if result['base64'] is True:
                result['data'] = base64.b64encode(json.dumps(result['data']))
            print "Send message \n%s" % result
            objetxmpp.send_message(mto=message['from'],
                                   mbody=json.dumps(result),
                                   mtype='chat')
        except BaseException:
            print "Send error message\n%s" % dataerreur
            objetxmpp.send_message(mto=message['from'],
                                   mbody=json.dumps(dataerreur),
                                   mtype='chat')
            return
        return response
    return wrapper


# decorateur pour simplifier les plugins
def pulgindeploy(func):
    def wrapper(objetxmpp, action, sessionid, data, message, dataerreur):
        resultaction = action
        result = {}
        result['action'] = resultaction
        result['ret'] = 0
        result['sessionid'] = sessionid
        result['base64'] = False
        result['data'] = {}
        dataerreur['action'] = resultaction
        dataerreur['data']['msg'] = "ERROR : %s" % action
        dataerreur['sessionid'] = sessionid
        try:
            response = func(
                objetxmpp,
                action,
                sessionid,
                data,
                message,
                dataerreur,
                result)
            if result['data'] != "end":
                if result['base64'] is True:
                    result['data'] = base64.b64encode(
                        json.dumps(result['data']))
                objetxmpp.send_message(mto=message['from'],
                                       mbody=json.dumps(result),
                                       mtype='chat')
        except BaseException:
            if result['data'] != "end":
                objetxmpp.send_message(mto=message['from'],
                                       mbody=json.dumps(dataerreur),
                                       mtype='chat')
            return
        return response
    return wrapper

# decorateur pour simplifier les plugins


def pulgindeploy1(func):
    def wrapper(objetxmpp, action, sessionid, data, message, dataerreur):
        result = {}
        result['action'] = action
        result['ret'] = 0
        result['sessionid'] = sessionid
        result['base64'] = False
        result['data'] = {}
        dataerreur['action'] = action
        dataerreur['data']['msg'] = "ERROR : %s" % action
        dataerreur['sessionid'] = sessionid
        try:
            response = func(
                objetxmpp,
                action,
                sessionid,
                data,
                message,
                dataerreur,
                result)

            if not 'end' in result['data']:
                result['data']['end'] = False

            print "----------------------------------------------------------------"
            print "sent message to %s " % message['from']
            if "Devent" in data:
                print "Devent : %s" % data["Devent"]
            if "Dtypequery" in data:
                print "Dtypequery : %s" % data["Dtypequery"]
            if "Deventindex" in data:
                print "Deventindex : %s" % data["Deventindex"]

            if not result['data']['end']:
                print "Envoi Message"
                print "result", result
                if result['base64'] is True:
                    result['data'] = base64.b64encode(
                        json.dumps(result['data']))
                objetxmpp.send_message(mto=message['from'],
                                       mbody=json.dumps(result),
                                       mtype='chat')
            else:
                print "envoi pas de message"
        except BaseException:
            if not result['data']['end']:
                print "Send error message"
                print "result", dataerreur
                objetxmpp.send_message(mto=message['from'],
                                       mbody=json.dumps(dataerreur),
                                       mtype='chat')
            else:
                print "Envoi pas de Message erreur"
            return
        print "---------------------------------------------------------------"
        return response
    return wrapper

# determine address ip utiliser pour xmpp


def getIpXmppInterface(ipadress1, Port):
    resultip = ''
    ipadress = ipfromdns(ipadress1)
    if sys.platform.startswith('linux'):
        logging.log(DEBUGPULSE, "Searching for the XMPP Server IP Adress")
        print "netstat -an |grep %s |grep %s| grep ESTABLISHED | grep -v tcp6" % (Port, ipadress)
        obj = simplecommand(
            "netstat -an |grep %s |grep %s| grep ESTABLISHED | grep -v tcp6" %
            (Port, ipadress))
        logging.log(
            DEBUGPULSE, "netstat -an |grep %s |grep %s| grep ESTABLISHED | grep -v tcp6" %
            (Port, ipadress))
        if obj['code'] != 0:
            logging.getLogger().error('error command netstat : %s'%obj['result'])
            logging.getLogger().error('error install package net-tools')
        if len(obj['result']) != 0:
            for i in range(len(obj['result'])):
                obj['result'][i] = obj['result'][i].rstrip('\n')
            a = "\n".join(obj['result'])
            b = [x for x in a.split(' ') if x != ""]
            if len(b) != 0:
                resultip = b[3].split(':')[0]
    elif sys.platform.startswith('win'):
        logging.log(DEBUGPULSE, "Searching for the XMPP Server IP Adress")
        print "netstat -an | findstr %s | findstr ESTABLISHED" % Port
        obj = simplecommand(
            "netstat -an | findstr %s | findstr ESTABLISHED" %
            Port)
        logging.log(
            DEBUGPULSE, "netstat -an | findstr %s | findstr ESTABLISHED" %
            Port)
        if len(obj['result']) != 0:
            for i in range(len(obj['result'])):
                obj['result'][i] = obj['result'][i].rstrip('\n')
            a = "\n".join(obj['result'])
            b = [x for x in a.split(' ') if x != ""]
            if len(b) != 0:
                resultip = b[1].split(':')[0]
    elif sys.platform.startswith('darwin'):
        logging.log(DEBUGPULSE, "Searching for the XMPP Server IP Adress")
        print "netstat -an |grep %s |grep %s| grep ESTABLISHED" % (Port, ipadress)
        obj = simplecommand(
            "netstat -an |grep %s |grep %s| grep ESTABLISHED" %
            (Port, ipadress))
        logging.log(
            DEBUGPULSE, "netstat -an |grep %s |grep %s| grep ESTABLISHED" %
            (Port, ipadress))
        if len(obj['result']) != 0:
            for i in range(len(obj['result'])):
                obj['result'][i] = obj['result'][i].rstrip('\n')
            a = "\n".join(obj['result'])
            b = [x for x in a.split(' ') if x != ""]
            if len(b) != 0:
                resultip = b[3][:b[3].rfind(".")]
    else:
        obj = simplecommand("netstat -a | grep %s | grep ESTABLISHED" % Port)
        if len(obj['result']) != 0:
            for i in range(len(obj['result'])):
                obj['result'][i] = obj['result'][i].rstrip('\n')
            a = "\n".join(obj['result'])
            b = [x for x in a.split(' ') if x != ""]
            if len(b) != 0:
                resultip = b[1].split(':')[0]
    return resultip

# 3 functions used for subnet network


def ipV4toDecimal(ipv4):
    d = ipv4.split('.')
    return (int(d[0]) * 256 * 256 * 256) + (int(d[1])
                                            * 256 * 256) + (int(d[2]) * 256) + int(d[3])


def decimaltoIpV4(ipdecimal):
    a = float(ipdecimal) / (256 * 256 * 256)
    b = (a - int(a)) * 256
    c = (b - int(b)) * 256
    d = (c - int(c)) * 256
    return "%s.%s.%s.%s" % (int(a), int(b), int(c), int(d))


def subnetnetwork(adressmachine, mask):
    adressmachine = adressmachine.split(":")[0]
    reseaumachine = ipV4toDecimal(adressmachine) & ipV4toDecimal(mask)
    return decimaltoIpV4(reseaumachine)


def searchippublic(site=1):
    if site == 1:
        try:
            page = urllib.urlopen("http://ifconfig.co/json").read()
            objip = json.loads(page)
            if is_valid_ipv4(objip['ip']):
                return objip['ip']
            else:
                return searchippublic(2)
        except BaseException:
            return searchippublic(2)
    elif site == 2:
        try:
            page = urllib.urlopen("http://www.monip.org/").read()
            ip = page.split("IP : ")[1].split("<br>")[0]
            if is_valid_ipv4(ip):
                return ip
            else:
                return searchippublic(3)
        except Exception:
            return searchippublic(3)
    elif site == 3:
        try:
            ip =   urllib.urlopen("http://ip.42.pl/raw").read()
            if is_valid_ipv4(ip):
                return ip
            else:
                return searchippublic(4)
        except Exception:
            searchippublic(4)
    elif site == 4:
        return find_ip()
    return None

def find_ip():
    candidates =[]
    for test_ip in ['192.0.2.0',"192.51.100.0","203.0.113.0"]:
        try:
            s=socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect((test_ip,80))
            ip_adrss = s.getsockname()[0]
            if ip_adrss in candidates:
                return ip_adrss
            candidates.append(ip_adrss)
        except Exception:
            pass
        finally:
            s.close()
    if len(candidates) >=1:
        return candidates[0]
    return None

# decorateur pour simplifier les plugins
# verify session exist.
# pas de session end
def pulginmaster(func):
    def wrapper(objetxmpp, action, sessionid, data, message, ret):
        if action.startswith("result"):
            action = action[:6]
        if objetxmpp.session.isexist(sessionid):
            objsessiondata = objetxmpp.session.sessionfromsessiondata(
                sessionid)
        else:
            objsessiondata = None
        response = func(
            objetxmpp,
            action,
            sessionid,
            data,
            message,
            ret,
            objsessiondata)
        return response
    return wrapper


def pulginmastersessionaction(sessionaction, timeminute=10):
    def decorateur(func):
        def wrapper(objetxmpp, action, sessionid, data, message, ret, dataobj):
            # avant
            if action.startswith("result"):
                action = action[6:]
            if objetxmpp.session.isexist(sessionid):
                if sessionaction == "actualise":
                    objetxmpp.session.reactualisesession(sessionid, 10)
                objsessiondata = objetxmpp.session.sessionfromsessiondata(
                    sessionid)
            else:
                objsessiondata = None
            response = func(
                objetxmpp,
                action,
                sessionid,
                data,
                message,
                ret,
                dataobj,
                objsessiondata)
            if sessionaction == "clear" and objsessiondata != None:
                objetxmpp.session.clear(sessionid)
            elif sessionaction == "actualise":
                objetxmpp.session.reactualisesession(sessionid, 10)
            return response
        return wrapper
    return decorateur


def merge_dicts(*dict_args):
    result = {}
    for dictionary in dict_args:
        result.update(dictionary)
    return result


def portline(result):
    column = [x.strip() for x in result.split(' ') if x != ""]
    print column
    return column[-2:-1][0].split(':')[1]


def protoandport():
    protport = {}
    if sys.platform.startswith('win'):
        for process in psutil.process_iter():
            if 'tvnserver.exe' in process.name():
                process_handler = psutil.Process(process.pid)
                for cux in process_handler.connections():
                    if cux.status == psutil.CONN_LISTEN:
                        protport['vnc'] = cux.laddr.port
            elif 'sshd.exe' in process.name():
                process_handler = psutil.Process(process.pid)
                for cux in process_handler.connections():
                    if cux.status == psutil.CONN_LISTEN:
                        protport['ssh'] = cux.laddr.port
        for service in psutil.win_service_iter():
            if 'TermService' in service.name():
                service_handler = psutil.win_service_get('TermService')
                if service_handler.status() == 'running':
                    pid = service_handler.pid()
                    process_handler = psutil.Process(pid)
                    for cux in process_handler.connections():
                        if cux.status == psutil.CONN_LISTEN:
                            protport['rdp'] = cux.laddr.port

    elif sys.platform.startswith('linux'):
        for process in psutil.process_iter():
            if 'x11vnc' in process.name():
                process_handler = psutil.Process(process.pid)
                for cux in process_handler.connections():
                    try:
                        ip = cux.laddr[0]
                        port = cux.laddr[1]
                    except Exception:
                        ip = cux.laddr.ip
                        port = cux.laddr.port
                    if cux.status == psutil.CONN_LISTEN and ip == "0.0.0.0":
                        protport['vnc'] = port
            elif 'sshd' in process.name():
                process_handler = psutil.Process(process.pid)
                for cux in process_handler.connections():
                    try:
                        ip = cux.laddr[0]
                        port = cux.laddr[1]
                    except Exception:
                        ip = cux.laddr.ip
                        port = cux.laddr.port
                    if cux.status == psutil.CONN_LISTEN and ip == "0.0.0.0":
                        protport['ssh'] = port
            elif 'xrdp' in process.name():
                process_handler = psutil.Process(process.pid)
                for cux in process_handler.connections():
                    try:
                        ip = cux.laddr[0]
                        port = cux.laddr[1]
                    except Exception:
                        ip = cux.laddr.ip
                        port = cux.laddr.port
                    if cux.status == psutil.CONN_LISTEN and ip == "0.0.0.0":
                        protport['rdp'] = port

    elif sys.platform.startswith('darwin'):
        for process in psutil.process_iter():
            if 'ARDAgent' in process.name():
                protport['vnc'] = '5900'
        for cux in psutil.net_connections():
            if cux.laddr.port == 22 and cux.status == psutil.CONN_LISTEN:
                protport['ssh'] = '22'

    return protport


def ipfromdns(name_domaine_or_ip):
    """ This function converts a dns to ipv4
        If not find return ""
        function tester on OS:
        MAcOs, linux (debian, redhat, ubuntu), windows
        eg : print ipfromdns("sfr.fr")
        80.125.163.172
    """
    if name_domaine_or_ip != "" and name_domaine_or_ip != None:
        if is_valid_ipv4(name_domaine_or_ip):
            return name_domaine_or_ip
        try:
            return socket.gethostbyname(name_domaine_or_ip)
        except socket.gaierror:
            return ""
        except Exception:
            return ""
    return ""


def check_exist_ip_port(name_domaine_or_ip, port):
    """ This function check if socket valid for connection
        return True or False
    """
    ip = ipfromdns(name_domaine_or_ip)
    try:
        socket.getaddrinfo(ip, port)
        return True
    except socket.gaierror:
        return False
    except Exception:
        return False


def install_or_uninstall_keypub_authorized_keys(
        install=True, keypub=None, user="pulse"):
    """
        This function installs or uninstall the public key in the authorized_keys file for user "user"
        If keypub is not specified then the function uninstall the key for user "user"
    """
    path_ssh = os.path.join(os.path.expanduser('~%s' % user), ".ssh")
    path_authorized_keys = os.path.join(path_ssh, "authorized_keys")
    logging.log(
        DEBUGPULSE,
        "file path_authorized_keys : %s" %
        path_authorized_keys)
    if not os.path.isdir(path_ssh):
        try:
            os.makedirs(path_ssh, 0o700)
        except OSError:
            logging.log(DEBUGPULSE, "error create directory : %s" % path_ssh)
            return False
    if not os.path.exists(path_authorized_keys):
        try:
            open(path_authorized_keys, 'a').close()
            if not sys.platform.startswith('win'):
                os.chmod(path_authorized_keys, 0o600)
                obj = simplecommandstr(
                    "grep %s /etc/passwd | cut -d':' -f3" % user)
                os.chown(path_authorized_keys, int(obj['result']), -1)
        except Exception as e:
            logging.log(DEBUGPULSE, "ERROR %s" % str(e))
            logging.log(
                DEBUGPULSE,
                "error create file : %s" %
                path_authorized_keys)
            return False
    if install:
        logging.log(DEBUGPULSE, "install key if key missing")
        # See if the key is already installed
        addkey = True
        try:
            source = open(path_authorized_keys, "r")
            for ligne in source.readlines():
                if ligne.startswith(keypub):
                    addkey = False
                    break
            source.close()
        except Exception as e:
            logging.log(DEBUGPULSE, "ERROR %s" % str(e))
            return False
        if addkey:
            logging.log(
                DEBUGPULSE,
                "key missing, install key in  %s" %
                path_authorized_keys)
            try:
                source = open(path_authorized_keys, "a")
                source.write('\n')
                source.write(keypub)
                source.close()
            except Exception as e:
                logging.log(DEBUGPULSE, "ERROR %s" % str(e))
                return False
    else:
        logging.log(DEBUGPULSE, "uninstall key")
        filesouce = ""
        source = open(path_authorized_keys, "r")
        for ligne in source:
            if ligne.startswith(os.sep):
                continue
            if not ligne.startswith(keypub):
                filesouce = filesouce + ligne
        source.close()
        source = open(path_authorized_keys, "w").write(filesouce)
        source.close()
    return True


def get_keypub_ssh(name="id_rsa.pub", user="root"):
    """
        return key public
        only for linux
    """
    path_ssh = os.path.join(os.path.expanduser('~%s' % user), ".ssh", name)
    source = open(path_ssh, "r")
    keypub = source.read().strip(" \n\t")
    source.close()
    return keypub


def get_sid_user(name):
    """
        for windows only
    """
    wmi_obj = wmi.WMI()
    wmi_sql = "select * from Win32_UserAccount Where Name ='%s'" % name
    wmi_out = wmi_obj.query(wmi_sql)
    for dev in wmi_out:
        return dev.SID


if sys.platform.startswith('win'):
    def set_reg(name, value, subkey, key=wr.HKEY_LOCAL_MACHINE,
                type=wr.REG_SZ):
        try:
            wr.CreateKey(key, subkey)
            registry_key = wr.OpenKey(wr.HKEY_CURRENT_USER,
                                      subkey,
                                      0,
                                      wr.KEY_WRITE)
            wr.SetValueEx(registry_key, name, 0, type, value)
            wr.CloseKey(registry_key)
            return True
        except WindowsError:
            return False

    def get_reg(name, subkey, key=wr.HKEY_LOCAL_MACHINE):
        try:
            registry_key = wr.OpenKey(key,
                                      subkey,
                                      0,
                                      wr.KEY_READ)
            value, regtype = wr.QueryValueEx(registry_key, name)
            wr.CloseKey(registry_key)
            return value
        except WindowsError:
            return None

def shutdown_command(time = 0, msg=''):
    """
        This  function allow to shutdown a machine, and if needed
        to display a message

        Args:
            time: the delay before the shutdown
            msg:  the message that will be displayed

    """
    if sys.platform.startswith('linux'):
        if int(time) == 0 or msg =='':
            cmd = "shutdown now"
        else:
            cmd = "shutdown -P -f -t %s %s"%(time, msg)
            logging.debug(cmd)
            os.system(cmd)
    elif sys.platform.startswith('win'):
        if int(time) == 0 or msg =='':
            cmd = "shutdown /p"
        else:
            cmd = "shutdown /s /t %s /c %s"%(time, msg)
            logging.debug(cmd)
            os.system(cmd)
    elif sys.platform.startswith('darwin'):
        if int(time) == 0 or msg =='':
            cmd = "shutdown -h now"
        else:
            cmd = "shutdown -h +%s \"%s\""%(time, msg)
            logging.debug(cmd)
            os.system(cmd)
    return

def vnc_set_permission(askpermission = 1):
    """
    This function allows to change the setting of VNC to ask for
    permission from user before connecting to Windows machines

    Args:
        askpermission: 0 or 1

    """
    if sys.platform.startswith('linux'):
        pass
    elif sys.platform.startswith('win'):
        if askpermission == 0:
            cmd = 'reg add "HKLM\SOFTWARE\TightVNC\Server" /f /v QueryAcceptOnTimeout /t REG_DWORD /d 1 && reg add "HKLM\SOFTWARE\TightVNC\Server" /f /v QueryTimeout /t REG_DWORD /d 1 && net stop tvnserver && net start tvnserver'
        else:
            cmd = 'reg add "HKLM\SOFTWARE\TightVNC\Server" /f /v QueryAcceptOnTimeout /t REG_DWORD /d 0 && reg add "HKLM\SOFTWARE\TightVNC\Server" /f /v QueryTimeout /t REG_DWORD /d 20 && net stop tvnserver && net start tvnserver'
        logging.debug(cmd)
        os.system(cmd)
    elif sys.platform.startswith('darwin'):
        pass

    return

def reboot_command():
    """
        This function allow to reboot a machine.
    """
    if sys.platform.startswith('linux'):
        os.system("shutdown -r now")
    elif sys.platform.startswith('win'):
        os.system("shutdown /r")
    elif sys.platform.startswith('darwin'):
        os.system("shutdown -r now")

    return

def isBase64(s):
    try:
        if base64.b64encode(base64.b64decode(s)) == s:
            return True;
    except Exception:
        pass;
    return False;

def decode_strconsole(x):
    """ imput str decode to default coding python(# -*- coding: utf-8; -*-)"""
    if sys.platform.startswith('linux'):
        return x.decode('utf-8','ignore')
    elif sys.platform.startswith('win'):
        return x.decode('cp850','ignore')
    elif sys.platform.startswith('darwin'):
        return x.decode('utf-8','ignore')
    else:
        return x

def encode_strconsole(x):
    """ output str encode to coding other system """
    if sys.platform.startswith('linux'):
        return x.encode('utf-8')
    elif sys.platform.startswith('win'):
        return x.encode('cp850')
    elif sys.platform.startswith('darwin'):
        return x.encode('utf-8')
    else:
        return x


def savejsonfile(filename, data, indent = 4):
    with open(filename, 'w') as outfile:
        json.dump(data, outfile)

def loadjsonfile(filename):
    if os.path.isfile(filename ):
        with open(filename,'r') as info:
            dd = info.read()
        try:
            return json.loads(decode_strconsole(dd))
        except Exception as e:
            logger.error("filename %s error decodage [%s]"%(filename ,str(e)))
    return None

def save_user_current(name = None):
    loginuser = os.path.join(Setdirectorytempinfo(), 'loginuser')
    if name is None:
        userlist = list(set([users[0]  for users in psutil.users()]))
        if len(userlist) > 0:
            name = userlist[0]
    else:
        name = "system"

    if not os.path.exists(loginuser):
        result = { name : 1,
                  'suite' : [name],
                  'curent' : name}
        savejsonfile(loginuser,result)
        return  result['curent']

    datauseruser = loadjsonfile(loginuser)
    if name in datauseruser:
        datauseruser[name] = datauseruser[name] + 1
        datauseruser['suite'].insert(0, name)
    else:
        datauseruser[name] = 1

    datauseruser['suite'].insert(0, name)
    datauseruser['suite'] = datauseruser['suite'][0:15]

    element = set(datauseruser['suite'])
    max = 0
    for t in element:
        valcount = datauseruser['suite'].count(t)
        if valcount > max :
            datauseruser['curent'] = t
    savejsonfile(loginuser, datauseruser)
    return datauseruser['curent']


def test_kiosk_presence():
    """Test if the kiosk is installed in the machine.
    Returns:
        string "True" if the directory is founded
        or
        string "False" if the directory is not founded"""

    def _get_kiosk_path():
        """This private function find the path for the pytho3 install.
        If no installation is found the the function returns  None.
        Returns:
            string: the path of python3/site-packages
            or
            None if no path is founded"""
        list = []
        if sys.platform.startswith("win"):
            list = [
                os.path.join(os.environ["ProgramFiles"], "Python36", "Lib", "site-packages"),
                os.path.join(os.environ["ProgramFiles"], "Python36-32", "Lib", "site-packages")
            ]
        elif sys.platform == "darwin":
            list = ["usr","local","lib","python3.6","dist-packages"]
        elif sys.platform == "linux":
            list = ["usr","lib","python3.6","dist-packages",
                    "usr", "lib", "python3.5", "dist-packages"]

        for element in list:
            if os.path.isdir(element):
                return element
        return None

    path = _get_kiosk_path()
    if path is not None and os.path.isdir(os.path.join(path, 'kiosk_interface')):
        return "True"
    else:
        return "False"

def utc2local (utc):
    """
    utc2local transform a utc datetime object to local object.

    Param:
        utc datetime which is not naive (the utc timezone must be precised)
    Returns:
        datetime in local timezone
    """
    epoch = time.mktime(utc.timetuple())
    offset = datetime.fromtimestamp (epoch) - datetime.utcfromtimestamp (epoch)
    return utc + offset

def keypub():
    keypubstring = ""
    if sys.platform.startswith('linux'):
        if not os.path.isfile("/root/.ssh/id_rsa"):
            obj = simplecommand('ssh-keygen -b 2048 -t rsa -f /root/.ssh/id_rsa -q -N ""')
        return file_get_contents("/root/.ssh/id_rsa.pub")
    elif sys.platform.startswith('win'):
        try:
            win32net.NetUserGetInfo('','pulseuser',0)
            pathkey = os.path.join("c:\Users\pulseuser", ".ssh")
        except:
            pathkey = os.path.join(os.environ["ProgramFiles"], "pulse" ,'.ssh')
        if not os.path.isfile(os.path.join(pathkey , "id_rsa")):
            obj = simplecommand('"C:\Program Files\OpenSSH\ssh-keygen.exe" -b 2048 -t rsa -f "%s" -q -N ""'%os.path.join(pathkey, "id_rsa"))
        return file_get_contents(os.path.join(pathkey, "id_rsa.pub"))
    elif sys.platform.startswith('darwin'):
        if not os.path.isfile("/var/root/.ssh/id_rsa"):
            obj = simplecommand('ssh-keygen -b 2048 -t rsa -f /var/root/.ssh/id_rsa -q -N ""')
        return file_get_contents("/var/root/.ssh/id_rsa.pub")

#use function for relayserver
def deletekey(file, key, back = True):
    if os.path.isfile(file):
        if back:
            simplecommand("sed -i.bak '/%s/d' %s"%( key, file))
        else:
            simplecommand("sed -i '/%s/d' %s"%( key, file))

def installkey(file, key, back = True):
    deletekey(file, key, back = back)
    simplecommand('echo "%s" >> %s'%( key, file))

def connection_established(Port):
    """ verify connection etablish
        return true if etablish
    """
    if sys.platform.startswith('linux'):
        obj = simplecommandstr("netstat -an |grep %s | grep ESTABLISHED | grep -v tcp6" %(Port))
    elif sys.platform.startswith('win'):
        obj = simplecommandstr("netstat -an | findstr %s | findstr ESTABLISHED"%Port)
    elif sys.platform.startswith('darwin'):
        obj = simplecommandstr("netstat -an |grep %s | grep ESTABLISHED" %(Port))
    if "ESTABLISHED" in obj['result']:
        return True
    else:
        logger.warning("connection xmpp low")
        return False

def showlinelog(nbline = 200):
    obj = { "result" : ""}
    if sys.platform.startswith('win'):
        na = os.path.join(os.environ['ProgramFiles'], "Pulse", "var", "log","xmpp-agent.log")
        if os.path.isfile(na):
            obj = simplecommandstr(encode_strconsole("powershell \"Get-Content '%s' | select -last %s\""%(na, nbline)))
    elif sys.platform.startswith('linux'):
        na = os.path.join("/", "var", "log", "pulse", "xmpp-agent.log")
        if os.path.isfile(na):
            obj = simplecommandstr("cat %s | tail -n %s"%(na, nbline))
    return obj['result']

def is_findHostfromHostname(hostname):
    try:
        host = socket.gethostbyname(hostname)
        return True
    except:
        pass
    return False

def is_findHostfromIp(ip):
    try:
        host = socket.gethostbyaddr(ip)
        return True
    except:
        pass
    return False

def is_connectedServer(ip, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(5.0)
    port=int(port)
    try:
        sock.connect((ip, port))
        return True
    except socket.error:
        return False
    finally:
        sock.close()

class Program:
    def __init__(self):
        self.programlist = {}
        self.logger = logging.getLogger()

    def startprogram(self, pathprogram, uniqexecutablename):
        #['/bin/vikings', '-input', 'eggs.txt', '-output', 'spam spam.txt', '-cmd', "echo '$MONEY'"]
        #p = subprocess.Popen(args) # Success!
        #flag windows -> https://docs.microsoft.com/fr-fr/windows/desktop/ProcThread/process-creation-flags


        if sys.platform.startswith('win'):
            CREATE_NEW_PROCESS_GROUP=0x00000200
            DETACHED_PROCESS=0x00000008
            progrm = subprocess.Popen(pathprogram,
                                    shell=False,
                                    creationflags=DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP,
                                    close_fds=True)
            self.programlist[uniqexecutablename]=progrm
        elif sys.platform.startswith('linux') or sys.platform.startswith('darwin'):
            progrm = subprocess.Popen(pathprogram,
                                      shell=True,
                                      stdout=None,
                                      stderr=None,
                                      close_fds=True)
            self.programlist[uniqexecutablename]=progrm
        else:
            self.logger.error("The launch command for syncthing is not implemented for this OS")

    def stopprogram(self, uniqexecutablename):
        subprocess.Popen.kill(self.programlist[uniqexecutablename])
        del self.programlist[uniqexecutablename]

    def stopallprogram(self):
        for prog in self.programlist:
            subprocess.Popen.kill(self.programlist[prog])
        self.programlist.clear()

unpad = lambda s : s[0:-ord(s[-1])]
class AESCipher:

    def __init__( self, key , BS = 32):
        self.key = key
        self.BS = BS

    def _pad(self, s):
        return s + (self.BS - len(s) % self.BS) * chr(self.BS - len(s) % self.BS)

    def encrypt( self, raw ):
        raw = self._pad(raw)
        iv = Random.new().read( AES.block_size )
        cipher = AES.new( self.key, AES.MODE_CBC, iv )
        return base64.b64encode( iv + cipher.encrypt( raw ) )

    def decrypt( self, enc ):
        enc = base64.b64decode(enc)
        iv = enc[:16]
        cipher = AES.new(self.key, AES.MODE_CBC, iv )
        return unpad(cipher.decrypt( enc[16:] ))


def setgetcountcycle(data = None):
    chemin = os.path.join(os.path.dirname(os.path.realpath(__file__)),
                          "..",
                          "cycle",
                          "countcyclealternatif")
    try:
        countcyclealternatif = int( file_get_contents(chemin).strip(" \n\t"))
    except Exception:
        countcyclealternatif =  0
        data=None
    if data is None:
        #initialise variable
        file_put_contents(chemin, "0")
        return 0
    elif data == -1:
        return countcyclealternatif
    elif data >= 0:
        countcyclealternatif = countcyclealternatif + data
        file_put_contents(chemin, str(countcyclealternatif))
        return countcyclealternatif

def setgetrestart(data = None):
    chemin = os.path.join(os.path.dirname(os.path.realpath(__file__)),
                          "..",
                          "cycle",
                          "restart")
    try:
        restart = int(file_get_contents(chemin).strip(" \n\t"))
    except Exception:
        restart =  0
        data=None
    if data is None:
        #initialise variable
        file_put_contents(chemin, "0")
        return 0
    elif data == -1:
        return restart
    elif data == 0:
        file_put_contents(chemin,"0")
        return 0
    elif  data == 1:
        file_put_contents(chemin, "1")
        return 1

def detectantivirus():
    def SECURITY_PROVIDER(keyobject, data):
        str = data[0:2]
        if str   == "00" : return "NONE"
        elif str == "01" : return "FIREWALL"
        elif str == "02" : return "AUTOUPDATE_SETTINGS"
        elif str == "04" : return "ANTIVIRUS"
        elif str == "08" : return "ANTISPYWARE"
        elif str == "16" : return "INTERNET_SETTINGS"
        elif str == "32" : return "USER_ACCOUNT_CONTROL"
        elif str == "64" : return "SERVICE"
        else : return keyobject.upper()

    def SECURITY_PRODUCT_STATE(data):
        str = data[2:4]
        if str   == "00" : return "OFF"
        elif str == "01" : return "EXPIRED"
        elif str == "10" : return "ON"
        elif str == "11" : return "SNOOZED"
        else :  return "UNKNOWN"

    def SECURITY_SIGNATURE_STATUS(data):
        str = data[4:6]
        if str    =="00" : return "UP_TO_DATE"
        elif str == "10" : return "OUT_OF_DATE"
        else : return "UNKNOWN"

    def elemenstructure():
        return {
            "displayName" : "",
            "instanceGuid" : "",
            "pathToSignedProductExe" : "",
            "pathToSignedReportingExe" : "",
            "productState" : 0,
            "hex" : "000000",
            "SECURITY_PROVIDER" : "NONE",
            "SECURITY_PRODUCT_STATE" : "UNKNOWN",
            "SECURITY_SIGNATURE_STATUS" : "UNKNOWN",
            "timestamp" : "",
            }
    if sys.platform.startswith('win'):
        result={}
        objWMI = {"Antivirus" : GetObject('winmgmts:\\\\.\\root\\SecurityCenter2').InstancesOf('AntiVirusProduct'),
                  "Firewall" : GetObject('winmgmts:\\\\.\\root\\SecurityCenter2').InstancesOf('FirewallProduct'),
                  "AntiSpyware" :  GetObject('winmgmts:\\\\.\\root\\SecurityCenter2').InstancesOf('AntiSpywareProduct')}
        for key in objWMI:
            result[key]=[]
            for i in objWMI[key]:
                infoprotection = elemenstructure()
                try:
                    infoprotection['displayName'] = i.displayName.strip()
                except Exception:
                    pass
                try:
                    infoprotection['instanceGuid'] = i.instanceGuid.strip()
                except Exception:
                    pass
                try:
                    infoprotection['pathToSignedProductExe'] = i.pathToSignedProductExe.strip()
                except Exception:
                    pass
                try:
                    infoprotection['pathToSignedReportingExe'] = i.pathToSignedReportingExe.strip()
                except Exception:
                    pass
                try:
                    infoprotection['productState'] = i.productState
                    infoprotection['hex'] = "%06x"%i.productState
                    infoprotection['SECURITY_PROVIDER'] = SECURITY_PROVIDER(key, infoprotection['hex'])
                    infoprotection['SECURITY_PRODUCT_STATE'] = SECURITY_PRODUCT_STATE(infoprotection['hex'])
                    infoprotection['SECURITY_SIGNATURE_STATUS'] = SECURITY_SIGNATURE_STATUS(infoprotection['hex'])
                except Exception:
                    print "kkkkk"
                    pass
                try:
                    infoprotection['timestamp'] = i.timestamp.strip()
                except Exception:
                    pass
                result[key].append(infoprotection)
        return result

def information_machine():
    result={}
    def WMIDateStringToDate(dtmDate):
        strDateTime = ""
        if (dtmDate[4] == 0):
            strDateTime = dtmDate[5] + '/'
        else:
            strDateTime = dtmDate[4] + dtmDate[5] + '/'
        if (dtmDate[6] == 0):
            strDateTime = strDateTime + dtmDate[7] + '/'
        else:
            strDateTime = strDateTime + dtmDate[6] + dtmDate[7] + '/'
            strDateTime = strDateTime + dtmDate[0] + dtmDate[1] + dtmDate[2] + dtmDate[3] + " " + dtmDate[8] + dtmDate[9] + ":" + dtmDate[10] + dtmDate[11] +':' + dtmDate[12] + dtmDate[13]
        return strDateTime

    if sys.platform.startswith('win'):
        strComputer = "."
        objWMIService = win32com.client.Dispatch("WbemScripting.SWbemLocator")
        objSWbemServices = objWMIService.ConnectServer(strComputer,"root\cimv2")
        colItems = objSWbemServices.ExecQuery("SELECT * FROM Win32_ComputerSystem")
        for objItem in colItems:
            if objItem.AdminPasswordStatus != None:
                result[ "AdminPasswordStatus"] = objItem.AdminPasswordStatus
            if objItem.AutomaticResetBootOption != None:
                result[ "AutomaticResetBootOption"] = objItem.AutomaticResetBootOption
            if objItem.AutomaticResetCapability != None:
                result[ "AutomaticResetCapability"] = objItem.AutomaticResetCapability
            if objItem.BootOptionOnLimit != None:
                result[ "BootOptionOnLimit"] = objItem.BootOptionOnLimit
            if objItem.BootOptionOnWatchDog != None:
                result[ "BootOptionOnWatchDog"] = objItem.BootOptionOnWatchDog
            if objItem.BootROMSupported != None:
                result[ "BootROMSupported"] = objItem.BootROMSupported
            if objItem.BootupState != None:
                result[ "BootupState"] = objItem.BootupState
            if objItem.Caption != None:
                result[ "Caption"] = objItem.Caption
            if objItem.ChassisBootupState != None:
                result[ "ChassisBootupState"] = objItem.ChassisBootupState
            if objItem.CreationClassName != None:
                result[ "CreationClassName"] = objItem.CreationClassName
            if objItem.CurrentTimeZone != None:
                result[ "CurrentTimeZone"] = objItem.CurrentTimeZone
            if objItem.DaylightInEffect != None:
                result[ "DaylightInEffect"] = objItem.DaylightInEffect
            if objItem.Description != None:
                result[ "Description"] = objItem.Description
            if objItem.DNSHostName != None:
                result[ "DNSHostName"] = objItem.DNSHostName
            if objItem.Domain != None:
                result[ "Domain"] = objItem.Domain
            if objItem.DomainRole != None:
                result[ "DomainRole"] = objItem.DomainRole
            if objItem.EnableDaylightSavingsTime != None:
                result[ "EnableDaylightSavingsTime"] = objItem.EnableDaylightSavingsTime
            if objItem.FrontPanelResetStatus != None:
                result[ "FrontPanelResetStatus"] = objItem.FrontPanelResetStatus
            if objItem.InfraredSupported != None:
                result[ "InfraredSupported"] = objItem.InfraredSupported

            strList = "null"
            try :
                strList = ",".join([ str(x) for x in objItem.InitialLoadInfo])
            except:
                pass
            result[ "InitialLoadInfo"] = strList

            if objItem.InstallDate != None:
                result[ "InstallDate"] + WMIDateStringToDate(objItem.InstallDate)
            if objItem.KeyboardPasswordStatus != None:
                result[ "KeyboardPasswordStatus"] = objItem.KeyboardPasswordStatus
            if objItem.LastLoadInfo != None:
                result[ "LastLoadInfo"] = objItem.LastLoadInfo
            if objItem.Manufacturer != None:
                result[ "Manufacturer"] = objItem.Manufacturer
            if objItem.Model != None:
                result[ "Model"] = objItem.Model
            if objItem.Name != None:
                result[ "Name"] = objItem.Name
            if objItem.NameFormat != None:
                result[ "NameFormat"] = objItem.NameFormat
            if objItem.NetworkServerModeEnabled != None:
                result[ "NetworkServerModeEnabled"] = objItem.NetworkServerModeEnabled
            if objItem.NumberOfProcessors != None:
                result[ "NumberOfProcessors"] = objItem.NumberOfProcessors

            strList = "null"
            try :
                strList = ",".join([ str(x) for x in objItem.OEMLogoBitmap])
            except:
                pass
            result[ "OEMLogoBitmap"] = strList

            strList = "null"
            try :
                strList = ",".join([ str(x) for x in objItem.OEMStringArray])
            except:
                pass
            result[ "OEMStringArray"] = strList

            if objItem.PartOfDomain != None:
                result[ "PartOfDomain"] = objItem.PartOfDomain
            if objItem.PauseAfterReset != None:
                result[ "PauseAfterReset"] = objItem.PauseAfterReset

            strList = "null"
            try :
                strList = ",".join([ str(x) for x in objItem.PowerManagementCapabilities])
            except:
                pass
            result[ "PowerManagementCapabilities"] = strList

            if objItem.PowerManagementSupported != None:
                result[ "PowerManagementSupported"] = objItem.PowerManagementSupported
            if objItem.PowerOnPasswordStatus != None:
                result[ "PowerOnPasswordStatus"] = objItem.PowerOnPasswordStatus
            if objItem.PowerState != None:
                result[ "PowerState"] = objItem.PowerState
            if objItem.PowerSupplyState != None:
                result[ "PowerSupplyState"] = objItem.PowerSupplyState
            if objItem.PrimaryOwnerContact != None:
                result[ "PrimaryOwnerContact"] = objItem.PrimaryOwnerContact
            if objItem.PrimaryOwnerName != None:
                result[ "PrimaryOwnerName"] = objItem.PrimaryOwnerName
            if objItem.ResetCapability != None:
                result[ "ResetCapability"] = objItem.ResetCapability
            if objItem.ResetCount != None:
                result[ "ResetCount"] = objItem.ResetCount
            if objItem.ResetLimit != None:
                result[ "ResetLimit"] = objItem.ResetLimit

            strList = "null"
            try :
                strList = ",".join([ str(x) for x in objItem.Roles])
            except:
                pass
            result[ "Roles"] = strList

            if objItem.Status != None:
                result[ "Status"] = objItem.Status

            strList = "null"
            try :
                strList = ",".join([ str(x) for x in objItem.SupportContactDescription])
            except:
                pass
            result[ "SupportContactDescription"] = strList

            if objItem.SystemStartupDelay != None:
                result[ "SystemStartupDelay"] = objItem.SystemStartupDelay

            strList = "null"
            try :
                strList = ",".join([ str(x) for x in objItem.SystemStartupOptions])
            except:
                pass
            result[ "SystemStartupOptions"] = strList

            if objItem.SystemStartupSetting != None:
                result[ "SystemStartupSetting"] = objItem.SystemStartupSetting
            if objItem.SystemType != None:
                result[ "SystemType"] = objItem.SystemType
            if objItem.ThermalState != None:
                result[ "ThermalState"] = objItem.ThermalState
            if objItem.TotalPhysicalMemory != None:
                result[ "TotalPhysicalMemory"] = objItem.TotalPhysicalMemory
            if objItem.UserName != None:
                result[ "UserName"] = objItem.UserName
            if objItem.WakeUpType != None:
                result[ "WakeUpType"] = objItem.WakeUpType
            if objItem.Workgroup != None:
                result[ "Workgroup"] = objItem.Workgroup
    return result

def sshdup():
    if sys.platform.startswith('linux'):
        #verify sshd up
        cmd = "ps aux | grep sshd | grep -v grep | grep -v pts"
        result = simplecommand(cmd)
        if result['code'] == 0:
            return True
        return False
    elif sys.platform.startswith('darwin'):
        cmd = "launchctl list com.openssh.sshd"
        result = simplecommand(cmd)
        if result['code'] == 0:
            return True
        return False
    elif sys.platform.startswith('win'):
        cmd="TASKLIST | FINDSTR sshd"
        result = simplecommand(cmd)
        if len (result['result']) > 0:
            return True
    return False

def restartsshd():
    if sys.platform.startswith('linux'):
        #verify sshd up
        if not sshdup():
            cmd = "systemctrl restart sshd"
            result = simplecommand(cmd)
    elif sys.platform.startswith('darwin'):
        if not sshdup():
            cmd="launchctl restart /System/Library/LaunchDaemons/ssh.plist"
            result = simplecommand(cmd)
    elif sys.platform.startswith('win'):
        if not sshdup():
            # on cherche le nom reel du service pour sshd.
            cmd='sc query state= all | findstr \"sshd\" | findstr \"SERVICE_NAME\"'
            result = simplecommand(cmd)
            if len(result['result'])>0:
                try:
                    nameservice = result['result'][0].split()[1]
                    #restart service windows.
                    cmd='sc start \"%s\"'%nameservice
                    result = simplecommand(cmd)
                except Exception:
                    pass
