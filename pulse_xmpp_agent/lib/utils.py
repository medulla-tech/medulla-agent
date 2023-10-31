#!/usr/bin/env python
# -*- coding: utf-8; -*-
# SPDX-FileCopyrightText: 2016-2023 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-2.0-or-later

import netifaces
import json
import subprocess
import threading
import sys
import os
import fnmatch
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
import requests

from requests.exceptions import Timeout

from Crypto import Random
from Crypto.Cipher import AES
import tarfile
from functools import wraps
import string
import platform

logger = logging.getLogger()

DEBUGPULSE = 25


if sys.platform.startswith('win'):
    import wmi
    import pythoncom
    import _winreg as wr
    #import win32netcon
    import win32api
    import win32security
    import ntsecuritycon
    import win32net
    import ctypes
    import win32com.client
    from win32com.client import GetObject
    from ctypes.wintypes import LPCWSTR, LPCSTR

if sys.platform.startswith('linux'):
    import pwd
    import grp

if sys.platform.startswith('darwin'):
    import pwd
    import grp


class Env(object):
    agenttype = None # Non specified by default
    @staticmethod
    def user_dir():
        """Get the user folder for linux OS."""
        if Env.agenttype is None:
            raise NotImplementedError("The class attribute aggenttype need to be initialized\neg:  Env.agenttype = 'machine'")
        if Env.agenttype == "relayserver":
            return os.path.join("/", "var", "lib", "pulse2")
        else:
            return os.path.expanduser('~pulseuser')



def os_version():
    """
        Retrieve the name of the real Windows version
    """
    os_version_name = platform.platform()
    if sys.platform.startswith('win'):
        pythoncom.CoInitialize()
        c = wmi.WMI()
        for os in c.Win32_OperatingSystem():
            os_version_name = os.Caption
    return os_version_name

# debug decorator
def minimum_runtime(t):
    """
        Function decorator constrains the minimum execution time of the function
    """
    def decorated(f):
        def wrapper(*args, **kwargs):
            start = time.time()
            result = f(*args, **kwargs)
            runtime = time.time() - start
            if runtime < t:
                time.sleep(t - runtime)
            return result
        return wrapper
    return decorated

def dump_parameter(para=True, out=True, timeprocess=True):
    """
        Function decorator logging in and out function.
    """
    def decorated(decorated_function):
        @wraps(decorated_function)
        def wrapper(*dec_fn_args, **dec_fn_kwargs):
            # Log function entry
            start = time.time()
            func_name = decorated_function.__name__
            log = logging.getLogger(func_name)

            filepath = os.path.basename(__file__)
            # get function params (args and kwargs)
            if para:
                arg_names = decorated_function.__code__.co_varnames
                params = dict(
                    args=dict(zip(arg_names, dec_fn_args)),
                    kwargs=dec_fn_kwargs)
                result = ', '.join([
                    '{}={}'.format(str(k), repr(v)) for k, v in params.items()])
                log.info('\n@@@ call func : {}({}) file {}'.format(func_name, result, filepath))
                log.info('\n@@@ call func : {}({}) file {}'.format(func_name, result, filepath))
            else:
                log.info('\n@@@ call func : {}() file {}'.format(func_name, filepath))
            # Execute wrapped (decorated) function:
            outfunction = decorated_function(*dec_fn_args, **dec_fn_kwargs)
            timeruntime = time.time() - start
            if out:
                if timeprocess:
                    log.info('\n@@@ out func :{}() in {}s is -->{}'.format(func_name,
                                                                           timeruntime,
                                                                           outfunction))
                else:
                    log.info('\n@@@ out func :{}() is -->{}'.format(func_name,
                                                                    outfunction))
            else:
                if timeprocess:
                    log.info('\n@@@ out func :{}() in {}s'.format(func_name,
                                                                  timeruntime))
                else:
                    log.info('\n@@@ out func :{}()'.format(func_name))
            return outfunction
        return wrapper
    return decorated

def Setdirectorytempinfo():
    """
    This functions create a temporary directory.

    @returns path directory INFO Temporaly and key RSA
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
        del objectxmpp.back_to_deploy[session]
    if len(delsession) != 0:
        logging.log(DEBUGPULSE, "Clear dependency : %s" % delsession)
        save_back_to_deploy(objectxmpp.back_to_deploy)

def networkinfoexist():
    """
    This function checks if the fingerprintnetwork file exists.

    Returns:
        it returns True if the file exists. False otherwise
    """
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
        return 1
    countstart = file_get_contents(filecount)
    try:
        if countstart != "":
            countstart = int(countstart.strip())
            countstart += 1
        else:
            countstart = 1
    except ValueError:
        countstart = 1
    file_put_contents(filecount, str(countstart))
    return countstart

def unregister_agent(user, domain, resource):
    """
    This function is used to know if we need to unregister an old jid.
    Args:
        domain: the domain of the ejabberd.
        resource: The ressource used in the ejabberd jid.
    Returns:
        It returns True if we need to unregister the old jid. False otherwise.
    """
    jidinfo = {"user": user, "domain" : domain, "resource": resource}
    filejid = os.path.join(Setdirectorytempinfo(), 'jid')
    if not os.path.exists(filejid):
        savejsonfile(filejid, jidinfo)
        return False, jidinfo
    oldjid = loadjsonfile(filejid)
    
    if oldjid['user'] != user or oldjid['domain'] != domain:
        savejsonfile(filejid, jidinfo)
        return True, {"user":  oldjid['user'], "domain" : oldjid['domain'], "resource": oldjid['resource']}
    if oldjid['resource'] != resource:
        savejsonfile(filejid, jidinfo)
    return False, jidinfo

def unregister_subscribe(user, domain, resource):
    """
    This function is used to know if we need to unregister an old jid.
    Args:
        domain: the domain of the ejabberd.
        resource: The ressource used in the ejabberd jid.
    Returns:
        It returns True if we need to unregister the old jid. False otherwise.
    """
    jidinfosubscribe = {"user": user, "domain" : domain, "resource": resource}
    filejidsubscribe = os.path.join(Setdirectorytempinfo(), 'subscribe')
    if not os.path.exists(filejidsubscribe):
        savejsonfile(filejidsubscribe, jidinfosubscribe)
        return False, jidinfosubscribe
    oldjidsubscribe = loadjsonfile(filejidsubscribe)
    if oldjidsubscribe['user'] != user or oldjidsubscribe['domain'] != domain:
        savejsonfile(filejidsubscribe, jidinfosubscribe)
        return True, jidinfosubscribe
    if oldjidsubscribe['resource'] != resource:
        savejsonfile(filejidsubscribe, jidinfosubscribe)
    return False, jidinfosubscribe

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
    """
    Test the configuration file to see if it is completly configured and working.
    Args:
        typeconf: Type of the agent (machine, relayserver)

    Returns:
        It returns True if this is a relayserver or a valid config file.
    """
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

def isTemplateConfFile(typeconf):
    """
    Test the configuration file to see if this is a valid template file.
    Args:
        typeconf: Type of the agent (machine, relayserver)

    Returns:
        It returns True if this is a relayserver or a valid template file.
    """
    if typeconf == "relayserver":
        return True
    Config = ConfigParser.ConfigParser()
    namefileconfig = conffilename(typeconf)
    Config.read(namefileconfig)
    if Config.has_option("configuration_server", "confserver")\
            and Config.has_option('configuration_server', 'confport')\
            and Config.has_option('configuration_server', 'confpassword')\
            and Config.has_option('configuration_server', 'confdomain')\
            and Config.get('configuration_server', 'keyAES32') != "":
        return True
    return False


def createfingerprintnetwork():
    md5network = ""
    if sys.platform.startswith('win'):
        obj = simplecommandstr("ipconfig")
        if obj['code'] != 0 or obj['result'] == "":
            logger.error("A error occured while determining the network. ipconfig failed.")
            createfingerprintnetwork()

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
    if filename.find('://') > 0:
        ret = urllib2.urlopen(filename).read()
        if offset > 0:
            ret = ret[offset:]
        if maxlen > 0:
            ret = ret[:maxlen]
        return ret
    else:
        fp = open(filename, 'rb')
        try:
            if offset > 0:
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


def file_put_contents_w_a(filename, data, option="w"):
    if not os.path.exists(os.path.dirname(filename)):
        os.makedirs(os.path.dirname(filename))
    if option == "a" or  option == "w":
        f = open(filename, option)
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
    if searchPath not in sys.path:
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
    if args[0].config.plugin_action :
        if args[1] not in args[0].config.excludedplugins:
            nameplugin = os.path.join(args[0].modulepath, "plugin_%s" % args[1])
            logger.debug("Loading plugin %s" % args[1])
            # Add compteur appel plugins
            count = 0
            try:
                count = getattr(args[0], "num_call%s" % args[1])
            except AttributeError:
                count = 0
                setattr(args[0], "num_call%s"%args[1], count)
            pluginaction = loadModule(nameplugin)
            pluginaction.action(*args, **kwargs)
            setattr(args[0], "num_call%s" % args[1], count + 1)
        else:
                logging.getLogger().debug("The scheduled plugin %s is excluded" % args[1])
    else:
        logging.getLogger().debug("The plugin %s is not allowed due to plugin_action parameter" % args[1])

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
    """
    This function permit to find a macaddress based on the IP address

    Args:
        ip: the ip address used to find the macaddress
    Return:
        Returns a MAC for interfaces that have given IP, returns None if not found
    """
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
    """
    This function reduce the format of the provided mac address by removing some caracteres.

    Args:
        mac: mac address to reduce
    Return:
        Returns a string which is the reduced mac address
    """
    mac = mac.lower()
    mac = mac.replace(":", "")
    mac = mac.replace("-", "")
    mac = mac.replace(" ", "")
    return mac


def is_valid_ipv4(ip):
    """
        Validates IPv4 addresses.
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
    """
    Validates IPv6 addresses
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

        Returns:
            Return the used init system between init.d or systemd
    """
    p = subprocess.Popen('cat /proc/1/comm',
                         shell=True,
                         stdout=subprocess.PIPE,
                         stderr=subprocess.STDOUT)
    result = p.stdout.readlines()
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
    print "powershell -ExecutionPolicy Bypass -File  %s" % namescript
    obj = simplecommandstr(encode_strconsole("powershell -ExecutionPolicy Bypass -File %s" % namescript))
    return obj


class shellcommandtimeout(object):
    def __init__(self, cmd, timeout=15):
        self.process = None
        self.obj = {}
        self.obj['timeout'] = timeout
        self.obj['cmd'] = cmd
        self.obj['result'] = "result undefined"
        self.obj['code'] = 255
        self.obj['separateurline'] = os.linesep

    def run(self):
        def target():
            self.process = subprocess.Popen(self.obj['cmd'],
                                            shell=True,
                                            stdout=subprocess.PIPE,
                                            stderr=subprocess.STDOUT)
            self.obj['result'] = self.process.stdout.readlines()
            self.obj['code'] = self.process.wait()
            self.process.communicate()
        thread = threading.Thread(target=target)
        thread.start()

        thread.join(self.obj['timeout'])
        if thread.is_alive():
            print 'Terminating process'
            print "timeout %s" % self.obj['timeout']
            self.process.terminate()
            thread.join()

        self.obj['codereturn'] = self.process.returncode

        if self.obj['codereturn'] == -15:
            self.result = "error tineout"

        return self.obj


def servicelinuxinit(name, action):
    """
    This function allow to send actions to old linux init system

    Args:
        name: The name of the service
        action: The action we want to perform (stop, start, restart, reload)

    Returns:
        The return code of the command
    """
    obj = {}
    p = subprocess.Popen("/etc/init.d/%s %s" % (name, action),
                         shell=True,
                         stdout=subprocess.PIPE,
                         stderr=subprocess.STDOUT)
    result = p.stdout.readlines()
    obj['code'] = p.wait()
    obj['result'] = result
    return obj

def service(name, action):
    """
    This function allow to send actions to the system init.

    Windows, MacOS and linux are supported

    Args:
        name: The name of the service
        action: The action we want to perform (stop, start, restart, reload)

    Returns:
        The return code of the command
    """

    obj = {}
    if sys.platform.startswith('linux'):
        system = ""
        p = subprocess.Popen('cat /proc/1/comm',
                             shell=True,
                             stdout=subprocess.PIPE,
                             stderr=subprocess.STDOUT)
        result = p.stdout.readlines()
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
    """
    This function lists the available windows services
    """

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

            if 'end' not in result['data']:
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

def getIpXmppInterface(xmpp_server_ipaddress_or_dns, Port):
    """
        This function is used to retrieve the local IP from the client which is talking
        with the ejabberd server.
        For this we need to use netstat.
        It returns:
            TCP    10.16.53.17:49711      10.16.24.239:5222      ESTABLISHED
        and we split to obtain the first IP of the line.

        Args:
            xmpp_server_ipaddress: IP of the xmpp server
        Returns:
            It returns the local IP from the client which is talking
            with the ejabberd server.
    """
    resultip = ''
    xmpp_server_ipaddress = ipfromdns(xmpp_server_ipaddress_or_dns)
    logger.debug("Searching with which IP the agent is connected to the Ejabberd server") 
    if sys.platform.startswith('linux'):
        obj = simplecommand(
            "netstat -an |grep %s |grep %s| grep ESTABLISHED | grep -v tcp6" %
            (Port, xmpp_server_ipaddress))
        if obj['code'] != 0:
            logging.getLogger().error('error command netstat : %s' % obj['result'])
            logging.getLogger().error('error install package net-tools')
        if len(obj['result']) != 0:
            for i in range(len(obj['result'])):
                obj['result'][i] = obj['result'][i].rstrip('\n')
            a = "\n".join(obj['result'])
            b = [x for x in a.split(' ') if x != ""]
            if len(b) != 0:
                resultip = b[3].split(':')[0]
    elif sys.platform.startswith('win'):
        obj = simplecommand(
            'netstat -an | findstr %s | findstr "ESTABLISHED SYN_SENT SYN_RECV"' %
            Port)
        if len(obj['result']) != 0:
            for i in range(len(obj['result'])):
                obj['result'][i] = obj['result'][i].rstrip('\n')
            a = "\n".join(obj['result'])
            b = [x for x in a.split(' ') if x != ""]
            if len(b) != 0:
                resultip = b[1].split(':')[0]
    elif sys.platform.startswith('darwin'):
        obj = simplecommand(
            "netstat -an |grep %s |grep %s| grep ESTABLISHED" %
            (Port, xmpp_server_ipaddress))
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
    logger.debug("The agent is connected to the Ejabberd server with the IP: %s" % resultip)
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
            ip = urllib.urlopen("http://ip.42.pl/raw").read()
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
    candidates = []
    for test_ip in ["192.0.2.0", "192.51.100.0", "203.0.113.0"]:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect((test_ip, 80))
            ip_adrss = s.getsockname()[0]
            if ip_adrss in candidates:
                return ip_adrss
            candidates.append(ip_adrss)
        except Exception:
            pass
        finally:
            s.close()
    if len(candidates) >= 1:
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

class protodef:
    def __init__(self):
        self.fileprotoinfo = os.path.join(Setdirectorytempinfo(),
                                          'fingerprintproto')
        self.boolchangerproto, self.proto = self.protochanged()

    def protoinfoexist(self):
        if os.path.exists(self.fileprotoinfo):
            return True
        return False

    def protochanged(self):
        if self.protoinfoexist():
            fproto = protodef.protoandport()
            self.fingerprintproto = file_get_contents(self.fileprotoinfo)
            newfingerprint = pickle.dumps(fproto) #on recalcule le proto
            if self.fingerprintproto == newfingerprint:
                self.proto = fproto
                return False, self.proto
        self.refreshfingerprintproto()
        self.fingerprintproto = file_get_contents(self.fileprotoinfo)
        self.proto = pickle.loads(self.fingerprintproto)
        return True, self.proto

    def refreshfingerprintproto(self):
        fproto = protodef.protoandport()
        with open(self.fileprotoinfo, 'wb') as handle:
            pickle.dump(fproto, handle)
        return fproto

    @staticmethod
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
            for services in psutil.win_service_iter():
                if 'TermService' in services.name():
                    service_handler = psutil.win_service_get('TermService')
                    if service_handler.status() == 'running':
                        pid = service_handler.pid()
                        process_handler = psutil.Process(pid)
                        for cux in process_handler.connections():
                            if cux.status == psutil.CONN_LISTEN:
                                protport['rdp'] = cux.laddr.port

        elif sys.platform.startswith('linux'):
            for process in psutil.process_iter():
                if process.name() == 'x11vnc':
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
                elif process.name() == 'sshd':
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
                elif process.name() == 'xrdp':
                    process_handler = psutil.Process(process.pid)
                    for cux in process_handler.connections():
                        try:
                            ip = cux.laddr[0]
                            port = cux.laddr[1]
                        except Exception:
                            ip = cux.laddr.ip
                            port = cux.laddr.port
                        if cux.status == psutil.CONN_LISTEN and (ip == "0.0.0.0" or ip == "::"):
                            protport['rdp'] = port

        elif sys.platform.startswith('darwin'):
            for process in psutil.process_iter():
                if 'ARDAgent' in process.name():
                    protport['vnc'] = '5900'
            for cux in psutil.net_connections():
                if cux.laddr.port == 22 and cux.status == psutil.CONN_LISTEN:
                    protport['ssh'] = '22'

        return protport

def protoandport():
    return protodef.protoandport()

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
            logger.error("The hostname %s is invalid or temporarily unresolved" % name_domaine_or_ip)
            return ""
        except Exception:
            return ""
    return ""


def data_struct_message(action, data={}, ret=0, base64=False, sessionid=None):
    if sessionid == None or sessionid == "" or not isinstance(sessionid, basestring):
        sessionid = action.strip().replace(" ", "")
    return {'action': action,
            'data': data,
            'ret': 0,
            "base64": False,
            "sessionid": getRandomName(4, sessionid)}


def check_exist_ip_port(name_domaine_or_ip, port):
    """ This function check if socket valid for connection
        return True or False
    """
    ip = ipfromdns(name_domaine_or_ip)
    try:
        socket.getaddrinfo(ip, port)
        return True
    except socket.gaierror:
        logger.error("The hostname %s is invalid or temporarily unresolved" % name_domaine_or_ip)
        return False
    except Exception:
        return False


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
        except WindowsError:  # skipcq: PYL-E0602
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
        except WindowsError:  # skipcq: PYL-E0602
            return None


def shutdown_command(time=0, msg=''):
    """
        This  function allow to shutdown a machine, and if needed
        to display a message

        Args:
            time: the delay before the shutdown
            msg:  the message that will be displayed

    """
    if msg != "":
        msg = msg.strip("\" ")
        msg = '"%s"' % msg
    if sys.platform.startswith('linux'):
        if int(time) == 0 or msg == '':
            cmd = "shutdown now"
        else:
            cmd = "shutdown -P -f -t %s %s" % (time, msg)
        logging.debug(cmd)
        os.system(cmd)
    elif sys.platform.startswith('win'):
        if int(time) == 0 or msg == '':
            cmd = "shutdown /p"
        else:
            cmd = "shutdown /s /t %s /c %s" % (time, msg)
        logging.debug(cmd)
        os.system(cmd)
    elif sys.platform.startswith('darwin'):
        if int(time) == 0 or msg == '':
            cmd = "shutdown -h now"
        else:
            cmd = "shutdown -h +%s \"%s\"" % (time, msg)
        logging.debug(cmd)
        os.system(cmd)
    return


def vnc_set_permission(askpermission=1):
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
            return True
    except Exception:
        pass
    return False


def decode_strconsole(x):
    """
        imput str decode to default coding python(# -*- coding: utf-8; -*-)
    """
    if sys.platform.startswith('linux'):
        return x.decode('utf-8', 'ignore')
    elif sys.platform.startswith('win'):
        return x.decode('cp850', 'ignore')
    elif sys.platform.startswith('darwin'):
        return x.decode('utf-8', 'ignore')
    else:
        return x


def encode_strconsole(x):
    """
        output str encode to coding other system
    """
    if sys.platform.startswith('linux'):
        return x.encode('utf-8')
    elif sys.platform.startswith('win'):
        return x.encode('cp850')
    elif sys.platform.startswith('darwin'):
        return x.encode('utf-8')
    else:
        return x


def savejsonfile(filename, data, indent=4):
    with open(filename, 'w') as outfile:
        json.dump(data, outfile)


def loadjsonfile(filename):
    if os.path.isfile(filename):
        with open(filename, 'r') as info:
            dd = info.read()
        try:
            return json.loads(decode_strconsole(dd))
        except Exception as e:
            logger.error("filename %s error decodage [%s]" % (filename, str(e)))
    return None


def save_user_current(name=None):
    loginuser = os.path.join(Setdirectorytempinfo(), 'loginuser')
    if name is None:
        userlist = list(set([users[0] for users in psutil.users()]))
        if len(userlist) > 0:
            name = userlist[0]
    else:
        name = "system"

    if not os.path.exists(loginuser):
        result = {name: 1,
                  'suite': [name],
                  'curent': name}
        savejsonfile(loginuser, result)
        return result['curent']

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
        if valcount > max:
            datauseruser['curent'] = t
    savejsonfile(loginuser, datauseruser)
    return datauseruser['curent']


def test_kiosk_presence():
    """
    Test if the kiosk is installed in the machine.
    Returns:
        string "True" if the directory is founded
        or
        string "False" if the directory is not founded
    """

    def _get_kiosk_path():
        """
        This private function find the path for the pytho3 install.
        If no installation is found the the function returns  None.
        Returns:
            string: the path of python3/site-packages
            or
            None if no path is found
            """
        list = []
        if sys.platform.startswith("win"):
            list = [
                os.path.join(os.environ["ProgramFiles"], "Python36", "Lib", "site-packages"),
                os.path.join(os.environ["ProgramFiles"], "Python36-32", "Lib", "site-packages")
            ]
        elif sys.platform == "darwin":
            list = ["usr", "local", "lib", "python3.6", "dist-packages"]
        elif sys.platform == "linux":
            list = ["usr", "lib", "python3.6", "dist-packages",
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


def utc2local(utc):
    """
    utc2local transform a utc datetime object to local object.

    Param:
        utc datetime which is not naive (the utc timezone must be precised)
    Returns:
        datetime in local timezone
    """
    epoch = time.mktime(utc.timetuple())
    offset = datetime.fromtimestamp(epoch) - datetime.utcfromtimestamp(epoch)
    return utc + offset

def getHomedrive(username='pulseuser'):
    """
        Retrieve the path to the home of the user `username`
        Args:
            username: The username of the user for which we are searching the homepath

        Returns:
            It returns the path to the home of `username`
    """
    homedrive = os.path.join("c:\\", "Users", "pulseuser")
    usersid = get_user_sid(username)

    try:
        regquery = 'REG QUERY "HKLM\Software\Microsoft\Windows NT\CurrentVersion\ProfileList\%s" /v "ProfileImagePath" /s'% usersid
        resultquery = simplecommand(encode_strconsole(regquery))

    except Exception as e:
        logger.error("An error occured whil trying to %s" % (str(e)))

    if resultquery['code'] == 0:
        homedrive = resultquery["result"][-3].split("    ")[-1].replace("\r\n", "")

    return homedrive.lower()

def keypub():
    keypubstring = ""
    if sys.platform.startswith('linux'):
        if not os.path.isfile("/root/.ssh/id_rsa"):
            obj = simplecommand('ssh-keygen -b 2048 -t rsa -f /root/.ssh/id_rsa -q -N ""')
        return file_get_contents("/root/.ssh/id_rsa.pub")
    elif sys.platform.startswith('win'):
        try:
            win32net.NetUserGetInfo('', 'pulseuser', 0)
            pathkey = os.path.join(getHomedrive(), ".ssh")
        except:
            pathkey = os.path.join(os.environ["ProgramFiles"], "pulse", '.ssh')
        if not os.path.isfile(os.path.join(pathkey, "id_rsa")):
            obj = simplecommand('"C:\Program Files\OpenSSH\ssh-keygen.exe" -b 2048 -t rsa -f "%s" -q -N ""' % os.path.join(pathkey, "id_rsa"))
        return file_get_contents(os.path.join(pathkey, "id_rsa.pub"))
    elif sys.platform.startswith('darwin'):
        if not os.path.isfile("/var/root/.ssh/id_rsa"):
            obj = simplecommand('ssh-keygen -b 2048 -t rsa -f /var/root/.ssh/id_rsa -q -N ""')
        return file_get_contents("/var/root/.ssh/id_rsa.pub")

#use function for relayserver
def deletekey(file, key, back=True):
    if os.path.isfile(file):
        if back:
            simplecommand("sed -i.bak '/%s/d' %s" % (key, file))
        else:
            simplecommand("sed -i '/%s/d' %s" % (key, file))

def installkey(file, key, back=True):
    deletekey(file, key, back=back)
    simplecommand('echo "%s" >> %s' % (key, file))

def connection_established(Port):
    """ verify connection etablish
        return true if etablish
    """
    if sys.platform.startswith('linux'):
        obj = simplecommandstr("netstat -an |grep %s | grep ESTABLISHED | grep -v tcp6" % (Port))
    elif sys.platform.startswith('win'):
        obj = simplecommandstr("netstat -an | findstr %s | findstr ESTABLISHED" % Port)
    elif sys.platform.startswith('darwin'):
        obj = simplecommandstr("netstat -an |grep %s | grep ESTABLISHED" % (Port))
    if "ESTABLISHED" in obj['result']:
        return True
    else:
        logger.warning("connection xmpp low")
        return False

def showlinelog(nbline=200, logfile=None):
    obj = {"result": ""}
    if logfile is not None:
        na = logfile
    if sys.platform.startswith('win'):
        if logfile is None:
            na = os.path.join(os.environ['ProgramFiles'], "Pulse", "var", "log", "xmpp-agent-machine.log")
        if os.path.isfile(na):
            obj = simplecommandstr(encode_strconsole("powershell \"Get-Content '%s' | select -last %s\"" % (na, nbline)))
    elif sys.platform.startswith('linux'):
        if logfile is None:
            na = os.path.join("/", "var", "log", "pulse", "xmpp-agent-machine.log")
        if os.path.isfile(na):
            obj = simplecommandstr("cat %s | tail -n %s" % (na, nbline))
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
    port = int(port)
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
        # ['/bin/vikings', '-input', 'eggs.txt', '-output', 'spam spam.txt', '-cmd', "echo '$MONEY'"]
        # p = subprocess.Popen(args) # Success!
        # flag windows -> https://docs.microsoft.com/fr-fr/windows/desktop/ProcThread/process-creation-flags


        if sys.platform.startswith('win'):
            CREATE_NEW_PROCESS_GROUP = 0x00000200
            DETACHED_PROCESS = 0x00000008
            progrm = subprocess.Popen(pathprogram,
                                      shell=False,
                                      creationflags=DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP,
                                      close_fds=True)
            self.programlist[uniqexecutablename] = progrm
        elif sys.platform.startswith('linux') or sys.platform.startswith('darwin'):
            progrm = subprocess.Popen(pathprogram,
                                      shell=True,
                                      stdout=None,
                                      stderr=None,
                                      close_fds=True)
            self.programlist[uniqexecutablename] = progrm
        else:
            self.logger.error("The launch command for syncthing is not implemented for this OS")

    def stopprogram(self, uniqexecutablename):
        subprocess.Popen.kill(self.programlist[uniqexecutablename])
        del self.programlist[uniqexecutablename]

    def stopallprogram(self):
        for prog in self.programlist:
            subprocess.Popen.kill(self.programlist[prog])
        self.programlist.clear()

unpad = lambda s: s[0:-ord(s[-1])]
class AESCipher:

    def __init__(self, key, BS=32):
        self.key = key
        self.BS = BS

    def _pad(self, s):
        return s + (self.BS - len(s) % self.BS) * chr(self.BS - len(s) % self.BS)

    def encrypt(self, raw):
        raw = self._pad(raw)
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return base64.b64encode(iv + cipher.encrypt(raw))

    def decrypt(self, enc):
        enc = base64.b64decode(enc)
        iv = enc[:16]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return unpad(cipher.decrypt(enc[16:]))


def setgetcountcycle(data=None):
    chemin = os.path.join(os.path.dirname(os.path.realpath(__file__)),
                          "..",
                          "cycle",
                          "countcyclealternatif")
    try:
        countcyclealternatif = int(file_get_contents(chemin).strip(" \n\t"))
    except Exception:
        countcyclealternatif = 0
        data = None
    if data is None:
        file_put_contents(chemin, "0")
        return 0
    elif data == -1:
        return countcyclealternatif
    elif data >= 0:
        countcyclealternatif = countcyclealternatif + data
        file_put_contents(chemin, str(countcyclealternatif))
        return countcyclealternatif

def setgetrestart(data=None):
    chemin = os.path.join(os.path.dirname(os.path.realpath(__file__)),
                          "..",
                          "cycle",
                          "restart")
    try:
        restart = int(file_get_contents(chemin).strip(" \n\t"))
    except Exception:
        restart = 0
        data = None
    if data is None:
        file_put_contents(chemin, "0")
        return 0
    elif data == -1:
        return restart
    elif data == 0:
        file_put_contents(chemin, "0")
        return 0
    elif data == 1:
        file_put_contents(chemin, "1")
        return 1

def detectantivirus():
    def SECURITY_PROVIDER(keyobject, data):
        str = data[0:2]
        if str == "00":
            return "NONE"
        elif str == "01":
            return "FIREWALL"
        elif str == "02":
            return "AUTOUPDATE_SETTINGS"
        elif str == "04":
            return "ANTIVIRUS"
        elif str == "08":
            return "ANTISPYWARE"
        elif str == "16":
            return "INTERNET_SETTINGS"
        elif str == "32":
            return "USER_ACCOUNT_CONTROL"
        elif str == "64":
            return "SERVICE"
        else:
            return keyobject.upper()

    def SECURITY_PRODUCT_STATE(data):
        str = data[2:4]
        if str == "00":
            return "OFF"
        elif str == "01":
            return "EXPIRED"
        elif str == "10":
            return "ON"
        elif str == "11":
            return "SNOOZED"
        else:
            return "UNKNOWN"

    def SECURITY_SIGNATURE_STATUS(data):
        str = data[4:6]
        if str == "00":
            return "UP_TO_DATE"
        elif str == "10":
            return "OUT_OF_DATE"
        else:
            return "UNKNOWN"

    def elemenstructure():
        return {
            "displayName": "",
            "instanceGuid": "",
            "pathToSignedProductExe": "",
            "pathToSignedReportingExe": "",
            "productState": 0,
            "hex": "000000",
            "SECURITY_PROVIDER": "NONE",
            "SECURITY_PRODUCT_STATE": "UNKNOWN",
            "SECURITY_SIGNATURE_STATUS": "UNKNOWN",
            "timestamp": "",
            }
    if sys.platform.startswith('win'):
        result = {}
        objWMI = {"Antivirus": GetObject('winmgmts:\\\\.\\root\\SecurityCenter2').InstancesOf('AntiVirusProduct'),
                  "Firewall": GetObject('winmgmts:\\\\.\\root\\SecurityCenter2').InstancesOf('FirewallProduct'),
                  "AntiSpyware": GetObject('winmgmts:\\\\.\\root\\SecurityCenter2').InstancesOf('AntiSpywareProduct')}
        for key in objWMI:
            result[key] = []
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
                    infoprotection['hex'] = "%06x" % i.productState
                    infoprotection['SECURITY_PROVIDER'] = SECURITY_PROVIDER(key, infoprotection['hex'])
                    infoprotection['SECURITY_PRODUCT_STATE'] = SECURITY_PRODUCT_STATE(infoprotection['hex'])
                    infoprotection['SECURITY_SIGNATURE_STATUS'] = SECURITY_SIGNATURE_STATUS(infoprotection['hex'])
                except Exception:
                    pass
                try:
                    infoprotection['timestamp'] = i.timestamp.strip()
                except Exception:
                    pass
                result[key].append(infoprotection)
        return result

def information_machine():
    result = {}

    def WMIDateStringToDate(dtmDate):
        strDateTime = ""
        if dtmDate[4] == 0:
            strDateTime = dtmDate[5] + '/'
        else:
            strDateTime = dtmDate[4] + dtmDate[5] + '/'
        if dtmDate[6] == 0:
            strDateTime = strDateTime + dtmDate[7] + '/'
        else:
            strDateTime = strDateTime + dtmDate[6] + dtmDate[7] + '/'
            strDateTime = strDateTime + dtmDate[0] + dtmDate[1] + dtmDate[2] + dtmDate[3] + " " + dtmDate[8] + dtmDate[9] + ":" + dtmDate[10] + dtmDate[11] +':' + dtmDate[12] + dtmDate[13]
        return strDateTime

    if sys.platform.startswith('win'):
        strComputer = "."
        objWMIService = win32com.client.Dispatch("WbemScripting.SWbemLocator")
        objSWbemServices = objWMIService.ConnectServer(strComputer, "root\cimv2")
        colItems = objSWbemServices.ExecQuery("SELECT * FROM Win32_ComputerSystem")
        for objItem in colItems:
            if objItem.AdminPasswordStatus != None:
                result["AdminPasswordStatus"] = objItem.AdminPasswordStatus
            if objItem.AutomaticResetBootOption != None:
                result["AutomaticResetBootOption"] = objItem.AutomaticResetBootOption
            if objItem.AutomaticResetCapability != None:
                result["AutomaticResetCapability"] = objItem.AutomaticResetCapability
            if objItem.BootOptionOnLimit != None:
                result["BootOptionOnLimit"] = objItem.BootOptionOnLimit
            if objItem.BootOptionOnWatchDog != None:
                result["BootOptionOnWatchDog"] = objItem.BootOptionOnWatchDog
            if objItem.BootROMSupported != None:
                result["BootROMSupported"] = objItem.BootROMSupported
            if objItem.BootupState != None:
                result["BootupState"] = objItem.BootupState
            if objItem.Caption != None:
                result["Caption"] = objItem.Caption
            if objItem.ChassisBootupState != None:
                result["ChassisBootupState"] = objItem.ChassisBootupState
            if objItem.CreationClassName != None:
                result["CreationClassName"] = objItem.CreationClassName
            if objItem.CurrentTimeZone != None:
                result["CurrentTimeZone"] = objItem.CurrentTimeZone
            if objItem.DaylightInEffect != None:
                result["DaylightInEffect"] = objItem.DaylightInEffect
            if objItem.Description != None:
                result["Description"] = objItem.Description
            if objItem.DNSHostName != None:
                result["DNSHostName"] = objItem.DNSHostName
            if objItem.Domain != None:
                result["Domain"] = objItem.Domain
            if objItem.DomainRole != None:
                result["DomainRole"] = objItem.DomainRole
            if objItem.EnableDaylightSavingsTime != None:
                result["EnableDaylightSavingsTime"] = objItem.EnableDaylightSavingsTime
            if objItem.FrontPanelResetStatus != None:
                result["FrontPanelResetStatus"] = objItem.FrontPanelResetStatus
            if objItem.InfraredSupported != None:
                result["InfraredSupported"] = objItem.InfraredSupported

            strList = "null"
            try:
                strList = ",".join([str(x) for x in objItem.InitialLoadInfo])
            except:
                pass
            result["InitialLoadInfo"] = strList

            if objItem.InstallDate != None:
                result["InstallDate"] = WMIDateStringToDate(objItem.InstallDate)
            if objItem.KeyboardPasswordStatus != None:
                result["KeyboardPasswordStatus"] = objItem.KeyboardPasswordStatus
            if objItem.LastLoadInfo != None:
                result["LastLoadInfo"] = objItem.LastLoadInfo
            if objItem.Manufacturer != None:
                result["Manufacturer"] = objItem.Manufacturer
            if objItem.Model != None:
                result["Model"] = objItem.Model
            if objItem.Name != None:
                result["Name"] = objItem.Name
            if objItem.NameFormat != None:
                result["NameFormat"] = objItem.NameFormat
            if objItem.NetworkServerModeEnabled != None:
                result["NetworkServerModeEnabled"] = objItem.NetworkServerModeEnabled
            if objItem.NumberOfProcessors != None:
                result["NumberOfProcessors"] = objItem.NumberOfProcessors

            strList = "null"
            try:
                strList = ",".join([str(x) for x in objItem.OEMLogoBitmap])
            except:
                pass
            result["OEMLogoBitmap"] = strList

            strList = "null"
            try:
                strList = ",".join([str(x) for x in objItem.OEMStringArray])
            except:
                pass
            result["OEMStringArray"] = strList

            if objItem.PartOfDomain != None:
                result["PartOfDomain"] = objItem.PartOfDomain
            if objItem.PauseAfterReset != None:
                result["PauseAfterReset"] = objItem.PauseAfterReset

            strList = "null"
            try:
                strList = ",".join([str(x) for x in objItem.PowerManagementCapabilities])
            except:
                pass
            result["PowerManagementCapabilities"] = strList

            if objItem.PowerManagementSupported != None:
                result["PowerManagementSupported"] = objItem.PowerManagementSupported
            if objItem.PowerOnPasswordStatus != None:
                result["PowerOnPasswordStatus"] = objItem.PowerOnPasswordStatus
            if objItem.PowerState != None:
                result["PowerState"] = objItem.PowerState
            if objItem.PowerSupplyState != None:
                result["PowerSupplyState"] = objItem.PowerSupplyState
            if objItem.PrimaryOwnerContact != None:
                result["PrimaryOwnerContact"] = objItem.PrimaryOwnerContact
            if objItem.PrimaryOwnerName != None:
                result["PrimaryOwnerName"] = objItem.PrimaryOwnerName
            if objItem.ResetCapability != None:
                result["ResetCapability"] = objItem.ResetCapability
            if objItem.ResetCount != None:
                result["ResetCount"] = objItem.ResetCount
            if objItem.ResetLimit != None:
                result["ResetLimit"] = objItem.ResetLimit

            strList = "null"
            try:
                strList = ",".join([str(x) for x in objItem.Roles])
            except:
                pass
            result["Roles"] = strList

            if objItem.Status != None:
                result["Status"] = objItem.Status

            strList = "null"
            try:
                strList = ",".join([str(x) for x in objItem.SupportContactDescription])
            except:
                pass
            result["SupportContactDescription"] = strList

            if objItem.SystemStartupDelay != None:
                result["SystemStartupDelay"] = objItem.SystemStartupDelay

            strList = "null"
            try:
                strList = ",".join([str(x) for x in objItem.SystemStartupOptions])
            except:
                pass
            result["SystemStartupOptions"] = strList

            if objItem.SystemStartupSetting != None:
                result["SystemStartupSetting"] = objItem.SystemStartupSetting
            if objItem.SystemType != None:
                result["SystemType"] = objItem.SystemType
            if objItem.ThermalState != None:
                result["ThermalState"] = objItem.ThermalState
            if objItem.TotalPhysicalMemory != None:
                result["TotalPhysicalMemory"] = objItem.TotalPhysicalMemory
            if objItem.UserName != None:
                result["UserName"] = objItem.UserName
            if objItem.WakeUpType != None:
                result["WakeUpType"] = objItem.WakeUpType
            if objItem.Workgroup != None:
                result["Workgroup"] = objItem.Workgroup
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
        cmd = "TASKLIST | FINDSTR sshd"
        result = simplecommand(cmd)
        if len(result['result']) > 0:
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
            cmd = "launchctl restart /System/Library/LaunchDaemons/ssh.plist"
            result = simplecommand(cmd)
    elif sys.platform.startswith('win'):
        if not sshdup():
            # on cherche le nom reel du service pour sshd.
            cmd = 'sc query state= all | findstr \"sshd\" | findstr \"SERVICE_NAME\"'
            result = simplecommand(cmd)
            if len(result['result']) > 0:
                try:
                    nameservice = result['result'][0].split()[1]
                    cmd = 'sc start \"%s\"' % nameservice
                    result = simplecommand(cmd)
                except Exception:
                    pass

def make_tarfile(output_file_gz_bz2, source_dir, compresstype="gz"):
    """
        creation archive tar.gz or tar.bz2
        compresstype "gz" or "bz2"
    """
    try:
        with tarfile.open(output_file_gz_bz2, "w:%s" % compresstype) as tar:
            tar.add(source_dir, arcname=os.path.basename(source_dir))
        return True
    except Exception as e:
        logger.error("Error creating tar.%s archive : %s" % (compresstype, str(e)))
        return False

def extract_file(imput_file__gz_bz2, to_directory='.', compresstype="gz"):
    """
        extract archive tar.gz or tar.bz2
        compresstype "gz" or "bz2"
    """
    cwd = os.getcwd()
    absolutepath = os.path.abspath(imput_file__gz_bz2)
    try:
        os.chdir(to_directory)
        with tarfile.open(absolutepath, "r:%s" % compresstype) as tar:
            tar.extractall()
        return True
    except OSError as e:
        logger.error("Error extracting tar.%s : %s" % (str(e), compresstype))
        return False
    except Exception as e:
        logger.error("Error extracting tar.%s : %s" % (str(e), compresstype))
        return False
    finally:
        os.chdir(cwd)
    return True

def find_files(directory, pattern):
    """
        use f
    """
    for root, dirs, files in os.walk(directory):
        for basename in files:
            if fnmatch.fnmatch(basename, pattern):
                filename = str(os.path.join(root, basename))
                yield filename

def listfile(directory, abspath=True):
    listfile = []
    for root, dirs, files in os.walk(directory):
        for basename in files:
            if abspath:
                listfile.append(os.path.join(root, basename))
            else:
                listfile.append(os.path.join(basename))
    return listfile

def md5folder(directory):
    hash = hashlib.md5()
    strmdr = []
    for root, dirs, files in os.walk(directory):
        for basename in files:
            hash.update(md5(os.path.join(root, basename)))
    return hash.hexdigest()

def _path_package():
    return os.path.join("/", "var", "lib", "pulse2", "packages")

def _path_packagequickaction():
    pathqd = os.path.join("/", "var", "lib", "pulse2", "qpackages")
    if not os.path.isdir(pathqd):
        try:
            os.makedirs(pathqd)
        except OSError as e:
            logger.error("Error creating folder for quick deployment packages : %s" % (str(e)))
    return pathqd

def qdeploy_generate(folder, max_size_stanza_xmpp):
    try:
        namepackage = os.path.basename(folder)
        pathaqpackage = os.path.join(_path_packagequickaction(), namepackage)
        pathxmpppackage = "%s.xmpp" % pathaqpackage

        # if dependency in package do not generate the qpackage
        with open(os.path.join(folder, 'xmppdeploy.json')) as json_data:
            data_dict = json.load(json_data)
        if len(data_dict['info']['Dependency']) > 0:
            logger.debug("Package %s has dependencies. Quick deployment package not generated." % (pathxmpppackage))
            logger.debug("Deleting quick deployment package if found %s" % (pathxmpppackage))
            try:
                if "qpackages" in pathaqpackage:
                    simplecommand("rm %s.*" % pathaqpackage)
            except Exception:
                pass
            return 3

        if os.path.exists(pathxmpppackage) and \
            int((time.time()-os.stat(pathxmpppackage).st_mtime))/60 < 10:
            logger.debug("No need to generate quick deployment package %s" % (pathxmpppackage))
            simplecommand("touch -c %s" % pathxmpppackage)
            return 2
        else:
            logger.debug("Deleting quick deployment package if found %s" % (pathxmpppackage))
            try:
                if "qpackages" in pathaqpackage:
                    simplecommand("rm %s.*" % pathaqpackage)
            except Exception:
                pass
        logger.debug("Checking if quick deployment package needs to be generated")

        result = simplecommand("du -b %s" % folder)
        taillebytefolder = int(result['result'][0].split()[0])
        if taillebytefolder > max_size_stanza_xmpp:
            logger.debug("Package is too large for quick deployment.\n%s"\
                " greater than defined max_size_stanza_xmpp %s" % (taillebytefolder,
                                                                   max_size_stanza_xmpp))
            logger.debug("Deleting quick deployment package if found %s" % (pathxmpppackage))
            try:
                if "qpackages" in pathaqpackage:
                    simplecommand("rm %s.*" % pathaqpackage)
            except Exception:
                pass
            return 6
            ### creation d'un targetos
        logger.debug("Preparing quick deployment package for package %s" % (namepackage))
        calculemd5 = md5folder(pathaqpackage)

        if os.path.exists("%s.md5" % pathaqpackage):
            content = file_get_contents("%s.md5" % pathaqpackage)
            if content == calculemd5:
                #pas de modifications du package
                logger.debug("Quick deployment package found")
                #creation only si if fille missing
                create_msg_xmpp_quick_deploy(folder, create=False)
                return 1
        file_put_contents("%s.md5" % pathaqpackage, calculemd5)
        create_msg_xmpp_quick_deploy(folder, create=True)
        return 0
    except Exception:
        logger.error("Error generating quick deployment package : %s" % folder)
        logger.error("%s" % (traceback.format_exc()))
        try:
            if "qpackages" in pathaqpackage:
                simplecommand("rm %s.*" % pathaqpackage)
        except Exception:
            pass
        return 100

def get_message_xmpp_quick_deploy(folder, sessionid):
    # read le fichier
    namepackage = os.path.basename(folder)
    pathaqpackage = os.path.join(_path_packagequickaction(), namepackage)
    with open("%s.xmpp" % pathaqpackage, 'r') as f:
        data = f.read()
    return data.replace("@-TEMPLSESSQUICKDEPLOY@", sessionid, 1)

def get_template_message_xmpp_quick_deploy(folder):
    # read le fichier
    namepackage = os.path.basename(folder)
    pathaqpackage = os.path.join(_path_packagequickaction(), namepackage)
    with open("%s.xmpp" % pathaqpackage, 'r') as f:
        data = f.read()
    return data

def get_xmpp_message_with_sessionid(template_message, sessionid):
    # read le fichier
    return template_message.replace("@-TEMPLSESSQUICKDEPLOY@", sessionid, 1)

def create_msg_xmpp_quick_deploy(folder, create=False):
    namepackage = os.path.basename(folder)
    pathaqpackage = os.path.join(_path_packagequickaction(), namepackage)
    # create compress file folder
    if not os.path.exists("%s.xmpp" % pathaqpackage) or create:
        logger.debug("Creating compressed archive %s.gz" % pathaqpackage)
        make_tarfile("%s.gz" % pathaqpackage, folder, compresstype="gz")
        with open("%s.gz" % pathaqpackage, 'rb') as f:
            dataraw = base64.b64encode(f.read())
        msgxmpptemplate = """{"sessionid": "@-TEMPLSESSQUICKDEPLOY@",
                              "action": "qdeploy",
                              "data": {"nbpart": 1,
                                       "part": 1,
                                       "namepackage": "%s",
                                       "filebase64": "%s"}}""" % (namepackage, dataraw)
        try:
            logger.debug("Writing new quick deployment pakage %s.xmpp" % pathaqpackage)
            with open("%s.xmpp"%pathaqpackage, 'w') as f:
                f.write(msgxmpptemplate)
            # The compressed file is useless
            if os.path.exists("%s.gz" % pathaqpackage):
                os.remove("%s.gz" % pathaqpackage)
        except Exception:
            logger.error("%s" % (traceback.format_exc()))
    else:
        logger.debug("Quick deployment package %s.xmpp found" % pathaqpackage)

def pulseuser_useraccount_mustexist(username='pulseuser'):
    """
    This function checks if the a given user exists.
    Args:
        username: This is the username we need to check ( default is pulseuser )

    Returns:
        It returns True if the account has been correctly created or if the
        account already exists, it return False otherwise.
    """
    if sys.platform.startswith('linux'):
        try:
            uid = pwd.getpwnam(username).pw_uid
            gid = grp.getgrnam(username).gr_gid
            msg = '%s user account already exists. Nothing to do.' % username
            return True, msg
        except Exception:
            adduser_cmd = 'adduser --system --quiet --group '\
                '--home /var/lib/pulse2 --shell /bin/rbash '\
                '--disabled-password %s' % username
    elif sys.platform.startswith('win'):
        try:
            win32net.NetUserGetInfo('', username, 0)
            # User exists. Adding it to Admins group
            adminsgrpsid = win32security.ConvertStringSidToSid('S-1-5-32-544')
            adminsgroup = win32security.LookupAccountSid('', adminsgrpsid)[0]
            simplecommand(encode_strconsole('net localgroup %s "%s" /ADD' % (adminsgroup, username)))
            msg = '%s user account already exists. Nothing to do.' % username
            return True, msg
        except Exception:
            passwdchars = string.hexdigits + '-' + '$' + '#' + ',' + '_'
            userpassword = ''.join(random.sample(list(passwdchars), 14))
            adduser_cmd = 'net user "%s" "%s" /ADD /COMMENT:"Pulse '\
                'user with admin rights on the system"' % (username, userpassword)
    elif sys.platform.startswith('darwin'):
        try:
            uid = pwd.getpwnam(username).pw_uid
            gid = grp.getgrnam(username).gr_gid
            msg = '%s user account already exists. Nothing to do.' % username
            return True, msg
        except Exception:
            passwdchars = string.hexdigits + '-' + '$' + '#' + ',' + '_'
            userpassword = ''.join(random.sample(list(passwdchars), 14))
            adduser_cmd = 'dscl . -create /Users/%s '\
                'UserShell /usr/local/bin/rbash && '\
                'dscl . -passwd /Users/%s %s' % (username, username, userpassword)
    # Create the account
    result = simplecommand(encode_strconsole(adduser_cmd))
    if result['code'] == 0:
        msg = 'Creation of %s user account successful: %s' % (username, result)
        # Other operations specific to Windows
        if sys.platform.startswith('win'):
            result = simplecommand(encode_strconsole('wmic useraccount where "Name=\'%s\'" set PasswordExpires=False' % username))
            if result['code'] != 0:
                msg = 'Error setting %s user account to not expire: %s' % (username, result)
                return False, msg
            adminsgrpsid = win32security.ConvertStringSidToSid('S-1-5-32-544')
            adminsgroup = win32security.LookupAccountSid('', adminsgrpsid)[0]
            result = simplecommand(encode_strconsole('net localgroup %s "%s" /ADD' % (adminsgroup, username)))
            if result['code'] != 0:
                msg = 'Error adding %s account to administrators group: %s' % (username, result)
                return False, msg
            result = simplecommand(encode_strconsole('REG ADD "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList" /v "%s" /t REG_DWORD /d 0 /f' % username))
            if result['code'] != 0:
                msg = 'Error hiding %s account: %s' % (username, result)
                return False, msg
            user_home = os.path.normpath(getHomedrive())
            hide_from_explorer = simplecommand(encode_strconsole('attrib +h %s' % user_home))
            if hide_from_explorer['code'] != 0:
                msg = 'Error hiding %s account: %s' % (username, hide_from_explorer)
                return False, msg
        return True, msg
    else:
        msg = 'Creation of %s user account failed: %s' % (username, result)
        return False, msg

def pulseuser_profile_mustexist(username='pulseuser'):
    """
    This function checks if the a given profile exists.
    Args:
        username: This is the username we need to check ( default is pulseuser )

    Returns:
        It returns True if the profile has been correctly created or if the
        profile already exists, it return False otherwise.
    """
    if sys.platform.startswith('win'):
        # We define the sid
        usersid = get_user_sid(username)

        regquery = 'REG QUERY "HKLM\Software\Microsoft\Windows NT\CurrentVersion\ProfileList\%s.bak" /v "ProfileImagePath" /s'% usersid
        resultquery = simplecommand(encode_strconsole(regquery))
        if resultquery['code'] == 0:
            # There a .bak entry, we need to remove the it
            regdel = 'REG DELETE "HKLM\Software\Microsoft\Windows NT\CurrentVersion\ProfileList\%s.bak" /f' % usersid
            resultdel = simplecommand(encode_strconsole(regdel))
            if resultdel['code'] == 0:
                logging.getLogger().info("We correctly removed the backup profile")
            else:
                logging.getLogger().error("Error while deleting the backup profile")
        else:
            logging.getLogger().debug("There is not .bak entry, we have nothing to do")

        # Initialise userenv.dll
        userenvdll = ctypes.WinDLL('userenv.dll')
        # Define profile path that is needed
        defined_profilepath = getHomedrive()
        # Get user profile as created on the machine
        profile_location = os.path.normpath(get_user_profile(username)).strip().lower()
        if not profile_location or profile_location != defined_profilepath:
            # Delete all profiles if found
            delete_profile(username)
            # Create the profile
            ptr_profilepath = ctypes.create_unicode_buffer(260)
            userenvdll.CreateProfile(LPCWSTR(usersid),
                                     LPCWSTR(username),
                                     ptr_profilepath,
                                     240)
            if os.path.normpath(ptr_profilepath.value).strip().lower() == defined_profilepath:
                msg = '%s profile created successfully at %s' % (username, ptr_profilepath.value)
                return True, msg
            else:
                msg = 'Error creating %s profile at %s' % (username, ptr_profilepath.value)
                return False, msg
        else:
            # Profile found
            msg = '%s profile already exists at %s. Nothing to do.' % (username, profile_location)
            return True, msg
    elif sys.platform.startswith('linux'):
        try:
            uid = pwd.getpwnam(username).pw_uid
            gid = grp.getgrnam(username).gr_gid
            homedir = os.path.expanduser('~%s' % username)
        except Exception as e:
            msg = 'Error getting information for creating home folder for user %s' % username
            return False, msg
        if not os.path.isdir(homedir):
            os.makedirs(homedir, 0751)
        os.chmod(homedir, 0751)
        os.chown(homedir, uid, gid)
        packagedir = os.path.join(homedir, 'packages')
        if not os.path.isdir(packagedir):
            os.makedirs(packagedir, 0764)
        gidroot = grp.getgrnam("root").gr_gid
        os.chmod(packagedir, 0764)
        os.chown(packagedir, uid, gidroot)
        msg = '%s profile created successfully at %s' % (username, homedir)
        return True, msg
    elif sys.platform.startswith('darwin'):
        try:
            uid = pwd.getpwnam(username).pw_uid
            gid = grp.getgrnam(username).gr_gid
            homedir = os.path.expanduser('~%s' % username)
        except Exception as e:
            msg = 'Error getting information for creating home folder for user %s' % username
            return False, msg
        if not os.path.isdir(homedir):
            os.makedirs(homedir, 0751)
        os.chmod(homedir, 0751)
        os.chown(homedir, uid, gid)
        packagedir = os.path.join(homedir, 'packages')
        if not os.path.isdir(packagedir):
            os.makedirs(packagedir, 0764)
        gidroot = grp.getgrnam("root").gr_gid
        os.chmod(packagedir, 0764)
        os.chown(packagedir, uid, gidroot)
        msg = '%s profile created successfully at %s' % (username, homedir)
        return True, msg

def get_user_profile(username='pulseuser'):
    usersid = get_user_sid(username)
    if not usersid:
        return ''
    check_profile_cmd = 'powershell "Get-ItemProperty '\
    '-Path \'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\*\' '\
    '| Where-Object { $_.PSChildName -eq \'%s\' } '\
    '| Select -ExpandProperty ProfileImagePath"' % usersid
    result = simplecommand(encode_strconsole(check_profile_cmd))
    if result['code'] == 0 and result['result']:
        return result['result'][0]
    else:
        return ''

def get_user_sid(username='pulseuser'):
    try:
        usersid = win32security.ConvertSidToStringSid(
            win32security.LookupAccountName(None, username)[0])
        return usersid
    except Exception as e:
        return False

def delete_profile(username='pulseuser'):
    if sys.platform.startswith('win'):
        # Delete profile folder in C:\Users if any
        try:
            delete_folder_cmd = 'rd /s /q "%s" ' % getHomedrive()
            result = simplecommand(encode_strconsole(delete_folder_cmd))
            if result['code'] == 0:
                logger.debug('Deleted %s folder' % getHomedrive())
            else:
                logger.error('Error deleting %s folder' % getHomedrive())
        except Exception as e:
            pass
        # Delete profile
        userenvdll = ctypes.WinDLL('userenv.dll')
        usersid = get_user_sid(username)
        delete_profile_result = userenvdll.DeleteProfileA(LPCSTR(usersid))
        if delete_profile_result == 0:
            logger.debug('%s profile deleted.' % username)
        else:
            logger.error('Error deleting %s profile: %s' % (username, delete_profile_result))
    return True

def create_idrsa_on_client(username='pulseuser', key=''):
    """
    Used on client machine for connecting to relay server
    """
    if sys.platform.startswith('win'):
        id_rsa_path = os.path.join(getHomedrive(), '.ssh', 'id_rsa')
    else:
        id_rsa_path = os.path.join(os.path.expanduser('~%s' % username), '.ssh', 'id_rsa')
    delete_keyfile_cmd = 'del /f /q "%s" ' % id_rsa_path
    result = simplecommand(encode_strconsole(delete_keyfile_cmd))
    logger.debug('Creating id_rsa file in %s' % id_rsa_path)
    if not os.path.isdir(os.path.dirname(id_rsa_path)):
        os.makedirs(os.path.dirname(id_rsa_path), 0700)
    file_put_contents(id_rsa_path, key)
    result, logs = apply_perms_sshkey(id_rsa_path, True)
    if result is False:
        return False, logs
    msg = 'Key %s successfully created' % id_rsa_path
    return True, msg

def apply_perms_sshkey(path, private=True):
    """
    Apply permissions on ssh key.
    If private = True, the permissions are based on the user that is executing Medulla Agent
    If private = False, the permissions are based on pulseuser
    """
    if not os.path.isfile(path):
        msg = 'Error: File %s does not exist' % path
        return False, msg
    if sys.platform.startswith('win'):
        if private is True:
            # We are using id_rsa. The owner must be the user running the Agent
            username = win32api.GetUserName().lower()
        else:
            # The owner must be pulseuser
            username = 'pulseuser'
        try:
            sd = win32security.GetFileSecurity(path,
                                               win32security.DACL_SECURITY_INFORMATION)
            dacl = win32security.ACL()
            user, domain, type = win32security.LookupAccountName("", username)
            dacl.AddAccessAllowedAce(win32security.ACL_REVISION,
                                     ntsecuritycon.FILE_ALL_ACCESS,
                                     user)
            sd.SetSecurityDescriptorDacl(1, dacl, 0)
            win32security.SetFileSecurity(path,
                                          win32security.DACL_SECURITY_INFORMATION,
                                          sd)
            if private is False:
                user, domain, type = win32security.LookupAccountName("", "system")
                dacl.AddAccessAllowedAce(win32security.ACL_REVISION,
                                         ntsecuritycon.FILE_ALL_ACCESS,
                                         user)
                sd.SetSecurityDescriptorDacl(1, dacl, 0)
                win32security.SetFileSecurity(path,
                                              win32security.DACL_SECURITY_INFORMATION,
                                              sd)
        except Exception as e:
            msg = 'Error setting permissions on %s for user %s: %s' % (path, user, str(e))
            return False, msg
    else:
        if private is True:
            # We are using id_rsa. The owner must be the user running the Agent
            uid = os.geteuid()
            gid = os.getegid()
        else:
            # The owner must be pulseuser
            username = 'pulseuser'
            uid = pwd.getpwnam(username).pw_uid
            gid = grp.getgrnam(username).gr_gid
        try:
            os.chown(os.path.dirname(path), uid, gid)
            os.chown(path, uid, gid)
            os.chmod(os.path.dirname(path), 0700)
            os.chmod(path, 0600)
        except Exception as e:
            msg = 'Error setting permissions on %s for user %s: %s' % (path, pwd.getpwuid(uid).pw_name, str(e))
            return False, msg
    if sys.platform.startswith('win'):
        list_perms_cmd = 'powershell "(get-acl %s).access '\
        '| ft IdentityReference,FileSystemRights,AccessControlType"' % path
    elif sys.platform.startswith('linux'):
        list_perms_cmd = 'getfacl %s' % path
    elif sys.platform.startswith('darwin'):
        list_perms_cmd = 'ls -e -l %s' % path
    result = simplecommand(encode_strconsole(list_perms_cmd))
    logger.debug('Permissions on file %s:' % path)
    logger.debug("%s" % ''.join(result['result']))
    msg = 'Success applying permissions to file %s' % path
    return True, msg

def add_key_to_authorizedkeys_on_client(username='pulseuser', key=''):
    """
    Used on client machine for allowing connections from relay server

    Args:
        username: username where the key is copied to
        key:      the ssh key copied in the authorized_keys file

    Returns:
        message sent telling if the key have been well copied or not.
    """
    if sys.platform.startswith('win'):
        authorized_keys_path = os.path.join(getHomedrive(),'.ssh', 'authorized_keys')
    else:
        authorized_keys_path = os.path.join(os.path.expanduser('~%s' % username), '.ssh', 'authorized_keys')
    if not os.path.isfile(authorized_keys_path):
        logger.debug('Creating authorized_keys file in %s' % authorized_keys_path)
        if not os.path.isdir(os.path.dirname(authorized_keys_path)):
            os.makedirs(os.path.dirname(authorized_keys_path), 0700)
        file_put_contents(authorized_keys_path, key)
    else:
        authorized_keys_content = file_get_contents(authorized_keys_path)
        if not key.strip(' \t\n\r') in authorized_keys_content:
            logger.debug('Adding key to %s' % authorized_keys_path)
            file_put_contents_w_a(authorized_keys_path, "\n" + key, "a")
        else:
            logger.debug('Key is already present in %s' % authorized_keys_path)
    # Check if key is present
    authorized_keys_content = file_get_contents(authorized_keys_path)
    if key.strip(' \t\n\r') in authorized_keys_content:
        msg = 'Key successfully present in %s' % authorized_keys_path
        result, logs = apply_perms_sshkey(authorized_keys_path, False)
        if result is False:
            return False, logs
        return True, msg
    # Function didn't return earlier, meaning the key is not present
    msg = 'An error occured while adding the public key to the authorized_keys file. The id_rsa.pub key is missing'
    return False, msg

def reversessh_useraccount_mustexist_on_relay(username='reversessh'):
    try:
        uid = pwd.getpwnam(username).pw_uid
        msg = '%s user account already exists. Nothing to do.' % username
        return True, msg
    except Exception:
        adduser_cmd = 'adduser --system --quiet --group '\
            '--home /var/lib/pulse2/clients/reversessh '\
            '--shell /bin/rbash --disabled-password %s' % username
    result = simplecommand(encode_strconsole(adduser_cmd))
    if result['code'] == 0:
        msg = 'Creation of %s user account successful: %s' % (username, result)
        return True, msg
    else:
        msg = 'Creation of %s user account failed: %s' % (username, result)
        return False, msg

def reversessh_keys_mustexist_on_relay(username='reversessh'):
    try:
        uid = pwd.getpwnam(username).pw_uid
        homedir = os.path.expanduser('~%s' % username)
    except Exception as e:
        msg = 'Error getting information for creating home folder for user %s' % username
        return False, msg
    if not os.path.isdir(homedir):
        os.makedirs(homedir, 0751)
    os.chmod(homedir, 0751)
    os.chown(homedir, uid, -1)
    # Check keys
    id_rsa_key_path = os.path.join(os.path.expanduser('~%s' % username), '.ssh', 'id_rsa')
    public_key_path = os.path.join(os.path.expanduser('~%s' % username), '.ssh', 'id_rsa.pub')
    keycheck_cmd = 'ssh-keygen -y -f %s > %s' % (id_rsa_key_path, public_key_path)
    result = simplecommand(encode_strconsole(keycheck_cmd))
    if result['code'] != 0:
        logger.debug('Creating id_rsa file in %s' % id_rsa_key_path)
        if not os.path.isdir(os.path.dirname(id_rsa_key_path)):
            os.makedirs(os.path.dirname(id_rsa_key_path), 0700)
        keygen_cmd = 'ssh-keygen -q -N "" -b 2048 -t rsa -f %s' % id_rsa_key_path
        result = simplecommand(encode_strconsole(keygen_cmd))
    authorized_keys_path = os.path.join(os.path.expanduser('~%s' % username), '.ssh', 'authorized_keys')
    addtoauth_cmd = 'ssh-keygen -y -f %s > %s' % (id_rsa_key_path, authorized_keys_path)
    simplecommand(encode_strconsole(addtoauth_cmd))
    os.chmod(os.path.dirname(id_rsa_key_path), 0700)
    os.chown(os.path.dirname(id_rsa_key_path), uid, -1)
    os.chmod(id_rsa_key_path, 0600)
    os.chown(id_rsa_key_path, uid, -1)
    os.chmod(public_key_path, 0644)
    os.chown(public_key_path, uid, -1)
    os.chmod(authorized_keys_path, 0600)
    os.chown(authorized_keys_path, uid, -1)
    return True, 'Keys permissions applied on relay'

def get_relayserver_pubkey(username='root'):
    """
        returns relayserver's root public key
    """
    public_key_path = os.path.join(os.path.expanduser('~%s' % username), '.ssh', 'id_rsa.pub')
    return file_get_contents(public_key_path)

def get_relayserver_reversessh_idrsa(username='reversessh'):
    """
        returns relayserver's reversessh private key
    """
    idrsa_key_path = os.path.join(os.path.expanduser('~%s' % username), '.ssh', 'id_rsa')
    return file_get_contents(idrsa_key_path)


class geolocalisation_agent:

    def __init__(self,
                 typeuser="public",
                 geolocalisation=True,
                 ip_public=None,
                 strlistgeoserveur=""):
        self.determination = False
        self.geolocalisation = geolocalisation
        self.ip_public = ip_public
        self.typeuser = typeuser
        self.filegeolocalisation = os.path.join(Setdirectorytempinfo(),
                                                'filegeolocalisation')
        self.listgeoserver = ["http://%s/json" % x for x in re.split(r'[;,\[\(\]\)\{\}\:\=\+\*\\\?\/\#\+\&\-\$\|\s]',
                                              strlistgeoserveur) if x.strip() != ""]
        self.localisation = None

        self.getgeolocalisation()
        if self.localisation is None:
            self.localisation = self.getdatafilegeolocalisation()

    def getgeolocalisationobject(self):
        """
            This function is used to return the localisation file.

            Returns:
                It return the localisation file if it exists, None otherwise
        """
        if self.localisation is None:
            return {}
        return self.localisation

    def getdatafilegeolocalisation(self):
        """
            This function read the geolocalisation file if it exists
        """
        if self.geoinfoexist():
            try:
                with open(self.filegeolocalisation) as json_data:
                    self.localisation = json.load(json_data)
                self.determination = False
                return self.localisation
            except Exception:
                pass
        return None

    def setdatafilegeolocalisation(self):
        """
            This function write the geolocalisation file as a JSON file
        """
        if self.localisation is not None:
            try:
                with open(self.filegeolocalisation, 'w') as json_data:
                    json.dump(self.localisation, json_data, indent=4)
                self.determination = True
            except Exception:
                pass

    def geoinfoexist(self):
        """
            This function tests if the geolocalisation file exists

            Returns:
                It returns True if the file exists, False otherwise
        """
        if os.path.exists(self.filegeolocalisation):
            return True
        return False

    def getgeolocalisation(self):
        """
            This function permit to retrieve geolocalisation informations

            Returns:
                It returns geolocalisation informations if they exists
        """
        if self.typeuser in ["public", "nomade", "both"]:
            # We search for geolocalisation informations each time
            self.localisation = geolocalisation_agent.searchgeolocalisation(self.listgeoserver)
            self.determination = True
            self.setdatafilegeolocalisation()
        else:
            if self.localisation is not None:
                return self.localisation

            if self.geolocalisation:
                # We reload geolocalisation
                if self.geoinfoexist():
                    self.getdatafilegeolocalisation()
                    self.determination = False
                else:
                    self.localisation = geolocalisation_agent.searchgeolocalisation(self.listgeoserver)
                    self.setdatafilegeolocalisation()
                    self.determination = True
            else:
                if self.geoinfoexist():
                    self.getdatafilegeolocalisation()
                    self.determination = False
                else:
                    return None

        return self.localisation

    def get_ip_public(self):
        """
            This function is used to determine the public IP

            Returns:
                It returns the public IP
        """
        if self.geolocalisation:
            if self.localisation is None:
                self.getgeolocalisation()

            if self.localisation is not None and is_valid_ipv4(self.localisation['ip']):
                if not self.determination:
                    logger.warning("Determination use file")
                self.ip_public = self.localisation['ip']
                return self.localisation['ip']
            else:
                return None
        else:
            if not self.determination:
                logger.warning("Using the old way of determination for the ip_public")
            if self.localisation is  None:
                if self.geoinfoexist():
                    localisationData = self.getdatafilegeolocalisation()
                    logger.warning("%s" % localisationData)
                    if self.localisation is not None:
                        return self.localisation['ip']
            else:
                return self.localisation['ip']
        return self.ip_public

    @staticmethod
    def call_simple_page(url):
        try:
            r = requests.get(url)
            return r.json()
        except:
            return None

    @staticmethod
    def call_simple_page_urllib(url):
        try:
            result = urllib2.urlopen(url, timeout=5)
            objip = json.loads(result.read())
            if result.getcode() != 200:
                raise
            return objip
        except:
            return None

    @staticmethod
    def searchgeolocalisation(http_url_list_geo_server):
        """
            return objet
        """
        for url in http_url_list_geo_server:
            try:
                objip = geolocalisation_agent.call_simple_page(url)
                if  objip is None:
                    raise
                return objip
            except BaseException:
                pass
        return None


class downloadfile():
    def __init__(self, url, urllocalfile=None):
        """
        Instanciate a downloadfile object.

        Params:
            - url string of the download url
            - urllocalfile string of the dest (i.e.: /tmp/my_file.zip).
                If urllocalfile is None the file is downloaded in the current dir.
        """

        self.url = url
        self.urllocalfile = urllocalfile

    def code_return_html(self, code):
        """
        This function allow to provide userfriendly return messages
        Args:
            code: The return code provided by urllib2

        Returns:
            It returns a userfriendly return message based on the code provided by
            urllib2.
        """
        msghtml = "error html code %s" % code
        if code == 200:
            msghtml = "[%s succes]" % code
        if code == 301:
            msghtml = "[%s Moved Permanently]" % code
        if code == 302:
            msghtml = "[%s Moved temporarily]" % code
        if code == 400:
            msghtml = "[%s Bad Request]" % code
        if code == 401:
            msghtml = "[%s Unauthorized]" % code
        elif code == 403:
            msghtml = "[%s Forbidden]" % code
        elif code == 404:
            msghtml = "[%s Not Found]" % code
        elif code == 408:
            msghtml = "[%s Request Timeout]" % code
        elif code == 500:
            msghtml = "[%s Internal Server Error]" % code
        elif code == 503:
            msghtml = "[%s Service Unavailable]" % code
        elif code == 504:
            msghtml = "[%s Gateway Timeout]" % code
        return msghtml

    def downloadurl(self):
        """
        Download the url specified during instanciation.
        Returns:
            bool success, string return code
        """
        try:
            f = urllib2.urlopen(self.url)
            if self.urllocalfile is None:
                with open(os.path.basename(self.url), "wb") as local_file:
                    local_file.write(f.read())
            else:
                with open(self.urllocalfile, "wb") as local_file:
                    local_file.write(f.read())
            return True, "Download successful"
        except urllib2.HTTPError as e:
            return False, "HTTP Error %s while downloading %s: %s" % (self.code_return_html(e.code), self.url, e.reason)
        except urllib2.URLError as e:
            return False, "URL Error on %s: %s" % (self.url, e.reason)
        except IOError as e:
            return False, "I/O error {0} on file {1}: {2}".format(e.errno, self.urllocalfile, e.strerror)
        except:  # handle other exceptions such as attribute errors skipcq: FLK-E722
            return False, "Unexpected error: %s", sys.exc_info()[0]

def minifyjsonstring(strjson):
    """
    This function minifies the json string in input
        if json has incorrect '' and not "" this function will reformat
    Returns:
        string containining the minified json
    """
    # remove comments (//) and line breaks
    strjson = ''.join([row.split('//')[0] for row in strjson.split("\n") if len(row.strip())!=0])
    # remove tabs, line breaks and end of lines
    regex = re.compile(r'[\n\r\t]')
    strjson = regex.sub("", strjson)
    # protect json strings
    reg=re.compile(r"""(\".*?\n?.*?\")|(\'.*?\n?.*?\')""")
    newjson = re.sub(reg,
                     lambda x: '"%s"'%str(x.group(0)).strip('\"\'').strip().replace(' ','@@ESP@@'),
                     strjson)
    # remove blanks
    newjson=newjson.replace(' ','')
    # reinsert protected blanks
    newjson=newjson.replace('@@ESP@@',' ')
    # remove errors that are found often in json files
    newjson=newjson.replace(",}","}")
    newjson=newjson.replace("{,","{")
    newjson=newjson.replace("[,","[")
    newjson=newjson.replace(",]","]")
    return newjson

def serialnumbermachine():
    serial_uuid_machine=""
    try:
        if sys.platform.startswith('win'):
            result = simplecommand("wmic csproduct get uuid")
            if result['code'] == 0 and result['result']:
                a=[ x.strip().decode('utf-8', 'ignore') for x in result['result']]
                serial_uuid_machine = ''.join(a).replace('UUID','').strip()
        elif sys.platform.startswith('linux'):
            result = simplecommand('dmidecode -s system-uuid')
            if result['code'] == 0 and result['result']:
                serial_uuid_machine = ''.join(result['result']).strip()
        elif sys.platform.startswith('darwin'):
            cmd=r"""ioreg -d2 -c IOPlatformExpertDevice | awk -F\" '/IOPlatformUUID/{print $(NF-1)}'"""
            result = simplecommand(cmd)
            if result['code'] == 0 and result['result']:
                a=[x.strip().decode('utf-8', 'ignore') for x in result['result']]
                serial_uuid_machine = ''.join(a).replace('UUID','').strip()
        else:
            logger.warning("the serialnumbermachine function is not implemented for your os: %s" % sys.platform)
    except Exception:
        logger.error("An error occured while using the serialnumbermachine function \n we got the error below \n%s" % (traceback.format_exc()))
    return serial_uuid_machine


def send_data_tcp(datastrdata, hostaddress="127.0.0.1", port=8766):
    """Send tcp message throught a web socket
    Params:
        datastrdata string of datas sent
        hostaddress string of the destination addresse
        port int is the port on which the data are sent
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_address = (hostaddress, port)
    data = None
    try:
        sock.connect(server_address)
        sock.sendall(datastrdata.encode('ascii'))
        data = sock.recv(2048)
    except Exception as e:
        logger.error("[%s]" % (str(e)))
        data = None
    finally:
        sock.close()
        return data


class kb_catalogue:
    """
        class for request catalog update site
        eg : utilisation
            print( kb_catalogue().KB_update_exits("KB4586864"))
    """
    URL = "https://www.catalog.update.microsoft.com/Search.aspx"
    filter = "We did not find any results for"
    def __init__(self):
        pass

    def KB_update_exits(self, location):
        """
            return if kb existe in update catalogue
        """
        PARAMS = { 'q' : location }
        status, textresult = self.__get_requests(kb_catalogue.URL, params = PARAMS)
        if status == 200 and textresult.find(kb_catalogue.filter) == -1:
            return True
        else:
            return False

    def __get_requests(self, url, params, timeout=5):
        """
        this function send get to url
        return status et content text request
        status 200 correct reponse
        status 408 incorrect reponse content text empty
        """
        status = 408 # error timeout
        text_result = ""
        try:
            r = requests.get(url = url, params = params, timeout=timeout)
            status = r.status_code
            if status == 200:
                text_result = r.text
        except Timeout:
            status = 408,
        return status, text_result



def powerschellscript1ps1(namescript):
    namescript = windowspath(namescript)
    obj={"code" : -1, "result" : ""}
    try:
        obj = simplecommand(
            "powershell -ExecutionPolicy Bypass -File %s" % namescript
        )
    except Exception:
        logger.error("\n%s" % (traceback.format_exc()))
    return obj

class offline_search_kb:
    def __init__(self):
        self.info_package={ "history_package_uuid" : [],
                                "version_net" :{},
                                "kb_installed" : [],
                                "version_edge": "",
                                "infobuild" : { },
                                "platform_info" : {}}

        try:
            self.info_package['platform_info'] = self.platform_info()
        except Exception:
            logger.error("\n%s" % (traceback.format_exc()))

        try:
            self.info_package['malicious_software_removal_tool'] = self.search_malicious_software_removal_tool()
        except Exception:
            logger.error("\n%s" % (traceback.format_exc()))

        try:
            self.info_package['version_edge'] = self.search_version_edge()
        except Exception:
            logger.error("\n%s" % (traceback.format_exc()))

        try:
            self.info_package['history_package_uuid'] = self.search_history_update()
        except Exception:
            logger.error("\n%s" % (traceback.format_exc()))
        try:
            self.info_package['version_net'] = self.search_net_info_reg()
        except Exception:
            logger.error("\n%s" % (traceback.format_exc()))
        try:
            searchkb =  self.searchpackage()
            self.info_package['kb_installed'] = searchkb
            self.info_package['kb_list'] = self.compact_kb(searchkb )
        except Exception:
            logger.error("\n%s" % (traceback.format_exc()))
        try:
            self.info_package['infobuild'] = self.search_system_info_reg()
        except Exception:
            logger.error("\n%s" % (traceback.format_exc()))


    def get_json(self):
        return json.dumps(self.info_package, indent=4, ensure_ascii=False)

    def get(self):
        return self.info_package

    def compact_kb(self, listkb ):
        compactlist=[]
        for t in listkb:
            compactlist.append(t['HotFixID'][2:])
        return "(" + ",".join(compactlist) + ")"

    def searchpackage(self):
        endresult=[]
        if sys.platform.startswith("win"):
            try:
                ret=simplecommand(encode_strconsole("wmic qfe list brief /format:texttablewsys"))
                if ret["code"] == 0:
                    for t in ret["result"]:
                        t=decode_strconsole(t)
                        resultat={}
                        resultat['description'] =t[0:16].strip()
                        # resultat['FixComments'] =t[17:29].strip()
                        resultat['HotFixID'] =t[30:40].strip()
                        if not resultat['HotFixID'].startswith("KB"):
                            continue
                        # resultat['InstallDate'] =t[41:53].strip()
                        resultat['InstalledBy'] =t[54:74].strip()
                        resultat['InstalledOn'] =t[75:87].strip()
                        # resultat['Name'] =t[88:93].strip()
                        # resultat['ServicePackInEffect'] =t[94:114].strip()
                        # resultat['Status'] =t[115:].strip()
                        endresult.append(resultat)
            except Exception as e:
                logger.error("searchpackage : %s" %e)
                logger.error (traceback.format_exc())
        return endresult

    def search_malicious_software_removal_tool(self):
        # 'Windows Malicious Software Removal Tool x64 - v5.100 (KB890830)'
        # version de mrt.exec  (voir meta data)
        # (Get-ChildItem 'C:\Windows\System32\mrt.exe').VersionInfo | Format-List *
        # (Get-ChildItem 'C:\Windows\System32\mrt.exe').VersionInfo.ProductVersion
        result_cmd={}
        if sys.platform.startswith("win"):
            if os.path.exists('C:\\Windows\\System32\\mrt.exe'):
                informationlist = ("FileMajorPart", "FileMinorPart", "ProductVersion","ProductName")
                try:
                    cmd="""powershell "(Get-ChildItem 'C:\Windows\System32\mrt.exe').VersionInfo | Format-List *" """
                    result = simplecommand(encode_strconsole(cmd))
                    if int(result["code"]) == 0:
                        line = [ decode_strconsole(x.strip()) for x in result['result'] if x.strip().startswith(informationlist)]
                        for t in line:
                            lcmd = [ x for x in t.split (" ") if x != ""]
                            if len(lcmd) >= 3:
                                keystring = ' '.join(lcmd[2:])
                                result_cmd[lcmd[0]] = keystring
                        if "FileMajorPart" in result_cmd and "FileMinorPart" in result_cmd:
                            result = "Windows Malicious Software Removal Tool %s - v%s.%s"%(self.info_package['platform_info']["machine"],
                                                                                            result_cmd["FileMajorPart"],
                                                                                            result_cmd["FileMinorPart"] )
                            result_cmd["ProductName"]=result
                    else:
                        logging.getLogger().error("search search_malicious_software_removal_tool %s" % result['result'])
                except:
                    logging.getLogger().error(("%s" % (traceback.format_exc())))
        return result_cmd

    def search_version_edge(self):
        Versionedge=""
        if sys.platform.startswith("win"):
            try:
                cmd = """powershell.exe "(Get-AppxPackage Microsoft.MicrosoftEdge).Version" """
                result = simplecommand(encode_strconsole(cmd))
                if int(result["code"]) == 0:
                    vers=[ x.strip() for x in result['result'] if x.strip() != ""]
                    if vers:
                        Versionedge=vers[0]
            except:
                logging.getLogger().error(("%s" % (traceback.format_exc())))
        return Versionedge

    def search_history_update(self):
        ret = []
        if sys.platform.startswith("win"):
            script = os.path.abspath(
                os.path.join(
                    os.path.dirname(os.path.realpath(__file__)),
                    "..",
                    "script",
                    "history_update.ps1"
                )
            )
            result = powerschellscript1ps1(script)
            try:
                if result["code"] == 0:
                    line =[
                        decode_strconsole(x.strip())
                        for x in result["result"] if x.strip()]
                    if line:
                        line.pop(0)
                        line.pop(0)
                        retdict ={}
                        for t in set(line):
                            t=t.split()
                            retdict[t[1]]=t[0]
                            ret.append(t[1])
                        strt=("%s"%retdict.keys()).replace('[','').replace(']','').replace('dict_keys','')
            except IndexError as e:
                logger.error("An error occured while trying to get the history update. \n We obtained this error:%s" % e)
                logger.error("We hit this backtrace: \n %s" % traceback.format_exc())
        return ret

    def search_net_info_reg(self):
        result_cmd = { }
        if sys.platform.startswith("win"):
            informationlist = ("CBS", "Install", "InstallPath", "Release," "Servicing", "TargetVersion", "Version")
            cmd = """REG QUERY "HKLM\\SOFTWARE\\Microsoft\\NET Framework Setup\\NDP\\v4\\Full" """
            result = simplecommand(encode_strconsole(cmd))
            if int(result["code"]) == 0:
                # analyse result
                line = [ decode_strconsole(x.strip()) for x in result['result'] if x.strip().startswith(informationlist)]
                for t in line:
                    lcmd = [ x for x in t.split (" ") if x != ""]
                    if len(lcmd) >= 3:
                        keystring = ' '.join(lcmd[2:])
                        result_cmd[lcmd[0]] = keystring
            else:
                logging.getLogger().error("search REG QUERY \"HKLM\\SOFTWARE\\Microsoft\\NET Framework Setup\\NDP\\v4\\Full\"")
        return result_cmd

    def search_system_info_reg(self):
        result_cmd = { }
        if sys.platform.startswith("win"):
            informationlist = ("CurrentBuild", "CurrentVersion", "InstallationType", "ProductName," "ReleaseId", "DisplayVersion","RegisteredOwner")
            cmd = """REG QUERY "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion" | findstr REG_SZ"""
            result = simplecommand(encode_strconsole(cmd))
            if int(result["code"]) == 0:
                # analyse result
                line = [ x.decode('ascii', 'ignore').encode('utf-8').strip() for x in result['result'] if x.strip().startswith(informationlist)]
                for t in line:
                    lcmd = [ x for x in t.split (" ") if x != ""]
                    if len(lcmd) >= 3:
                        result_cmd[lcmd[0]] = lcmd[2]
            else:
                logging.getLogger().error("search REG QUERY \"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\"")
            # search code langue
            try:
                result_cmd["Locale"] = {"LCID" : None , "Name" : "", "DisplayName" : "", "ThreeLetterWindowsLanguageName" : "" }
                cmd = """powershell -ExecutionPolicy Bypass Get-WinSystemLocale"""
                result = simplecommand(encode_strconsole(cmd))
                if int(result["code"]) == 0:
                    langs=[  x.decode('ascii', 'ignore').encode('utf-8').strip() for x in result['result'] if x.strip() != ""][-1:]
                    langs=[  x.decode('ascii', 'ignore').encode('utf-8').strip() for x in langs[0].split('  ') if x != ""]
                    if len(langs) >= 3:
                        result_cmd["Locale"]["LCID"] = langs[0]
                        result_cmd["Locale"]["Name"] = langs[1]
                        result_cmd["Locale"]["DisplayName"] = langs[2]
                else:
                    logging.getLogger().error("search WinSystemLocale : %s" % result['result'])
            except:
                logging.getLogger().error(("%s" % (traceback.format_exc())))
            try:
                cmd="""powershell -ExecutionPolicy Bypass "Get-WinSystemLocale| select ThreeLetterWindowsLanguageName" """
                result = simplecommand(encode_strconsole(cmd))
                if int(result["code"]) == 0:

                    T_L_W_LanguageName = [ decode_strconsole(x.strip()) for x in result['result'] if x.strip() != ""][-1:][0]
                    result_cmd["Locale"]["ThreeLetterWindowsLanguageName"] = T_L_W_LanguageName
                else:
                    logging.getLogger().error("search ThreeLetterWindowsLanguageName %s" % result['result'])
            except:
                logging.getLogger().error(("%s" % (traceback.format_exc())))
        return result_cmd


    def platform_info(self):
        res={"machine" :  platform.machine(),
                "type" : "%s %s"%(platform.system(), platform.release() ),
                "node" : platform.node(),
                "platform" : platform.platform(aliased=0, terse=0),
                "processor" : platform.processor(),
                "version":platform.version()}
                 # x.decode('cp850', 'ignore')
        if sys.platform.startswith("win"):
            informationlist ={}
            cmd = """systeminfo.exe /FO csv /NH"""
            result = simplecommand(cmd)
            if int(result["code"]) == 0:
                result['result'][0] = result['result'][0].decode('ascii', 'ignore').encode('utf-8')
                line = [ x.strip("\" ") for x in result['result'][0].split('","')]
                informationlist ={ "node": str(line[0]),
                            "platform": line[1].lower(),
                            "version":line[2],
                            "OS Configuration":line[4],
                            "Product ID":line[8],
                            "Original Install Date":line[9],
                            "System Model":line[12],
                            "System Type":line[13],
                            "BIOS Version":line[15],
                            "System Locale":line[19],
                            "Time Zone":line[21],
                            "processor" : str(platform.processor()),
                            "machine":line[13]
                            }
                if "x64" in informationlist["System Type"]:
                    informationlist["machine"] = "x64"
                if "windows 10" in informationlist["platform"]:
                    informationlist["type"] = "Windows 10"
                else:
                    informationlist["type"] = informationlist["platform"]

                return informationlist
            else:
                logging.getLogger().error("systeminfo error")
        return res




def download_file_windows_update(url, connecttimeout=30, outdirname=None):
    """
        Cette function download file dans base windows
        wget system linux is used
    """
    if sys.platform.startswith("linux"):
        regex = re.compile(
            r'^(?:http|ftp)s?://' # http:// or https://
            r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|' #domain...
            r'localhost|' #localhost...
            r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})' # ...or ip
            r'(?::\d+)?' # optional port
            r'(?:/?|[/?]\S+)$', re.IGNORECASE)
        if not re.match(regex,url) is not None:
            "url non conforme"
            logging.getLogger().error("incorrect url [%s]" % (url))
            return False
        if  outdir is None:
            base_file= os.path.join("/","var","lib","pulse2","base_file_update")
        else:
            base_file= os.path.join("/","var","lib","pulse2",outdirname)
        if os.path.dirname(base_file) !=  os.path.join("/","var","lib","pulse2"):
            # name repertoire non conforme
            logging.getLogger().error("download_file_windows_update incorrect path [%s]" % (base_file))
            return False
        try:
            os.makedirs(base_file)
        except OSError:
            if not os.path.isdir(base_file):
                Raise
        #os.makedirs(base_file, exist_ok=True)
        res=simplecommand("wget --connect-timeout=20 '%s'"% sys.argv[1])
        if res["code"] == 0:
            # correct download
            logging.getLogger().debug("download %s in [%s]" % (url, base_file))
            return True
        else:
            # incorrect download
            logging.getLogger().error("download_file_windows_update incorrect download %s [%s]" % (url, res['result']))
    else:
        logging.getLogger().error("download_file_windows_update function download_file_windows_update linux only")
    return False


