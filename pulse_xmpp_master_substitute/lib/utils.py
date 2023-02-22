#!/usr/bin/python3
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
# file : pulse_xmpp_master_substitute/lib/utils.py
#

"""
    This file contains shared functions use in pulse client/server agents.
"""

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
import urllib.request
import pickle
from .agentconffile import conffilename
import configparser
import socket
import psutil
import time
from datetime import datetime
import imp
import requests
from functools import wraps  # This convenience func preserves name and docstring
import uuid
from Crypto import Random
from Crypto.Cipher import AES
import tarfile
import string
import asyncio as aio

# 3rd party modules
import posix_ipc

if sys.platform.startswith("win"):
    import wmi
    import pythoncom
    import winreg as wr
    import win32api
    import win32security
    import ntsecuritycon
    import win32net
    import ctypes
    import win32com.client
    from win32com.client import GetObjectif
    import ctypes
    from ctypes.wintypes import LPCWSTR, LPCSTR, WinError
if sys.platform.startswith("linux"):
    import pwd
    import grp

if sys.platform.startswith("darwin"):
    import pwd
    import grp

logger = logging.getLogger()

DEBUGPULSE = 25


class Env(object):
    agenttype = None  # Non specified by default

    @staticmethod
    def user_dir():
        """Get the user folder for linux OS."""
        if Env.agenttype is None:
            raise NotImplementedError(
                "The class attribute aggenttype need to be initialized\neg:  Env.agenttype = 'machine'"
            )
        if Env.agenttype == "relayserver":
            return os.path.join("/", "var", "lib", "pulse2")

        return os.path.expanduser("~pulseuser")


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
                    args=dict(list(zip(arg_names, dec_fn_args))), kwargs=dec_fn_kwargs
                )
                result = ", ".join(
                    ["{}={}".format(str(k), repr(v)) for k, v in list(params.items())]
                )
                log.info(
                    "\n@@@ call func : {}({}) file {}".format(
                        func_name, result, filepath
                    )
                )
                log.info(
                    "\n@@@ call func : {}({}) file {}".format(
                        func_name, result, filepath
                    )
                )
            else:
                log.info("\n@@@ call func : {}() file {}".format(func_name, filepath))
            # Execute wrapped (decorated) function:
            outfunction = decorated_function(*dec_fn_args, **dec_fn_kwargs)
            timeruntime = time.time() - start
            if out:
                if timeprocess:
                    log.info(
                        "\n@@@ out func :{}() in {}s is -->{}".format(
                            func_name, timeruntime, outfunction
                        )
                    )
                else:
                    log.info(
                        "\n@@@ out func :{}() is -->{}".format(func_name, outfunction)
                    )
            else:
                if timeprocess:
                    log.info(
                        "\n@@@ out func :{}() in {}s".format(func_name, timeruntime)
                    )
                else:
                    log.info("\n@@@ out func :{}()".format(func_name))
            return outfunction

        return wrapper

    return decorated


def Setdirectorytempinfo():
    """
    This function is used to obtain the path to the temporary directory used
    by the agent to store informations like network or configuration fingerprints.


    Returns:
        It returns the path to the temporary directory.

    """
    dirtempinfo = os.path.join(os.path.dirname(os.path.realpath(__file__)), "INFOSTMP")
    if not os.path.exists(dirtempinfo):
        os.makedirs(dirtempinfo, mode=0o007)
    return dirtempinfo


def cleanbacktodeploy(objectxmpp):
    delsession = [
        session
        for session in objectxmpp.back_to_deploy
        if not objectxmpp.session.isexist(session)
    ]
    for session in delsession:
        del objectxmpp.back_to_deploy[session]
    if len(delsession) != 0:
        logging.log(DEBUGPULSE, "Clear dependency : %s" % delsession)
        save_back_to_deploy(objectxmpp.back_to_deploy)


def networkinfoexist():
    """
    This function is used to check that the fingerprintnetwork folder
    exists.

    Returns:
        True if the file exists
        False if the file does not exists
    """
    filenetworkinfo = os.path.join(Setdirectorytempinfo(), "fingerprintnetwork")
    if os.path.exists(filenetworkinfo):
        return True
    return False


def save_count_start():
    filecount = os.path.join(Setdirectorytempinfo(), "countstart")
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
    This function is used to know if we need to unregister an old JID
        Args:
            user: User for the JID
            domain: Domain for the JID
            resource: Resource of the JID
        Returns:
            It returns `True` if we need to unregister an old JID.
    """
    jidinfo = {"user": user, "domain": domain, "resource": resource}
    filejid = os.path.join(Setdirectorytempinfo(), "jid")
    if not os.path.exists(filejid):
        savejsonfile(filejid, jidinfo)
        return False, jidinfo
    oldjid = loadjsonfile(filejid)
    if oldjid["user"] != user or oldjid["domain"] != domain:
        savejsonfile(filejid, jidinfo)
        return True, jidinfo
    if oldjid["resource"] != resource:
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
    jidinfosubscribe = {"user": user, "domain": domain, "resource": resource}
    filejidsubscribe = os.path.join(Setdirectorytempinfo(), "subscribe")
    if not os.path.exists(filejidsubscribe):
        savejsonfile(filejidsubscribe, jidinfosubscribe)
        return False, jidinfosubscribe
    oldjidsubscribe = loadjsonfile(filejidsubscribe)
    if oldjidsubscribe["user"] != user or oldjidsubscribe["domain"] != domain:
        savejsonfile(filejidsubscribe, jidinfosubscribe)
        return True, jidinfosubscribe
    if oldjidsubscribe["resource"] != resource:
        savejsonfile(filejidsubscribe, jidinfosubscribe)
    return False, jidinfosubscribe


def save_back_to_deploy(obj):
    fileback_to_deploy = os.path.join(Setdirectorytempinfo(), "back_to_deploy")
    save_obj(obj, fileback_to_deploy)


def load_back_to_deploy():
    fileback_to_deploy = os.path.join(Setdirectorytempinfo(), "back_to_deploy")
    return load_obj(fileback_to_deploy)


def listback_to_deploy(objectxmpp):
    if len(objectxmpp.back_to_deploy) != 0:
        print("list session pris en compte back_to_deploy")
        for u in objectxmpp.back_to_deploy:
            print(u)


def testagentconf(typeconf):
    if typeconf == "relayserver":
        return True
    Config = configparser.ConfigParser()
    namefileconfig = conffilename(typeconf)
    Config.read(namefileconfig)
    if (
        Config.has_option("type", "guacamole_baseurl")
        and Config.has_option("connection", "port")
        and Config.has_option("connection", "server")
        and Config.has_option("global", "relayserver_agent")
        and Config.get("type", "guacamole_baseurl") != ""
        and Config.get("connection", "port") != ""
        and Config.get("connection", "server") != ""
        and Config.get("global", "relayserver_agent") != ""
    ):
        return True
    return False


def createfingerprintnetwork():
    md5network = ""
    if sys.platform.startswith("win"):
        obj = simplecommandstr("ipconfig")
        if sys.version_info[0] == 3:
            md5network = hashlib.md5(bytes(obj["result"], "utf-8")).hexdigest()
        else:
            md5network = hashlib.md5(obj["result"]).hexdigest()
    elif sys.platform.startswith("linux"):
        obj = simplecommandstr(
            "LANG=C ifconfig | egrep '.*(inet|HWaddr).*' | grep -v inet6"
        )
        if sys.version_info[0] == 3:
            md5network = hashlib.md5(bytes(obj["result"], "utf-8")).hexdigest()
        else:
            md5network = hashlib.md5(obj["result"]).hexdigest()
    elif sys.platform.startswith("darwin"):
        obj = simplecommandstr("ipconfig")
        if sys.version_info[0] == 3:
            md5network = hashlib.md5(bytes(obj["result"], "utf-8")).hexdigest()
        else:
            md5network = hashlib.md5(obj["result"]).hexdigest()
    return md5network


def createfingerprintconf(typeconf):
    namefileconfig = conffilename(typeconf)
    return hashlib.md5(file_get_contents(namefileconfig)).hexdigest()


def confinfoexist():
    filenetworkinfo = os.path.join(Setdirectorytempinfo(), "fingerprintconf")
    if os.path.exists(filenetworkinfo):
        return True
    return False


def confchanged(typeconf):
    """
    This function is used to know if the configuration changed.

    If the checked file does not exist or if the fingerprint have
    changed we consider that the configuration changed.

    We check the fingerprint between the old saved configuration
    which is stored in the `fingerprintconf` variable.

    Returns:
        True if we consider that the configuration changed
        False if we consider that the configuration has not changed
    """
    if confinfoexist():
        fingerprintconf = file_get_contents(
            os.path.join(Setdirectorytempinfo(), "fingerprintconf")
        )
        newfingerprintconf = createfingerprintconf(typeconf)
        if newfingerprintconf == fingerprintconf:
            return False

    return True


def refreshfingerprintconf(typeconf):
    fp = createfingerprintconf(typeconf)
    file_put_contents(os.path.join(Setdirectorytempinfo(), "fingerprintconf"), fp)
    return fp


def networkchanged():
    """
    This function is used to know if the network changed.

    If the checked file does not exist or if the fingerprint have
    changed we consider that the network changed.

    A network change means that the interfaces changed ( new or deleted )

    Returns:
        True if we consider that the network changed
        False if we consider that the network has not changed
    """
    if networkinfoexist():
        fingerprintnetwork = file_get_contents(
            os.path.join(Setdirectorytempinfo(), "fingerprintnetwork")
        )
        newfingerprint = createfingerprintnetwork()
        if fingerprintnetwork == newfingerprint:
            return False

    return True


def refreshfingerprint():
    fp = createfingerprintnetwork()
    file_put_contents(os.path.join(Setdirectorytempinfo(), "fingerprintnetwork"), fp)
    return fp


def file_get_contents(
    filename, use_include_path=0, context=None, offset=-1, maxlen=-1, encoding=None
):
    if filename.find("://") > 0:
        ret = urllib.request.urlopen(filename).read()
        if offset > 0:
            ret = ret[offset:]
        if maxlen > 0:
            ret = ret[:maxlen]
        return ret
    else:
        if encoding:
            fp = open(filename, "r", encoding=encoding)
        else:
            fp = open(filename, "r")
        try:
            if offset > 0:
                fp.seek(offset)
            ret = fp.read(maxlen)
            return ret
        finally:
            fp.close()


def file_get_binarycontents(filename, offset=-1, maxlen=-1):
    fp = open(filename, "rb")
    try:
        if offset > 0:
            fp.seek(offset)
        ret = fp.read(maxlen)
        return ret
    finally:
        fp.close()


def file_put_contents(filename, data):
    f = open(filename, "w")
    f.write(data)
    f.close()


def file_put_contents_w_a(filename, data, option="w"):
    if option == "a" or option == "w":
        f = open(filename, option)
        f.write(data)
        f.close()


def save_obj(obj, name):
    """
    funct save serialised object
    """
    with open(name + ".pkl", "wb") as f:
        pickle.dump(obj, f, pickle.HIGHEST_PROTOCOL)


def load_obj(name):
    """
    function load serialized object
    """
    with open(name + ".pkl", "rb") as f:
        return pickle.load(f)


def getCurrentWorkingDirectory():
    return os.path.abspath(os.getcwd())


def getScriptPath():
    return os.path.abspath(os.path.join(getCurrentWorkingDirectory(), "script"))


def getPluginsPath():
    return os.path.abspath(os.path.join(getCurrentWorkingDirectory(), "plugins"))


def getLibPath():
    return os.path.abspath(os.path.join(getCurrentWorkingDirectory(), "lib"))


def getPerlScriptPath(name):
    return os.path.abspath(
        os.path.join(getCurrentWorkingDirectory(), "script", "perl", name)
    )


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
        self.linebuf = ""

    def write(self, buf):
        for line in buf.rstrip().splitlines():
            self.logger.log(self.debug, line.rstrip())


# windows


def get_connection_name_from_guid(iface_guids):
    iface_names = ["(unknown)" for i in range(len(iface_guids))]
    reg = wr.ConnectRegistry(None, wr.HKEY_LOCAL_MACHINE)
    reg_key = wr.OpenKey(
        reg,
        r"SYSTEM\CurrentControlSet\Control\Network\{4d36e972-e325-11ce-bfc1-08002be10318}",
    )
    for i in range(len(iface_guids)):
        try:
            reg_subkey = wr.OpenKey(reg_key, iface_guids[i] + r"\Connection")
            iface_names[i] = wr.QueryValueEx(reg_subkey, "Name")[0]
        except BaseException:
            pass
    return iface_names


def isWinUserAdmin():
    if os.name == "nt":
        import ctypes

        # WARNING: requires Windows XP SP2 or higher!
        try:
            return ctypes.windll.shell32.IsUserAnAdmin()
        except BaseException:
            logger.error("\n%s" % (traceback.format_exc()))
            print("Admin check failed, assuming not an admin.")
            return False
    elif os.name == "posix":
        # Check for root on Posix
        return os.getuid() == 0
    else:
        raise RuntimeError(
            "Unsupported operating system for this module: %s" % (os.name,)
        )


def isMacOsUserAdmin():
    # pour linux "cat /etc/shadow")
    obj = simplecommand("cat /etc/master.passwd")
    if int(obj["code"]) == 0:
        return True
    else:
        return False


# listplugins = ['.'.join(fn.split('.')[:-1]) for fn in os.listdir(getPluginsPath) if fn.endswith(".py") and fn != "__init__.py"]
def getRandomName(nb, pref=""):
    a = "abcdefghijklnmopqrstuvwxyz0123456789"
    d = pref
    for t in range(nb):
        d = d + a[random.randint(0, 35)]
    return d


def name_random(nb, pref=""):
    a = "abcdefghijklnmopqrstuvwxyz0123456789"
    d = pref
    for t in range(nb):
        d = d + a[random.randint(0, 35)]
    return d


def name_randomplus(nb, pref=""):
    a = "abcdefghijklnmopqrstuvwxyz0123456789"
    q = str(uuid.uuid4())
    q = pref + q.replace("-", "")
    for t in range(nb):
        d = a[random.randint(0, 35)]
    res = q + d
    return res[:nb]


def md5(fname):
    hash = hashlib.md5()
    with open(fname, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash.update(chunk)
    return hash.hexdigest()


# def load_plugin(name):
# mod = __import__("plugin_%s" % name)
# return mod


def loadModule(filename):
    module = None
    if filename == "":
        raise RuntimeError("Empty filename cannot be loaded")
    # filename = "plugin_%s" % filename
    # logger.debug("Loading module %s" % (filename))
    searchPath, file = os.path.split(filename)
    if searchPath not in sys.path:
        sys.path.append(searchPath)
        sys.path.append(os.path.normpath(searchPath + "/../"))
    moduleName, ext = os.path.splitext(file)

    try:
        fp, pathName, description = imp.find_module(
            moduleName,
            [
                searchPath,
            ],
        )
    except Exception:
        logger.error("We hit a backtrace when searching for Modules")
        logger.error("We got the backtrace\n%s" % (traceback.format_exc()))
        return None

    try:
        module = imp.load_module(moduleName, fp, pathName, description)
    except Exception:
        logger.error("We hit a backtrace when loading Modules")
        logger.error("We got the backtrace \n%s" % (traceback.format_exc()))
    finally:
        if fp:
            fp.close()
    return module


def call_plugin_separate(name, *args, **kwargs):
    # add compteur appel plugins
    loop = aio.get_event_loop()
    count = 0
    try:
        count = getattr(args[0], "num_call%s" % args[1])
        setattr(args[0], "num_call%s" % args[1], count + 1)
    except AttributeError:
        count = 0
        setattr(args[0], "num_call%s" % args[1], count)
    pluginaction = loadModule(name)
    loop.call_soon_threadsafe(pluginaction.action, *args, **kwargs)


def call_plugin(name, *args, **kwargs):
    # util only asyncio
    # add compteur appel plugins
    loop = aio.new_event_loop()
    count = 0
    try:
        count = getattr(args[0], "num_call%s" % args[1])
        setattr(args[0], "num_call%s" % args[1], count + 1)
    except AttributeError:
        setattr(args[0], "num_call%s" % args[1], 0)
    pluginaction = loadModule(name)
    # loop.call_soon_threadsafe(pluginaction.action, *args, **kwargs)
    result = loop.run_in_executor(None, pluginaction.action, *args, **kwargs)


def call_plugin_sequentially(name, *args, **kwargs):
    # add compteur appel plugins
    count = 0
    try:
        count = getattr(args[0], "num_call%s" % args[1])
        setattr(args[0], "num_call%s" % args[1], count + 1)
    except AttributeError:
        count = 0
        setattr(args[0], "num_call%s" % args[1], count)
    pluginaction = loadModule(name)
    pluginaction.action(*args, **kwargs)


def getshortenedmacaddress():
    listmacadress = {}
    for i in netifaces.interfaces():
        addrs = netifaces.ifaddresses(i)
        try:
            if_mac = reduction_mac(addrs[netifaces.AF_LINK][0]["addr"])
            addrs[netifaces.AF_INET][0]["addr"]
            address = int(if_mac, 16)
            if address != 0:
                listmacadress[address] = if_mac
        except BaseException:
            pass
    return listmacadress


def getMacAdressList():
    listmacadress = []
    for interfacenet in netifaces.interfaces():
        try:
            macadress = netifaces.ifaddresses(interfacenet)[netifaces.AF_LINK][0][
                "addr"
            ]
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
                if link["addr"] != "127.0.0.1":
                    ip_list.append(link["addr"])
        except BaseException:
            pass
    return ip_list


def MacAdressToIp(ip):
    """
    Returns a MAC for interfaces that have given IP, returns None if not found
    """
    for i in netifaces.interfaces():
        addrs = netifaces.ifaddresses(i)
        try:
            if_mac = addrs[netifaces.AF_LINK][0]["addr"]
            if_ip = addrs[netifaces.AF_INET][0]["addr"]
        except (
            BaseException
        ):  # IndexError, KeyError: #ignore ifaces that dont have MAC or IP
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
    # mac = mac.replace("/","")
    return mac


def is_valid_ipv4(ip):
    """
    Validates IPv4 addresses.
    """
    pattern = re.compile(
        r"""
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
    """,
        re.VERBOSE | re.IGNORECASE,
    )
    return pattern.match(ip) is not None


def is_valid_ipv6(ip):
    """
    Validates IPv6 addresses.
    """
    pattern = re.compile(
        r"""
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
    """,
        re.VERBOSE | re.IGNORECASE | re.DOTALL,
    )
    return pattern.match(ip) is not None


def typelinux():
    """
    This function is used to tell which init system is used on the server.

    Returns:
        Return the used init system between init.d or systemd
    """
    p = subprocess.Popen(
        "cat /proc/1/comm", shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT
    )
    result = p.stdout.readlines()
    # code_result = p.wait()
    system = result[0].rstrip("\n")
    return system


def isprogramme(name):
    obj = {}
    p = subprocess.Popen(
        "which %s" % (name),
        shell=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    result = p.stdout.readlines()
    obj["code"] = p.wait()
    obj["result"] = result
    if obj["result"] != "":
        return True
    else:
        return False


def simplecommand(cmd, strimresult=False):
    obj = {"code": -1, "result": ""}
    p = subprocess.Popen(
        cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT
    )
    result = p.stdout.readlines()
    obj["code"] = p.wait()
    if sys.version_info[0] == 3:
        if strimresult:
            obj["result"] = [x.decode("utf-8").strip() for x in result]
        else:
            obj["result"] = [x.decode("utf-8") for x in result]
    else:
        if strimresult:
            obj["result"] = [x.strip() for x in result]
        else:
            obj["result"] = [x for x in result]
    return obj


def simplecommandstr(cmd):
    obj = {}
    p = subprocess.Popen(
        cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT
    )
    obj["code"] = p.wait()
    result = p.stdout.readlines()
    if sys.version_info[0] == 3:
        result = [x.decode("utf-8") for x in result]
    else:
        result = [x for x in result]
    obj["result"] = "".join(result)
    return obj


def windowspath(namescript):
    if sys.platform.startswith("win"):
        return '"' + namescript + '"'
    else:
        return namescript


def powerschellscriptps1(namescript):
    namescript = windowspath(namescript)
    print("powershell -ExecutionPolicy Bypass -File  %s" % namescript)
    obj = simplecommandstr(
        encode_strconsole("powershell -ExecutionPolicy Bypass -File %s" % namescript)
    )
    return obj


class shellcommandtimeout(object):
    def __init__(self, cmd, timeout=15, strimresult=False):
        self.process = None
        self.obj = {}
        self.strimresult = strimresult
        self.obj["timeout"] = timeout
        self.obj["cmd"] = cmd
        self.obj["result"] = "result undefined"
        self.obj["code"] = 255
        self.obj["separateurline"] = os.linesep

    def run(self):
        def target():
            self.process = subprocess.Popen(
                self.obj["cmd"],
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
            )
            if sys.version_info[0] == 3:
                if self.strimresult:
                    self.obj["result"] = [
                        x.decode("utf-8").strip()
                        for x in self.process.stdout.readlines()
                    ]
                else:
                    self.obj["result"] = [
                        x.decode("utf-8") for x in self.process.stdout.readlines()
                    ]
            else:
                self.obj["result"] = self.process.stdout.readlines()
            self.obj["code"] = self.process.wait()
            self.process.communicate()

        thread = threading.Thread(target=target)
        thread.start()
        thread.join(self.obj["timeout"])
        if thread.is_alive():
            print("Terminating process")
            print("timeout %s" % self.obj["timeout"])
            self.process.terminate()
            thread.join()
        self.obj["codereturn"] = self.process.returncode
        if self.obj["codereturn"] == -15:
            self.result = "error tineout"
        return self.obj


def servicelinuxinit(name, action):
    obj = {}
    p = subprocess.Popen(
        "/etc/init.d/%s %s" % (name, action),
        shell=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    result = p.stdout.readlines()
    obj["code"] = p.wait()
    obj["result"] = result
    return obj


# restart service


def service(name, action):
    """
    TODO: Write doc, possible actions
        start | stop | restart | reload
    """
    obj = {}
    if sys.platform.startswith("linux"):
        system = ""
        p = subprocess.Popen(
            "cat /proc/1/comm",
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )
        result = p.stdout.readlines()
        # code_result = p.wait()
        system = result[0].rstrip("\n")
        if system == "init":
            p = subprocess.Popen(
                "/etc/init.d/%s %s" % (name, action),
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
            )
            result = p.stdout.readlines()
            obj["code"] = p.wait()
            obj["result"] = result
        elif system == "systemd":
            p = subprocess.Popen(
                "systemctl %s %s" % (action, name),
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
            )
            result = p.stdout.readlines()
            obj["code"] = p.wait()
            obj["result"] = result
    elif sys.platform.startswith("win"):
        pythoncom.CoInitialize()
        try:
            wmi_obj = wmi.WMI()
            wmi_sql = "select * from Win32_Service Where Name ='%s'" % name
            wmi_out = wmi_obj.query(wmi_sql)
        finally:
            pythoncom.CoUninitialize()
        for dev in wmi_out:
            print(dev.Caption)
        pass
    elif sys.platform.startswith("darwin"):
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
        print(dev.Caption)
        print(dev.DisplayName)


def joint_compteAD(domain, password, login, group):
    # https://msdn.microsoft.com/en-us/library/windows/desktop/aa392154%28v=vs.85%29.aspx
    pythoncom.CoInitialize()
    try:
        c = wmi.WMI()
        for computer in c.Win32_ComputerSystem():
            if computer.PartOfDomain:
                print(computer.Domain)  # DOMCD
                print(computer.SystemStartupOptions)
                computer.JoinDomainOrWorkGroup(domain, password, login, group, 3)
    finally:
        pythoncom.CoUninitialize()


def windowsservice(name, action):
    pythoncom.CoInitialize()
    try:
        wmi_obj = wmi.WMI()
        wmi_sql = "select * from Win32_Service Where Name ='%s'" % name
        print(wmi_sql)
        wmi_out = wmi_obj.query(wmi_sql)
    finally:
        pythoncom.CoUninitialize()
    print(len(wmi_out))
    for dev in wmi_out:
        print(dev.caption)
        if action.lower() == "start":
            dev.StartService()
        elif action.lower() == "stop":
            print(dev.Name)
            dev.StopService()
        elif action.lower() == "restart":
            dev.StopService()
            dev.StartService()
        else:
            pass


def methodservice():
    pythoncom.CoInitialize()
    try:
        c = wmi.WMI()
        for method in c.Win32_Service._methods:
            print(method)
    finally:
        pythoncom.CoUninitialize()


def file_get_content(path):
    inputFile = open(path, "r")  # Open test.txt file in read mode
    content = inputFile.read()
    inputFile.close()
    return content


def file_put_content(filename, contents, mode="w"):
    fh = open(filename, mode)
    fh.write(contents)
    fh.close()


# windows
# def listusergroup():
# import wmi
# c = wmi.WMI()
# for group in c.Win32_Group():
# print group.Caption
# for user in group.associators("Win32_GroupUser"):
# print ("  ", user.Caption)

# decorateur pour simplifier les plugins


def pluginprocess(func):
    def wrapper(objetxmpp, action, sessionid, data, message, dataerreur):
        resultaction = "result%s" % action
        result = {}
        result["action"] = resultaction
        result["ret"] = 0
        result["sessionid"] = sessionid
        result["base64"] = False
        result["data"] = {}
        dataerreur["action"] = resultaction
        dataerreur["data"]["msg"] = "ERROR : %s" % action
        dataerreur["sessionid"] = sessionid
        try:
            response = func(
                objetxmpp, action, sessionid, data, message, dataerreur, result
            )
            # encode  result['data'] si besoin
            # print result
            if result["base64"] is True:
                result["data"] = base64.b64encode(json.dumps(result["data"]))
            print("Send message \n%s" % result)
            objetxmpp.send_message(
                mto=message["from"], mbody=json.dumps(result), mtype="chat"
            )
        except BaseException:
            print("Send error message\n%s" % dataerreur)
            objetxmpp.send_message(
                mto=message["from"], mbody=json.dumps(dataerreur), mtype="chat"
            )
            return
        return response

    return wrapper


# decorateur pour simplifier les plugins
def pulgindeploy(func):
    def wrapper(objetxmpp, action, sessionid, data, message, dataerreur):
        resultaction = action
        result = {}
        result["action"] = resultaction
        result["ret"] = 0
        result["sessionid"] = sessionid
        result["base64"] = False
        result["data"] = {}
        dataerreur["action"] = resultaction
        dataerreur["data"]["msg"] = "ERROR : %s" % action
        dataerreur["sessionid"] = sessionid
        try:
            response = func(
                objetxmpp, action, sessionid, data, message, dataerreur, result
            )
            if result["data"] != "end":
                if result["base64"] is True:
                    result["data"] = base64.b64encode(json.dumps(result["data"]))
                objetxmpp.send_message(
                    mto=message["from"], mbody=json.dumps(result), mtype="chat"
                )
        except BaseException:
            if result["data"] != "end":
                objetxmpp.send_message(
                    mto=message["from"], mbody=json.dumps(dataerreur), mtype="chat"
                )
            return
        return response

    return wrapper


# decorateur pour simplifier les plugins


def pulgindeploy1(func):
    def wrapper(objetxmpp, action, sessionid, data, message, dataerreur):
        result = {}
        result["action"] = action
        result["ret"] = 0
        result["sessionid"] = sessionid
        result["base64"] = False
        result["data"] = {}
        dataerreur["action"] = action
        dataerreur["data"]["msg"] = "ERROR : %s" % action
        dataerreur["sessionid"] = sessionid
        try:
            response = func(
                objetxmpp, action, sessionid, data, message, dataerreur, result
            )

            if "end" not in result["data"]:
                result["data"]["end"] = False

            print("----------------------------------------------------------------")
            print("sent message to %s " % message["from"])
            if "Devent" in data:
                print("Devent : %s" % data["Devent"])
            if "Dtypequery" in data:
                print("Dtypequery : %s" % data["Dtypequery"])
            if "Deventindex" in data:
                print("Deventindex : %s" % data["Deventindex"])

            if not result["data"]["end"]:
                print("Envoi Message")
                print("result", result)
                if result["base64"] is True:
                    result["data"] = base64.b64encode(json.dumps(result["data"]))
                objetxmpp.send_message(
                    mto=message["from"], mbody=json.dumps(result), mtype="chat"
                )
            else:
                print("envoi pas de message")
        except BaseException:
            if not result["data"]["end"]:
                print("Send error message")
                print("result", dataerreur)
                objetxmpp.send_message(
                    mto=message["from"], mbody=json.dumps(dataerreur), mtype="chat"
                )
            else:
                print("Envoi pas de Message erreur")
            return
        print("---------------------------------------------------------------")
        return response

    return wrapper


# determine address ip utiliser pour xmpp


def getIpXmppInterface(ipadress1, Port):
    resultip = ""
    ipadress = ipfromdns(ipadress1)
    if sys.platform.startswith("linux"):
        logging.log(DEBUGPULSE, "Searching for the XMPP Server IP Adress")
        print(
            "netstat -an |grep %s |grep %s| grep ESTABLISHED | grep -v tcp6"
            % (Port, ipadress)
        )
        obj = simplecommand(
            "netstat -an |grep %s |grep %s| grep ESTABLISHED | grep -v tcp6"
            % (Port, ipadress)
        )
        logging.log(
            DEBUGPULSE,
            "netstat -an |grep %s |grep %s| grep ESTABLISHED | grep -v tcp6"
            % (Port, ipadress),
        )
        if obj["code"] != 0:
            logging.getLogger().error("error command netstat : %s" % obj["result"])
            logging.getLogger().error("error install package net-tools")
        if len(obj["result"]) != 0:
            for i in range(len(obj["result"])):
                obj["result"][i] = obj["result"][i].rstrip("\n")
            a = "\n".join(obj["result"])
            b = [x for x in a.split(" ") if x != ""]
            if len(b) != 0:
                resultip = b[3].split(":")[0]
    elif sys.platform.startswith("win"):
        logging.log(DEBUGPULSE, "Searching for the XMPP Server IP Adress")
        print("netstat -an | findstr %s | findstr ESTABLISHED" % Port)
        obj = simplecommand("netstat -an | findstr %s | findstr ESTABLISHED" % Port)
        logging.log(DEBUGPULSE, "netstat -an | findstr %s | findstr ESTABLISHED" % Port)
        if len(obj["result"]) != 0:
            for i in range(len(obj["result"])):
                obj["result"][i] = obj["result"][i].rstrip("\n")
            a = "\n".join(obj["result"])
            b = [x for x in a.split(" ") if x != ""]
            if len(b) != 0:
                resultip = b[1].split(":")[0]
    elif sys.platform.startswith("darwin"):
        logging.log(DEBUGPULSE, "Searching for the XMPP Server IP Adress")
        print("netstat -an |grep %s |grep %s| grep ESTABLISHED" % (Port, ipadress))
        obj = simplecommand(
            "netstat -an |grep %s |grep %s| grep ESTABLISHED" % (Port, ipadress)
        )
        logging.log(
            DEBUGPULSE,
            "netstat -an |grep %s |grep %s| grep ESTABLISHED" % (Port, ipadress),
        )
        if len(obj["result"]) != 0:
            for i in range(len(obj["result"])):
                obj["result"][i] = obj["result"][i].rstrip("\n")
            a = "\n".join(obj["result"])
            b = [x for x in a.split(" ") if x != ""]
            if len(b) != 0:
                resultip = b[3][: b[3].rfind(".")]
    else:
        obj = simplecommand("netstat -a | grep %s | grep ESTABLISHED" % Port)
        if len(obj["result"]) != 0:
            for i in range(len(obj["result"])):
                obj["result"][i] = obj["result"][i].rstrip("\n")
            a = "\n".join(obj["result"])
            b = [x for x in a.split(" ") if x != ""]
            if len(b) != 0:
                resultip = b[1].split(":")[0]
    return resultip


# 3 functions used for subnet network


def ipV4toDecimal(ipv4):
    d = ipv4.split(".")
    return (
        (int(d[0]) * 256 * 256 * 256)
        + (int(d[1]) * 256 * 256)
        + (int(d[2]) * 256)
        + int(d[3])
    )


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


def subnet_address(address, maskvalue):
    addr = [int(x) for x in address.split(".")]
    mask = [int(x) for x in maskvalue.split(".")]
    subnet = [addr[i] & mask[i] for i in range(4)]
    broadcast = [(addr[i] & mask[i]) | (255 ^ mask[i]) for i in range(4)]
    return ".".join([str(x) for x in subnet]), ".".join([str(x) for x in broadcast])


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
            objsessiondata = objetxmpp.session.sessionfromsessiondata(sessionid)
        else:
            objsessiondata = None
        response = func(
            objetxmpp, action, sessionid, data, message, ret, objsessiondata
        )
        return response

    return wrapper


def pulginmastersessionaction(sessionaction, timeminute=10):
    def decorateur(func):
        def wrapper(objetxmpp, action, sessionid, data, message, ret, dataobj):
            if action.startswith("result"):
                action = action[6:]
            if objetxmpp.session.isexist(sessionid):
                if sessionaction == "actualise":
                    objetxmpp.session.reactualisesession(sessionid, 10)
                objsessiondata = objetxmpp.session.sessionfromsessiondata(sessionid)
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
                objsessiondata,
            )
            if sessionaction == "clear" and objsessiondata is not None:
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
    column = [x.strip() for x in result.split(" ") if x != ""]
    return column[-2:-1][0].split(":")[1]


def ipfromdns(name_domaine_or_ip):
    """This function converts a dns to ipv4
    If not find return ""
    function tester on OS:
    MAcOs, linux (debian, redhat, ubuntu), windows
    eg : print ipfromdns("sfr.fr")
    80.125.163.172
    """
    if name_domaine_or_ip != "" and name_domaine_or_ip is not None:
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
    """This function check if socket valid for connection
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


if sys.platform.startswith("win"):

    def set_reg(name, value, subkey, key=wr.HKEY_LOCAL_MACHINE, type=wr.REG_SZ):
        try:
            wr.CreateKey(key, subkey)
            registry_key = wr.OpenKey(wr.HKEY_CURRENT_USER, subkey, 0, wr.KEY_WRITE)
            wr.SetValueEx(registry_key, name, 0, type, value)
            wr.CloseKey(registry_key)
            return True
        except WindowsError:  # skipcq: PYL-E0602
            return False

    def get_reg(name, subkey, key=wr.HKEY_LOCAL_MACHINE):
        try:
            registry_key = wr.OpenKey(key, subkey, 0, wr.KEY_READ)
            value, regtype = wr.QueryValueEx(registry_key, name)
            wr.CloseKey(registry_key)
            return value
        except WindowsError:  # skipcq: PYL-E0602
            return None


def shutdown_command(time=0, msg=""):
    """
    This  function allow to shutdown a machine, and if needed
    to display a message

    Args:
        time: the delay before the shutdown
        msg:  the message that will be displayed

    """
    if sys.platform.startswith("linux"):
        if int(time) == 0 or msg == "":
            cmd = "shutdown now"
        else:
            cmd = "shutdown -P -f -t %s %s" % (time, msg)
            logging.debug(cmd)
            os.system(cmd)
    elif sys.platform.startswith("win"):
        if int(time) == 0 or msg == "":
            cmd = "shutdown /p"
        else:
            cmd = "shutdown /s /t %s /c %s" % (time, msg)
            logging.debug(cmd)
            os.system(cmd)
    elif sys.platform.startswith("darwin"):
        if int(time) == 0 or msg == "":
            cmd = "shutdown -h now"
        else:
            cmd = 'shutdown -h +%s "%s"' % (time, msg)
            logging.debug(cmd)
            os.system(cmd)


def vnc_set_permission(askpermission=1):
    """
    This function allows to change the setting of VNC to ask for
    permission from user before connecting to Windows machines

    Args:
        askpermission: 0 or 1

    """
    if sys.platform.startswith("linux"):
        pass
    elif sys.platform.startswith("win"):
        if askpermission == 0:
            cmd = 'reg add "HKLM\SOFTWARE\TightVNC\Server" /f /v QueryAcceptOnTimeout /t REG_DWORD /d 1 && reg add "HKLM\SOFTWARE\TightVNC\Server" /f /v QueryTimeout /t REG_DWORD /d 1 && net stop tvnserver && net start tvnserver'
        else:
            cmd = 'reg add "HKLM\SOFTWARE\TightVNC\Server" /f /v QueryAcceptOnTimeout /t REG_DWORD /d 0 && reg add "HKLM\SOFTWARE\TightVNC\Server" /f /v QueryTimeout /t REG_DWORD /d 20 && net stop tvnserver && net start tvnserver'
        logging.debug(cmd)
        os.system(cmd)
    elif sys.platform.startswith("darwin"):
        pass


def reboot_command():
    """
    This function allow to reboot a machine.
    """
    if sys.platform.startswith("linux"):
        os.system("shutdown -r now")
    elif sys.platform.startswith("win"):
        os.system("shutdown /r")
    elif sys.platform.startswith("darwin"):
        os.system("shutdown -r now")


def isBase64(s):
    try:
        if base64.b64encode(base64.b64decode(s)) == s:
            return True
    except Exception:
        pass
    return False


def decode_strconsole(x):
    """
    Decode strings into the format used on the OS.
    Supported OS are: linux, windows and darwin

    Args:
        x: the string we want to encode

    Returns:
        The decoded `x` string
    """
    if sys.platform.startswith("linux"):
        return x.decode("utf-8", "ignore")

    if sys.platform.startswith("win"):
        return x.decode("cp850", "ignore")

    if sys.platform.startswith("darwin"):
        return x.decode("utf-8", "ignore")

    return x


def encode_strconsole(x):
    """
    Encode strings into the format used on the OS.
    Supported OS are: linux, windows and darwin

    Args:
        x: the string we want to encode

    Returns:
        The encoded `x` string
    """

    if sys.platform.startswith("linux"):
        return x.encode("utf-8")

    if sys.platform.startswith("win"):
        return x.encode("cp850")

    if sys.platform.startswith("darwin"):
        return x.encode("utf-8")

    return x


def savejsonfile(filename, data, indent=4):
    with open(filename, "w") as outfile:
        json.dump(data, outfile)


def loadjsonfile(filename):
    if os.path.isfile(filename):
        with open(filename, "r") as info:
            dd = info.read()
        try:
            return json.loads(decode_strconsole(dd))
        except Exception as e:
            logger.error("filename %s error decodage [%s]" % (filename, str(e)))
    return None


def save_user_current(name=None):
    loginuser = os.path.join(Setdirectorytempinfo(), "loginuser")
    if name is None:
        userlist = list(set([users[0] for users in psutil.users()]))
        if len(userlist) > 0:
            name = userlist[0]
    else:
        name = "system"

    if not os.path.exists(loginuser):
        result = {name: 1, "suite": [name], "curent": name}
        savejsonfile(loginuser, result)
        return result["curent"]

    datauseruser = loadjsonfile(loginuser)
    if name in datauseruser:
        datauseruser[name] = datauseruser[name] + 1
        datauseruser["suite"].insert(0, name)
    else:
        datauseruser[name] = 1

    datauseruser["suite"].insert(0, name)
    datauseruser["suite"] = datauseruser["suite"][0:15]

    element = set(datauseruser["suite"])
    max = 0
    for t in element:
        valcount = datauseruser["suite"].count(t)
        if valcount > max:
            datauseruser["curent"] = t
    savejsonfile(loginuser, datauseruser)
    return datauseruser["curent"]


def test_kiosk_presence():
    """
    Test if the kiosk is installed in the machine.

    Returns:
        True if the directory is found, False otherwise
    """

    def _get_kiosk_path():
        """This private function find the path for the python3 install.
        If no installation is found the the function returns  None.
        Returns:
            string: the path of python3/site-packages
            or
            None if no path is founded"""
        list = []
        if sys.platform.startswith("win"):
            list = [
                os.path.join(
                    os.environ["ProgramFiles"], "Python36", "Lib", "site-packages"
                ),
                os.path.join(
                    os.environ["ProgramFiles"], "Python36-32", "Lib", "site-packages"
                ),
            ]
        elif sys.platform == "darwin":
            list = ["usr", "local", "lib", "python3.6", "dist-packages"]
        elif sys.platform == "linux":
            list = [
                "usr",
                "lib",
                "python3.6",
                "dist-packages",
                "usr",
                "lib",
                "python3.5",
                "dist-packages",
            ]

        for element in list:
            if os.path.isdir(element):
                return element
        return None

    path = _get_kiosk_path()
    if path is not None and os.path.isdir(os.path.join(path, "kiosk_interface")):
        return "True"
    else:
        return "False"


def utc2local(utc):
    """
    utc2local transform a utc datetime object to local object.

    Param:
        utc: datetime which is not naive (the utc timezone must be precised)
    Return:
        datetime in local timezone
    """
    epoch = time.mktime(utc.timetuple())
    offset = datetime.fromtimestamp(epoch) - datetime.utcfromtimestamp(epoch)
    return utc + offset


def data_struct_message(action, data={}, ret=0, base64=False, sessionid=None):
    if sessionid is None or sessionid == "" or not isinstance(sessionid, str):
        sessionid = action.strip().replace(" ", "")
    return {
        "action": action,
        "data": data,
        "ret": 0,
        "base64": False,
        "sessionid": getRandomName(4, sessionid),
    }


def add_method(cls):
    """decorateur a utiliser pour ajouter une methode a un object"""

    def decorator(func):
        @wraps(func)
        def wrapper(self, *args, **kwargs):
            return func(*args, **kwargs)

        setattr(cls, func.__name__, wrapper)
        # Note we are not binding func, but wrapper which accepts self but does exactly the same as func
        return func  # returning func means func can still be used normally

    return decorator


def is_findHostfromHostname(hostname):
    try:
        host = socket.gethostbyname(hostname)
        return True
    except Exception:
        pass
    return False


def is_findHostfromIp(ip):
    try:
        host = socket.gethostbyaddr(ip)
        return True
    except Exception:
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


class AESCipher:
    def __init__(self, key, BS=32):
        if isinstance(key, str):
            self.key = key.encode("utf-8")
        else:
            self.key = key  # self.key is bytes

        self.BS = BS

    def _bchr(self, s):
        return bytes([s])

    def bord(self, s):
        return s

    def pad(self, data_to_pad):
        padding_len = self.BS - len(data_to_pad) % self.BS
        padding = self._bchr(padding_len) * padding_len
        return data_to_pad + padding

    def encrypt_base64_byte(self, raw):
        if isinstance(raw, str):
            raw = raw.encode("utf-8")
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        result = iv + cipher.encrypt(self.pad(raw))
        return base64.b64encode(result)

    def encrypt(self, raw):
        return self.encrypt_base64_byte(raw).decode("utf-8")

    def decrypt(self, enc):
        if isinstance(enc, str):
            enc = enc.encode("utf-8")
        enc = base64.b64decode(enc)
        iv = enc[: AES.block_size]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return self._unpad(cipher.decrypt(enc[AES.block_size :]))

    def decrypt_base64_byte(self, enc):
        return self.decrypt_base64_str(enc).encode("utf-8")

    def _unpad(self, s):
        dtrdata = s[: -ord(s[len(s) - 1 :])]
        return dtrdata.decode("utf-8")


def sshdup():
    if sys.platform.startswith("linux"):
        # verify sshd up
        cmd = "ps aux | grep sshd | grep -v grep | grep -v pts"
        result = simplecommand(cmd)
        if result["code"] == 0:
            return True
        return False
    if sys.platform.startswith("darwin"):
        cmd = "launchctl list com.openssh.sshd"
        result = simplecommand(cmd)
        if result["code"] == 0:
            return True
        return False
    if sys.platform.startswith("win"):
        cmd = "TASKLIST | FINDSTR sshd"
        result = simplecommand(cmd)
        if len(result["result"]) > 0:
            return True
    return False


def restartsshd():
    if sys.platform.startswith("linux"):
        # verify sshd up
        if not sshdup():
            cmd = "systemctrl restart sshd"
            result = simplecommand(cmd)
    if sys.platform.startswith("darwin"):
        if not sshdup():
            cmd = "launchctl restart /System/Library/LaunchDaemons/ssh.plist"
            result = simplecommand(cmd)
    if sys.platform.startswith("win"):
        if not sshdup():
            # on cherche le nom reel du service pour sshd.
            cmd = 'sc query state= all | findstr "sshd" | findstr "SERVICE_NAME"'
            result = simplecommand(cmd)
            if len(result["result"]) > 0:
                try:
                    nameservice = result["result"][0].split()[1]
                    # restart service windows.
                    cmd = 'sc start "%s"' % nameservice
                    result = simplecommand(cmd)
                except Exception:
                    pass


def make_tarfile(output_file_gz_bz2, source_dir, compresstype="gz"):
    """
    creation archive tar.gz or tat.bz2
    compresstype "gz" or "bz2"
    """
    try:
        with tarfile.open(output_file_gz_bz2, "w:%s" % compresstype) as tar:
            tar.add(source_dir, arcname=os.path.basename(source_dir))
        return True
    except Exception as e:
        logger.error("error create archive tar.%s %s" % (str(e), compresstype))
        return False


def extract_file(imput_file__gz_bz2, to_directory=".", compresstype="gz"):
    """
    extract archive tar.gz or tat.bz2
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
        logger.error("error extract tar.%s %s" % (str(e), compresstype))
        return False
    except Exception as e:
        logger.error("error extract tar.%s %s" % (str(e), compresstype))
        return False
    finally:
        os.chdir(cwd)
    return True


def find_files(directory, pattern):
    """ """
    for root, dirs, files in os.walk(directory):
        for basename in files:
            if fnmatch.fnmatch(basename, pattern):
                filename = str(os.path.join(root, basename))
                yield filename


def listfile(directory, abspath=True):
    fileList = []
    for root, dirs, files in os.walk(directory):
        for basename in files:
            if abspath:
                fileList.append(os.path.join(root, basename))
            else:
                fileList.append(os.path.join(basename))
    return fileList


def md5folder(directory):
    hash = hashlib.md5()
    strmdr = []
    for root, dirs, files in os.walk(directory):
        for basename in files:
            hash.update(md5(os.path.join(root, basename)))
    return hash.hexdigest()


class protodef:
    def __init__(self):
        self.fileprotoinfo = os.path.join(Setdirectorytempinfo(), "fingerprintproto")
        self.boolchangerproto, self.proto = self.protochanged()

    def protoinfoexist(self):
        if os.path.exists(self.fileprotoinfo):
            return True
        return False

    def protochanged(self):
        if self.protoinfoexist():
            fproto = protodef.protoandport()
            self.fingerprintproto = file_get_contents(self.fileprotoinfo)
            newfingerprint = pickle.dumps(fproto)  # on recalcule le proto
            if self.fingerprintproto == newfingerprint:
                self.proto = fproto
                return False, self.proto
        self.refreshfingerprintproto()
        self.fingerprintproto = file_get_contents(self.fileprotoinfo)
        self.proto = pickle.loads(self.fingerprintproto)
        return True, self.proto

    def refreshfingerprintproto(self):
        fproto = protodef.protoandport()
        with open(self.fileprotoinfo, "wb") as handle:
            pickle.dump(fproto, handle)
        return fproto

    @staticmethod
    def protoandport():
        protport = {}
        if sys.platform.startswith("win"):
            for process in psutil.process_iter():
                if "tvnserver.exe" in process.name():
                    process_handler = psutil.Process(process.pid)
                    for cux in process_handler.connections():
                        if cux.status == psutil.CONN_LISTEN:
                            protport["vnc"] = cux.laddr.port
                elif "sshd.exe" in process.name():
                    process_handler = psutil.Process(process.pid)
                    for cux in process_handler.connections():
                        if cux.status == psutil.CONN_LISTEN:
                            protport["ssh"] = cux.laddr.port
            for services in psutil.win_service_iter():
                if "TermService" in services.name():
                    service_handler = psutil.win_service_get("TermService")
                    if service_handler.status() == "running":
                        pid = service_handler.pid()
                        process_handler = psutil.Process(pid)
                        for cux in process_handler.connections():
                            if cux.status == psutil.CONN_LISTEN:
                                protport["rdp"] = cux.laddr.port

        elif sys.platform.startswith("linux"):
            for process in psutil.process_iter():
                if process.name() == "x11vnc":
                    process_handler = psutil.Process(process.pid)
                    for cux in process_handler.connections():
                        try:
                            ip = cux.laddr[0]
                            port = cux.laddr[1]
                        except Exception:
                            ip = cux.laddr.ip
                            port = cux.laddr.port
                        if cux.status == psutil.CONN_LISTEN and ip == "0.0.0.0":
                            protport["vnc"] = port
                elif process.name() == "sshd":
                    process_handler = psutil.Process(process.pid)
                    for cux in process_handler.connections():
                        try:
                            ip = cux.laddr[0]
                            port = cux.laddr[1]
                        except Exception:
                            ip = cux.laddr.ip
                            port = cux.laddr.port
                        if cux.status == psutil.CONN_LISTEN and ip == "0.0.0.0":
                            protport["ssh"] = port
                elif process.name() == "xrdp":
                    process_handler = psutil.Process(process.pid)
                    for cux in process_handler.connections():
                        try:
                            ip = cux.laddr[0]
                            port = cux.laddr[1]
                        except Exception:
                            ip = cux.laddr.ip
                            port = cux.laddr.port
                        if cux.status == psutil.CONN_LISTEN and (
                            ip == "0.0.0.0" or ip == "::"
                        ):
                            protport["rdp"] = port

        elif sys.platform.startswith("darwin"):
            for process in psutil.process_iter():
                if "ARDAgent" in process.name():
                    protport["vnc"] = "5900"
            for cux in psutil.net_connections():
                if cux.laddr.port == 22 and cux.status == psutil.CONN_LISTEN:
                    protport["ssh"] = "22"

        return protport


def protoandport():
    return protodef.protoandport()


def pulseuser_useraccount_mustexist(username="pulseuser"):
    """
    This function checks if the a given user exists.
    Args:
        username: This is the username we need to check ( default is pulseuser )

    Returns:
        It returns True if the account has been correctly created or if the
        account already exists, it return False otherwise.
    """
    if sys.platform.startswith("linux"):
        try:
            uid = pwd.getpwnam(username).pw_uid
            gid = grp.getgrnam(username).gr_gid
            msg = "%s user account already exists. Nothing to do." % username
            return True, msg
        except Exception:
            adduser_cmd = (
                "adduser --system --quiet --group "
                "--home /var/lib/pulse2 --shell /bin/rbash "
                "--disabled-password %s" % username
            )
    elif sys.platform.startswith("win"):
        try:
            win32net.NetUserGetInfo("", username, 0)
            msg = "%s user account already exists. Nothing to do." % username
            return True, msg
        except Exception:
            passwdchars = string.hexdigits + "-" + "$" + "#" + "," + "_"
            userpassword = "".join(random.sample(list(passwdchars), 14))
            adduser_cmd = (
                'net user "%s" "%s" /ADD /COMMENT:"Pulse '
                'user with admin rights on the system"' % (username, userpassword)
            )
    elif sys.platform.startswith("darwin"):
        try:
            uid = pwd.getpwnam(username).pw_uid
            gid = grp.getgrnam(username).gr_gid
            msg = "%s user account already exists. Nothing to do." % username
            return True, msg
        except Exception:
            passwdchars = string.hexdigits + "-" + "$" + "#" + "," + "_"
            userpassword = "".join(random.sample(list(passwdchars), 14))
            adduser_cmd = (
                "dscl . -create /Users/%s "
                "UserShell /usr/local/bin/rbash && "
                "dscl . -passwd /Users/%s %s" % (username, username, userpassword)
            )
    # Create the account
    result = simplecommand(encode_strconsole(adduser_cmd))
    if result["code"] == 0:
        msg = "Creation of %s user account successful: %s" % (username, result)
        # Other operations specific to Windows
        if sys.platform.startswith("win"):
            result = simplecommand(
                encode_strconsole(
                    "wmic useraccount where \"Name='%s'\" set PasswordExpires=False"
                    % username
                )
            )
            if result["code"] != 0:
                msg = "Error setting %s user account to not expire: %s" % (
                    username,
                    result,
                )
                return False, msg
            adminsgrpsid = win32security.ConvertStringSidToSid("S-1-5-32-544")
            adminsgroup = win32security.LookupAccountSid("", adminsgrpsid)[0]
            result = simplecommand(
                encode_strconsole(
                    'net localgroup %s "%s" /ADD' % (adminsgroup, username)
                )
            )
            if result["code"] != 0:
                msg = "Error adding %s account to administrators group: %s" % (
                    username,
                    result,
                )
                return False, msg
            result = simplecommand(
                encode_strconsole(
                    'REG ADD "HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\SpecialAccounts\\UserList" /v "%s" /t REG_DWORD /d 0 /f'
                    % username
                )
            )
            if result["code"] != 0:
                msg = "Error hiding %s account: %s" % (username, result)
                return False, msg
        return True, msg
    else:
        msg = "Creation of %s user account failed: %s" % (username, result)
        return False, msg


def pulseuser_profile_mustexist(username="pulseuser"):
    """
    This function checks if the a given profile exists.
    Args:
        username: This is the username we need to check ( default is pulseuser )

    Returns:
        It returns True if the profile has been correctly created or if the
        profile already exists, it return False otherwise.
    """
    if sys.platform.startswith("win"):
        # Initialise userenv.dll
        userenvdll = ctypes.WinDLL("userenv.dll")
        # Define profile path that is needed
        defined_profilepath = os.path.normpath("C:/Users/%s" % username).strip()
        # Get user profile as created on the machine
        profile_location = os.path.normpath(get_user_profile(username)).strip()
        if not profile_location or profile_location != defined_profilepath:
            # Delete all profiles if found
            delete_profile(username)
            # Create the profile
            usersid = get_user_sid(username)
            ptr_profilepath = ctypes.create_unicode_buffer(260)
            userenvdll.CreateProfile(
                LPCWSTR(usersid), LPCWSTR(username), ptr_profilepath, 240
            )
            if os.path.normpath(ptr_profilepath.value).strip() == defined_profilepath:
                msg = "%s profile created successfully at %s" % (
                    username,
                    ptr_profilepath.value,
                )
                return True, msg
            else:
                msg = "Error creating %s profile at %s" % (
                    username,
                    ptr_profilepath.value,
                )
                return False, msg
        else:
            # Profile found
            msg = "%s profile already exists at %s. Nothing to do." % (
                username,
                profile_location,
            )
            return True, msg
    elif sys.platform.startswith("linux"):
        try:
            uid = pwd.getpwnam(username).pw_uid
            gid = grp.getgrnam(username).gr_gid
            homedir = os.path.expanduser(username)
        except Exception as e:
            msg = (
                "Error getting information for creating home folder for user %s"
                % username
            )
            return False, msg
        if not os.path.isdir(homedir):
            os.makedirs(homedir, 0o751)
        os.chmod(homedir, 0o751)
        os.chown(homedir, uid, gid)
        packagedir = os.path.join(homedir, "packages")
        if not os.path.isdir(packagedir):
            os.makedirs(packagedir, 0o764)
        gidroot = grp.getgrnam("root").gr_gid
        os.chmod(packagedir, 0o764)
        os.chown(packagedir, uid, gidroot)
        msg = "%s profile created successfully at %s" % (username, homedir)
        return True, msg
    elif sys.platform.startswith("darwin"):
        try:
            uid = pwd.getpwnam(username).pw_uid
            gid = grp.getgrnam(username).gr_gid
            homedir = os.path.expanduser(username)
        except Exception as e:
            msg = (
                "Error getting information for creating home folder for user %s"
                % username
            )
            return False, msg
        if not os.path.isdir(homedir):
            os.makedirs(homedir, 0o751)
        os.chmod(homedir, 0o751)
        os.chown(homedir, uid, gid)
        packagedir = os.path.join(homedir, "packages")
        if not os.path.isdir(packagedir):
            os.makedirs(packagedir, 0o764)
        gidroot = grp.getgrnam("root").gr_gid
        os.chmod(packagedir, 0o764)
        os.chown(packagedir, uid, gidroot)
        msg = "%s profile created successfully at %s" % (username, homedir)
        return True, msg


def get_user_profile(username="pulseuser"):
    usersid = get_user_sid(username)
    if not usersid:
        return ""
    check_profile_cmd = (
        'powershell "Get-ItemProperty '
        "-Path 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList\*' "
        "| Where-Object { $_.PSChildName -eq '%s' } "
        '| Select -ExpandProperty ProfileImagePath"' % usersid
    )
    result = simplecommand(encode_strconsole(check_profile_cmd))
    if result["code"] == 0 and result["result"]:
        return result["result"][0]

    return ""


def get_user_sid(username="pulseuser"):
    try:
        usersid = win32security.ConvertSidToStringSid(
            win32security.LookupAccountName(None, username)[0]
        )
        return usersid
    except Exception as e:
        return False


def delete_profile(username="pulseuser"):
    if sys.platform.startswith("win"):
        # Delete profile folder in C:\\Users if any
        try:
            for name in os.listdir("C:/Users/"):
                if name.startswith(username):
                    delete_folder_cmd = 'rd /s /q "C:\\Users\\%s" ' % name
                    result = simplecommand(encode_strconsole(delete_folder_cmd))
                    if result["code"] == 0:
                        logger.debug(
                            "Deleted %s folder" % os.path.join("C:/Users/", name)
                        )
                    else:
                        logger.debug(
                            "Error deleting %s folder" % os.path.join("C:/Users/", name)
                        )
        except Exception as e:
            pass
        # Delete profile
        userenvdll = ctypes.WinDLL("userenv.dll")
        usersid = get_user_sid(username)
        delete_profile_result = userenvdll.DeleteProfileA(LPCSTR(usersid))
        if delete_profile_result == 0:
            logger.debug("%s profile deleted." % username)
        else:
            logger.debug(
                "Error deleting %s profile: %s" % (username, delete_profile_result)
            )
    return True


def create_idrsa_on_client(username="pulseuser", key=""):
    """
    Used on client machine for connecting to relay server
    """
    if sys.platform.startswith("win"):
        id_rsa_path = os.path.join("C:\\Users", username, ".ssh", "id_rsa")
    else:
        id_rsa_path = os.path.join(
            os.path.expanduser("~%s" % username), ".ssh", "id_rsa"
        )
    delete_keyfile_cmd = 'del /f /q "%s" ' % id_rsa_path
    result = simplecommand(encode_strconsole(delete_keyfile_cmd))
    logger.debug("Creating id_rsa file in %s" % id_rsa_path)
    if not os.path.isdir(os.path.dirname(id_rsa_path)):
        os.makedirs(os.path.dirname(id_rsa_path), 0o700)
    file_put_contents(id_rsa_path, key)
    result, logs = apply_perms_sshkey(id_rsa_path, True)
    if result is False:
        return False, logs
    msg = "Key %s successfully created" % id_rsa_path
    return True, msg


def apply_perms_sshkey(path, private=True):
    """
    Apply permissions on ssh key.
    If private = True, the permissions are based on the user that is executing Pulse Agent
    If private = False, the permissions are based on pulseuser
    """
    if not os.path.isfile(path):
        msg = "Error: File %s does not exist" % path
        return False, msg
    if sys.platform.startswith("win"):
        if private is True:
            # We are using id_rsa. The owner must be the user running the Agent
            username = win32api.GetUserName().lower()
        else:
            # The owner must be pulseuser
            username = "pulseuser"
        try:
            sd = win32security.GetFileSecurity(
                path, win32security.DACL_SECURITY_INFORMATION
            )
            dacl = win32security.ACL()
            user, domain, type = win32security.LookupAccountName("", username)
            dacl.AddAccessAllowedAce(
                win32security.ACL_REVISION, ntsecuritycon.FILE_ALL_ACCESS, user
            )
            sd.SetSecurityDescriptorDacl(1, dacl, 0)
            win32security.SetFileSecurity(
                path, win32security.DACL_SECURITY_INFORMATION, sd
            )
            if private is False:
                user, domain, type = win32security.LookupAccountName("", "system")
                dacl.AddAccessAllowedAce(
                    win32security.ACL_REVISION, ntsecuritycon.FILE_ALL_ACCESS, user
                )
                sd.SetSecurityDescriptorDacl(1, dacl, 0)
                win32security.SetFileSecurity(
                    path, win32security.DACL_SECURITY_INFORMATION, sd
                )
        except Exception as e:
            msg = "Error setting permissions on %s for user %s: %s" % (
                path,
                user,
                str(e),
            )
            return False, msg
    else:
        if private is True:
            # We are using id_rsa. The owner must be the user running the Agent
            uid = os.geteuid()
            gid = os.getegid()
        else:
            # The owner must be pulseuser
            username = "pulseuser"
            uid = pwd.getpwnam(username).pw_uid
            gid = grp.getgrnam(username).gr_gid
        try:
            os.chown(os.path.dirname(path), uid, gid)
            os.chown(path, uid, gid)
            os.chmod(os.path.dirname(path), 0o700)
            os.chmod(path, 0o600)
        except Exception as e:
            msg = "Error setting permissions on %s for user %s: %s" % (
                path,
                pwd.getpwuid(uid).pw_name,
                str(e),
            )
            return False, msg
    if sys.platform.startswith("win"):
        list_perms_cmd = (
            'powershell "(get-acl %s).access '
            '| ft IdentityReference,FileSystemRights,AccessControlType"' % path
        )
    elif sys.platform.startswith("linux"):
        list_perms_cmd = "getfacl %s" % path
    elif sys.platform.startswith("darwin"):
        list_perms_cmd = "ls -e -l %s" % path
    result = simplecommand(encode_strconsole(list_perms_cmd))
    logger.debug("Permissions on file %s:" % path)
    logger.debug("%s" % "".join(result["result"]))
    msg = "Success applying permissions to file %s" % path
    return True, msg


def add_key_to_authorizedkeys_on_client(username="pulseuser", key=""):
    """
    Used on client machine for allowing connections from relay server

    Args:
        username: username where the key is copied to
        key:      the ssh key copied in the authorized_keys file

    Returns:
        message sent telling if the key have been well copied or not.
    """
    if sys.platform.startswith("win"):
        authorized_keys_path = os.path.join(
            "C:\\Users", username, ".ssh", "authorized_keys"
        )
    else:
        authorized_keys_path = os.path.join(
            os.path.expanduser("~%s" % username), ".ssh", "authorized_keys"
        )
    if not os.path.isfile(authorized_keys_path):
        logger.debug("Creating authorized_keys file in %s" % authorized_keys_path)
        if not os.path.isdir(os.path.dirname(authorized_keys_path)):
            os.makedirs(os.path.dirname(authorized_keys_path), 0o700)
        file_put_contents(authorized_keys_path, key)
    else:
        authorized_keys_content = file_get_contents(authorized_keys_path)
        if not key.strip(" \t\n\r") in authorized_keys_content:
            logger.debug("Adding key to %s" % authorized_keys_path)
            file_put_contents_w_a(authorized_keys_path, "\n" + key, "a")
        else:
            logger.debug("Key is already present in %s" % authorized_keys_path)
    # Check if key is present
    authorized_keys_content = file_get_contents(authorized_keys_path)
    if key.strip(" \t\n\r") in authorized_keys_content:
        msg = "Key successfully present in %s" % authorized_keys_path
        result, logs = apply_perms_sshkey(authorized_keys_path, False)
        if result is False:
            return False, logs
        return True, msg
    # Function didn't return earlier, meaning the key is not present
    msg = "Error add key to authorizedkeys id_rsa missing"
    return False, msg


def reversessh_useraccount_mustexist_on_relay(username="reversessh"):
    try:
        uid = pwd.getpwnam(username).pw_uid
        msg = "%s user account already exists. Nothing to do." % username
        return True, msg
    except Exception:
        adduser_cmd = (
            "adduser --system --quiet --group "
            "--home /var/lib/pulse2/clients/reversessh "
            "--shell /bin/rbash --disabled-password %s" % username
        )
    result = simplecommand(encode_strconsole(adduser_cmd))
    if result["code"] == 0:
        msg = "Creation of %s user account successful: %s" % (username, result)
        return True, msg

    msg = "Creation of %s user account failed: %s" % (username, result)
    return False, msg


def reversessh_keys_mustexist_on_relay(username="reversessh"):
    try:
        uid = pwd.getpwnam(username).pw_uid
        homedir = os.path.expanduser(username)
    except Exception as e:
        msg = (
            "Error getting information for creating home folder for user %s" % username
        )
        return False, msg
    if not os.path.isdir(homedir):
        os.makedirs(homedir, 0o751)
    os.chmod(homedir, 0o751)
    os.chown(homedir, uid, -1)
    # Check keys
    id_rsa_key_path = os.path.join(
        os.path.expanduser("~%s" % username), ".ssh", "id_rsa"
    )
    public_key_path = os.path.join(
        os.path.expanduser("~%s" % username), ".ssh", "id_rsa.pub"
    )
    keycheck_cmd = "ssh-keygen -y -f %s > %s" % (id_rsa_key_path, public_key_path)
    result = simplecommand(encode_strconsole(keycheck_cmd))
    if result["code"] != 0:
        logger.debug("Creating id_rsa file in %s" % id_rsa_key_path)
        if not os.path.isdir(os.path.dirname(id_rsa_key_path)):
            os.makedirs(os.path.dirname(id_rsa_key_path), 0o700)
        keygen_cmd = 'ssh-keygen -q -N "" -b 2048 -t rsa -f %s' % id_rsa_key_path
        result = simplecommand(encode_strconsole(keygen_cmd))
    authorized_keys_path = os.path.join(
        os.path.expanduser("~%s" % username), ".ssh", "authorized_keys"
    )
    addtoauth_cmd = "ssh-keygen -y -f %s > %s" % (id_rsa_key_path, authorized_keys_path)
    simplecommand(encode_strconsole(addtoauth_cmd))
    os.chmod(os.path.dirname(id_rsa_key_path), 0o700)
    os.chown(os.path.dirname(id_rsa_key_path), uid, -1)
    os.chmod(id_rsa_key_path, 0o600)
    os.chown(id_rsa_key_path, uid, -1)
    os.chmod(public_key_path, 0o644)
    os.chown(public_key_path, uid, -1)
    os.chmod(authorized_keys_path, 0o600)
    os.chown(authorized_keys_path, uid, -1)
    return True, "Keys permissions applied on relay"


def get_relayserver_pubkey(username="root"):
    """
    returns relayserver's root public key
    """
    public_key_path = os.path.join(
        os.path.expanduser("~%s" % username), ".ssh", "id_rsa.pub"
    )
    return file_get_contents(public_key_path)


def get_relayserver_reversessh_idrsa(username="reversessh"):
    """
    returns relayserver's reversessh private key
    """
    idrsa_key_path = os.path.join(
        os.path.expanduser("~%s" % username), ".ssh", "id_rsa"
    )
    return file_get_contents(idrsa_key_path)


class geolocalisation_agent:
    def __init__(
        self,
        typeuser="public",
        geolocalisation=True,
        ip_public=None,
        strlistgeoserveur="",
    ):
        self.determination = False
        self.geolocalisation = geolocalisation
        self.ip_public = ip_public
        self.typeuser = typeuser
        self.filegeolocalisation = os.path.join(
            Setdirectorytempinfo(), "filegeolocalisation"
        )
        self.listgeoserver = [
            "http://%s/json" % x
            for x in re.split(
                r"[;,\[\(\]\)\{\}\:\=\+\*\\\?\/\#\+\&\-\$\|\s]", strlistgeoserveur
            )
            if x.strip() != ""
        ]
        self.localisation = None
        self.getgeolocalisation()
        if self.localisation is None:
            self.localisation = self.getdatafilegeolocalisation()

    def getgeolocalisationobject(self):
        if self.localisation is None:
            return {}
        return self.localisation

    def getdatafilegeolocalisation(self):
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
        if self.localisation is not None:
            try:
                with open(self.filegeolocalisation, "w") as json_data:
                    json.dump(self.localisation, json_data, indent=4)
                self.determination = True
            except Exception:
                pass

    def geoinfoexist(self):
        """
        This function is used to determine if the geolocalisation file is present.

        Returns:
            It returns True if the file exists, False otherwise
        """
        if os.path.exists(self.filegeolocalisation):
            return True
        return False

    def getgeolocalisation(self):
        """
        This function is used to obtain geolocalisationof the machine.
        If the machine has the type: public, nomade of both of if
        self.localisation is set to None, we search for geolocalisation
        each time.

        Returns:
            It returns the geolocalistion of the machine if any.
        """
        if self.geolocalisation:
            if (
                self.typeuser in ["public", "nomade", "both"]
                or self.localisation is None
            ):
                self.localisation = geolocalisation_agent.searchgeolocalisation(
                    self.listgeoserver
                )
                self.determination = True
                self.setdatafilegeolocalisation()
                return self.localisation

            if self.localisation is not None:
                if not self.geoinfoexist():
                    self.setdatafilegeolocalisation()
                    self.determination = False
                return self.localisation

            if not self.geoinfoexist():
                self.localisation = geolocalisation_agent.searchgeolocalisation(
                    self.listgeoserver
                )
                self.setdatafilegeolocalisation()
                self.determination = True
                return self.localisation

            return None

        if not self.geoinfoexist():
            self.localisation = geolocalisation_agent.searchgeolocalisation(
                self.listgeoserver
            )
            self.setdatafilegeolocalisation()
            self.determination = True
            return self.localisation

        return self.localisation

    def get_ip_public(self):
        if self.geolocalisation:
            if self.localisation is None:
                self.getgeolocalisation()
            if self.localisation is not None and is_valid_ipv4(self.localisation["ip"]):
                if not self.determination:
                    logger.warning("Determination use file")
                self.ip_public = self.localisation["ip"]
                return self.localisation["ip"]
            else:
                return None
        else:
            if not self.determination:
                logger.warning("use old determination ip_public")
            if self.localisation is None:
                if self.geoinfoexist():
                    logger.warning("coucou")
                    dd = self.getdatafilegeolocalisation()
                    logger.warning("%s" % dd)
                    if self.localisation is not None:
                        return self.localisation["ip"]
            else:
                return self.localisation["ip"]
        return self.ip_public

    @staticmethod
    def call_simple_page(url):
        try:
            r = requests.get(url)
            return r.json()
        except Exception:
            return None

    @staticmethod
    def call_simple_page_urllib(url):
        try:
            objip = json.loads(urllib.request.urlopen(url).read())
            return objip
        except Exception:
            return None

    @staticmethod
    def searchgeolocalisation(http_url_list_geo_server):
        """
        return objet
        """
        for url in http_url_list_geo_server:
            try:
                objip = geolocalisation_agent.call_simple_page(url)
                if objip is None:
                    raise
                return objip
            except BaseException:
                pass
        return None


def base64strencode(data):
    result = ""
    if sys.version_info[0] == 3:
        if isinstance(data, str):
            data = bytes(data, "utf-8")
    else:
        if isinstance(data, bytes):
            data = data.decode("utf-8")
    try:
        result = base64.b64encode(data)
        if sys.version_info[0] == 3:
            result = result.decode()
    except Exception as e:
        logger.error("error decode data in function base64strencode %s" % str(e))
    finally:
        return result


class Singleton(object):
    def __new__(type, *args):
        if "_the_instance" not in type.__dict__:
            type._the_instance = object.__new__(type)
        return type._the_instance


class base_message_queue_posix(Singleton):
    file_reponse_iq = []
    timeoutmessagequeue = 120

    def __init__(self):
        logger.debug("*** INITIALISATION base_message_queue_posix")
        logger.debug("*** charge %s" % base_message_queue_posix.file_reponse_iq)

    def _is_exist(self, name_file):
        for fmp in base_message_queue_posix.file_reponse_iq:
            if fmp["name"] == name_file:
                return True
        return False

    def _is_exist_file(self, name_file, prefixe=""):
        name_file = self._namefile(name_file, prefixe)
        logger.debug("verify exist %s _______" % os.listdir("/dev/mqueue/"))
        list_file_name_file = [
            "/" + x for x in os.listdir("/dev/mqueue/") if x.startswith(prefixe)
        ]
        logger.debug("verify exist  %s in %s" % (name_file, list_file_name_file))
        if name_file in list_file_name_file:
            return True
        return False

    def load_file(self, prefixe):
        deltatime = time.time()
        if os.path.isdir("/dev/mqueue/"):
            list_file_name_file = [
                "/" + x for x in os.listdir("/dev/mqueue/") if x.startswith(prefixe)
            ]
        for name_file in list_file_name_file:
            if not self._is_exist(name_file):
                try:
                    mp = posix_ipc.MessageQueue(name_file)
                    ob = {"obj": mp, "name": name_file, "time": deltatime}
                    base_message_queue_posix.file_reponse_iq.append(ob)
                except:
                    pass

    def _namefile(self, name_file, prefixe=""):
        if not name_file.startswith("/"):
            return "/" + prefixe + name_file
        else:
            return name_file

    def __rep__(self):
        try:
            rep = "list message queue for agent :\n%s" % json.dumps(
                base_message_queue_posix.file_reponse_iq
            )
        except:
            rep = "%s" % base_message_queue_posix.file_reponse_iq
        return rep

    def open_file_message(self, name_file, prefixe=""):
        name_file = self._namefile(name_file, prefixe)
        logger.debug("debug open_file_message : open message queue %s" % name_file)
        try:
            mp = posix_ipc.MessageQueue(name_file)
            logger.debug("ERROR")
        except posix_ipc.ExistentialError:
            pass
        except OSError as e:
            logger.error("ERROR CREATE QUEUE POSIX %s" % e)
            logger.error("eg : admin (/etc/security/limits.conf and  /etc/sysctl.conf")
        except Exception as e:
            logger.error("exception %s" % e)
            logger.error("\n%s" % (traceback.format_exc()))
        logger.debug("open message queue %s" % name_file)
        return self

    def create_file_message(
        self,
        name_file,
        prefixe="",
        preservation=False,
        max_message_size=2097152,
        max_messages=1,
    ):
        name_file = self._namefile(name_file, prefixe)
        try:
            mp = posix_ipc.MessageQueue(
                name_file, posix_ipc.O_CREX, max_message_size=max_message_size
            )
            logger.debug("creation/registred message queue %s" % name_file)
            base_message_queue_posix.file_reponse_iq.append(
                {
                    "obj": mp,
                    "name": name_file,
                    "time": -1 if preservation else time.time(),
                }
            )
        except posix_ipc.ExistentialError:
            mp = posix_ipc.MessageQueue(name_file)
            logger.debug("creation/open message queue %s" % name_file)
        except OSError as e:
            logger.error("ERROR CREATE QUEUE POSIX %s" % e)
            logger.error("eg : admin (/etc/security/limits.conf and  /etc/sysctl.conf")
        except Exception as e:
            logger.error("exception %s" % e)
            logger.error("\n%s" % (traceback.format_exc()))
        logger.debug("open message queue %s" % name_file)
        logger.debug("*** charge %s" % base_message_queue_posix.file_reponse_iq)
        return self

    def close_file_message(self, name_file, prefixe=""):
        name_file = self._namefile(name_file, prefixe)
        listqueue = []
        for fmp in base_message_queue_posix.file_reponse_iq:
            if fmp["name"] == name_file:
                try:
                    fmp["obj"].close()
                    posix_ipc.unlink_message_queue(name_file)
                    logger.debug("close message queue %s" % name_file)
                except:
                    pass
            else:
                listqueue.append(fmp)
        base_message_queue_posix.file_reponse_iq = listqueue

    def clean_file_all_message(self, prefixe=""):
        listqueue = []
        for fmp in base_message_queue_posix.file_reponse_iq:
            if fmp["time"] == -1:
                listqueue.append(fmp)
                continue
            if fmp["name"].startswith("/" + prefixe):
                try:
                    posix_ipc.unlink_message_queue(fmp["name"])
                    continue
                except:
                    pass
            listqueue.append(fmp)
        base_message_queue_posix.file_reponse_iq = listqueue

    def clean_file_message_timeout(self, prefixe="", timeout=None):
        listqueue = []
        deltatime = time.time()
        if timeout is None:
            timeout = self.timeoutmessagequeue

        for fmp in base_message_queue_posix.file_reponse_iq:
            if fmp["time"] == -1:
                listqueue.append(fmp)
                continue
            if fmp["name"].startswith("/" + prefixe):
                if (deltatime - fmp["time"]) >= timeout:
                    try:
                        posix_ipc.unlink_message_queue(fmp["name"])
                        continue
                    except:
                        pass
            listqueue.append(fmp)
        base_message_queue_posix.file_reponse_iq = listqueue

    def sendbytes(self, name_file, msg, prefixe="", timeout=None, priority=9):
        name_file = self._namefile(name_file, prefixe)
        if isinstance(msg, str):
            msg.encode("utf-8")
        if isinstance(msg, bytes):
            for fmp in base_message_queue_posix.file_reponse_iq:
                if fmp["name"] == name_file:
                    fmp["obj"].send(msg, priority)

    def recvbytes(self, name_file, prefixe="", timeout=None, typeoutstr=False):
        if timeout is None:
            timeout = 20
        name_file = self._namefile(name_file, prefixe)
        dd = time.time()
        for fmp in base_message_queue_posix.file_reponse_iq:
            if fmp["name"] == name_file:
                logger.debug("TROUVER %s" % name_file)
                try:
                    logger.debug("Start attente %s" % dd)
                    msg, priority = fmp["obj"].receive(timeout)
                    logger.debug("stop attente %s" % dd - time.time())
                    if typeoutstr:
                        msg = bytes.decode(msg, "utf-8")
                    return msg, priority
                except posix_ipc.BusyError:
                    logger.error("BusyError timeout %s" % name_file)
                    ee = dd - time.time()
                    logger.debug("stop attente %s" % ee)
                    return None, None
