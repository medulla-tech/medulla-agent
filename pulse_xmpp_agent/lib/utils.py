#!/usr/bin/python3
# -*- coding: utf-8; -*-
# SPDX-FileCopyrightText: 2016-2023 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-3.0-or-later
"""
    This file contains shared functions use in pulse client/server agents.
"""
import shutil
import sys
import urllib.request as urllib2
from urllib.parse import urlparse
from configparser import ConfigParser
import binascii
import netifaces
import json
import subprocess
import threading
import os
import fnmatch
import logging
import random
import re
import traceback
from pprint import pprint
import hashlib
import base64
import pickle

import stat

from .agentconffile import (
    conffilename,
    medullaPath,
    directoryconffile,
    pulseTempDir,
    conffilenametmp,
    rotation_file,
)
from .manageUser import ManageUser

import socket
import psutil
import time
from datetime import datetime, timedelta, timezone
import importlib.util
import requests
import asyncio


if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

from concurrent.futures import ThreadPoolExecutor
from requests.exceptions import Timeout
import zlib

try:
    from Cryptodome import Random
    from Cryptodome.Cipher import AES
except:
    from Crypto import Random
    from Crypto.Cipher import AES
import tarfile
from functools import wraps
import string
import platform
import urllib
import yaml
import xml.etree.ElementTree as ET
from collections import OrderedDict
import gzip
from xml.dom.minidom import parseString

logger = logging.getLogger()

DEBUGPULSE = 25


if sys.platform.startswith("win"):
    # import wmi
    import pythoncom
    import winreg as wr

    import win32api
    import win32security
    import ntsecuritycon
    import win32net
    import ctypes
    import win32com.client
    from win32com.client import GetObject
    from ctypes.wintypes import LPCWSTR, LPCSTR
else:
    import pwd
    import grp
    import posix_ipc
    import xmltodict



import inspect


def set_logging_level(func):
    """
    Décorateur pour ajuster le niveau de journalisation (logging level) dans les plugins exécutés par Windows.

    Le décorateur doit être inclus dans les plugins exécutés par les agents machines.

    Parameters:
        func (callable): Fonction à décorer. Le premier paramètre doit être un objet xmppobject.

    Returns:
        callable: Fonction décorée.

    Usage:
        @set_logging_level
        def action(xmppobject, action, sessionid, data, message, dataerreur):
            ...

    Example:

    @set_logging_level
    def action(xmppobject, action, sessionid, data, message, dataerreur):
        ...

    Notes:
        Ce décorateur ajuste le niveau de journalisation uniquement sur les systèmes Windows. Sur les autres plateformes,
        ce décorateur ne modifie pas le niveau de journalisation et laisse la fonction inchangée.
    """

    def wrapper(*args, **kwargs):
        if platform.system() == "Windows":
            if args:
                arg = args[0]
                if hasattr(arg, "config"):
                    if hasattr(arg.config, "levellog"):
                        import logging

                        logging.getLogger().setLevel(logging.DEBUG)
                else:
                    import logging

                    logging.warning("L'objet n'a pas l'attribut config")
            return func(*args, **kwargs)
        else:
            return func(
                *args, **kwargs
            )  # Ne fait rien sur les autres plateformes, retourne simplement le résultat de la fonction

    return wrapper


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


class PythonVersionInfo:
    def __init__(self):
        """
        Initialise la classe PythonVersionInfo en extrayant les informations sur la version et le chemin de la bibliothèque standard.
        """
        (
            self.version_major,
            self.version_minor,
            self.version_revision,
        ) = self._extract_version_parts()
        self.version = self.version_major + self.version_minor
        self.path_lib = self._get_path_lib()

    def _extract_version_parts(self):
        """
        Extrait les parties majeure, mineure et de révision de la version de Python.
        """
        # Obtenir le numéro de version complet
        numero_version_complet = sys.version.split(" ")[0]

        # Extraire les parties de la version sous le format "3.11.3"
        numeros_version = numero_version_complet.split(".")
        if len(numeros_version) >= 3:
            version_majeur = numeros_version[0]
            version_mineur = numeros_version[1]
            version_revision = numeros_version[2]
            return version_majeur, version_mineur, version_revision
        else:
            return None, None, None

    def _get_path_lib(self):
        """
        Obtient le chemin de la bibliothèque standard en fonction du système d'exploitation.
        """
        if sys.platform.startswith("win"):
            return os.path.join(sys.prefix, "Lib")
        elif sys.platform.startswith("darwin"):
            return os.path.join(sys.prefix, "lib", "python" + sys.version[:3])
        else:
            return os.path.join(sys.prefix, "lib", "python" + sys.version[:3])

    def get_version(self):
        """
        Renvoie la version majeure et mineure combinée en une seule chaîne.
        """
        return self.version

    def get_major_version(self):
        """
        Renvoie le numéro de version majeure.
        """
        return self.version_major

    def get_minor_version(self):
        """
        Renvoie le numéro de version mineure.
        """
        return self.version_minor

    def get_revision(self):
        """
        Renvoie le numéro de révision de la version.
        """
        return self.version_revision

    def get_path_lib(self):
        """
        Renvoie le chemin de la bibliothèque standard.
        """
        return self.path_lib

    def get_path_root_files_python(self):
        """
        Renvoie le chemin racine des fichiers python
        """
        return os.path.dirname(self._get_path_lib())

    def get_path_packages_python(self):
        """
        Renvoie le chemin des packages python
        """
        if os.path.exists(os.path.join(self._get_path_lib(), "dist-packages")):
            return os.path.join(self._get_path_lib(), "dist-packages")
        else:
            return os.path.join(self._get_path_lib(), "site-packages")


def get_python_executable_console():
    """
    Renvoie le chemin absolu de l'exécutable Python en cours d'exécution.
    """
    executable_path = sys.executable
    if executable_path.lower().endswith("w.exe"):
        return executable_path[:-5] + ".exe"
    return executable_path


def get_python_exec():
    """
    Renvoie le chemin absolu de l'exécutable Python en cours d'exécution.
    """
    return sys.executable

import sys
import os
import platform
import subprocess
import json

def os_version(brelease_windows=1, bbuild_windows=0):
    """
    Version réécrite utilisant Get-CimInstance (CIM).
    """

    try:
        # ----- WINDOWS -----
        if sys.platform.startswith("win"):

            # Récupération via CIM (PowerShell)
            ps_cmd = [
                "powershell",
                "-NoProfile",
                "-Command",
                "Get-CimInstance -ClassName Win32_OperatingSystem | "
                "Select-Object Caption, Version, BuildNumber | ConvertTo-Json"
            ]

            try:
                output = subprocess.check_output(ps_cmd, text=True, encoding="utf-8")
                os_data = json.loads(output)
            except Exception:
                return platform.platform()

            name = os_data.get("Caption", "").strip()
            build = os_data.get("BuildNumber")
            version = os_data.get("Version")

            # Lecture du DisplayVersion (21H2, 22H2, etc.)
            release_id = None
            if brelease_windows:
                try:
                    import winreg
                    key = winreg.OpenKey(
                        winreg.HKEY_LOCAL_MACHINE,
                        r"SOFTWARE\Microsoft\Windows NT\CurrentVersion"
                    )
                    release_id, _ = winreg.QueryValueEx(key, "DisplayVersion")
                    winreg.CloseKey(key)
                except Exception:
                    pass

            # Construction de la chaîne finale
            parts = []
            if release_id:
                parts.append(release_id)
            if bbuild_windows:
                parts.append(f"build {build}")

            if parts:
                return f"{name} ({' - '.join(parts)})"
            else:
                return name

        # ----- LINUX -----
        elif sys.platform.startswith("linux"):
            os_release = "/etc/os-release"
            if os.path.exists(os_release):
                with open(os_release, "r") as f:
                    info = {}
                    for line in f:
                        if "=" in line:
                            k, v = line.strip().split("=", 1)
                            info[k] = v.strip('"')
                    name = info.get("PRETTY_NAME") or info.get("NAME", "Linux")
                    if 'linux' not in name.lower():
                        name += ' linux'
                    return name
            else:
                return platform.platform()

        # ----- MACOS -----
        elif sys.platform == "darwin":
            try:
                version, _, _ = platform.mac_ver()
                name = os.popen("sw_vers -productName").read().strip()
                return f"{name} {version}"
            except Exception:
                return "macOS (version inconnue)"

        # ----- AUTRES -----
        else:
            return platform.platform()

    except Exception:
        return platform.platform()

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
    if delsession:
        logging.log(DEBUGPULSE, f"Clear dependency : {delsession}")
        save_back_to_deploy(objectxmpp.back_to_deploy)


def networkinfoexist():
    """
    This function checks if the fingerprintnetwork file exists.

    Returns:
        it returns True if the file exists. False otherwise
    """
    filenetworkinfo = os.path.join(Setdirectorytempinfo(), "fingerprintnetwork")
    return bool(os.path.exists(filenetworkinfo))


def save_count_start():
    filecount = os.path.join(Setdirectorytempinfo(), "countstart")
    if not os.path.exists(filecount):
        file_put_contents(filecount, "1")
        return 1
    countstart = file_get_contents(filecount)
    try:
        countstart = int(countstart.strip()) + 1 if countstart != "" else 1
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
    jidinfo = {"user": user, "domain": domain, "resource": resource}
    filejid = os.path.join(Setdirectorytempinfo(), "jid")
    if not os.path.exists(filejid):
        savejsonfile(filejid, jidinfo)
        return False, jidinfo
    oldjid = loadjsonfile(filejid)

    if oldjid["user"] != user or oldjid["domain"] != domain:
        savejsonfile(filejid, jidinfo)
        return True, {
            "user": oldjid["user"],
            "domain": oldjid["domain"],
            "resource": oldjid["resource"],
        }
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
    """
    Test the configuration file to see if it is completly configured and working.
    Args:
        typeconf: Type of the agent (machine, relayserver)

    Returns:
        It returns True if this is a relayserver or a valid config file.
    """
    if typeconf == "relayserver":
        return True
    Config = ConfigParser()
    namefileconfig = conffilename(typeconf)
    Config.read(namefileconfig)
    return bool(
        (
            Config.has_option("type", "guacamole_baseurl")
            and Config.has_option("connection", "port")
            and Config.has_option("connection", "server")
            and Config.has_option("global", "relayserver_agent")
            and Config.get("type", "guacamole_baseurl") != ""
            and Config.get("connection", "port") != ""
            and Config.get("connection", "server") != ""
            and Config.get("global", "relayserver_agent") != ""
        )
    )


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
    return bool(
        (
            Config.has_option("configuration_server", "confserver")
            and Config.has_option("configuration_server", "confport")
            and Config.has_option("configuration_server", "confpassword")
            and Config.has_option("configuration_server", "confdomain")
            and Config.get("configuration_server", "keyAES32") != ""
        )
    )


def createfingerprintnetwork():
    """
    Create a fingerprint of the network configuration based on the platform.

    Returns:
        str: MD5 hash of the network configuration.
    """
    md5network = ""
    command_mapping = {
        "win32": "ipconfig",
        "linux": "LANG=C ifconfig | egrep '.*(inet|HWaddr).*' | grep -v inet6",
        "darwin": "ipconfig",
    }

    platform = sys.platform
    command = command_mapping.get(platform)

    if not command:
        logger.error("Unsupported platform.")
        return md5network

    obj = simplecommandstr(command)

    if obj["code"] != 0 or obj["result"] == "":
        logger.error(
            f"An error occurred while determining the network. {command} failed."
        )
    else:
        md5network = hashlib.md5(obj["result"].encode("utf-8")).hexdigest()

    return md5network


def createfingerprintconf(typeconf):
    namefileconfig = conffilename(typeconf)
    return hashlib.md5(file_get_binarycontents(namefileconfig)).hexdigest()


def confinfoexist():
    filenetworkinfo = os.path.join(Setdirectorytempinfo(), "fingerprintconf")
    return bool(os.path.exists(filenetworkinfo))


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
    if "://" in filename:
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
            return fp.read(maxlen)
        finally:
            fp.close()


def file_get_binarycontents(filename, offset=-1, maxlen=-1):
    fp = open(filename, "rb")
    try:
        if offset > 0:
            fp.seek(offset)
        return fp.read(maxlen)
    finally:
        fp.close()


def file_put_contents(filename, data):
    if not os.path.exists(os.path.dirname(filename)):
        os.makedirs(os.path.dirname(filename))
    with open(filename, "w") as f:
        f.write(data)


def file_put_contents_w_a(filename, data, option="w"):
    if not os.path.exists(os.path.dirname(filename)):
        os.makedirs(os.path.dirname(filename))
    if option in ["a", "w"]:
        with open(filename, option) as f:
            f.write(data)


def save_obj(obj, name):
    """
    funct save serialised object
    """
    with open(f"{name}.pkl", "wb") as f:
        pickle.dump(obj, f, pickle.HIGHEST_PROTOCOL)


def load_obj(name):
    """
    function load serialized object
    """
    with open(f"{name}.pkl", "rb") as f:
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
    iface_names = ["(unknown)" for _ in range(len(iface_guids))]
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
        raise RuntimeError(f"Unsupported operating system for this module: {os.name}")


def isMacOsUserAdmin():
    # pour linux "cat /etc/shadow")
    obj = simplecommand("cat /etc/master.passwd")
    return int(obj["code"]) == 0


def getRandomName(nb, pref=""):
    a = "abcdefghijklnmopqrstuvwxyz0123456789"
    d = pref
    for _ in range(nb):
        d = d + a[random.randint(0, 35)]
    return d


def md5(fname):
    hash = hashlib.md5()
    with open(fname, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash.update(chunk)
    return hash.hexdigest()


def loadModule(filename):
    """
    Charge un module Python à partir d'un fichier spécifié.

    :param filename: Le chemin d'accès au fichier du module à charger.
    :type filename: str
    :return: Le module chargé ou None en cas d'échec.
    :rtype: module
    """
    module = None
    try:
        if filename == "":
            raise RuntimeError("Empty filename cannot be loaded")
        search_path, file = os.path.split(filename)
        if search_path not in sys.path:
            sys.path.append(search_path)
            sys.path.append(os.path.normpath(f"{search_path}/../"))
        module_name, ext = os.path.splitext(file)

        try:
            spec = importlib.util.spec_from_file_location(module_name, filename)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
        except Exception:
            logging.getLogger().error("We hit a backtrace when loading Modules")
            logging.getLogger().error(
                "We got the backtrace\n%s" % (traceback.format_exc())
            )
            return None
    except:
        logging.getLogger().error(f"{traceback.format_exc()}")
    return module


def call_plugin_separate(name, *args, **kwargs):
    """
    Exécute un plugin spécifié de manière sécurisée et dans un thread séparé.

    Cette fonction détermine dynamiquement le script du plugin à exécuter en fonction des
    arguments fournis et des paramètres de configuration. Elle vérifie si les actions des
    plugins sont activées et si le plugin spécifié n'est pas exclu de l'exécution. Si ces
    conditions sont remplies, la fonction charge et exécute l'action du plugin dans la boucle
    d'événements, tout en suivant le nombre de fois que chaque plugin est appelé.

    Args:
        name (str): Le nom de base du plugin.
        *args: Liste d'arguments de longueur variable où :
            - args[0]: Un objet contenant la configuration et le chemin des modules.
            - args[1]: L'identifiant spécifique du plugin.
        **kwargs: Arguments nommés arbitraires à passer à l'action du plugin.

    Raises:
        None: Les erreurs et les informations de débogage sont enregistrées au lieu d'être levées.
    """

    try:
        nameplugin = name
        if args[0].config.plugin_action:
            if args[1] not in args[0].config.excludedplugins:
                nameplugin = os.path.join(args[0].modulepath, f"plugin_{args[1]}.py")
                if not os.path.exists(nameplugin):
                    logging.getLogger().error(
                        f"call_plugin_sequentially The file plugin {nameplugin} does not exist"
                    )
                    return
                # add compteur appel plugins
                loop = asyncio.get_event_loop()
                count = 0
                try:
                    count = getattr(args[0], f"num_call{args[1]}")
                    setattr(args[0], f"num_call{args[1]}", count + 1)
                except AttributeError:
                    count = 0
                    setattr(args[0], f"num_call{args[1]}", count)
                pluginaction = loadModule(nameplugin)
                loop.call_soon_threadsafe(pluginaction.action, *args, **kwargs)
            else:
                logging.getLogger().debug(f"The plugin {args[1]} is excluded")
        else:
            logging.getLogger().debug(
                f"The plugin {args[1]} is not allowed due to plugin_action parameter"
            )
    except:
        logging.getLogger().error(f"{traceback.format_exc()}")


def wait_until_msiexec_finishes():
    """
    Windows Msiexec can only be run one by one.

    Here if it is already running we keep the function in use
    and only release when it is available again.

    We check for more than one process because when we start msiexec.exe
    once it creates 2 processes but after the use it keeps one.
    This is the normal msiexec behaviour
    """
    while True:
        msiexec_count = 0

        # Iterate over all running processes
        for proc in psutil.process_iter(['name']):
            try:
                # Check if the process name is msiexec.exe
                if proc.info['name'] == 'msiexec.exe':
                    msiexec_count += 1
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                pass

        if msiexec_count < 2:  # Assuming less than 2 means no installation is in progress
            logger.info("No MSI installation is currently running. Proceeding with the new installation.")
            break

        logger.info(f"An MSI installation is already in progress ({msiexec_count} instances running). Waiting...")
        time.sleep(10)  # Wait for 10 seconds before checking again


class FunctionThread(threading.Thread):
    def __init__(self, function, *args, **kwargs):
        threading.Thread.__init__(self)
        self.function = function
        self.args = args
        self.kwargs = kwargs
        self.timeout = 900  # 15 minutes

    def run(self):
        # Exécution de la fonction dans le thread
        self.result = self.function(*self.args, **self.kwargs)

    def start(self):
        threading.Thread.start(self)
        self.join(self.timeout)  # Attendre jusqu'à la fin du thread ou le timeout
        if not self.is_alive():
            return self.result
        # Si le thread n'est pas terminé dans le délai imparti, on le termine de force
        self._stop()
        raise TimeoutError("Le thread a dépassé le temps d'exécution maximal.")


def call_mon_plugin(name, *args, **kwargs):
    """
    Exécute un plugin spécifié de manière sécurisée et dans un thread séparé.

    Cette fonction détermine dynamiquement le script du plugin à exécuter en fonction des
    arguments fournis et des paramètres de configuration. Elle vérifie si les actions des
    plugins sont activées et si le plugin spécifié n'est pas exclu de l'exécution. Si ces
    conditions sont remplies, la fonction charge et exécute l'action du plugin dans une
    nouvelle boucle d'événements, tout en suivant le nombre de fois que chaque plugin est
    appelé.

    Args:
        name (str): Le nom de base du plugin.
        *args: Liste d'arguments de longueur variable où :
            - args[0]: Un objet contenant la configuration et le chemin des modules.
            - args[1]: L'identifiant spécifique du plugin.
        **kwargs: Arguments nommés arbitraires à passer à l'action du plugin.

    Raises:
        None: Les erreurs et les informations de débogage sont enregistrées au lieu d'être levées.

    """
    try:
        nameplugin = name
        if args[0].config.plugin_action:
            if args[1] not in args[0].config.excludedplugins:
                nameplugin = os.path.join(args[0].modulepath, f"plugin_{args[1]}.py")
                if not os.path.exists(nameplugin):
                    logging.getLogger().error(
                        f"call_plugin_sequentially The file plugin {nameplugin} does not exist"
                    )
                    return
                logger.debug(f"Loading plugin {args[1]}")

                loop = asyncio.new_event_loop()
                count = 0
                try:
                    count = getattr(args[0], f"num_call{args[1]}")
                    setattr(args[0], f"num_call{args[1]}", count + 1)
                except AttributeError:
                    count = 0
                    setattr(args[0], f"num_call{args[1]}", count)
                pluginaction = loadModule(nameplugin)
                executor = ThreadPoolExecutor()
                thread = FunctionThread(pluginaction.action, *args, **kwargs)
                result = loop.run_in_executor(executor, thread.start)
            else:
                logging.getLogger().debug(f"The plugin {args[1]} is excluded")
        else:
            logging.getLogger().debug(
                f"The plugin {args[1]} is not allowed due to plugin_action parameter"
            )
    except:
        logging.getLogger().error(f"{traceback.format_exc()}")


def call_plugin(name, *args, **kwargs):
    """
    Appelle la fonction d'action d'un plugin spécifié par son nom.

    Cette fonction crée un nouveau compteur d'appels pour chaque plugin appelé et
    l'enregistre dans l'objet passé en premier argument. Le compteur est stocké
    dans un attribut nommé "num_call<nom_du_plugin>", où <nom_du_plugin> est le
    nom du plugin passé en argument.

    Cette fonction utilise un thread indépendant pour exécuter la fonction
    d'action du plugin, ce qui permet de ne pas bloquer la boucle d'événements
    asyncio en cours.

    :param name: Le nom du plugin à appeler.
    :type name: str
    :param args: Les arguments à passer à la fonction d'action du plugin.
    :type args: tuple
    :param kwargs: Les arguments nommés à passer à la fonction d'action du plugin.
    :type kwargs: dict
    :return: Le résultat de l'appel à la fonction d'action du plugin.
    :rtype: Any
    """
    try:
        nameplugin = name
        if args[0].config.plugin_action:
            if args[1] not in args[0].config.excludedplugins:
                nameplugin = os.path.join(args[0].modulepath, f"plugin_{args[1]}.py")
                if not os.path.exists(nameplugin):
                    logging.getLogger().error(
                        f"call_plugin The file plugin {nameplugin} does not exist"
                    )
                    return
                logger.debug(f"Loading plugin {args[1]}")
                loop = asyncio.new_event_loop()
                time.sleep(0.0002)  # 0,2 milliseconde permet au thread de monter
                count = 0
                try:
                    count = getattr(args[0], f"num_call{args[1]}")
                    setattr(args[0], f"num_call{args[1]}", count + 1)
                except AttributeError:
                    setattr(args[0], f"num_call{args[1]}", 0)
                pluginaction = loadModule(nameplugin)
                result = loop.run_in_executor(
                    None, pluginaction.action, *args, **kwargs
                )
                return result
            else:
                logging.getLogger().debug(f"The plugin {args[1]} is excluded")
        else:
            logging.getLogger().debug(
                f"The plugin {args[1]} is not allowed due to plugin_action parameter"
            )
    except:
        logging.getLogger().error(f"{traceback.format_exc()}")


def call_plugin_sequentially(name, *args, **kwargs):
    """
    Exécute un plugin spécifié de manière séquentielle.

    Cette fonction détermine dynamiquement le script du plugin à exécuter en fonction des
    arguments fournis et des paramètres de configuration. Elle vérifie si les actions des
    plugins sont activées et si le plugin spécifié n'est pas exclu de l'exécution. Si ces
    conditions sont remplies, la fonction charge et exécute l'action du plugin de manière
    séquentielle, tout en suivant le nombre de fois que chaque plugin est appelé.

    Args:
        name (str): Le nom de base du plugin.
        *args: Liste d'arguments de longueur variable où :
            - args[0]: Un objet contenant la configuration et le chemin des modules.
            - args[1]: L'identifiant spécifique du plugin.
        **kwargs: Arguments nommés arbitraires à passer à l'action du plugin.

    Raises:
        None: Les erreurs et les informations de débogage sont enregistrées au lieu d'être levées.
    """
    try:
        nameplugin = name
        if args[0].config.plugin_action:
            if args[1] not in args[0].config.excludedplugins:
                nameplugin = os.path.join(args[0].modulepath, f"plugin_{args[1]}.py")
                if not os.path.exists(nameplugin):
                    logging.getLogger().error(
                        f"call_plugin_sequentially The file plugin {nameplugin} does not exist"
                    )
                    return
                # add compteur appel plugins
                count = 0
                try:
                    count = getattr(args[0], f"num_call{args[1]}")
                    setattr(args[0], f"num_call{args[1]}", count + 1)
                except AttributeError:
                    count = 0
                    setattr(args[0], f"num_call{args[1]}", count)
                pluginaction = loadModule(nameplugin)
                pluginaction.action(*args, **kwargs)
            else:
                logging.getLogger().debug(f"The plugin {args[1]} is excluded")
        else:
            logging.getLogger().debug(
                f"The plugin {args[1]} is not allowed due to plugin_action parameter"
            )
    except:
        logging.getLogger().error(f"{traceback.format_exc()}")


def getshortenedmacaddress():
    listmacadress = {}
    for _ in range(20):
        for i in netifaces.interfaces():
            if i == "":
                continue
            addrs = netifaces.ifaddresses(i)
            try:
                if_mac = reduction_mac(addrs[netifaces.AF_LINK][0]["addr"])
                addrs[netifaces.AF_INET][0]["addr"]
                address = int(if_mac, 16)
                if address != 0:
                    listmacadress[address] = if_mac
            except BaseException:
                pass
        if listmacadress:
            break
        else:
            time.sleep(1)
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
            ip_list.extend(
                link["addr"]
                for link in netifaces.ifaddresses(interface)[netifaces.AF_INET]
                if link["addr"] != "127.0.0.1"
            )
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
        if i == "":
            continue
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
    Validates IPv6 addresses
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
    return result[0].rstrip("\n")


def isprogramme(name):
    """
    Get the absolute path of the specified program, then try to execute it.
    If the execution is successfull : it is a program

    Test if the program `name` exists or not

    Args:
        name: string of the name of the tested program

    Returns:
        It returns True if `name` exists on the system.
                   False otherwise
    """
    p = subprocess.Popen(
        f"which {name}",
        shell=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    result = p.stdout.readlines()
    obj = {"code": p.wait()}
    if sys.version_info[0] == 3:
        result = [binascii.b2a_qp(x) for x in result]
    obj["result"] = result
    return obj["result"] != ""


def simplecommand(cmd, strimresult=False):
    """
    Execute the command and return its result

    Param:
        cmd string of the executed command

    Returns:
        dict of the result and code.
        {
            "code": int command execution code,
            "result": list of string of the command result
        }
    """
    if isinstance(cmd, bytes):
        cmd = decode_strconsole(cmd)
    p = subprocess.Popen(
        cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT
    )
    result = p.stdout.readlines()
    obj = {"result": "", "code": p.wait()}
    if sys.version_info[0] == 3:
        obj["result"] = (
            [decode_strconsole(x).strip() for x in result]
            if strimresult
            else [decode_strconsole(x) for x in result]
        )
    elif strimresult:
        obj["result"] = [x.strip() for x in result]
    else:
        obj["result"] = list(result)
    return obj


def simplecommandstr(cmd):
    """
    Execute the command and return its result

    Param:
        cmd string of the executed command

    Returns:
        dict of the result and code.
        {
            "code": int command execution code,
            "result": string of the command result (instead of list of string for
                simplecommand function)
        }
    """
    if isinstance(cmd, bytes):
        cmd = decode_strconsole(cmd)
    p = subprocess.Popen(
        cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT
    )
    obj = {"result": "", "code": p.wait()}
    result = p.stdout.readlines()
    if sys.version_info[0] == 3:
        result = [decode_strconsole(x) for x in result]
    else:
        result = list(result)
    obj["result"] = "".join(result)
    return obj


def windowspath(namescript):
    return f'"{namescript}"' if sys.platform.startswith("win") else namescript


def powerschellscriptps1(namescript):
    namescript = windowspath(namescript)
    print(f"powershell -ExecutionPolicy Bypass -File  {namescript}")
    return simplecommandstr(
        encode_strconsole(f"powershell -ExecutionPolicy Bypass -File {namescript}")
    )


def powerschellscript1ps1(namescript):
    namescript = windowspath(namescript)
    obj = {"code": -1, "result": ""}
    try:
        obj = simplecommand(f"powershell -ExecutionPolicy Bypass -File {namescript}")
    except Exception:
        logger.error("\n%s" % (traceback.format_exc()))
    return obj


class shellcommandtimeout:
    """
    Classe pour exécuter une commande shell sur Linux, Windows ou macOS.

    Attributes:
        cmd (bytes, bytearray, str): La commande à exécuter (encodée selon l'OS).
        timeout (int): Le temps maximal en secondes pour attendre que la commande se termine.
        strimresult (bool): Indique si les lignes vides doivent être omises et si les espaces doivent être supprimés.

    Returns:
        dict: Un dictionnaire contenant le code d'erreur et le résultat de la commande.

    Raises:
        OSError: En cas d'erreur lors de l'exécution de la commande.
    """

    def __init__(self, cmd, timeout=15, strimresult=False):
        """
        Initialise un objet ShellCommandExecutor.

        Args:
            cmd (bytes, bytearray, str): La commande à exécuter (encodée selon l'OS).
            timeout (int, optional): Le temps maximal en secondes pour attendre que la commande se termine. Par défaut, 15 secondes.
            strimresult (bool, optional): Indique si les lignes vides doivent être omises et si les espaces doivent être supprimés. Par défaut, False.
        """
        if isinstance(cmd, str):
            self.cmd = cmd
        elif isinstance(cmd, (bytes, bytearray)):
            self.cmd = cmd.decode("utf-8")
        else:
            raise ValueError(
                "Le paramètre cmd doit être de type str, bytes ou bytearray."
            )

        self.timeout = timeout
        self.strimresult = strimresult
        self.obj = {
            "code": 255,
            "result": "result undefined",
            "separateurline": os.linesep,
            "cmd": self.cmd,
            "timeout": timeout,
        }

    def run_command(self):
        """
        Exécute la commande shell.

        Returns:
            dict: Un dictionnaire contenant le code d'erreur et le résultat de la commande.
        """
        try:
            if sys.platform == "win32":
                # Windows text=True indique texte doit être traité en tant que chaîne de caractères (UTF-8 par défaut).
                # Cela permet d'interpréter correctement les caractères spéciaux.
                self.process = subprocess.Popen(
                    self.cmd,
                    shell=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                )
            else:
                # Linux ou macOS
                self.process = subprocess.Popen(
                    self.cmd,
                    shell=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    encoding="utf-8",
                )

            self.obj["result"], _ = self.process.communicate(timeout=self.timeout)
            self.obj["result"] = self.obj["result"].splitlines()
            if self.strimresult:
                self.obj["result"] = [
                    line.strip() for line in self.obj["result"] if line != ""
                ]
            else:
                self.obj["result"] = [
                    line.replace(os.linesep, "\n")
                    for line in self.obj["result"]
                    if line != ""
                ]

            self.obj["code"] = self.process.returncode

        except subprocess.TimeoutExpired:
            self.obj["code"] = -15  # Timeout
            self.process.terminate()
            self.obj["result"] = "error timeout"
        except Exception as e:
            self.obj["code"] = 1
            self.obj["result"] = str(e)

    def run(self):
        """
        Exécute la commande shell avec le timeout spécifié.

        Returns:
            dict: Un dictionnaire contenant le code d'erreur et le résultat de la commande.
        """
        self.run_command()
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
    p = subprocess.Popen(
        f"/etc/init.d/{name} {action}",
        shell=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    result = p.stdout.readlines()
    obj = {"code": p.wait()}
    obj["result"] = result
    return obj

import sys
import subprocess

def service(name, action):
    """
    Perform actions on a system service (start, stop, restart, reload).
    Works on Windows, Linux (systemd/init), and macOS.

    Args:
        name: Service name
        action: 'start', 'stop', 'restart', 'reload'

    Returns:
        dict: {
            "code": return code (0 = success, -1 = error),
            "result": list of output lines or error message
        }
    """
    obj = {"code": -1, "result": []}

    try:
        if sys.platform.startswith("linux"):
            # Detect init system
            p = subprocess.Popen("cat /proc/1/comm", shell=True,
                                 stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            system = p.stdout.read().decode().strip()

            if system == "init":
                cmd = f"/etc/init.d/{name} {action}"
            elif system == "systemd":
                cmd = f"systemctl {action} {name}"
            else:
                obj["result"] = [f"Unsupported init system: {system}"]
                return obj

            p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            output = p.stdout.readlines()
            obj["code"] = p.wait()
            obj["result"] = [line.decode().strip() for line in output]

        elif sys.platform.startswith("win"):
            # Map restart -> Stop+Start
            ps_action = action.lower()
            if ps_action == "restart":
                cmd = f"powershell -Command \"Stop-Service -Name '{name}' -Force; Start-Service -Name '{name}'\""
            elif ps_action in ("start", "stop"):
                cmd = f"powershell -Command \"{ps_action.capitalize()}-Service -Name '{name}' -ErrorAction Stop\""
            else:
                obj["result"] = [f"Unsupported action: {action}"]
                return obj

            p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            output = p.stdout.read().decode()
            obj["code"] = 0 if p.wait() == 0 else -1
            obj["result"] = output.splitlines()

        elif sys.platform.startswith("darwin"):
            # macOS
            if action.lower() == "start":
                cmd = f"launchctl start {name}"
            elif action.lower() == "stop":
                cmd = f"launchctl stop {name}"
            elif action.lower() == "restart":
                cmd = f"launchctl stop {name}; launchctl start {name}"
            else:
                obj["result"] = [f"Unsupported action: {action}"]
                return obj

            p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            output = p.stdout.readlines()
            obj["code"] = p.wait()
            obj["result"] = [line.decode().strip() for line in output]

        else:
            obj["result"] = [f"Unsupported OS: {sys.platform}"]

    except Exception as e:
        obj["code"] = -1
        obj["result"] = [str(e)]

    return obj



def listservice(show=True, status=False):
    """
    Lists system services (Windows, Linux, macOS).

    Args:
        show (bool): print the list if True, otherwise return JSON
        status (bool): include service status if True

    Returns:
        If show=False:
            {
                "status": 1,
                "services": [
                    {"name": "...", "status": "..."}  # if status=True
                    {"name": "..."}                    # if status=False
                ]
            }
    """

    system = platform.system().lower()
    services = []

    # -----------------------------------------------------------
    # WINDOWS
    # -----------------------------------------------------------
    if system == "windows":
        cmd = (
            'powershell -Command '
            '"Get-Service | Select-Object Name,Status | ConvertTo-Json -Depth 2"'
        )

        p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        raw = p.stdout.read()
        rc = p.wait()

        if rc != 0:
            if show:
                print("Erreur lors de la recuperation des services Windows")
            return {"status": 0, "services": []}

        try:
            services_raw = json.loads(raw.decode("utf-8"))
        except:
            if show:
                print("Erreur JSON PowerShell")
            return {"status": 0, "services": []}

        if isinstance(services_raw, dict):
            services_raw = [services_raw]

        for svc in services_raw:
            entry = {"name": svc["Name"]}
            if status:
                entry["status"] = str(svc["Status"]).lower()
            services.append(entry)

    # -----------------------------------------------------------
    # LINUX (systemd)
    # -----------------------------------------------------------
    elif system == "linux":
        cmd = "systemctl list-units --type=service --all --no-pager --plain --no-legend"
        p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

        raw = p.stdout.read().decode("utf-8", errors="ignore")
        rc = p.wait()

        if rc != 0:
            if show:
                print("Erreur lors de l execution de systemctl")
            return {"status": 0, "services": []}

        for line in raw.splitlines():
            parts = line.split()
            if len(parts) >= 4:
                name = parts[0]
                svc_state = parts[3]

                entry = {"name": name}
                if status:
                    entry["status"] = svc_state.lower()

                services.append(entry)

    # -----------------------------------------------------------
    # macOS (launchctl)
    # -----------------------------------------------------------
    elif system == "darwin":
        cmd = "launchctl list"
        p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

        raw = p.stdout.read().decode("utf-8", errors="ignore")
        rc = p.wait()

        if rc != 0:
            if show:
                print("Erreur lors de l execution de launchctl")
            return {"status": 0, "services": []}

        lines = raw.splitlines()[1:]  # skip header
        for line in lines:
            parts = line.split()
            if len(parts) >= 3:
                pid = parts[0]
                label = parts[2]

                entry = {"name": label}
                if status:
                    entry["status"] = "running" if pid != "-" else "stopped"

                services.append(entry)

    # -----------------------------------------------------------
    # Autre OS non géré
    # -----------------------------------------------------------
    else:
        if show:
            print("OS non supporte :", system)
        return {"status": 0, "services": []}

    # -----------------------------------------------------------
    # Sortie show=True
    # -----------------------------------------------------------
    if show:
        for s in services:
            if status:
                print(f"{s['name']} - {s['status']}")
            else:
                print(s["name"])
        return ""

    # -----------------------------------------------------------
    # Sortie show=False → return JSON
    # -----------------------------------------------------------
    return {"status": 1, "services": services}


def joint_compteAD(domain, username, password, ou=None, restart=True):
    """
    Join the current Windows computer to an Active Directory domain
    using PowerShell Add-Computer

    Args:
        domain (str): Domain to join
        username (str): Domain user with privileges
        password (str): Password of the user
        ou (str): Optional OU (DistinguishedName) to place computer
        restart (bool): Restart after join (default True)

    Returns:
        dict: {
            "code": 0 if success, -1 if error,
            "result": list of output lines or error
        }
    """
    obj = {"code": -1, "result": []}

    try:
        # Build the PowerShell command
        ps_cmd = [
            "powershell", "-Command",
            f"$pass = ConvertTo-SecureString '{password}' -AsPlainText -Force;"
            f"$cred = New-Object System.Management.Automation.PSCredential('{username}', $pass);"
            f"Add-Computer -DomainName '{domain}' -Credential $cred"
        ]

        if ou:
            ps_cmd[-1] += f" -OUPath '{ou}'"
        if restart:
            ps_cmd[-1] += " -Restart"

        # Execute
        p = subprocess.Popen(ps_cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        output = p.stdout.read().decode()
        code = p.wait()

        obj["code"] = 0 if code == 0 else -1
        obj["result"] = output.splitlines()

    except Exception as e:
        obj["code"] = -1
        obj["result"] = [str(e)]

    return obj


def service_control(name, action):
    """
    Control a system service across Windows, Linux, macOS.

    Args:
        name (str): service name
        action (str): 'start', 'stop', 'restart'

    Returns:
        dict: {
            "code": 0 if success, -1 if error,
            "result": list of output lines or error messages
        }
    """
    obj = {"code": -1, "result": []}
    action = action.lower()
    system = platform.system().lower()

    try:
        if system == "windows":
            # Map restart -> Stop+Start
            if action == "restart":
                cmd = f"powershell -Command \"Stop-Service -Name '{name}' -Force; Start-Service -Name '{name}'\""
            elif action in ("start", "stop"):
                cmd = f"powershell -Command \"{action.capitalize()}-Service -Name '{name}' -ErrorAction Stop\""
            else:
                obj["result"] = [f"Unsupported action: {action}"]
                return obj

            p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            output = p.stdout.read().decode()
            obj["code"] = 0 if p.wait() == 0 else -1
            obj["result"] = output.splitlines()

        elif system == "linux":
            # Detect init system
            p = subprocess.Popen("cat /proc/1/comm", shell=True,
                                 stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            init_system = p.stdout.read().decode().strip()

            if init_system == "init":
                cmd = f"/etc/init.d/{name} {action}"
            elif init_system == "systemd":
                cmd = f"systemctl {action} {name}"
            else:
                obj["result"] = [f"Unsupported init system: {init_system}"]
                return obj

            p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            output = p.stdout.readlines()
            obj["code"] = p.wait()
            obj["result"] = [line.decode().strip() for line in output]

        elif system == "darwin":
            # macOS
            if action == "start":
                cmd = f"launchctl start {name}"
            elif action == "stop":
                cmd = f"launchctl stop {name}"
            elif action == "restart":
                cmd = f"launchctl stop {name}; launchctl start {name}"
            else:
                obj["result"] = [f"Unsupported action: {action}"]
                return obj

            p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            output = p.stdout.readlines()
            obj["code"] = p.wait()
            obj["result"] = [line.decode().strip() for line in output]

        else:
            obj["result"] = [f"Unsupported OS: {system}"]

    except Exception as e:
        obj["code"] = -1
        obj["result"] = [str(e)]

    return obj

def windowsservice(name, action):
    """
    Legacy wrapper for controlling Windows services.
    Now delegates to the modern cross-platform service_control function.

    Args:
        name (str): service name
        action (str): 'start', 'stop', 'restart'

    Returns:
        dict: same as service_control
    """
    import platform

    if not platform.system().lower() == "windows":
        return {"code": -1, "result": ["windowsservice can only run on Windows"]}

    # Delegate to service_control
    return service_control(name, action)


def methodservice_modern(service_name=None):
    """
    List available methods/actions for Windows services .
    If service_name is given, lists methods for that service.
    Otherwise, lists generic service methods.

    Returns:
        dict: {
            "code": 0 if success, -1 if error,
            "methods": list of method names
        }
    """
    obj = {"code": -1, "methods": []}

    try:
        # PowerShell command to list methods of the ServiceController object
        if service_name:
            ps_cmd = (
                f"powershell -Command "
                f"$svc = Get-Service -Name '{service_name}'; "
                f"$svc | Get-Member -MemberType Method | Select-Object -ExpandProperty Name"
            )
        else:
            # Generic: get methods of one service (first found)
            ps_cmd = (
                "powershell -Command "
                "$svc = Get-Service | Select-Object -First 1; "
                "$svc | Get-Member -MemberType Method | Select-Object -ExpandProperty Name"
            )

        p = subprocess.Popen(ps_cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        output = p.stdout.read().decode()
        code = p.wait()

        obj["code"] = 0 if code == 0 else -1
        obj["methods"] = [line.strip() for line in output.splitlines() if line.strip()]

    except Exception as e:
        obj["code"] = -1
        obj["methods"] = [str(e)]

    return obj

def file_get_content(path):
    with open(path, "r") as inputFile:
        content = inputFile.read()
    return content


def file_put_content(filename, contents, mode="w"):
    with open(filename, mode) as fh:
        fh.write(contents)



# decorateur pour simplifier les plugins
def pluginprocess(func):
    """
    Décorateur pour simplifier l'exécution des plugins XMPP.

    Ce décorateur :
    - Initialise un objet `result` avec les champs standards pour renvoyer le résultat.
    - Initialise un objet `dataerreur` pour gérer les erreurs.
    - Exécute la fonction décorée en lui passant `result` et `dataerreur`.
    - Encode les données en base64 si `result["base64"]` est True.
    - Envoie le message de résultat via `objetxmpp.send_message`.
    - En cas d'exception, envoie `dataerreur` au lieu du résultat.

    Args:
        func (callable): Fonction plugin à décorer. Signature attendue :
            func(objetxmpp, action, sessionid, data, message, dataerreur, result)

    Usage typique:
        @pluginprocess
        def mon_plugin(objetxmpp, action, sessionid, data, message, dataerreur, result):
            result["data"]["msg"] = "OK"
    """
    def wrapper(objetxmpp, action, sessionid, data, message, dataerreur):
        resultaction = f"result{action}"
        result = {}
        result["action"] = resultaction
        result["ret"] = 0
        result["sessionid"] = sessionid
        result["base64"] = False
        result["data"] = {}
        dataerreur["action"] = resultaction
        dataerreur["data"]["msg"] = f"ERROR : {action}"
        dataerreur["sessionid"] = sessionid
        try:
            response = func(
                objetxmpp, action, sessionid, data, message, dataerreur, result
            )
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
    """
    Décorateur pour simplifier le déploiement de plugins XMPP.

    Fonctionnalités :
    - Initialise un dictionnaire `result` pour la réponse standardisée.
    - Initialise `dataerreur` pour la gestion d'erreur.
    - Exécute la fonction décorée.
    - Encode les données en base64 si `result["base64"]` est True.
    - N'envoie pas le message si `result["data"]` vaut "end".
    - En cas d'exception, envoie le message d'erreur sauf si `result["data"] == "end"`.

    Args:
        func (callable): Fonction plugin à décorer. Signature attendue :
            func(objetxmpp, action, sessionid, data, message, dataerreur, result)

    Usage typique:
        @pulgindeploy
        def mon_plugin(objetxmpp, action, sessionid, data, message, dataerreur, result):
            result["data"]["msg"] = "Déploiement terminé"
    """
    def wrapper(objetxmpp, action, sessionid, data, message, dataerreur):
        resultaction = action
        result = {}
        result["action"] = resultaction
        result["ret"] = 0
        result["sessionid"] = sessionid
        result["base64"] = False
        result["data"] = {}
        dataerreur["action"] = resultaction
        dataerreur["data"]["msg"] = f"ERROR : {action}"
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
    """
    Décorateur pour simplifier le déploiement de plugins XMPP avec suivi détaillé.

    Fonctionnalités :
    - Initialise `result` et `dataerreur` comme dans les autres décorateurs.
    - Ajoute le champ `end` à `result["data"]` si absent.
    - Affiche des informations de debug détaillées (Devent, Dtypequery, Deventindex).
    - N'envoie le message que si `result["data"]["end"]` est False.
    - Encode les données en base64 si `result["base64"]` est True.
    - En cas d'exception, envoie le message d'erreur sauf si `result["data"]["end"]` est True.
    - Très utile pour les plugins qui font un traitement itératif ou long.

    Args:
        func (callable): Fonction plugin à décorer. Signature attendue :
            func(objetxmpp, action, sessionid, data, message, dataerreur, result)

    Usage typique:
        @pulgindeploy1
        def mon_plugin(objetxmpp, action, sessionid, data, message, dataerreur, result):
            result["data"]["msg"] = "Traitement en cours"
            result["data"]["end"] = False
    """
    def wrapper(objetxmpp, action, sessionid, data, message, dataerreur):
        result = {}
        result["action"] = action
        result["ret"] = 0
        result["sessionid"] = sessionid
        result["base64"] = False
        result["data"] = {}
        dataerreur["action"] = action
        dataerreur["data"]["msg"] = f"ERROR : {action}"
        dataerreur["sessionid"] = sessionid
        try:
            response = func(
                objetxmpp, action, sessionid, data, message, dataerreur, result
            )

            if "end" not in result["data"]:
                result["data"]["end"] = False

            print("----------------------------------------------------------------")
            print(f'sent message to {message["from"]} ')
            if "Devent" in data:
                print(f'Devent : {data["Devent"]}')
            if "Dtypequery" in data:
                print(f'Dtypequery : {data["Dtypequery"]}')
            if "Deventindex" in data:
                print(f'Deventindex : {data["Deventindex"]}')

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


def getIpXmppInterface(config):
    """
    This function is used to retrieve the local IP from the client which is talking
    with the ejabberd server.
    For this we need to use netstat.
    It returns:
        TCP    10.16.53.17:49711      10.16.24.239:5222      ESTABLISHED
    and we split to obtain the first IP of the line.

    Args:
        config (object): The configuration object containing server and port information.

    Returns:
        str: The local IP from the client which is talking with the ejabberd server.
    """
    resultip = ""

    # Validate xmpp_server_ipaddress_or_dns
    def is_valid_url_or_ipv4(value):
        try:
            # Check if it's a valid IPv4
            if is_valid_ipv4(value):
                return True
            # Check if it's a valid URL
            parsed = urlparse(value)
            return bool(parsed.scheme and parsed.netloc)
        except Exception:
            return False

    if hasattr(config, "Server") and is_valid_url_or_ipv4(config.Server):
        xmpp_server_ipaddress_or_dns = config.Server
    elif hasattr(config, "confserver") and is_valid_url_or_ipv4(config.confserver):
        xmpp_server_ipaddress_or_dns = config.confserver
    else:
        logger.error(
            "Invalid server configuration. Neither 'Server' nor 'confserver' is valid."
        )
        return None

    # Control on the Port variable
    if (
        hasattr(config, "Port")
        and isinstance(config.Port, int)
        and 0 <= config.Port <= 65535
    ):
        Port = config.Port
    elif (
        hasattr(config, "confPort")
        and isinstance(config.confPort, int)
        and 0 <= config.confPort <= 65535
    ):
        Port = config.confPort
    else:
        Port = 5222

    # Get the list of network interfaces
    interfaces = netifaces.interfaces()

    # Filter interfaces to keep only those with valid IPv4 addresses, excluding loopback addresses
    valid_interfaces = []
    for interface in interfaces:
        if interface == "":
            continue
        addrs = netifaces.ifaddresses(interface)
        if netifaces.AF_INET in addrs:
            for addr_info in addrs[netifaces.AF_INET]:
                ip = addr_info["addr"]
                if ip != "127.0.0.1" and is_valid_ipv4(ip):
                    valid_interfaces.append(interface)
                    logger.debug(f"Valid interface found: {interface} with IP: {ip}")
                    break

    # If there is only one valid interface, use its IPv4 address
    if len(valid_interfaces) == 1:
        addrs = netifaces.ifaddresses(valid_interfaces[0])
        if netifaces.AF_INET in addrs:
            for addr_info in addrs[netifaces.AF_INET]:
                ip = addr_info["addr"]
                if ip != "127.0.0.1" and is_valid_ipv4(ip):
                    resultip = ip
                    logger.debug(f"Using IP from the only valid interface: {ip}")
                    break

    if not resultip:
        xmpp_server_ipaddress = ipfromdns(xmpp_server_ipaddress_or_dns)
        logger.debug(
            "Searching with which IP the agent is connected to the Ejabberd server"
        )
        if sys.platform.startswith("linux"):
            obj = simplecommand(
                f"netstat -an | grep {Port} | grep ESTABLISHED | grep -v tcp6"
            )
            if obj["code"] != 0:
                logging.getLogger().error(f'error command netstat : {obj["result"]}')
                logging.getLogger().error("error install package net-tools")
            if len(obj["result"]) != 0:
                for i in range(len(obj["result"])):
                    obj["result"][i] = obj["result"][i].rstrip("\n")
                a = "\n".join(obj["result"])
                if b := [x for x in a.split(" ") if x != ""]:
                    resultip = b[3].split(":")[0]
        elif sys.platform.startswith("win"):
            obj = simplecommand(
                f'netstat -an | findstr {Port} | findstr "ESTABLISHED SYN_SENT SYN_RECV"'
            )
            if len(obj["result"]) != 0:
                for i in range(len(obj["result"])):
                    obj["result"][i] = obj["result"][i].rstrip("\n")
                a = "\n".join(obj["result"])
                if b := [x for x in a.split(" ") if x != ""]:
                    resultip = b[1].split(":")[0]
        elif sys.platform.startswith("darwin"):
            obj = simplecommand(f"netstat -an | grep {Port} | grep ESTABLISHED")
            if len(obj["result"]) != 0:
                for i in range(len(obj["result"])):
                    obj["result"][i] = obj["result"][i].rstrip("\n")
                a = "\n".join(obj["result"])
                if b := [x for x in a.split(" ") if x != ""]:
                    resultip = b[3][: b[3].rfind(".")]
        else:
            obj = simplecommand(f"netstat -a | grep {Port} | grep ESTABLISHED")
            if len(obj["result"]) != 0:
                for i in range(len(obj["result"])):
                    obj["result"][i] = obj["result"][i].rstrip("\n")
                a = "\n".join(obj["result"])
                if b := [x for x in a.split(" ") if x != ""]:
                    resultip = b[1].split(":")[0]

    if not resultip:
        if (
            sys.platform.startswith("linux")
            and config.agenttype == "relayserver"
            and hasattr(config, "public_ip")
        ):
            resultip = config.public_ip
            logger.debug(f"Using public IP from configuration: {resultip}")
        else:
            # Determine the most probable network interface
            for interface in interfaces:
                if interface == "":
                    continue
                addrs = netifaces.ifaddresses(interface)
                if netifaces.AF_INET in addrs:
                    resultip = addrs[netifaces.AF_INET][0]["addr"]
                    logger.debug(
                        f"Using IP from the most probable interface: {resultip}"
                    )
                    break
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
    return f"{int(a)}.{int(b)}.{int(c)}.{int(d)}"


def subnetnetwork(adressmachine, mask):
    adressmachine = adressmachine.split(":")[0]
    reseaumachine = ipV4toDecimal(adressmachine) & ipV4toDecimal(mask)
    return decimaltoIpV4(reseaumachine)


def searchippublic(site=1):
    if site == 1:
        try:
            objip = json.loads(urllib.urlopen("http://if.medulla-tech.io/json"))
            return objip["ip"] if is_valid_ipv4(objip["ip"]) else searchippublic(2)
        except BaseException:
            return searchippublic(2)
    elif site == 2:
        try:
            page = urllib.urlopen("http://www.monip.org/").read()
            ip = page.split("IP : ")[1].split("<br>")[0]
            return ip if is_valid_ipv4(ip) else searchippublic(3)
        except Exception:
            return searchippublic(3)
    elif site == 3:
        try:
            ip = urllib.urlopen("http://ip.42.pl/raw").read()
            return ip if is_valid_ipv4(ip) else searchippublic(4)
        except Exception:
            searchippublic(4)
    elif site == 4:
        return find_ip()
    return None

def find_ip():
    """
    Détecte l'adresse IP locale de l'ordinateur en testant plusieurs réseaux publics fictifs.

    La fonction crée une socket UDP et tente de se "connecter" à chaque IP de test
    (ici des plages documentées pour tests et exemples). Même si aucune donnée n'est envoyée,
    l'appel à `connect()` permet à la socket de déterminer automatiquement
    l'adresse IP locale utilisée pour atteindre ce réseau.

    La fonction retourne la **première IP locale détectée**, ou None si impossible.

    Returns:
        str | None: Adresse IP locale détectée, ou None si aucune IP trouvée.
    """

    candidates = []  # Liste des IP locales détectées sur chaque test
    # Liste d'IP de test réservées aux exemples/documentation (pas réelles)
    for test_ip in ["192.0.2.0", "192.51.100.0", "203.0.113.0"]:
        try:
            # Création d'une socket UDP
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            # La connexion ne transmet pas de données, elle sert juste à déterminer l'IP locale
            s.connect((test_ip, 80))
            ip_adrss = s.getsockname()[0]  # Récupère l'adresse locale utilisée

            # Si cette IP a déjà été trouvée, on la retourne immédiatement
            if ip_adrss in candidates:
                return ip_adrss
            candidates.append(ip_adrss)

        except Exception:
            # Ignorer les erreurs de connexion ou de socket
            pass
        finally:
            s.close()  # Toujours fermer la socket pour libérer les ressources

    # Retourne la première IP trouvée, ou None si aucune IP détectée
    return candidates[0] if candidates else None

def pulginmaster(func):
    """
    Décorateur pour les plugins XMPP qui vérifie l'existence d'une session avant d'exécuter la fonction.

    - Si l'action commence par "result", on tronque les 6 premiers caractères.
    - Vérifie si la session `sessionid` existe via `objetxmpp.session.isexist`.
    - Récupère les données de session si elles existent, sinon None.
    - Passe ces informations à la fonction décorée.

    Args:
        func (callable): fonction plugin à décorer.
            Signature attendue : func(objetxmpp, action, sessionid, data, message, ret, objsessiondata)

    Returns:
        callable: wrapper qui gère la vérification de session.

    💡 Commentaire :
    - Simplifie la gestion des plugins en évitant d'avoir à vérifier la session dans chaque plugin.
    """
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
    """
    Décorateur de plugin XMPP avec gestion avancée de session.

    Permet de définir une action sur la session avant et après l'exécution du plugin.

    Args:
        sessionaction (str): action sur la session, ex: "clear" ou "actualise".
        timeminute (int): durée pour actualiser la session en minutes (par défaut 10).

    Usage:
        @pulginmastersessionaction("actualise")
        def mon_plugin(objetxmpp, action, sessionid, data, message, ret, dataobj, objsessiondata):
            ...

    Fonctionnement :
    - Si l'action commence par "result", tronque les 6 premiers caractères.
    - Vérifie si la session existe :
        - "actualise" → réactualise la session avant l'exécution.
    - Exécute la fonction décorée en lui passant `objsessiondata`.
    - Après exécution :
        - "clear" → supprime la session.
        - "actualise" → réactualise la session.

    💡 Commentaire :
    - Utile pour les plugins nécessitant un suivi précis de session.
    - Permet de centraliser la logique de maintenance des sessions.
    """
    def decorateur(func):
        def wrapper(objetxmpp, action, sessionid, data, message, ret, dataobj):
            # Avant l'exécution
            if action.startswith("result"):
                action = action[6:]
            if objetxmpp.session.isexist(sessionid):
                if sessionaction == "actualise":
                    objetxmpp.session.reactualisesession(sessionid, timeminute)
                objsessiondata = objetxmpp.session.sessionfromsessiondata(sessionid)
            else:
                objsessiondata = None

            # Exécution de la fonction décorée
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

            # Après l'exécution
            if sessionaction == "clear" and objsessiondata is not None:
                objetxmpp.session.clear(sessionid)
            elif sessionaction == "actualise":
                objetxmpp.session.reactualisesession(sessionid, timeminute)

            return response

        return wrapper

    return decorateur


def merge_dicts(*dict_args):
    """
    Fusionne plusieurs dictionnaires en un seul.

    Si plusieurs dictionnaires contiennent la même clé, la valeur du dernier dictionnaire
    sera utilisée (comportement du `|=` en Python 3.9+).

    Args:
        *dict_args: dictionnaires à fusionner

    Returns:
        dict: dictionnaire fusionné

    💡 Commentaire :
    - Très utile pour combiner des résultats ou configurations venant de plusieurs sources.
    """
    result = {}
    for dictionary in dict_args:
        result |= dictionary
    return result


def portline(result):
    """
    Extrait le numéro de port à partir d'une ligne de texte formatée.

    Exemple de ligne : "0.0.0.0:80 0.0.0.0:* LISTEN"
    - Sépare la ligne en colonnes
    - Ignore les colonnes vides
    - Retourne le numéro de port (après le caractère ':')

    Args:
        result (str): ligne de texte contenant une adresse IP et un port

    Returns:
        str: numéro de port extrait

    💡 Commentaire :
    - Utile pour analyser la sortie de commandes comme `netstat` ou `ss`.
    - Le code `[ -2:-1 ][0]` prend l'avant-dernière colonne de la ligne, souvent la colonne IP:Port.
    """
    column = [x.strip() for x in result.split(" ") if x != ""]
    print(column)
    return column[-2:-1][0].split(":")[1]


class protodef:
    def __init__(self):
        self.fileprotoinfo = os.path.join(Setdirectorytempinfo(), "fingerprintproto")
        self.boolchangerproto, self.proto = self.protochanged()

    def protoinfoexist(self):
        return bool(os.path.exists(self.fileprotoinfo))

    def protochanged(self):
        if self.protoinfoexist():
            fproto = protodef.protoandport()
            self.fingerprintproto = file_get_binarycontents(self.fileprotoinfo)
            newfingerprint = pickle.dumps(fproto)  # on recalcule le proto
            if self.fingerprintproto == newfingerprint:
                self.proto = fproto
                return False, self.proto
        self.refreshfingerprintproto()
        self.fingerprintproto = file_get_binarycontents(self.fileprotoinfo)
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
                        if cux.status == psutil.CONN_LISTEN and ip in [
                            "0.0.0.0",
                            "::",
                        ]:
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
            logger.error(
                f"The hostname {name_domaine_or_ip} is invalid or temporarily unresolved"
            )
            return ""
        except Exception:
            return ""
    return ""

def data_struct_message(action, data={}, ret=0, base64=False, sessionid=None):
    """
    Crée une structure de message standardisée pour les plugins ou communications XMPP.

    Args:
        action (str): Nom de l'action associée au message.
        data (dict, optional): Contenu du message. Par défaut {}.
        ret (int, optional): Code de retour. Par défaut 0.
        base64 (bool, optional): Indique si les données doivent être encodées en base64. Par défaut False.
        sessionid (str, optional): ID de session. Si None ou invalide, un ID est généré automatiquement.

    Returns:
        dict: dictionnaire avec la structure standard :
            {
                "action": str,
                "data": dict,
                "ret": int,
                "base64": bool,
                "sessionid": str
            }

    💡 Commentaires :
    - Génère un `sessionid` unique si non fourni, basé sur l'action.
    - Simplifie la création de messages pour l'envoi via XMPP ou autre protocole.
    """
    if sessionid is None or sessionid == "" or not isinstance(sessionid, str):
        sessionid = action.strip().replace(" ", "")
    return {
        "action": action,
        "data": data,
        "ret": 0,
        "base64": False,
        "sessionid": getRandomName(4, sessionid),  # Génère un identifiant unique
    }


def check_exist_ip_port(name_domaine_or_ip, port):
    """
    Vérifie si un socket peut se connecter à une IP ou un nom de domaine sur un port donné.

    Args:
        name_domaine_or_ip (str): Nom de domaine ou adresse IP.
        port (int): Numéro de port.

    Returns:
        bool: True si l'adresse et le port sont valides pour une connexion, False sinon.

    💡 Commentaires :
    - Résout le nom de domaine en IP via `ipfromdns`.
    - Utilise `socket.getaddrinfo` pour vérifier la validité de l'adresse et du port.
    - Les erreurs de résolution DNS ou autres exceptions retournent False.
    """
    ip = ipfromdns(name_domaine_or_ip)

    try:
        socket.getaddrinfo(ip, int(port))
        return True
    except socket.gaierror:
        logger.error(
            f"The hostname {name_domaine_or_ip} is invalid or temporarily unresolved"
        )
        return False
    except Exception:
        return False


# -------------------------------------------------------------
# Fonctions spécifiques Windows pour manipuler le registre
# -------------------------------------------------------------
if sys.platform.startswith("win"):

    def set_reg(name, value, subkey, key=wr.HKEY_LOCAL_MACHINE, type=wr.REG_SZ):
        """
        Crée ou modifie une valeur dans le registre Windows.

        Args:
            name (str): Nom de la valeur du registre.
            value (str/int): Valeur à enregistrer.
            subkey (str): Chemin du sous-clé.
            key (int, optional): Clé racine (HKEY_LOCAL_MACHINE par défaut).
            type (int, optional): Type de valeur (ex: REG_SZ, REG_DWORD). Par défaut REG_SZ.

        Returns:
            bool: True si l'opération a réussi, False sinon.

        💡 Commentaires :
        - Crée la clé si elle n'existe pas.
        - Utilise `wr` (winreg) pour ouvrir et écrire la valeur.
        - Doit être exécuté avec les permissions appropriées (ex: admin pour HKEY_LOCAL_MACHINE).
        """
        try:
            wr.CreateKey(key, subkey)
            registry_key = wr.OpenKey(wr.HKEY_CURRENT_USER, subkey, 0, wr.KEY_WRITE)
            wr.SetValueEx(registry_key, name, 0, type, value)
            wr.CloseKey(registry_key)
            return True
        except WindowsError:  # skipcq: PYL-E0602
            return False


    def get_reg(name, subkey, key=wr.HKEY_LOCAL_MACHINE):
        """
        Lit une valeur dans le registre Windows.

        Args:
            name (str): Nom de la valeur du registre.
            subkey (str): Chemin du sous-clé.
            key (int, optional): Clé racine (HKEY_LOCAL_MACHINE par défaut).

        Returns:
            str/int | None: La valeur lue ou None si la clé/valeur n'existe pas.

        💡 Commentaires :
        - Utilise `wr` (winreg) pour ouvrir et lire la valeur.
        - Peut retourner None si la clé ou la valeur n'existe pas ou si permissions insuffisantes.
        """
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
    if msg != "":
        msg = msg.strip('" ')
        msg = f'"{msg}"'
    if sys.platform.startswith("linux"):
        if int(time) == 0 or msg == "":
            cmd = "shutdown now"
        else:
            cmd = f"shutdown -P -f -t {time} {msg}"
        logging.debug(cmd)
        os.system(cmd)
    elif sys.platform.startswith("win"):
        if int(time) == 0 or msg == "":
            cmd = "shutdown /p"
        else:
            cmd = f"shutdown /s /t {time} /c {msg}"
        logging.debug(cmd)
        os.system(cmd)
    elif sys.platform.startswith("darwin"):
        if int(time) == 0 or msg == "":
            cmd = "shutdown -h now"
        else:
            cmd = f'shutdown -h +{time} "{msg}"'
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
    if sys.platform.startswith("linux"):
        return
    if sys.platform.startswith("win"):
        if askpermission == 0:
            cmd = 'reg add "HKLM\\SOFTWARE\\TightVNC\\Server" /f /v QueryAcceptOnTimeout /t REG_DWORD /d 1 && reg add "HKLM\\SOFTWARE\\TightVNC\\Server" /f /v QueryTimeout /t REG_DWORD /d 1 && net stop tvnserver && net start tvnserver'
        else:
            cmd = 'reg add "HKLM\\SOFTWARE\\TightVNC\\Server" /f /v QueryAcceptOnTimeout /t REG_DWORD /d 0 && reg add "HKLM\\SOFTWARE\\TightVNC\\Server" /f /v QueryTimeout /t REG_DWORD /d 20 && net stop tvnserver && net start tvnserver'
        logging.debug(cmd)
        os.system(cmd)


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
    """
    Vérifie si la chaîne donnée est en base64.
    La fonction fait une vérification supplémentaire pour s'assurer que les données décodées peuvent être converties en une chaîne UTF-8.

    Args:
        s (str/bytes/bytearray): La chaîne à vérifier.

    Returns:
        bool: True si la chaîne est en base64, False sinon.
    """
    try:
        if isinstance(s, str):
            s = s.encode("utf-8")
        # Vérification si les caractères appartiennent au jeu de caractères Base64
        if not re.match(b"^[A-Za-z0-9+/]*={0,2}$", s):
            logger.warning(
                "La chaîne contient des caractères non valides pour du base64."
            )
            return False

        decoded = base64.b64decode(s, validate=True)
        decoded.decode("utf-8")
        return True
    except base64.binascii.Error as e:
        logger.warning(f"Erreur de décodage base64 : {e}")
        return False
    except UnicodeDecodeError as e:
        logger.warning(f"base64 mais le décodage UTF-8 erreur : {e}")
        return False
    except Exception as e:
        logger.error(f"Erreur inattendue : {e}")
        return False


def isBase64tostring(s):
    """
    Vérifie si la chaîne donnée est en base64. Si c'est le cas, la fonction la décode en utf-8.

    Args:
        s (str/bytes/bytearray): La chaîne à vérifier et potentiellement décoder.

    Returns:
        str: La chaîne décodée en utf-8 si elle était en base64, sinon la chaîne convertie en utf-8.
    """
    try:
        # Vérifier si la chaîne est en base64 en essayant de la décoder
        decoded = base64.b64decode(s)
        decoded_str = decoded.decode("utf-8")
        return decoded_str
    except (base64.binascii.Error, UnicodeDecodeError):
        # Si une erreur se produit, cela signifie que ce n'est pas du base64, donc on renvoie simplement la chaîne en utf-8
        return str(s, "utf-8")


def decode_strconsole(string_bytes):
    """
    Decode strings into the format used on the OS.
    Supported OS are: linux, windows and darwin

    Args:
       string_bytes : the stringin bytes type we want to encode

    Returns:
        The decoded `x` string
    """
    if isinstance(string_bytes, bytes):
        if sys.platform.startswith("linux"):
            return string_bytes.decode("utf-8", "ignore")
        if sys.platform.startswith("win"):
            return string_bytes.decode("cp850", "ignore")

        if sys.platform.startswith("darwin"):
            return string_bytes.decode("utf-8", "ignore")
    return string_bytes


def encode_strconsole(string_str):
    """
    Encode strings into the format used on the OS.
    Supported OS are: linux, windows and darwin

    Args:
        string_str : the string type str we want to encode

    Returns:
        The encoded `string_str` string type bytes
    """
    if isinstance(string_str, str):
        if sys.platform.startswith("linux"):
            return string_str.encode("utf-8")

        if sys.platform.startswith("win"):
            return string_str.encode("cp850")

        if sys.platform.startswith("darwin"):
            return string_str.encode("utf-8")
    return string_str


def savejsonfile(filename, data, indent=4):
    """
    Sauvegarde un objet Python au format JSON dans un fichier.

    Args:
        filename (str): Chemin du fichier où sauvegarder les données.
        data (any): Objet Python à sauvegarder (dict, list, etc.).
        indent (int, optional): Nombre d'espaces pour l'indentation JSON. Default 4.

    Returns:
        None
    """
    with open(filename, "w") as outfile:
        json.dump(data, outfile)


def loadjsonfile(filename):
    """
    Charge un fichier JSON et retourne son contenu sous forme de structure Python.

    Args:
        filename (str): Chemin du fichier JSON à lire.

    Returns:
        dict/list/None: Contenu décodé du fichier JSON, ou None si le fichier n'existe
        ou en cas d'erreur.
    """
    if os.path.isfile(filename):
        with open(filename, "r") as info:
            dd = info.read()
        try:
            return json.loads(decode_strconsole(dd))
        except Exception as e:
            logger.error(f"filename {filename} error decodage [{str(e)}]")
    return None


def save_user_current(name=None):
    """
    Sauvegarde ou met à jour l'utilisateur courant dans un fichier temporaire JSON
    (loginuser), et retourne le nom de l'utilisateur courant.

    - Si aucun nom n'est fourni, récupère le premier utilisateur actif via psutil.
    - Maintient une liste des 15 derniers utilisateurs les plus fréquents.
    - Incrémente un compteur d'occurrences pour chaque utilisateur.
    - Détermine l'utilisateur courant comme celui apparaissant le plus souvent dans la liste.

    Args:
        name (str, optional): Nom de l'utilisateur à sauvegarder. Si None, utilise le premier
        utilisateur actif. Si "system", utilise le nom "system".

    Returns:
        str: Nom de l'utilisateur courant déterminé après mise à jour du fichier JSON.
    """
    loginuser = os.path.join(Setdirectorytempinfo(), "loginuser")
    if name is None:
        if userlist := list({users[0] for users in psutil.users()}):
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
    datauseruser["suite"] = datauseruser["suite"][:15]

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
                os.path.join("c:\\", "progra~1", "Python3", "Lib", "site-packages"),
                os.path.join("c:\\", "progra~1", "Python3-32", "Lib", "site-packages"),
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
    Convertit un objet datetime UTC en datetime locale.

    Cette fonction prend un datetime UTC (non-naïf, c'est-à-dire avec tzinfo UTC ou supposé en UTC)
    et retourne l'heure correspondante dans le fuseau horaire local de la machine exécutant le code.

    La conversion se fait en calculant le décalage (offset) entre UTC et l'heure locale
    au moment donné.

    Args:
        utc (datetime.datetime): objet datetime en UTC (non-naïf, tzinfo doit être UTC ou implicite)

    Returns:
        datetime.datetime: objet datetime converti en heure locale

    Exemple:
        >>> from datetime import datetime, timezone
        >>> utc_time = datetime(2025, 11, 25, 12, 0, 0, tzinfo=timezone.utc)
        >>> local_time = utc2local(utc_time)
        >>> print(local_time)
        2025-11-25 13:00:00  # si le fuseau local est UTC+1

    💡 Commentaires :
    - `time.mktime(utc.timetuple())` : transforme le datetime UTC en timestamp local (seconds depuis epoch)
    - `datetime.fromtimestamp(epoch)` : interprète ce timestamp dans le fuseau local
    - `datetime.utcfromtimestamp(epoch)` : interprète ce timestamp en UTC
    - La différence entre les deux (`offset`) correspond au décalage horaire local
    - On ajoute cet offset à l'heure UTC pour obtenir l'heure locale
    """
    # Transformer le datetime UTC en timestamp (secondes depuis epoch)
    epoch = time.mktime(utc.timetuple())

    # Calculer le décalage entre l'heure locale et UTC
    offset = datetime.fromtimestamp(epoch) - datetime.utcfromtimestamp(epoch)

    # Ajouter le décalage à l'heure UTC pour obtenir l'heure locale
    return utc + offset


def getHomedrive(username=None):
    """
    Récupère le chemin du répertoire personnel (home) d'un utilisateur donné,
    compatible Windows, Linux et macOS.

    Args:
        username (str, optional): Nom de l'utilisateur.
            - Si None : utilise l'utilisateur courant.

    Returns:
        str: Chemin complet vers le répertoire home de l'utilisateur.
             Retourne None si le home n'a pas pu être déterminé.

    Exemple:
        >>> getHomedrive("pulseuser")
        'C:\\Users\\pulseuser'  # sur Windows
        '/home/pulseuser'       # sur Linux
        '/Users/pulseuser'      # sur macOS

    💡 Commentaires :
    - Windows : lit le registre pour trouver le chemin réel du profil via le SID.
      Si erreur ou échec, retourne `C:\\Users\\username` par défaut.
    - Linux/macOS : utilise `pwd.getpwnam` pour obtenir le home de l'utilisateur.
      Si username=None, utilise `os.path.expanduser("~")`.
    """
    if username is None:
        username = os.getlogin()  # utilisateur courant si non spécifié

    system = platform.system().lower()

    # -----------------------------
    # Windows
    # -----------------------------
    if system == "windows":
        homedrive = os.path.join("C:\\Users", username)
        try:
            # Récupère le SID de l'utilisateur
            usersid = get_user_sid(username)

            # Requête dans le registre pour obtenir ProfileImagePath
            regquery = (
                f'REG QUERY "HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList\\{usersid}" /v "ProfileImagePath" /s'
            )

            resultquery = simplecommand(encode_strconsole(regquery))

            if resultquery["code"] == 0:
                # La ligne contenant le chemin du profil est généralement -3 de la sortie
                homedrive = resultquery["result"][-3].split("    ")[-1].replace("\r\n", "")

        except Exception as e:
            logger.error("Erreur lors de la recuperation du home Windows : %s", e)

        return homedrive.lower()

    # -----------------------------
    # Linux / macOS
    # -----------------------------
    elif system in ["linux", "darwin"]:
        try:
            if username:
                homedrive = pwd.getpwnam(username).pw_dir
            else:
                homedrive = os.path.expanduser("~")
            return homedrive
        except KeyError:
            logger.error("Utilisateur %s non trouve sur le systeme", username)
            return None

    else:
        logger.error("OS non supporté pour getHomedrive: %s", system)
        return None



def keypub():
    """
    Retourne la clé publique SSH (id_rsa.pub) pour l'utilisateur root ou pulseuser selon l'OS.

    - Si la clé privée n'existe pas, elle est générée automatiquement avec ssh-keygen (RSA 2048 bits).
    - Supporte Linux, Windows et macOS.

    Comportement par OS :
        - Linux : utilise /root/.ssh/id_rsa
        - Windows : utilise .ssh dans le répertoire de pulseuser ou fallback vers medullaPath()
        - macOS : utilise /var/root/.ssh/id_rsa

    Returns:
        str: Contenu de la clé publique SSH (id_rsa.pub).

    Notes:
        - La clé privée est générée avec une passphrase vide (-N "").
        - La fonction dépend de `simplecommand()` pour exécuter ssh-keygen
          et de `file_get_contents()` pour lire le fichier.
    """
    keypubstring = ""
    if sys.platform.startswith("linux"):
        if not os.path.isfile("/root/.ssh/id_rsa"):
            obj = simplecommand(
                'ssh-keygen -b 2048 -t rsa -f /root/.ssh/id_rsa -q -N ""'
            )
        return file_get_contents("/root/.ssh/id_rsa.pub")
    elif sys.platform.startswith("win"):
        try:
            win32net.NetUserGetInfo("", "pulseuser", 0)
            pathkey = os.path.join(getHomedrive(pulseuser), ".ssh")
        except:
            pathkey = os.path.join(medullaPath(), ".ssh")
        if not os.path.isfile(os.path.join(pathkey, "id_rsa")):
            obj = simplecommand(
                '"C:\\progra~1\\OpenSSH\\ssh-keygen.exe" -b 2048 -t rsa -f "%s" -q -N ""'
                % os.path.join(pathkey, "id_rsa")
            )
        return file_get_contents(os.path.join(pathkey, "id_rsa.pub"))
    elif sys.platform.startswith("darwin"):
        if not os.path.isfile("/var/root/.ssh/id_rsa"):
            obj = simplecommand(
                'ssh-keygen -b 2048 -t rsa -f /var/root/.ssh/id_rsa -q -N ""'
            )
        return file_get_contents("/var/root/.ssh/id_rsa.pub")

def deletekey(file, key, back=True):
    """
    Supprime une ligne contenant `key` dans un fichier texte.

    Args:
        file (str): Chemin du fichier.
        key (str): Mot-clé à supprimer.
        back (bool, optional): Si True, crée un fichier de sauvegarde (.bak) avant modification. Default True.

    💡 Commentaires :
    - Utilise `sed` pour modifier le fichier directement.
    - Sur Linux/macOS, le fichier est modifié en place.
    - `simplecommand` exécute la commande shell et retourne le résultat.
    """
    if os.path.isfile(file):
        if back:
            simplecommand(f"sed -i.bak '/{key}/d' {file}")
        else:
            simplecommand(f"sed -i '/{key}/d' {file}")


def installkey(file, key, back=True):
    """
    Ajoute une ligne contenant `key` à la fin d'un fichier texte.
    Supprime d'abord les occurrences existantes pour éviter les doublons.

    Args:
        file (str): Chemin du fichier.
        key (str): Contenu à ajouter.
        back (bool, optional): Si True, crée un fichier de sauvegarde lors de la suppression. Default True.

    💡 Commentaires :
    - Appelle `deletekey` avant d'ajouter pour assurer l'unicité.
    - Utilise `echo >>` pour ajouter la ligne à la fin.
    """
    deletekey(file, key, back=back)
    simplecommand(f'echo "{key}" >> {file}')


def connection_established(Port):
    """
    Vérifie si une connexion TCP sur un port donné est établie.

    Args:
        Port (int or str): Numéro de port à vérifier.

    Returns:
        bool: True si une connexion ESTABLISHED est trouvée, False sinon.

    💡 Commentaires :
    - Utilise `netstat` ou `findstr` selon le système.
    - Filtre les connexions TCP établies et ignore IPv6 sur Linux.
    - Avertit via logger si aucune connexion trouvée.
    """
    if sys.platform.startswith("linux"):
        obj = simplecommandstr(
            f"netstat -an |grep {Port} | grep ESTABLISHED | grep -v tcp6"
        )
    elif sys.platform.startswith("win"):
        obj = simplecommandstr(f"netstat -an | findstr {Port} | findstr ESTABLISHED")
    elif sys.platform.startswith("darwin"):
        obj = simplecommandstr(f"netstat -an |grep {Port} | grep ESTABLISHED")

    if "ESTABLISHED" in obj["result"]:
        return True
    logger.warning("connection xmpp low")
    return False


def showlinelog(nbline=200, logfile=None):
    """
    Lit les dernières lignes d'un fichier log.

    Args:
        nbline (int, optional): Nombre de lignes à lire. Default 200.
        logfile (str, optional): Chemin du fichier log. Si None, prend le log par défaut du système.

    Returns:
        str: Contenu des dernières lignes du fichier log.

    💡 Commentaires :
    - Windows : utilise PowerShell `Get-Content | select -last`.
    - Linux : utilise `cat | tail -n`.
    - Retourne une chaîne vide si le fichier n'existe pas.
    """
    obj = {"result": ""}
    if logfile is not None:
        na = logfile

    if sys.platform.startswith("win"):
        if logfile is None:
            na = os.path.join(
                medullaPath(),
                "var",
                "log",
                "xmpp-agent-machine.log",
            )
        if os.path.isfile(na):
            obj = simplecommandstr(
                encode_strconsole(
                    f"powershell \"Get-Content '{na}' | select -last {nbline}\""
                )
            )
    elif sys.platform.startswith("linux"):
        if logfile is None:
            na = os.path.join("/", "var", "log", "pulse", "xmpp-agent-machine.log")
        if os.path.isfile(na):
            obj = simplecommandstr(f"cat {na} | tail -n {nbline}")

    return obj["result"]


def is_findHostfromHostname(hostname):
    """
    Vérifie si un nom d'hôte peut être résolu en adresse IP.

    Args:
        hostname (str): Nom de domaine ou hostname à vérifier.

    Returns:
        bool: True si le hostname est résolu, False sinon.

    💡 Commentaires :
    - Utilise `socket.gethostbyname`.
    - Les exceptions sont ignorées, renvoie False si échec.
    """
    try:
        host = socket.gethostbyname(hostname)
        return True
    except BaseException:
        pass
    return False


def is_findHostfromIp(ip):
    """
    Vérifie si une adresse IP peut être résolue en nom d'hôte.

    Args:
        ip (str): Adresse IP à vérifier.

    Returns:
        bool: True si l'IP est résolue, False sinon.

    💡 Commentaires :
    - Utilise `socket.gethostbyaddr`.
    - Les exceptions sont ignorées, renvoie False si échec.
    """
    try:
        host = socket.gethostbyaddr(ip)
        return True
    except BaseException:
        pass
    return False


def is_connectedServer(ip, port):
    """
    Vérifie si une connexion TCP peut être établie vers un serveur et port donnés.

    Args:
        ip (str): Adresse IP du serveur.
        port (int or str): Port TCP du serveur.

    Returns:
        bool: True si la connexion est réussie, False sinon.

    💡 Commentaires :
    - Utilise `socket.socket` avec timeout de 5 secondes.
    - Ferme toujours le socket dans le bloc `finally`.
    """
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
        # flag windows ->
        # https://docs.microsoft.com/fr-fr/windows/desktop/ProcThread/process-creation-flags

        if sys.platform.startswith("win"):
            CREATE_NEW_PROCESS_GROUP = 0x00000200
            DETACHED_PROCESS = 0x00000008
            progrm = subprocess.Popen(
                pathprogram,
                shell=False,
                creationflags=DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP,
                close_fds=True,
            )
            self.programlist[uniqexecutablename] = progrm
        elif sys.platform.startswith("linux") or sys.platform.startswith("darwin"):
            progrm = subprocess.Popen(
                pathprogram, shell=True, stdout=None, stderr=None, close_fds=True
            )
            self.programlist[uniqexecutablename] = progrm
        else:
            self.logger.error(
                "The launch command for syncthing is not implemented for this OS"
            )

    def stopprogram(self, uniqexecutablename):
        subprocess.Popen.kill(self.programlist[uniqexecutablename])
        del self.programlist[uniqexecutablename]

    def stopallprogram(self):
        for prog in self.programlist:
            subprocess.Popen.kill(self.programlist[prog])
        self.programlist.clear()


def check_socket_status(port):
    """
    Vérifie l'état d'un port socket.

    Cette fonction utilise la commande `netstat` pour vérifier l'état d'un port
    spécifié sur Windows, Linux ou macOS.

    Args:
        port (int): Le port à vérifier.

    Returns:
        str: Le statut du port (e.g., 'LISTEN', 'ESTABLISHED').
        None: Si le port n'est pas trouvé.

    Raises:
        OSError: Si le système d'exploitation n'est pas supporté.
    """
    # Déterminer la commande appropriée pour le système d'exploitation
    system = platform.system().lower()
    if system in ["windows", "linux", "darwin"]:
        # Commande netstat pour les systèmes Windows, Linux et macOS
        if system == "windows":
            result = subprocess.run(["netstat", "-an"], capture_output=True, text=True)
        else:
            result = subprocess.run(["netstat", "-tan"], capture_output=True, text=True)

        # Filtrer les lignes contenant le port
        lines = result.stdout.splitlines()
        port_line = [line for line in lines if f":{port} " in line]

        if port_line:
            # Extraire le statut de la ligne
            status = port_line[0].split()[-1]
            return status
        else:
            return None
    else:
        raise OSError(f"Système d'exploitation non supporté : {system}")

def get_process_using_port_details(port):
    """
    Obtient le processus utilisant un port spécifié, multi-OS.

    Args:
        port (int): Numéro du port TCP ou UDP.

    Returns:
        dict: Informations sur le processus utilisant le port.
              Exemple : {"pid": 1234, "name": "python", "status": "running"}
              Si aucun processus n’utilise le port, retourne None.

    Notes:
        - Sur Linux/macOS : utilise psutil pour lister les connections.
        - Sur Windows : utilise psutil aussi pour éviter les commandes netstat externes.
    """
    port = int(port)
    system = platform.system().lower()

    for conn in psutil.net_connections(kind='inet'):
        if conn.laddr.port == port:
            try:
                proc = psutil.Process(conn.pid)
                return {
                    "pid": conn.pid,
                    "name": proc.name(),
                    "status": proc.status(),
                    "local_address": f"{conn.laddr.ip}:{conn.laddr.port}",
                    "remote_address": f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else None,
                    "type": conn.type
                }
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                return {"pid": conn.pid, "name": None, "status": None}
    return None

def get_process_using_port(port):
    """
    Obtient le processus utilisant un port spécifié.

    Cette fonction utilise `lsof` sur Unix-like et `netstat` sur Windows
    pour trouver le processus qui utilise un port donné.

    Args:
        port (int): Le port à vérifier.

    Returns:
        str: Les informations du processus utilisant le port ou un message d'erreur.
    """
    system = platform.system()

    if system in ["Linux", "Darwin"]:
        command = ["lsof", "-i", f":{port}"]
    elif system == "Windows":
        command = ["netstat", "-ano"]
    else:
        return f"Système d'exploitation non supporté : {system}"

    try:
        result = subprocess.run(command, capture_output=True, text=True, check=True)
        if system == "Windows":
            # Filtrer la sortie pour trouver le port spécifique
            lines = result.stdout.splitlines()
            for line in lines:
                if (
                    f":{port} " in line
                ):  # espace après le port pour éviter les mauvaises correspondances
                    return line
            return f"Aucun processus n'utilise le port {port}."
        else:
            return result.stdout
    except subprocess.CalledProcessError as e:
        return f"Erreur : {e}"


def process_exists(pid):
    """
    Vérifie si un processus existe, multi-OS.

    Args:
        pid (int): Identifiant du processus à vérifier.

    Returns:
        bool: True si le processus existe, False sinon.

    Notes:
        - Utilise psutil pour être compatible Linux, macOS et Windows.
    """
    return psutil.pid_exists(pid)


def kill_process(pid):
    """
    Tue un processus par son PID.

    Cette fonction tente de tuer un processus donné par son PID sur Windows,
    Linux et macOS.

    Args:
        pid (int): L'identifiant du processus à tuer.

    Returns:
        bool: True si le processus a été tué avec succès, False sinon.
    """
    system = platform.system()
    if system == "Windows":
        try:
            subprocess.run(["taskkill", "/F", "/T", "/PID", str(pid)], check=True)
            logger.debug(f"Le processus avec le PID {pid} a été tué sur Windows.")
            return True
        except subprocess.CalledProcessError as e:
            logger.error(
                f"Echec de la tentative de tuer le processus avec le PID {pid} sur Windows : {e}"
            )
            return False
    elif system in ["Linux", "Darwin"]:
        try:
            subprocess.run(["kill", "-9", str(pid)], check=True)
            logger.debug(
                f"Le processus avec le PID {pid} a ete tue sur un systeme Unix-like."
            )
            return True
        except subprocess.CalledProcessError as e:
            logger.error(
                f"Echec de la tentative de tuer le processus avec le PID {pid} sur un systeme Unix-like : {e}"
            )
            return False
    else:
        logger.error(f"Systeme d exploitation non supporte : {system}")
        return False


def kill_process_tree(pid, parentprocess=False):
    """
    Tue un processus et tous ses processus enfants.

    Args:
        pid (int): L'identifiant du processus parent à tuer.
        parentprocess (bool): Indique si le processus parent doit également être tué.

    Returns:
        None
    """
    try:
        # Trouver tous les processus enfants du processus parent donné
        parent = psutil.Process(pid)
        children = parent.children(recursive=True)

        # Tuer chaque processus enfant récursivement
        for child in children:
            kill_process_tree(child.pid)

        # Tuer le processus enfant lui-même
        for child in children:
            child.terminate()
            child.wait(timeout=5)  # Attendre que le processus soit terminé
        if parentprocess:
            # Tuer le processus parent lui-même
            parent.terminate()
            parent.wait(timeout=5)  # Attendre que le processus soit terminé
    except psutil.NoSuchProcess:
        pass
    except psutil.AccessDenied:
        logger.error(f"Permission refusee pour terminer le processus {pid}")
    except psutil.TimeoutExpired:
        logger.error(
            f"Delai d attente expire lors de la tentative de terminer le processus {pid}"
        )

class AESCipher:
    """
    Classe pour chiffrer et déchiffrer des données avec AES en mode CBC.

    Args:
        key (str or bytes): Clé de chiffrement AES. Doit être 16, 24 ou 32 octets.
        BS (int, optional): Taille du bloc AES. Par défaut 32.

    Méthodes principales :
        - encrypt(raw): chiffre une chaîne et retourne une chaîne Base64.
        - encrypt_base64_byte(raw): chiffre une chaîne et retourne bytes Base64.
        - decrypt(enc): déchiffre une chaîne Base64 en texte.
        - decrypt_base64_byte(enc): déchiffre et retourne bytes.

    Notes :
        - CBC nécessite un vecteur d'initialisation (IV) aléatoire pour chaque chiffrement.
        - Les données sont remplies (_padding_) pour que la longueur soit un multiple du bloc.
        - Utilise PKCS#7 padding.
    """

    def __init__(self, key, BS=32):
        # Assurer que la clé est en bytes
        self.key = key.encode("utf-8") if isinstance(key, str) else key
        self.BS = BS  # Taille du bloc AES

    def _bchr(self, s):
        """Retourne un octet correspondant à un entier s (0-255)."""
        return bytes([s])

    def bord(self, s):
        """Méthode placeholder, retourne simplement s inchangé."""
        return s

    def pad(self, data_to_pad):
        """
        Ajoute du padding PKCS#7 pour que la longueur soit un multiple de BS.

        Args:
            data_to_pad (bytes): Données à chiffrer.

        Returns:
            bytes: Données avec padding ajouté.
        """
        padding_len = self.BS - len(data_to_pad) % self.BS  # calcul du padding
        padding = self._bchr(padding_len) * padding_len
        return data_to_pad + padding

    def encrypt_base64_byte(self, raw):
        """
        Chiffre les données et retourne le résultat en Base64 (bytes).

        Args:
            raw (str or bytes): Données à chiffrer.

        Returns:
            bytes: Données chiffrées en Base64.
        """
        if isinstance(raw, str):
            raw = raw.encode("utf-8")
        iv = Random.new().read(AES.block_size)  # vecteur d'initialisation aléatoire
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        result = iv + cipher.encrypt(self.pad(raw))  # IV + données chiffrées
        return base64.b64encode(result)

    def encrypt(self, raw):
        """
        Chiffre une chaîne et retourne une chaîne Base64.

        Args:
            raw (str): Données à chiffrer.

        Returns:
            str: Données chiffrées en Base64 sous forme de chaîne.
        """
        return self.encrypt_base64_byte(raw).decode("utf-8")

    def decrypt(self, enc):
        """
        Déchiffre une chaîne ou bytes encodée en Base64.

        Args:
            enc (str or bytes): Données chiffrées Base64.

        Returns:
            str: Données déchiffrées (texte UTF-8).
        """
        if isinstance(enc, str):
            enc = enc.encode("utf-8")
        enc = base64.b64decode(enc)
        iv = enc[:AES.block_size]  # récupérer le vecteur d'initialisation
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return self._unpad(cipher.decrypt(enc[AES.block_size:]))

    def decrypt_base64_byte(self, enc):
        """
        Déchiffre une chaîne Base64 et retourne bytes.

        Args:
            enc (str or bytes): Données chiffrées Base64.

        Returns:
            bytes: Données déchiffrées en bytes.
        """
        return self.decrypt(enc).encode("utf-8")

    def _unpad(self, s):
        """
        Retire le padding PKCS#7 après déchiffrement.

        Args:
            s (bytes): Données chiffrées.

        Returns:
            str: Données déchiffrées en UTF-8.
        """
        # ord(s[-1:]) donne la valeur de padding ajoutée
        dtrdata = s[:-ord(s[-1:])]
        return dtrdata.decode("utf-8")

def setgetcountcycle(data=None):
    """
    Lit ou met à jour le compteur de cycle alternatif stocké dans un fichier.

    Comportement :
        - Si data est None : réinitialise le compteur à 0 et retourne 0.
        - Si data est -1 : retourne la valeur actuelle sans modification.
        - Si data >= 0 : ajoute data au compteur existant et retourne la nouvelle valeur.

    Args:
        data (int, optional): Valeur à ajouter ou code spécial (-1, None). Default None.

    Returns:
        int: Valeur actuelle du compteur après traitement.
    """
    chemin = os.path.join(
        os.path.dirname(os.path.realpath(__file__)),
        "..",
        "cycle",
        "countcyclealternatif",
    )
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
        countcyclealternatif += data
        file_put_contents(chemin, str(countcyclealternatif))
        return countcyclealternatif


def setgetrestart(data=None):
    """
    Lit ou met à jour le flag de redémarrage stocké dans un fichier.

    Comportement :
        - Si data est None ou 0 : réinitialise le flag à 0 et retourne 0.
        - Si data est -1 : retourne la valeur actuelle sans modification.
        - Si data est 1 : met le flag à 1 et retourne 1.

    Args:
        data (int, optional): Valeur du flag (-1, 0, 1). Default None.

    Returns:
        int: Valeur actuelle du flag après traitement.
    """
    chemin = os.path.join(
        os.path.dirname(os.path.realpath(__file__)), "..", "cycle", "restart"
    )
    try:
        restart = int(file_get_contents(chemin).strip(" \n\t"))
    except Exception:
        restart = 0
        data = None
    if data is None or data != -1 and data == 0:
        file_put_contents(chemin, "0")
        return 0
    elif data == -1:
        return restart
    elif data == 1:
        file_put_contents(chemin, "1")
        return 1

def detectantivirus():
    """
    Detecte les produits de sécurité installés sur Windows : Antivirus, Firewall et AntiSpyware.

    Utilise PowerShell et Get-CimInstance pour interroger l'espace de noms SecurityCenter2,
    récupère les propriétés principales et décode l'état du produit.

    Returns:
        dict: Un dictionnaire contenant les informations de chaque type de protection.
              Exemple :
              {
                  "Antivirus": [ {...}, {...} ],
                  "Firewall": [ {...} ],
                  "AntiSpyware": [ {...} ]
              }
    """

    def SECURITY_PROVIDER(keyobject, data):
        """
        Décode le fournisseur de sécurité depuis les 2 premiers caractères de productState hex.

        Args:
            keyobject (str): Le type de produit (Antivirus, Firewall, AntiSpyware)
            data (str): productState en hex

        Returns:
            str: Nom du fournisseur de sécurité ou 'NONE'
        """
        prefix = data[:2]
        mapping = {
            "00": "NONE",
            "01": "FIREWALL",
            "02": "AUTOUPDATE_SETTINGS",
            "04": "ANTIVIRUS",
            "08": "ANTISPYWARE",
            "16": "INTERNET_SETTINGS",
            "32": "USER_ACCOUNT_CONTROL",
            "64": "SERVICE",
        }
        return mapping.get(prefix, keyobject.upper())

    def SECURITY_PRODUCT_STATE(data):
        """
        Décode l'état du produit depuis les caractères 3-4 du productState hex.

        Args:
            data (str): productState en hex

        Returns:
            str: Etat du produit (OFF, ON, EXPIRED, SNOOZED, UNKNOWN)
        """
        code = data[2:4]
        mapping = {
            "00": "OFF",
            "01": "EXPIRED",
            "10": "ON",
            "11": "SNOOZED",
        }
        return mapping.get(code, "UNKNOWN")

    def SECURITY_SIGNATURE_STATUS(data):
        """
        Décode l'état de la signature depuis les caractères 5-6 du productState hex.

        Args:
            data (str): productState en hex

        Returns:
            str: Etat de la signature (UP_TO_DATE, OUT_OF_DATE, UNKNOWN)
        """
        code = data[4:6]
        mapping = {
            "00": "UP_TO_DATE",
            "10": "OUT_OF_DATE",
        }
        return mapping.get(code, "UNKNOWN")

    def elemenstructure():
        """
        Structure vide pour un produit de sécurité.

        Returns:
            dict: dictionnaire avec toutes les clés par défaut.
        """
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

    if not sys.platform.startswith("win"):
        raise EnvironmentError("Cette fonction est uniquement disponible sur Windows.")

    result = {}
    # Pour chaque type de produit, exécuter Get-CimInstance via PowerShell et récupérer JSON
    product_classes = {
        "Antivirus": "AntiVirusProduct",
        "Firewall": "FirewallProduct",
        "AntiSpyware": "AntiSpywareProduct",
    }

    for key, cls in product_classes.items():
        cmd = (
            f"powershell -Command "
            f"\"Get-CimInstance -Namespace root/SecurityCenter2 -ClassName {cls} | ConvertTo-Json\""
        )
        p = subprocess.run(cmd, shell=True, capture_output=True, text=True)

        try:
            # Convertir la sortie JSON en liste
            data_list = json.loads(p.stdout)
            if isinstance(data_list, dict):
                data_list = [data_list]
        except json.JSONDecodeError:
            data_list = []

        result[key] = []

        for item in data_list:
            infoprotection = elemenstructure()
            # Remplir les propriétés disponibles
            infoprotection["displayName"] = item.get("displayName", "").strip()
            infoprotection["instanceGuid"] = item.get("instanceGuid", "").strip()
            infoprotection["pathToSignedProductExe"] = item.get("pathToSignedProductExe", "").strip()
            infoprotection["pathToSignedReportingExe"] = item.get("pathToSignedReportingExe", "").strip()
            infoprotection["productState"] = item.get("productState", 0)
            # Convertir en hex et décoder les états
            infoprotection["hex"] = f"{infoprotection['productState']:06x}"
            infoprotection["SECURITY_PROVIDER"] = SECURITY_PROVIDER(key, infoprotection["hex"])
            infoprotection["SECURITY_PRODUCT_STATE"] = SECURITY_PRODUCT_STATE(infoprotection["hex"])
            infoprotection["SECURITY_SIGNATURE_STATUS"] = SECURITY_SIGNATURE_STATUS(infoprotection["hex"])
            infoprotection["timestamp"] = item.get("timestamp", "").strip()
            result[key].append(infoprotection)

    return result


def information_machine():
    """
    Récupère les informations de la classe Win32_ComputerSystem via Get-CimInstance
    et retourne un dictionnaire contenant les propriétés de la machine.

    Returns:
        dict: Un dictionnaire contenant les propriétés de Win32_ComputerSystem.
    """
    result = {}

    # Vérifie si le système est Windows
    if sys.platform.startswith("win"):
        # Commande PowerShell pour récupérer les informations via Get-CimInstance
        ps_command = (
            "powershell -Command "
            "\"Get-CimInstance -ClassName Win32_ComputerSystem | ConvertTo-Json -Depth 3\""
        )

        # Exécute la commande PowerShell et récupère le résultat en JSON
        try:
            output = subprocess.check_output(ps_command, shell=True, text=True)
            # Parse le JSON pour obtenir un dictionnaire Python
            cim_data = json.loads(output)

            # Remplit le dictionnaire de résultat avec les propriétés disponibles
            for prop in cim_data["CimInstanceProperties"]:
                name = prop["Name"]
                value = prop["Value"]
                # Ignore les valeurs None ou NullValue
                if value is not None and not prop.get("Flags", "").endswith("NullValue"):
                    result[name] = value

            # Ajoute les propriétés directes (non imbriquées dans CimInstanceProperties)
            for key, value in cim_data.items():
                if key not in ["CimInstanceProperties", "CimSystemProperties", "CimClass"] and value is not None:
                    result[key] = value

        except subprocess.CalledProcessError as e:
            print(f"Erreur lors de l execution de la commande PowerShell: {e}")
        except json.JSONDecodeError as e:
            print(f"Erreur lors du decodage du JSON: {e}")

    return result

def sshdup():
    """
    Vérifie si le service SSH (sshd) est en cours d'exécution sur la machine.

    Cette fonction est multiplateforme et fonctionne sur Linux, macOS (Darwin) et Windows.
    Elle utilise des commandes système spécifiques à chaque OS pour détecter si le service SSH est actif.

    Returns:
        bool: True si le service SSH est en cours d'exécution, False sinon.
    """
    if sys.platform.startswith("linux"):
        # Sur Linux, on vérifie si le processus "sshd" est présent (en excluant les faux positifs comme "grep")
        cmd = "ps aux | grep sshd | grep -v grep | grep -v pts"
        result = simplecommand(cmd)
        return result["code"] == 0  # Code 0 signifie que le processus est trouvé

    elif sys.platform.startswith("darwin"):
        # Sur macOS, on utilise launchctl pour vérifier si le service com.openssh.sshd est chargé
        cmd = "launchctl list com.openssh.sshd"
        result = simplecommand(cmd)
        return result["code"] == 0  # Code 0 signifie que le service est actif

    elif sys.platform.startswith("win"):
        # Sur Windows, on utilise TASKLIST pour vérifier si "sshd" est dans la liste des processus
        cmd = "TASKLIST | FINDSTR sshd"
        result = simplecommand(cmd)
        if len(result["result"]) > 0:
            return True  # Le processus "sshd" est trouvé

    return False  # Par défaut, retourne False si le service n'est pas détecté


def restartsshd():
    """
    Redémarre le service SSH (sshd) si celui-ci n'est pas en cours d'exécution.

    Cette fonction est multiplateforme et utilise des commandes spécifiques à chaque OS pour redémarrer le service SSH.
    Elle vérifie d'abord si le service est actif avec `sshdup()`. Si ce n'est pas le cas, elle tente de le redémarrer.
    """
    if sys.platform.startswith("linux"):
        # Sur Linux, on redémarre le service sshd avec systemctl
        if not sshdup():
            cmd = "systemctl restart sshd"  # Note: "systemctrl" est une faute de frappe, corrigée en "systemctl"
            result = simplecommand(cmd)

    elif sys.platform.startswith("darwin"):
        # Sur macOS, on redémarre le service SSH via launchctl
        if not sshdup():
            cmd = "launchctl restart /System/Library/LaunchDaemons/ssh.plist"
            result = simplecommand(cmd)

    elif sys.platform.startswith("win"):
        # Sur Windows, on cherche le nom exact du service SSH et on le démarre
        if not sshdup():
            # Récupère le nom du service SSH (ex: "sshd" ou "OpenSSH Server")
            cmd = 'sc query state= all | findstr "sshd" | findstr "SERVICE_NAME"'
            result = simplecommand(cmd)
            if len(result["result"]) > 0:
                try:
                    # Extrait le nom du service depuis la sortie de la commande
                    nameservice = result["result"][0].split()[1]
                    # Démarre le service
                    cmd = f'sc start "{nameservice}"'
                    result = simplecommand(cmd)
                except Exception:
                    # En cas d'erreur, on ignore silencieusement
                    pass

def make_tarfile(output_file_gz_bz2, source_dir, compresstype="gz"):
    """
    Crée une archive compressée au format tar.gz ou tar.bz2 à partir d'un répertoire source.

    Args:
        output_file_gz_bz2 (str): Chemin complet du fichier de sortie (ex: "/chemin/vers/archive.tar.gz").
        source_dir (str): Répertoire source à archiver.
        compresstype (str, optional): Type de compression. Valeurs possibles : "gz" (par défaut) ou "bz2".

    Returns:
        bool: True si l'archivage a réussi, False en cas d'erreur.
    """
    try:
        # Ouvre le fichier de sortie en mode écriture avec le type de compression spécifié
        with tarfile.open(output_file_gz_bz2, f"w:{compresstype}") as tar:
            # Ajoute le répertoire source à l'archive, en utilisant le nom de base du répertoire comme nom dans l'archive
            tar.add(source_dir, arcname=os.path.basename(source_dir))
        return True
    except Exception as e:
        # En cas d'erreur, log l eur et retourne False
        logger.error(f"Erreur lors de la creation de l archive tar.{compresstype} : {str(e)}")
        return False

def extract_file(input_file_gz_bz2, to_directory=".", compresstype="gz"):
    """
    Extrait une archive compressée (tar.gz ou tar.bz2) dans un répertoire de destination.

    Args:
        input_file_gz_bz2 (str): Chemin complet du fichier d'archive à extraire.
        to_directory (str, optional): Répertoire de destination pour l'extraction. Par défaut, le répertoire courant (".").
        compresstype (str, optional): Type de compression de l'archive. Valeurs possibles : "gz" (par défaut) ou "bz2".

    Returns:
        bool: True si l'extraction a réussi, False en cas d'erreur.
    """
    cwd = os.getcwd()  # Sauvegarde le répertoire courant
    absolutepath = os.path.abspath(input_file_gz_bz2)  # Convertit le chemin en chemin absolu

    try:
        # Change le répertoire de travail pour la destination d'extraction
        os.chdir(to_directory)
        # Ouvre l'archive et extrait tout son contenu
        with tarfile.open(absolutepath, f"r:{compresstype}") as tar:
            tar.extractall()
        return True
    except Exception as e:
        # En cas d'erreur, log l eur et retourne False
        logger.error(f"Erreur lors de l extraction de l archive tar.{compresstype} : {str(e)}")
        return False
    finally:
        # Restaure le répertoire de travail initial
        os.chdir(cwd)


def find_files(directory, pattern):
    """
    Génère tous les fichiers dans un répertoire et ses sous-répertoires
    qui correspondent à un motif donné (wildcard).

    Args:
        directory (str): Répertoire de départ pour la recherche.
        pattern (str): Motif de fichier à rechercher (ex: '*.txt').

    Yields:
        str: Chemin complet des fichiers correspondant au motif.
    """
    for root, dirs, files in os.walk(directory):
        for basename in files:
            if fnmatch.fnmatch(basename, pattern):
                yield str(os.path.join(root, basename))


def listfile(directory, abspath=True):
    """
    Liste tous les fichiers dans un répertoire et ses sous-répertoires.

    Args:
        directory (str): Répertoire de départ.
        abspath (bool): Si True, retourne le chemin absolu, sinon juste le nom du fichier.

    Returns:
        list: Liste des fichiers trouvés.
    """
    listfile = []
    for root, dirs, files in os.walk(directory):
        for basename in files:
            if abspath:
                listfile.append(os.path.join(root, basename))
            else:
                listfile.append(os.path.join(basename))
    return listfile

def md5folder(directory):
    """
    Calcule le hash MD5 de tous les fichiers dans un répertoire et ses sous-répertoires.
    Le hash final est un MD5 cumulatif des MD5 de chaque fichier.

    Args:
        directory (str): Répertoire dont on veut calculer le hash.

    Returns:
        str: MD5 cumulatif de tous les fichiers.
    """
    hash = hashlib.md5()
    for root, dirs, files in os.walk(directory):
        for basename in files:
            hash.update(md5(os.path.join(root, basename)))  # md5() doit renvoyer le hash du fichier
    return hash.hexdigest()

def _path_package():
    """
    Renvoie le chemin du répertoire des packages principaux.

    Returns:
        str: Chemin absolu vers /var/lib/pulse2/packages
    """
    return os.path.join("/", "var", "lib", "pulse2", "packages")


def _path_packagequickaction():
    """
    Renvoie le chemin du répertoire pour les quick deployment packages.
    Crée le répertoire s'il n'existe pas.

    Returns:
        str: Chemin absolu vers /var/lib/pulse2/qpackages
    """
    pathqd = os.path.join("/", "var", "lib", "pulse2", "qpackages")
    if not os.path.isdir(pathqd):
        try:
            os.makedirs(pathqd)
        except OSError as e:
            logger.error(
                f"Error creating folder for quick deployment packages : {str(e)}"
            )
    return pathqd


def qdeploy_generate(folder, max_size_stanza_xmpp):
    """
    Génère un quick deployment package (.xmpp) pour un dossier de package donné.

    Vérifie plusieurs conditions :
        - Si le package a des dépendances, aucun package rapide n'est généré.
        - Si un package rapide existe et a moins de 10 minutes, il est mis à jour.
        - Si la taille du package dépasse max_size_stanza_xmpp, aucun package rapide n'est généré.
        - Sinon, génère le package rapide et calcule le MD5 pour détection de modifications.

    Args:
        folder (str): Chemin du dossier du package.
        max_size_stanza_xmpp (int): Taille maximale du package pour quick deployment.

    Returns:
        int: Code de retour :
            0 : package généré avec succès
            1 : package déjà existant et identique
            2 : package existant récent, pas besoin de régénération
            3 : package a des dépendances, pas de package rapide
            6 : package trop volumineux
            100 : erreur lors de la génération
    """
    try:
        namepackage = os.path.basename(folder)
        pathaqpackage = os.path.join(_path_packagequickaction(), namepackage)
        pathxmpppackage = f"{pathaqpackage}.xmpp"

        # if dependency in package do not generate the qpackage
        with open(os.path.join(folder, "xmppdeploy.json")) as json_data:
            data_dict = json.load(json_data)
        if len(data_dict["info"]["Dependency"]) > 0:
            logger.debug(
                f"Package {pathxmpppackage} has dependencies. Quick deployment package not generated."
            )
            logger.debug(
                f"Deleting quick deployment package if found {pathxmpppackage}"
            )
            try:
                if "qpackages" in pathaqpackage:
                    simplecommand(f"rm {pathaqpackage}.*")
            except Exception:
                pass
            return 3

        if (
            os.path.exists(pathxmpppackage)
            and int((time.time() - os.stat(pathxmpppackage).st_mtime)) < 600
        ):
            logger.debug(
                f"No need to generate quick deployment package {pathxmpppackage}"
            )
            simplecommand(f"touch -c {pathxmpppackage}")
            return 2
        else:
            logger.debug(
                f"Deleting quick deployment package if found {pathxmpppackage}"
            )
            try:
                if "qpackages" in pathaqpackage:
                    simplecommand(f"rm {pathaqpackage}.*")
            except Exception:
                pass
        logger.debug("Checking if quick deployment package needs to be generated")

        result = simplecommand(f"du -b {folder}")
        taillebytefolder = int(result["result"][0].split()[0])
        if taillebytefolder > max_size_stanza_xmpp:
            logger.debug(
                "Package is too large for quick deployment.\n%s"
                " greater than defined max_size_stanza_xmpp %s"
                % (taillebytefolder, max_size_stanza_xmpp)
            )
            logger.debug(
                f"Deleting quick deployment package if found {pathxmpppackage}"
            )
            try:
                if "qpackages" in pathaqpackage:
                    simplecommand(f"rm {pathaqpackage}.*")
            except Exception:
                pass
            return 6
            # creation d'un targetos
        logger.debug(f"Preparing quick deployment package for package {namepackage}")
        calculemd5 = md5folder(pathaqpackage)

        if os.path.exists(f"{pathaqpackage}.md5"):
            content = file_get_contents(f"{pathaqpackage}.md5")
            if content == calculemd5:
                # pas de modifications du package
                logger.debug("Quick deployment package found")
                # creation only si if fille missing
                create_msg_xmpp_quick_deploy(folder, create=False)
                return 1
        file_put_contents(f"{pathaqpackage}.md5", calculemd5)
        create_msg_xmpp_quick_deploy(folder, create=True)
        return 0
    except Exception:
        logger.error(f"Error generating quick deployment package : {folder}")
        logger.error(f"{traceback.format_exc()}")
        try:
            if "qpackages" in pathaqpackage:
                simplecommand(f"rm {pathaqpackage}.*")
        except Exception:
            pass
        return 100


def get_message_xmpp_quick_deploy(folder, sessionid):
    """
    Lit le message XMPP généré pour un package rapide et remplace le placeholder de session.

    Args:
        folder (str): Chemin du dossier du package.
        sessionid (str): Identifiant de session à insérer dans le message.

    Returns:
        str: Message XMPP final avec sessionid.
    """
    namepackage = os.path.basename(folder)
    pathaqpackage = os.path.join(_path_packagequickaction(), namepackage)
    with open(f"{pathaqpackage}.xmpp", "r") as f:
        data = f.read()
    return data.replace("@-TEMPLSESSQUICKDEPLOY@", sessionid, 1)


def get_template_message_xmpp_quick_deploy(folder):
    """
    Lit le template du message XMPP pour un package rapide (sans session).

    Args:
        folder (str): Chemin du dossier du package.

    Returns:
        str: Contenu du template XMPP.
    """
    namepackage = os.path.basename(folder)
    pathaqpackage = os.path.join(_path_packagequickaction(), namepackage)
    with open(f"{pathaqpackage}.xmpp", "r") as f:
        data = f.read()
    return data


def get_xmpp_message_with_sessionid(template_message, sessionid):
    """
    Remplace le placeholder de session dans un template XMPP avec la session donnée.

    Args:
        template_message (str): Contenu du template XMPP.
        sessionid (str): Identifiant de session à insérer.

    Returns:
        str: Message XMPP final avec sessionid.
    """
    return template_message.replace("@-TEMPLSESSQUICKDEPLOY@", sessionid, 1)

def create_msg_xmpp_quick_deploy(folder, create=False):
    """
    Crée ou met à jour un message XMPP pour le quick deployment d'un package.

    Cette fonction fait les étapes suivantes :
    1. Crée une archive compressée (.gz) du dossier du package si nécessaire.
    2. Encode le fichier compressé en Base64.
    3. Génère un message XMPP JSON avec le contenu Base64 et le nom du package.
    4. Sauvegarde le message dans un fichier .xmpp.
    5. Supprime le fichier compressé temporaire.

    Args:
        folder (str): Chemin du dossier contenant le package.
        create (bool, optional): Si True, force la création du package même s'il existe déjà.
    """
    # Nom du package basé sur le dossier
    namepackage = os.path.basename(folder)
    pathaqpackage = os.path.join(_path_packagequickaction(), namepackage)

    # Vérifie si le fichier .xmpp existe déjà ou si on force la création
    if not os.path.exists(f"{pathaqpackage}.xmpp") or create:
        logger.debug(f"Creating compressed archive {pathaqpackage}.gz")

        # Crée une archive tar compressée du dossier (gzip)
        make_tarfile(f"{pathaqpackage}.gz", folder, compresstype="gz")

        # Lit le contenu de l'archive et l'encode en Base64
        with open(f"{pathaqpackage}.gz", "rb") as f:
            dataraw = base64.b64encode(f.read())

        # Prépare le message XMPP en JSON
        msgxmpptemplate = """{"sessionid": "@-TEMPLSESSQUICKDEPLOY@",
                              "action": "qdeploy",
                              "data": {"nbpart": 1,
                                       "part": 1,
                                       "namepackage": "%s",
                                       "filebase64": "%s"}}""" % (
            namepackage,
            dataraw,
        )

        # Écrit le message dans le fichier .xmpp
        try:
            logger.debug(f"Writing new quick deployment package {pathaqpackage}.xmpp")
            with open(f"{pathaqpackage}.xmpp", "w") as f:
                f.write(msgxmpptemplate)

            # Supprime le fichier compressé temporaire
            if os.path.exists(f"{pathaqpackage}.gz"):
                os.remove(f"{pathaqpackage}.gz")
        except Exception:
            logger.error(f"{traceback.format_exc()}")
    else:
        # Si le package existe déjà et que create=False
        logger.debug(f"Quick deployment package {pathaqpackage}.xmpp found")

def pulseuser_useraccount_mustexist(username="pulseuser"):
    """
    This function checks if the a given user exists.
    Args:
        username: This is the username we need to check ( default is pulseuser )

    Returns:
        It returns True if the account has been correctly created or if the
        account already exists, it return False otherwise.
    """
    Config = ConfigParser()
    namefileconfig = conffilename("machine")
    Config.read(namefileconfig)

    if sys.platform.startswith("linux"):
        try:
            uid = pwd.getpwnam(username).pw_uid
            gid = grp.getgrnam(username).gr_gid
            msg = f"{username} user account already exists. Nothing to do."
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
            if Config.has_option("type", "sshuser_isadmin") and Config.getboolean(
                "type", "sshuser_isadmin"
            ):
                adminsgrpsid = win32security.ConvertStringSidToSid("S-1-5-32-544")
                adminsgroup = win32security.LookupAccountSid("", adminsgrpsid)[0]
                simplecommand(
                    encode_strconsole(f'net localgroup {adminsgroup} "{username}" /ADD')
                )
            # User exists
            msg = f"{username} user account already exists. Nothing to do."
            return True, msg
        except Exception:
            passwdchars = f"{string.hexdigits}-$#,_"
            userpassword = "".join(random.sample(list(passwdchars), 14))
            adduser_cmd = (
                'net user "%s" "%s" /ADD /COMMENT:"Pulse '
                'user with admin rights on the system"' % (username, userpassword)
            )
    elif sys.platform.startswith("darwin"):
        try:
            uid = pwd.getpwnam(username).pw_uid
            gid = grp.getgrnam(username).gr_gid
            msg = f"{username} user account already exists. Nothing to do."
            return True, msg
        except Exception:
            passwdchars = f"{string.hexdigits}-$#,_"
            userpassword = "".join(random.sample(list(passwdchars), 14))
            adduser_cmd = (
                "dscl . -create /Users/%s "
                "UserShell /usr/local/bin/rbash && "
                "dscl . -passwd /Users/%s %s" % (username, username, userpassword)
            )
    # Create the account
    result = simplecommand(encode_strconsole(adduser_cmd))
    if result["code"] == 0:
        msg = f"Creation of {username} user account successful: {result}"
        # Other operations specific to Windows
        if sys.platform.startswith("win"):
            # Désactiver l'expiration du mot de passe avec `net user`
            result = simplecommand(
                encode_strconsole(
                    'net user "%s" /passwordchg:no' % username
                )
            )
            if result["code"] != 0:
                msg = f"Error setting {username} user account to not expire: {result}"
                return False, msg

            # Masquer le compte dans l'écran de connexion
            result = simplecommand(
                encode_strconsole(
                    'REG ADD "HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\SpecialAccounts\\UserList" /v "%s" /t REG_DWORD /d 0 /f'
                    % username
                )
            )
            if result["code"] != 0:
                msg = f"Error hiding {username} account: {result}"
                return False, msg

            # Masquer le dossier utilisateur dans l'explorateur
            user_home = getHomedrive()
            hide_from_explorer = simplecommand(
                encode_strconsole("attrib +h %s" % user_home)
            )
            if hide_from_explorer["code"] != 0:
                msg = "Error hiding %s account: %s" % (username, hide_from_explorer)
                return False, msg
        return True, msg
    else:
        msg = f"Creation of {username} user account failed: {result}"
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
        usersid = get_user_sid(username)
        regdel = ('REG DELETE "HKLM\\Software\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList\\%s.bak" /f'
                 % usersid)
        logging.getLogger().info(regdel)
        resultdel = simplecommand(encode_strconsole(regdel))
        if resultdel["code"] == 0:
            logging.getLogger().info("We correctly removed the backup profile")
        else:
            logging.getLogger().info("No backup profile (.bak) to delete")

        # We define the sid
        mu = ManageUser()
        infos = mu.get_user_info(username)
        if not mu.user_exists(username) or not infos:
            directorysearch=[]
            # il n'y a pas de profils ou pas de comptes
            mu.delete_user(username)
            passwdchars = f"{string.hexdigits}-$#,_"
            userpassword = "".join(random.sample(list(passwdchars), 14))
            logging.getLogger().debug(f"Recreation compte {username} userpassword {userpassword}")
            creationinfo = mu.create_user(username, password=userpassword)
            creationprofile = mu.create_profile(username,password=userpassword)
            logging.getLogger().info(creationprofile)
            logging.getLogger().debug(f"Profile Machine")
            directorysearch = mu.get_dir("c:\\users")
            mu.display_dir(directorysearch)
            return creationprofile['success'], creationprofile['stdout'] + " " + creationprofile['stderr']
        return True, f"compte {username} exist"

    elif sys.platform.startswith("linux"):
        try:
            uid = pwd.getpwnam(username).pw_uid
            gid = grp.getgrnam(username).gr_gid
            homedir = os.path.expanduser(f"~{username}")
        except Exception as e:
            msg = f"Error getting information for creating home folder for user {username}"
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
        msg = f"{username} profile created successfully at {homedir}"
        return True, msg
    elif sys.platform.startswith("darwin"):
        try:
            uid = pwd.getpwnam(username).pw_uid
            gid = grp.getgrnam(username).gr_gid
            homedir = os.path.expanduser(f"~{username}")
        except Exception as e:
            msg = f"Error getting information for creating home folder for user {username}"
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
        msg = f"{username} profile created successfully at {homedir}"
        return True, msg


def get_user_profile(username="pulseuser"):
    usersid = get_user_sid(username)
    if not usersid:
        return ""
    check_profile_cmd = (
        'powershell "Get-ItemProperty '
        "-Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\ProfileList\\*' "
        "| Where-Object { $_.PSChildName -eq '%s' } "
        '| Select -ExpandProperty ProfileImagePath"' % usersid
    )
    result = simplecommand(encode_strconsole(check_profile_cmd))
    return result["result"][0] if result["code"] == 0 and result["result"] else ""


def get_user_sid(username="pulseuser"):
    try:
        return win32security.ConvertSidToStringSid(
            win32security.LookupAccountName(None, username)[0]
        )
    except Exception as e:
        return False


def delete_profile(username="pulseuser"):
    if sys.platform.startswith("win"):
        # Delete profile folder in C:\Users if any
        try:
            delete_folder_cmd = 'rd /s /q "%s" ' % getHomedrive(username)
            result = simplecommand(encode_strconsole(delete_folder_cmd))
            if result["code"] == 0:
                logger.debug("Deleted %s folder" % getHomedrive(username))
            else:
                logger.error("Error deleting %s folder" % getHomedrive(username))
        except Exception as e:
            pass
        # Delete profile
        userenvdll = ctypes.WinDLL("userenv.dll")
        usersid = get_user_sid(username)
        delete_profile_result = userenvdll.DeleteProfileA(LPCSTR(usersid))
        if delete_profile_result == 0:
            logger.debug("%s profile deleted." % username)
        else:
            logger.error(
                "Error deleting %s profile: %s" % (username, delete_profile_result)
            )
    return True


def delete_profile(name_user_profile="pulseuser"):
    result={}
    try:
        manager = ManageUser()
        # Activer le contrôle de dureté du mot de passe
        # manager.controle_durete_mot_de_passe = True
        result = manager.delete_profile(name_user_profile)
        logging.getLogger().debug(f"delete profile utilisateur {name_user_profile} : {result}")
    except Exception as e:
        logging.getLogger().error(f"Une erreur inattendue s est produite : {str(e)}")
    print("delete_profile utilisateur :", result)

def create_idrsa_on_client(username="pulseuser", key=""):
    """
    Used on client machine for connecting to relay server
    """
    if sys.platform.startswith("win"):
        id_rsa_path = os.path.join(getHomedrive(username), ".ssh", "id_rsa")
    else:
        id_rsa_path = os.path.join(os.path.expanduser(f"~{username}"), ".ssh", "id_rsa")
    delete_keyfile_cmd = f'del /f /q "{id_rsa_path}" '
    result = simplecommand(encode_strconsole(delete_keyfile_cmd))
    logger.debug(f"Creating id_rsa file in {id_rsa_path}")
    if not os.path.isdir(os.path.dirname(id_rsa_path)):
        os.makedirs(os.path.dirname(id_rsa_path), 0o700)
    file_put_contents(id_rsa_path, key)
    result, logs = apply_perms_sshkey(id_rsa_path, True)
    if result is False:
        return False, logs
    msg = f"Key {id_rsa_path} successfully created"
    return True, msg

def set_windows_permissions(path, username="pulseuser"):
    """
    Applique les permissions complètes à un fichier/dossier sous Windows
    en utilisant icacls.
    """
    try:
        import subprocess
        # Donner les droits complets à l'utilisateur sur le fichier
        cmd = f'icacls "{path}" /grant {username}:F /inheritance:r'
        subprocess.run(cmd, shell=True, check=True)
        # Donner les droits complets à l'utilisateur sur le dossier parent (.ssh)
        ssh_dir = os.path.dirname(path)
        cmd = f'icacls "{ssh_dir}" /grant {username}:F /inheritance:r'
        subprocess.run(cmd, shell=True, check=True)
        return True, f"Permissions appliquées avec succès pour {username} sur {path}."
    except subprocess.CalledProcessError as e:
        return False, f"Erreur lors de l'application des permissions avec icacls: {e}"
    except Exception as e:
        return False, f"Erreur inattendue: {e}"

def apply_perms_sshkey(path, private=True):
    """
    Applique les permissions correctes sur un fichier de clé SSH.
    """
    if not os.path.isfile(path):
        msg = f"Error: File {path} does not exist"
        return False, msg

    if sys.platform.startswith("win"):
        try:
            import win32api
            import win32security
            import ntsecuritycon

            username = win32api.GetUserName().lower() if private else "pulseuser"

            # Appliquer les permissions pour l'utilisateur
            sd = win32security.GetFileSecurity(path, win32security.DACL_SECURITY_INFORMATION)
            dacl = win32security.ACL()
            user, domain, type = win32security.LookupAccountName("", username)
            dacl.AddAccessAllowedAce(win32security.ACL_REVISION, ntsecuritycon.FILE_ALL_ACCESS, user)
            sd.SetSecurityDescriptorDacl(1, dacl, 0)
            win32security.SetFileSecurity(path, win32security.DACL_SECURITY_INFORMATION, sd)

            # Si private=False, accorder aussi les droits au compte SYSTEM
            if not private:
                user, domain, type = win32security.LookupAccountName("", "SYSTEM")
                dacl.AddAccessAllowedAce(win32security.ACL_REVISION, ntsecuritycon.FILE_ALL_ACCESS, user)
                sd.SetSecurityDescriptorDacl(1, dacl, 0)
                win32security.SetFileSecurity(path, win32security.DACL_SECURITY_INFORMATION, sd)

            return True, f"Permissions appliquées avec succès pour {username} sur {path}."
        except Exception as e:
            msg = f"Error setting permissions on {path} for user {username}: {str(e)}"
            return False, msg

    else:  # Linux/macOS
        try:
            import pwd
            import grp
            username = "pulseuser"
            uid = pwd.getpwnam(username).pw_uid
            gid = grp.getgrnam(username).gr_gid
            os.chown(os.path.dirname(path), uid, gid)
            os.chown(path, uid, gid)
            os.chmod(os.path.dirname(path), 0o700)
            os.chmod(path, 0o600)
            return True, f"Permissions appliquées avec succès pour {username} sur {path}."
        except Exception as e:
            msg = f"Error setting permissions on {path} for user {username}: {str(e)}"
            return False, msg

def set_windows_permissions(
    target,
    owner=None,               # Ex: "pulseuser"
    grants=None,              # Ex: ["pulseuser:F", "Administrateurs:R"]
    recursive=True
):
    """
    Applique des ACL Windows sur un fichier ou dossier en utilisant takeown + icacls.
    Fonction générique pour remplacer fix_windows_authorized_keys.
    """

    # Normalisation
    target = os.path.normpath(target)
    dirname = target if os.path.isdir(target) else os.path.dirname(target)

    # Options /T pour récursif
    rec = "/T" if recursive else ""

    # -------------------------
    # 1. Take Ownership (groupe Administrators)
    # -------------------------
    subprocess.run(
        ["powershell", "-NoLogo", "-NoProfile",
         f"takeown /F '{target}' /A {('/R' if recursive else '')}"],
        capture_output=True
    )

    # -------------------------
    # 2. Définir nouveau propriétaire (si demandé)
    # -------------------------
    if owner:
        subprocess.run(
            ["powershell", "-NoLogo", "-NoProfile",
             f"icacls '{target}' /setowner {owner} {rec}"],
            capture_output=True
        )

    # -------------------------
    # 3. Donner des permissions personnalisées
    # -------------------------
    if grants:
        for rule in grants:
            # Exemple : "pulseuser:F", "Administrateurs:RX"
            subprocess.run(
                ["powershell", "-NoLogo", "-NoProfile",
                 f"icacls '{target}' /grant {rule} {rec}"],
                capture_output=True
            )

    return True

def fix_unix_permissions(path, username, mode="ssh"):
    """
    Applique des permissions standard selon un profil :
    - mode="ssh"      : 700 pour dossier, 600 pour fichiers
    - mode="readonly" : 755 pour dossiers, 644 pour fichiers
    - mode="full"     : 755 pour dossiers, 755 pour fichiers
    """

    # Profils de permissions
    profiles = {
        "ssh": {
            "dir_mode": 0o700,
            "file_mode": 0o600
        },
        "readonly": {
            "dir_mode": 0o755,
            "file_mode": 0o644
        },
        "full": {
            "dir_mode": 0o755,
            "file_mode": 0o755
        }
    }

    if mode not in profiles:
        raise ValueError(f"Mode invalide : {mode}. Choisissez parmi {list(profiles.keys())}")

    pm = profiles[mode]

    # Détermine si c'est un fichier ou un dossier
    is_dir = os.path.isdir(path)
    folder = path if is_dir else os.path.dirname(path)

    # Créer le dossier si nécessaire
    os.makedirs(folder, exist_ok=True)

    # Récupère UID/GID
    try:
        pw = pwd.getpwnam(username)
        uid, gid = pw.pw_uid, pw.pw_gid
    except KeyError:
        raise ValueError(f"L’utilisateur '{username}' n’existe pas sur ce système")

    # Change ownership récursivement si dossier
    if is_dir:
        for root, dirs, files in os.walk(path):
            os.chown(root, uid, gid)
            os.chmod(root, pm["dir_mode"])
            for f in files:
                full = os.path.join(root, f)
                os.chown(full, uid, gid)
                os.chmod(full, pm["file_mode"])

    else:
        # Applique au dossier parent
        os.chown(folder, uid, gid)
        os.chmod(folder, pm["dir_mode"])

        # Applique au fichier si existant
        if os.path.exists(path):
            os.chown(path, uid, gid)
            os.chmod(path, pm["file_mode"])
        else:
            open(path, "a").close()   # crée le fichier
            os.chown(path, uid, gid)
            os.chmod(path, pm["file_mode"])

def delete_ssh_directory(dossier):
    """
    Supprime le dossier .ssh en s'assurant de prendre la propriété et d'appliquer les droits.
    Utilise takeown + icacls (outils windows) puis supprime le dossier en Python.
    Retour: (success: bool, message: str, details: dict)
    """
    details = {"stdout": "", "stderr": ""}

    # Normaliser le chemin
    dossier = os.path.normpath(dossier)

    if not os.path.exists(dossier):
        return True, f"Le dossier {dossier} n'existe pas.", details

    try:
        # 1) Prendre la propriété avec takeown (nécessite élévation)
        cmd_takeown = ["takeown", "/F", dossier, "/R", "/A"]  # /A = assign to administrators
        logger.debug("Lancement: %s", " ".join(cmd_takeown))
        p = subprocess.run(cmd_takeown, capture_output=True, text=True)
        details["takeown_stdout"] = p.stdout
        details["takeown_stderr"] = p.stderr
        logger.debug("takeown stdout: %s", p.stdout)
        logger.debug("takeown stderr: %s", p.stderr)

        # 2) Donner le contrôle total aux Administrateurs avec icacls
        # Note: 'Administrators' ou 'Administrateurs' selon la langue du système.
        # On appelle icacls avec le SID BUILTIN\Administrators pour plus de robustesse (S-1-5-32-544)
        cmd_icacls = ["icacls", dossier, "/grant", "S-1-5-32-544:(OI)(CI)F", "/T", "/C"]
        logger.debug("Lancement: %s", " ".join(cmd_icacls))
        p2 = subprocess.run(cmd_icacls, capture_output=True, text=True)
        details["icacls_stdout"] = p2.stdout
        details["icacls_stderr"] = p2.stderr
        logger.debug("icacls stdout: %s", p2.stdout)
        logger.debug("icacls stderr: %s", p2.stderr)

        # 3) Supprimer le dossier en Python (plus fiable que Remove-Item via powershell pour reporting)
        # On essaye d'abord shutil.rmtree (peut échouer si fichiers verrouillés)
        try:
            shutil.rmtree(dossier)
            details["rm_method"] = "shutil.rmtree"
            return True, f"Dossier {dossier} supprimé avec succès.", details
        except Exception as e_sh:
            logger.warning("shutil.rmtree a échoué: %s", e_sh)
            details["rmtree_exception"] = str(e_sh)
            # Comme fallback, utiliser PowerShell Remove-Item avec ExecutionPolicy Bypass depuis un .ps1 temporaire
            ps_script = f"""
            Remove-Item -LiteralPath '{dossier}' -Force -Recurse -ErrorAction Stop
            """
            tf = tempfile.NamedTemporaryFile(delete=False, suffix=".ps1", mode="w", encoding="utf-8")
            tf.write(ps_script)
            tf.close()
            cmd_ps = [
                "powershell",
                "-NoProfile",
                "-ExecutionPolicy", "Bypass",
                "-File", tf.name
            ]
            logger.debug("Lancement PowerShell fallback: %s", " ".join(cmd_ps))
            p3 = subprocess.run(cmd_ps, capture_output=True, text=True)
            details["ps_rm_stdout"] = p3.stdout
            details["ps_rm_stderr"] = p3.stderr
            # supprimer le fichier temporaire de script
            try:
                os.unlink(tf.name)
            except Exception:
                pass

            if p3.returncode == 0:
                return True, f"Dossier {dossier} supprimé via PowerShell fallback.", details
            else:
                # Tout a échoué, renvoyer message d'erreur détaillé
                msg = ("Impossible de supprimer le dossier. "
                       "Voir détails pour takeown/icacls/powershell outputs.")
                return False, msg, details

    except Exception as e:
        logger.exception("Erreur inattendue lors de la suppression de %s", dossier)
        details["exception"] = str(e)
        return False, f"Erreur inattendue : {e}", details

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
        ssh_directory = os.path.join(getHomedrive(username), ".ssh")
        authorized_keys_path = os.path.join(ssh_directory, "authorized_keys")
        delete_ssh_directory(ssh_directory )
    else:
        authorized_keys_path = os.path.join(
            os.path.expanduser(f"~{username}"), ".ssh", "authorized_keys"
        )
    # Create directory if it doesn't exist
    if not os.path.isdir(os.path.dirname(ssh_directory)):
        os.makedirs(os.path.dirname(ssh_directory), 0o700)
    # Read existing authorized_keys content
    authorized_keys_content = ""
    if os.path.isfile(authorized_keys_path):
        authorized_keys_content = file_get_contents(authorized_keys_path)

    # Check if the key is already present
    if key.strip(" \t\n\r") in authorized_keys_content:
        logger.debug(f"Key is already present in {authorized_keys_path}")
        msg = f"Key already present in {authorized_keys_path}"
        return True, msg

    # Append the key to authorized_keys file
    logger.debug(f"Adding key to {authorized_keys_path}")
    file_put_contents_w_a(authorized_keys_path, "\n" + key, "a")
    # Check if key is now present
    authorized_keys_content = file_get_contents(authorized_keys_path)
    if key.strip(" \t\n\r") in authorized_keys_content:
        msg = f"Key successfully present in {authorized_keys_path}"
        result, logs = apply_perms_sshkey(authorized_keys_path, False)
        return (False, logs) if result is False else (True, msg)

    # Function didn't return earlier, meaning the key is not present
    msg = "An error occurred while adding the public key to the authorized_keys file. The id_rsa.pub key is missing"
    return False, msg


def reversessh_useraccount_mustexist_on_relay(username="reversessh"):
    try:
        uid = pwd.getpwnam(username).pw_uid
        msg = f"{username} user account already exists. Nothing to do."
        return True, msg
    except Exception:
        adduser_cmd = (
            "adduser --system --quiet --group "
            "--home /var/lib/pulse2/clients/reversessh "
            "--shell /bin/rbash --disabled-password %s" % username
        )
    result = simplecommand(encode_strconsole(adduser_cmd))
    if result["code"] == 0:
        msg = f"Creation of {username} user account successful: {result}"
        return True, msg
    else:
        msg = f"Creation of {username} user account failed: {result}"
        return False, msg


def reversessh_keys_mustexist_on_relay(username="reversessh"):
    try:
        uid = pwd.getpwnam(username).pw_uid
        homedir = os.path.expanduser(f"~{username}")
    except Exception as e:
        msg = f"Error getting information for creating home folder for user {username}"
        return False, msg
    if not os.path.isdir(homedir):
        os.makedirs(homedir, 0o751)
    os.chmod(homedir, 0o751)
    os.chown(homedir, uid, -1)
    # Check keys
    id_rsa_key_path = os.path.join(os.path.expanduser(f"~{username}"), ".ssh", "id_rsa")
    public_key_path = os.path.join(
        os.path.expanduser(f"~{username}"), ".ssh", "id_rsa.pub"
    )
    keycheck_cmd = f"ssh-keygen -y -f {id_rsa_key_path} > {public_key_path}"
    result = simplecommand(encode_strconsole(keycheck_cmd))
    if result["code"] != 0:
        logger.debug(f"Creating id_rsa file in {id_rsa_key_path}")
        if not os.path.isdir(os.path.dirname(id_rsa_key_path)):
            os.makedirs(os.path.dirname(id_rsa_key_path), 0o700)
        keygen_cmd = f'ssh-keygen -q -N "" -b 2048 -t rsa -f {id_rsa_key_path}'
        result = simplecommand(encode_strconsole(keygen_cmd))
    authorized_keys_path = os.path.join(
        os.path.expanduser(f"~{username}"), ".ssh", "authorized_keys"
    )
    addtoauth_cmd = f"grep -qxF \"$(ssh-keygen -y -f {id_rsa_key_path})\" {authorized_keys_path} || ssh-keygen -y -f {id_rsa_key_path}) >> {authorized_keys_path}"
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
    returns relayserver s root public key
    """
    public_key_path = os.path.join(
        os.path.expanduser(f"~{username}"), ".ssh", "id_rsa.pub"
    )
    return file_get_contents(public_key_path)


def get_relayserver_reversessh_idrsa(username="reversessh"):
    """
    returns relayserver s reversessh private key
    """
    idrsa_key_path = os.path.join(os.path.expanduser(f"~{username}"), ".ssh", "id_rsa")
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
            f"http://{x}/json"
            for x in re.split(
                r"[;,\[\(\]\)\{\}\:\=\+\*\\\?\/\#\+\&\$\|\s]", strlistgeoserveur
            )
            if x.strip() != ""
        ]
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
        return {} if self.localisation is None else self.localisation

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
                with open(self.filegeolocalisation, "w") as json_data:
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
        return bool(os.path.exists(self.filegeolocalisation))

    def getgeolocalisation(self):
        """
        This function permit to retrieve geolocalisation informations

        Returns:
            It returns geolocalisation informations if they exists
        """
        if self.typeuser in ["public", "nomade", "both"]:
            # We search for geolocalisation informations each time
            self.localisation = geolocalisation_agent.searchgeolocalisation(
                self.listgeoserver
            )
            self.determination = True
            self.setdatafilegeolocalisation()
        else:
            if self.localisation is not None:
                return self.localisation

            if (
                self.geolocalisation
                and self.geoinfoexist()
                or not self.geolocalisation
                and self.geoinfoexist()
            ):
                self.getdatafilegeolocalisation()
                self.determination = False
            elif self.geolocalisation and not self.geoinfoexist():
                self.localisation = geolocalisation_agent.searchgeolocalisation(
                    self.listgeoserver
                )
                self.setdatafilegeolocalisation()
                self.determination = True
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

            if self.localisation is None or not is_valid_ipv4(self.localisation["ip"]):
                return None
            if not self.determination:
                logger.warning("Determination use file")
            self.ip_public = self.localisation["ip"]
            return self.localisation["ip"]
        else:
            if not self.determination:
                logger.warning("Using the old way of determination for the ip_public")
            if self.localisation is not None:
                return self.localisation["ip"]
            if self.geoinfoexist():
                localisationData = self.getdatafilegeolocalisation()
                logger.warning(f"{localisationData}")
                if self.localisation is not None:
                    return self.localisation["ip"]
        return self.ip_public

    @staticmethod
    def call_simple_page(url, timeout=20):
        """
        This function makes a GET request to the given URL and returns the JSON response.

        Args:
            url (str): The URL to make the GET request to.
            timeout (int): The timeout value for the request.

        Returns:
            dict: The JSON response if the request is successful and contains 'longitude', None otherwise.
        """
        try:
            r = requests.get(url, timeout=timeout)
            if r.status_code > 299:
                logger.warning(
                    "url localisation %s code error is %s" % (url, r.status_code)
                )
                return None
            result = r.json()
            return None if "longitude" not in result else result
        except Timeout:
            logger.warning(f"Request to {url} timed out after {timeout} seconds")
            return None
        except BaseException as e:
            logger.error(f"Error making request to {url}: {e}")
            return None

    @staticmethod
    def call_simple_page_urllib(url):
        try:
            result = urllib2.urlopen(url, timeout=5)
            objip = json.loads(result)
            if result.getcode() != 200:
                raise
            return objip
        except BaseException:
            return None

    @staticmethod
    def searchgeolocalisation(http_url_list_geo_server):
        """
        return objet
        """
        serveur = ""
        objip = None
        for url in http_url_list_geo_server:
            serveur = url
            try:
                logger.debug(f"The geolocalisation server used is:  {url}")
                objip = geolocalisation_agent.call_simple_page(url)
                if objip is not None:
                    break
            except BaseException:
                pass
        if objip is not None:
            logger.debug(
                f"geolocalisation serveur {serveur}  {json.dumps(objip, indent=4)}"
            )
        return objip


class downloadfile:
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
        msghtml = f"error html code {code}"
        if code == 200:
            msghtml = f"[{code} succes]"
        if code == 301:
            msghtml = f"[{code} Moved Permanently]"
        if code == 302:
            msghtml = f"[{code} Moved temporarily]"
        if code == 400:
            msghtml = f"[{code} Bad Request]"
        if code == 401:
            msghtml = f"[{code} Unauthorized]"
        elif code == 403:
            msghtml = f"[{code} Forbidden]"
        elif code == 404:
            msghtml = f"[{code} Not Found]"
        elif code == 408:
            msghtml = f"[{code} Request Timeout]"
        elif code == 500:
            msghtml = f"[{code} Internal Server Error]"
        elif code == 503:
            msghtml = f"[{code} Service Unavailable]"
        elif code == 504:
            msghtml = f"[{code} Gateway Timeout]"
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
            return (
                False,
                f"HTTP Error {self.code_return_html(e.code)} while downloading {self.url}: {e.reason}",
            )
        except urllib2.URLError as e:
            return False, f"URL Error on {self.url}: {e.reason}"
        except IOError as e:
            return False, "I/O error {0} on file {1}: {2}".format(
                e.errno, self.urllocalfile, e.strerror
            )
        except (
            BaseException
        ):  # handle other exceptions such as attribute errors skipcq: FLK-E722
            return False, "Unexpected error: %s", sys.exc_info()[0]


def minifyjsonstring(strjson):
    """
    This function minifies the json string in input
        if json has incorrect '' and not "" this function will reformat
    Returns:
        string containining the minified json
    """
    # remove comments (//) and line breaks
    strjson = "".join(
        [row.split("//")[0] for row in strjson.split("\n") if len(row.strip()) != 0]
    )
    # remove tabs, line breaks and end of lines
    regex = re.compile(r"[\n\r\t]")
    strjson = regex.sub("", strjson)
    # protect json strings
    reg = re.compile(r"""(\".*?\n?.*?\")|(\'.*?\n?.*?\')""")
    newjson = re.sub(
        reg,
        lambda x: '"%s"' % str(x.group(0)).strip("\"'").strip().replace(" ", "@@ESP@@"),
        strjson,
    )
    # remove blanks
    newjson = newjson.replace(" ", "")
    # reinsert protected blanks
    newjson = newjson.replace("@@ESP@@", " ")
    # remove errors that are found often in json files
    newjson = newjson.replace(",}", "}")
    newjson = newjson.replace("{,", "{")
    newjson = newjson.replace("[,", "[")
    newjson = newjson.replace(",]", "]")
    return newjson


def serialnumbermachine():
    """
    Retourne le UUID/serial number de la machine selon le système.
    Windows utilise PowerShell, Linux et macOS comme avant.
    """
    serial_uuid_machine = ""
    try:
        if sys.platform.startswith("win"):
            # PowerShell command to get UUID
            ps_cmd = 'powershell -NoProfile -Command "Get-CimInstance -ClassName Win32_ComputerSystemProduct | Select-Object -ExpandProperty UUID"'
            result = simplecommand(ps_cmd)
            if result["code"] == 0 and result["result"]:
                serial_uuid_machine = "".join(result["result"]).strip()

        elif sys.platform.startswith("linux"):
            result = simplecommand("dmidecode -s system-uuid")
            if result["code"] == 0 and result["result"]:
                serial_uuid_machine = "".join(result["result"]).strip()

        elif sys.platform.startswith("darwin"):
            cmd = r"""ioreg -d2 -c IOPlatformExpertDevice | awk -F\" '/IOPlatformUUID/{print $(NF-1)}'"""
            result = simplecommand(cmd)
            if result["code"] == 0 and result["result"]:
                serial_uuid_machine = "".join(result["result"]).strip()

        else:
            logger.warning(f"serialnumbermachine not implemented for OS: {sys.platform}")

    except Exception:
        logger.error("Error in serialnumbermachine:\n%s" % traceback.format_exc())

    return serial_uuid_machine



def base64strencode(data):
    result = ""
    if sys.version_info[0] == 3:
        if isinstance(data, str):
            data = bytes(data, "utf-8")
    elif isinstance(data, bytes):
        data = data.decode("utf-8")
    try:
        result = base64.b64encode(data)
        if sys.version_info[0] == 3:
            result = result.decode()
    except Exception as e:
        logger.error(f"error decode data in function base64strencode {str(e)}")
    finally:
        return result


class Singleton(object):
    def __new__(cls, *args):
        if "_the_instance" not in cls.__dict__:
            cls._the_instance = object.__new__(cls)
        return cls._the_instance


class base_message_queue_posix(Singleton):
    file_reponse_iq = []
    timeoutmessagequeue = 120

    def __init__(self):
        logger.debug("*** INITIALISATION base_message_queue_posix")
        logger.debug(f"*** charge {base_message_queue_posix.file_reponse_iq}")

    def _is_exist(self, name_file):
        return any(
            fmp["name"] == name_file for fmp in base_message_queue_posix.file_reponse_iq
        )

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
        logger.debug("clean_file_all_message base_message_queue_posix.file_reponse_iq")

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


class DateTimebytesEncoderjson(json.JSONEncoder):
    """
    Used to handle datetime in json files.
    """

    def default(self, obj):
        if isinstance(obj, datetime):
            encoded_object = obj.isoformat()
        elif isinstance(obj, bytes):
            encoded_object = obj.decode("utf-8")
        else:
            encoded_object = json.JSONEncoder.default(self, obj)
        return encoded_object


class file_message_iq:
    def __init__(self, dev_mod=False):
        self.iqdata = {}
        self.setscrutationtime()
        self.index = 0
        self.base_message = os.path.join(
            os.path.dirname(os.path.realpath(__file__)), "file_message_base"
        )
        self.persitance_file = 3600
        if not os.path.exists(self.base_message):
            os.makedirs(self.base_message)
        self.dev_mod = dev_mod
        self.del_timeout_iq_old()
        if self.dev_mod:
            logger.info(
                "initialisation file_message_iq\n "
                "debug_file_message_iq in %s" % self.base_message
            )
            logger.info("Message iq send est recv in base %s" % self.base_message)
            logger.info("Persistance file is %s secondes" % self.persitance_file)

    def setscrutationtime(self, timescrutation=0.5):
        self.timescrutation = timescrutation

    def create_ref_iq(self, id_iq, time_out_iq):
        """creation demande iq"""
        self.index += 1
        createtime = time.time() + time_out_iq
        item_iq = {"time": createtime, "id_iq": id_iq, "result": None}
        self.iqdata[self.index] = item_iq

    def removekey(self, indexkey):
        """renove key index indexkey"""
        if indexkey in self.iqdata:
            if self.dev_mod:
                logger.info(
                    "delete iq index [%s] %s" % (indexkey, self.iqdata[indexkey])
                )
            del self.iqdata[indexkey]
        else:
            if self.dev_mod:
                logger.info("delete iq index [%s] not exits" % (indexkey))

    def del_timeout_iq_old(self):
        """delete les items qui sont en timeout"""
        indexdel = []
        nowtime = time.time()
        for indexitem in self.iqdata:
            if nowtime > self.iqdata[indexitem]["time"]:
                indexdel.append(indexitem)
        for deleteitemindexe in indexdel:
            self.removekey(deleteitemindexe)
        filelist = [
            os.path.join(self.base_message, x)
            for x in os.listdir(self.base_message)
            if (x.endswith("result") or x.endswith("send"))
        ]
        delfile = [
            x
            for x in filelist
            if (nowtime - os.path.getmtime(x)) > self.persitance_file
        ]
        if self.dev_mod and delfile:
            logger.info("list file deleted [%s] iq" % (delfile))
        for filefordelname in delfile:
            if os.path.exists(filefordelname):
                os.remove(filefordelname)

    def search_iq(self, id_iq):
        """
        search si 1 iq a renvoyer 1 resultat
        """
        try:
            for indexitem in self.iqdata:
                if self.iqdata[indexitem]["id_iq"] == id_iq:
                    return indexitem, self.iqdata[indexitem]["result"]
            return None, None
        except Exception:
            logger.error("\n%s" % (traceback.format_exc()))
            return None, None

    def set_iq_result(self, id_iq, data):
        logger.debug("set_iq_result [%s] pour data %s" % (id_iq, data))
        iqindex, iq_data = self.search_iq(id_iq)
        if iqindex:
            self.iqdata[iqindex]["result"] = data
            if self.dev_mod:
                logger.info(
                    "update RECV result IQ %s" % (self.iqdata[iqindex]["id_iq"])
                )
                # write iq dans file id_iq.result
                # logger.debug("set iq [%s]" % (id_iq))
                filename = os.path.join(self.base_message, "%s.result" % id_iq)
                file_put_contents(
                    filename, json.dumps(data, cls=DateTimebytesEncoderjson, indent=4)
                )


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
        sock.sendall(datastrdata.encode("ascii"))
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
        PARAMS = {"q": location}
        status, textresult = self.__get_requests(kb_catalogue.URL, params=PARAMS)
        if status == 200 and textresult.find(kb_catalogue.filter) == -1:
            return True
        else:
            return False

    def get_iq_result(
        self, id_iq, strmsg=None, timeout=10, delta_time=None, time_max_loop=120
    ):
        """
        boucle attente iq for traitement
        on regarde si 1 iq est a traiter toutes les deltatimes.
        """
        try:
            if strmsg is not None:
                logger.warning("creation object attente get_iq_result")
                self.dumps_msg_iq_in_file(id_iq, strmsg)
            logger.warning("creation object attente get_iq_result")

            if self.dev_mod:
                logger.info("waitting (%s)s max result iq %s" % (timeout, id_iq))
            self.create_ref_iq(id_iq, timeout)
            time_end = time.time() + time_max_loop
            if delta_time is None:
                delta_time = self.timescrutation
            while True:
                if time.time() > time_end:
                    logger.warning("quit sur timeout")
                    if self.dev_mod:
                        logger.info("iq [%s] in timeout" % (id_iq))
                    return None
                # delete les items qui sont en timeout
                self.del_timeout_iq_old()
                time.sleep(delta_time)
                logger.warning("start boucle analyse %s" % id_iq)
                logger.warning("start boucle analyse reslytat %s" % self.iqdata)

                iqindex, iq_data = self.search_iq(id_iq)

                logger.warning("retout  search_iq %s %s" % (iqindex, iq_data))

                if iqindex and iq_data:
                    logger.warning("on a trouve ")
                if iqindex:
                    if not iq_data:
                        continue
                    else:
                        # renvoi iq trouver

                        if self.dev_mod:
                            logger.info("result iq [%s] %s" % (id_iq, iq_data))
                        self.removekey(iqindex)
                        return iq_data
                else:
                    return None
        except Exception:
            logger.error("\n%s" % (traceback.format_exc()))
        return None

    def dumps_msg_iq_in_file(self, id_iq, msg):
        if self.dev_mod:
            timestamp = time.time()
            date_time = datetime.fromtimestamp(timestamp).strftime("%c")
            filename = os.path.join(self.base_message, "%s.send" % id_iq)
            msgdump = """%s\n send iq %s\n%s\n\n""" % (date_time, id_iq, msg)
            file_put_contents(filename, msgdump)

    def add_msg_iq_in_file(self, id_iq, textmsg):
        if self.dev_mod:
            timestamp = time.time()
            date_time = datetime.fromtimestamp(timestamp).strftime("%c")
            msgdump = """%s : %s""" % (date_time, textmsg)
            filename = os.path.join(self.base_message, "%s.send" % id_iq)
            file_put_contents_w_a(filename, textmsg, option="a")

    def __get_requests(self, url, params, timeout=5):
        """
        this function send get to url
        return status et content text request
        status 200 correct reponse
        status 408 incorrect reponse content text empty
        """
        status = 408  # error timeout
        text_result = ""
        try:
            r = requests.get(url=url, params=params, timeout=timeout)
            status = r.status_code
            if status == 200:
                text_result = r.text
        except Timeout:
            status = (408,)
        return status, text_result


def powerschellscript1ps1(namescript):
    namescript = windowspath(namescript)
    obj = {"code": -1, "result": ""}
    try:
        obj = simplecommand("powershell -ExecutionPolicy Bypass -File %s" % namescript)
    except Exception:
        logger.error("\n%s" % (traceback.format_exc()))
    return obj


class offline_search_kb:
    def __init__(self):
        self.info_package = {
            "history_package_uuid": [],
            "version_net": {},
            "kb_installed": [],
            "version_edge": "",
            "infobuild": {},
            "platform_info": {},
            "office" :{},
            "visual" : {},
        }

        try:
            self.info_package["platform_info"] = self.platform_info()
        except Exception:
            logger.error("\n%s" % (traceback.format_exc()))

        try:
            self.info_package["visual"] = self.search_visual_version()
        except Exception:
            logger.error("\n%s" % (traceback.format_exc()))

        try:
            self.info_package["office"] = self.search_office_version()
        except Exception:
            logger.error("\n%s" % (traceback.format_exc()))

        try:
            self.info_package["malicious_software_removal_tool"] = (
                self.search_malicious_software_removal_tool()
            )
        except Exception:
            logger.error("\n%s" % (traceback.format_exc()))

        try:
            self.info_package["version_edge"] = self.search_version_edge()
        except Exception:
            logger.error("\n%s" % (traceback.format_exc()))

        try:
            self.info_package["history_package_uuid"] = []
        except Exception:
            logger.error("\n%s" % (traceback.format_exc()))
        try:
            self.info_package["version_net"] = self.search_net_info_reg()
        except Exception:
            logger.error("\n%s" % (traceback.format_exc()))
        try:
            searchkb = self.searchpackage()
            self.info_package["kb_installed"] = searchkb
            self.info_package["kb_list"] = self.compact_kb(searchkb)
        except Exception:
            logger.error("\n%s" % (traceback.format_exc()))
        try:
            self.info_package["infobuild"] = self.search_system_info_reg()
        except Exception:
            logger.error("\n%s" % (traceback.format_exc()))

    def get_json(self):
        return json.dumps(self.info_package, indent=4, ensure_ascii=False)

    def get(self):
        return self.info_package

    def compact_kb(self, listkb):
        compactlist = []
        for t in listkb:
            compactlist.append(t["HotFixID"][2:])
        return "(" + ",".join(compactlist) + ")"


    def searchpackage(self):
        endresult = []
        if sys.platform.startswith("win"):
            try:
                # Commande PowerShell JSON propre
                ps_cmd = (
                    'powershell -NoProfile -Command '
                    '"Get-HotFix | '
                    "Select-Object @{Name='Source';Expression={$_.PSComputerName}}, "
                    "Description, HotFixID, InstalledBy, "
                    "@{Name='InstalledOn';Expression={$_.InstalledOn.ToString('MM/dd/yyyy')}} | "
                    'ConvertTo-Json -Depth 3"'
                )

                ret = simplecommand(encode_strconsole(ps_cmd))
                if ret["code"] != 0:
                    return endresult

                # Reconstituer la sortie PowerShell
                text = "".join([decode_strconsole(l) for l in ret["result"]]).strip()

                # Certaines versions ajoutent du texte avant/après → extraction du JSON
                try:
                    data = json.loads(text)
                except json.JSONDecodeError:
                    import re
                    m = re.search(r'(\[.*\]|\{.*\})', text, flags=re.S)
                    if not m:
                        return endresult
                    data = json.loads(m.group(1))

                # Normaliser en liste
                if isinstance(data, dict):
                    data = [data]

                for entry in data:
                    hotfix = entry.get("HotFixID", "") or ""
                    if not hotfix.startswith("KB"):  # filtrer uniquement les KB
                        continue

                    endresult.append({
                        "Source": (entry.get("Source") or "").strip(),
                        "description": (entry.get("Description") or "").strip(),
                        "HotFixID": hotfix.strip(),
                        "InstalledBy": (entry.get("InstalledBy") or "").strip(),
                        "InstalledOn": (entry.get("InstalledOn") or "").strip(),
                    })

            except Exception as e:
                print(f"searchpackage : {e}")
                print(traceback.format_exc())

        return endresult

    def search_malicious_software_removal_tool(self):
        # 'Windows Malicious Software Removal Tool x64 - v5.100 (KB890830)'
        # version de mrt.exec  (voir meta data)
        # (Get-ChildItem 'C:\Windows\System32\mrt.exe').VersionInfo | Format-List *
        # (Get-ChildItem 'C:\Windows\System32\mrt.exe').VersionInfo.ProductVersion
        result_cmd = {}
        if sys.platform.startswith("win"):
            if os.path.exists("C:\\Windows\\System32\\mrt.exe"):
                informationlist = (
                    "FileMajorPart",
                    "FileMinorPart",
                    "ProductVersion",
                    "ProductName",
                )
                try:
                    cmd = """powershell "(Get-ChildItem 'C:\Windows\System32\mrt.exe').VersionInfo | Format-List *" """
                    result = simplecommand(encode_strconsole(cmd))
                    if int(result["code"]) == 0:
                        line = [
                            decode_strconsole(x.strip())
                            for x in result["result"]
                            if x.strip().startswith(informationlist)
                        ]
                        for t in line:
                            lcmd = [x for x in t.split(" ") if x != ""]
                            if len(lcmd) >= 3:
                                keystring = " ".join(lcmd[2:])
                                result_cmd[lcmd[0]] = keystring
                        if (
                            "FileMajorPart" in result_cmd
                            and "FileMinorPart" in result_cmd
                        ):
                            result = (
                                "Windows Malicious Software Removal Tool %s - v%s.%s"
                                % (
                                    self.info_package["platform_info"]["machine"],
                                    result_cmd["FileMajorPart"],
                                    result_cmd["FileMinorPart"],
                                )
                            )
                            result_cmd["ProductName"] = result
                    else:
                        logging.getLogger().error(
                            "search search_malicious_software_removal_tool %s"
                            % result["result"]
                        )
                except:
                    logging.getLogger().error(("%s" % (traceback.format_exc())))
        return result_cmd

    def search_version_edge(self):
        Versionedge = ""
        if sys.platform.startswith("win"):
            try:
                cmd = """powershell.exe "(Get-AppxPackage Microsoft.MicrosoftEdge).Version" """
                result = simplecommand(encode_strconsole(cmd))
                if int(result["code"]) == 0:
                    vers = [x.strip() for x in result["result"] if x.strip() != ""]
                    if vers:
                        Versionedge = vers[0]
            except:
                logging.getLogger().error(("%s" % (traceback.format_exc())))
        return Versionedge

    def search_net_info_reg(self):
        result_cmd = {}
        if sys.platform.startswith("win"):
            informationlist = (
                "CBS",
                "Install",
                "InstallPath",
                "Release," "Servicing",
                "TargetVersion",
                "Version",
            )
            cmd = """REG QUERY "HKLM\\SOFTWARE\\Microsoft\\NET Framework Setup\\NDP\\v4\\Full" """
            result = simplecommand(encode_strconsole(cmd))
            if int(result["code"]) == 0:
                # analyse result
                line = [
                    decode_strconsole(x.strip())
                    for x in result["result"]
                    if x.strip().startswith(informationlist)
                ]
                for t in line:
                    lcmd = [x for x in t.split(" ") if x != ""]
                    if len(lcmd) >= 3:
                        keystring = " ".join(lcmd[2:])
                        result_cmd[lcmd[0]] = keystring
            else:
                logging.getLogger().error(
                    'search REG QUERY "HKLM\\SOFTWARE\\Microsoft\\NET Framework Setup\\NDP\\v4\\Full"'
                )
        return result_cmd

    def get_windows_version_major(self):
        version = platform.version()
        match = re.search(r"(\d+)\.(\d+)\.(\d+)", version)
        if match:
            major, minor, build = match.groups()
            if major == "10" and int(build) >= 22000:
                return "11"
            elif major == "10":
                return "10"
            elif major == "6" and minor == "1":
                return "7"
        return ""

    def search_office_version(self):
        office_info = {}
        if sys.platform.startswith("win"):
            try:
                cmd = r'powershell -Command "Get-ChildItem \"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\" | ForEach-Object { Get-ItemProperty $_.PsPath } | Where-Object { $_.DisplayName -like \"*Microsoft Office*\" } | Select-Object -First 1 -ExpandProperty DisplayName"'
                result = simplecommand(encode_strconsole(cmd))
                if int(result["code"]) == 0:
                    office_name = [x.strip() for x in result["result"] if x.strip() != ""]
                    if office_name:
                        office_info["version"] = office_name[0]
                        # Extraction de l'année si présente dans la chaîne
                        match = re.search(r"(\d{4})", office_name[0])
                        if match:
                            office_info["year"] = match.group(1)
            except Exception:
                logger.error("\n%s" % (traceback.format_exc()))
                office_info = {}
        return office_info

    def search_visual_version(self):
        visual_info = {}
        if sys.platform.startswith("win"):
            try:
                cmd = r'powershell -Command "Get-ChildItem \"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\" | ForEach-Object { Get-ItemProperty $_.PsPath } | Where-Object { $_.DisplayName -like \"*Visual Studio*\" } | Select-Object -First 1 -ExpandProperty DisplayName"'
                result = simplecommand(encode_strconsole(cmd))
                if int(result["code"]) == 0:
                    visual_name = [x.strip() for x in result["result"] if x.strip() != ""]
                    if visual_name:
                        visual_info["version"] = visual_name[0]
                        # Extraction de l'année si présente dans la chaîne
                        match = re.search(r"(\d{4})", visual_name[0])
                        if match:
                            visual_info["year"] = match.group(1)
            except Exception:
                logger.error("\n%s" % (traceback.format_exc()))
                visual_info = {}
        return visual_info

    def get_locale_id_iso(self):
        cmd = """REG QUERY "HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Nls\\Language" """
        result = simplecommand(encode_strconsole(cmd))
        if int(result["code"]) == 0:
            # analyse result
            line = [
                decode_strconsole(x.strip())
                for x in result["result"]
                if x.strip().startswith("InstallLanguage")
            ]
            if line:
                for sline in line:
                    lcmd = [x for x in sline.split(" ") if x != ""]
                    logging.getLogger().error(lcmd)
                    if len(lcmd) == 3:
                        return lcmd[2]
        return ""

    def search_system_info_reg(self):
        result_cmd = {}
        if sys.platform.startswith("win"):
            datalang = {
                "0416": {
                    "OSL": "Brazilian Portuguese",
                    "VSV": "English, Brazilian Portuguese",
                    "code_lang": "pt-br",
                },
                "0405": {"OSL": "Czech", "VSV": "English, Czech", "code_lang": "cs"},
                "0409": {"OSL": "English", "VSV": "English", "code_lang": "en"},
                "040C": {"OSL": "French", "VSV": "English, French", "code_lang": "fr"},
                "0407": {"OSL": "German", "VSV": "English, German", "code_lang": "de"},
                "040E": {
                    "OSL": "Hungarian",
                    "VSV": "English, Hungarian",
                    "code_lang": "hu",
                },
                "0410": {
                    "OSL": "Italian",
                    "VSV": "English, Italian",
                    "code_lang": "it",
                },
                "0411": {
                    "OSL": "Japanese",
                    "VSV": "English, Japanese",
                    "code_lang": "ja",
                },
                "0412": {"OSL": "Korean", "VSV": "English, Korean", "code_lang": "ko"},
                "0415": {"OSL": "Polish", "VSV": "English, Polish", "code_lang": "pl"},
                "0419": {
                    "OSL": "Russian",
                    "VSV": "English, Russian",
                    "code_lang": "ru",
                },
                "0C0A": {
                    "OSL": "Spanish",
                    "VSV": "English, Spanish",
                    "code_lang": "es",
                },
                "0804": {
                    "OSL": "Simplified Chinese",
                    "VSV": "English",
                    "code_lang": "zh-cn",
                },
            }

            informationlist = (
                "CurrentBuild",
                "CurrentVersion",
                "InstallationType",
                "ProductName",
                "ReleaseId",
                "DisplayVersion",
                "RegisteredOwner",
            )

            cmd = """REG QUERY "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion" | findstr REG_SZ"""
            result = simplecommand(encode_strconsole(cmd))
            if int(result["code"]) == 0:
                # analyse result
                line = [
                    decode_strconsole(x.strip())
                    for x in result["result"]
                    if x.strip().startswith(informationlist)
                ]
                for t in line:
                    lcmd = [x for x in t.split(" ") if x != ""]
                    if len(lcmd) >= 3:
                        keystring = " ".join(lcmd[2:])
                        result_cmd[lcmd[0]] = keystring
            # major update
            result_cmd["major_version"] = self.get_windows_version_major()
            result_cmd["InstallLanguage"] = self.get_locale_id_iso()
            if result_cmd["InstallLanguage"] in datalang:
                result_cmd["code_lang_iso"] = datalang[result_cmd["InstallLanguage"]][
                    "code_lang"
                ]
                result_cmd["update_major"] = "win%s_upd_%s" % (
                    result_cmd["major_version"],
                    datalang[result_cmd["InstallLanguage"]]["code_lang"],
                )
            # search code langue
            try:
                result_cmd["Locale"] = {
                    "LCID": None,
                    "Name": "",
                    "DisplayName": "",
                    "ThreeLetterWindowsLanguageName": "",
                }
                cmd = """powershell -ExecutionPolicy Bypass Get-WinSystemLocale"""
                result = simplecommand(encode_strconsole(cmd))
                if int(result["code"]) == 0:
                    langs = [
                        self.ascii_to_utf8(x).strip()
                        for x in result["result"]
                        if x.strip() != ""
                    ]
                    langs = [
                        self.ascii_to_utf8(x).strip()
                        for x in result["result"]
                        if x.strip() != ""
                    ][-1:]

                    langs = [x.strip() for x in langs[0].split("  ") if x != ""]
                    if len(langs) >= 3:
                        result_cmd["Locale"]["LCID"] = langs[0]
                        result_cmd["Locale"]["Name"] = langs[1]
                        result_cmd["Locale"]["DisplayName"] = langs[2]
                else:
                    logging.getLogger().error(
                        "search WinSystemLocale : %s" % result["result"]
                    )
            except:
                logging.getLogger().error(("%s" % (traceback.format_exc())))
            try:
                cmd = """powershell -ExecutionPolicy Bypass "Get-WinSystemLocale| select ThreeLetterWindowsLanguageName" """
                result = simplecommand(encode_strconsole(cmd))
                if int(result["code"]) == 0:
                    T_L_W_LanguageName = [
                        decode_strconsole(x.strip())
                        for x in result["result"]
                        if x.strip() != ""
                    ][-1:][0]
                    result_cmd["Locale"][
                        "ThreeLetterWindowsLanguageName"
                    ] = T_L_W_LanguageName
                else:
                    logging.getLogger().error(
                        "search ThreeLetterWindowsLanguageName %s" % result["result"]
                    )
            except:
                logging.getLogger().error(("%s" % (traceback.format_exc())))
        return result_cmd

    def bytes_to_string(self, x):
        if isinstance(x, str):
            return x
        else:
            return x.decode("utf-8")

    def string_to_bytes(self, x):
        if isinstance(x, bytes):
            return x
        else:
            return x.encode("utf-8")

    def ascii_to_utf8(self, x):
        if isinstance(x, bytes):
            return x.decode("utf-8")
        else:
            return x.encode("ascii", "ignore").decode("utf-8")

    def platform_info(self):
        res = {
            "machine": platform.machine(),
            "type": "%s %s" % (platform.system(), platform.release()),
            "node": platform.node(),
            "platform": platform.platform(aliased=0, terse=0),
            "processor": platform.processor(),
            "version": platform.version(),
        }
        if sys.platform.startswith("win"):
            informationlist = {}
            cmd = """systeminfo.exe /FO csv /NH"""
            result = simplecommand(cmd)
            if int(result["code"]) == 0:
                result["result"][0] = self.ascii_to_utf8(result["result"][0])
                line = [x.strip('" ') for x in result["result"][0].split('","')]
                informationlist = {
                    "node": str(line[0]),
                    "platform": line[1].lower(),
                    "version": line[2],
                    "OS Configuration": line[4],
                    "Product ID": line[8],
                    "Original Install Date": line[9],
                    "System Model": line[12],
                    "System Type": line[13],
                    "BIOS Version": line[15],
                    "System Locale": line[19],
                    "Time Zone": line[21],
                    "processor": str(platform.processor()),
                    "machine": line[13],
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


def get_extracted_driver_key():
    """This function check the presence of the key HKEY/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/Medulla Extract Drivers.
    This function is called only on windows machines.
    The key is added by the package Extract Drivers, only if the extraction step succeeded
        - return True if the key is present
        - return False if the key is absent
    """

    cmd = """REG QUERY "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Medulla Extract Drivers" """
    result = simplecommand(encode_strconsole(cmd))
    if result["code"] == 0:
        return True
    return False


def download_file_windows_update(url, connecttimeout=30, outdirname=None):
    """
    Cette function download file dans base windows
    wget system linux is used
    """
    if sys.platform.startswith("linux"):
        regex = re.compile(
            r"^(?:http|ftp)s?://"  # http:// or https://
            r"(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|"  # domain...
            r"localhost|"  # localhost...
            r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"  # ...or ip
            r"(?::\d+)?"  # optional port
            r"(?:/?|[/?]\S+)$",
            re.IGNORECASE,
        )
        if not re.match(regex, url) is not None:
            # url non conforme
            logging.getLogger().error("incorrect url [%s]" % (url))
            return False
        if outdirname is None:
            base_file = os.path.join("/", "var", "lib", "pulse2", "base_file_update")
        else:
            base_file = os.path.join("/", "var", "lib", "pulse2", outdirname)
        if os.path.dirname(base_file) != os.path.join("/", "var", "lib", "pulse2"):
            # name repertoire non conforme
            logging.getLogger().error(
                "download_file_windows_update incorrect path [%s]" % (base_file)
            )
            return False
        try:
            os.makedirs(base_file)
        except OSError:
            if not os.path.isdir(base_file):
                raise
        # os.makedirs(base_file, exist_ok=True)
        res = simplecommand("wget --connect-timeout=20 '%s'" % sys.argv[1])
        if res["code"] == 0:
            # correct download
            logging.getLogger().debug("download %s in [%s]" % (url, base_file))
            return True
        else:
            # incorrect download
            logging.getLogger().error(
                "download_file_windows_update incorrect download %s [%s]"
                % (url, res["result"])
            )
    else:
        logging.getLogger().error(
            "download_file_windows_update function download_file_windows_update linux only"
        )
    return False


# decorateur mesure temps d'une fonction
def measure_time(func):
    """
    Decorator that measures and prints the execution time of the wrapped function.

    This decorator calculates and prints the execution time of the wrapped function
    and displays the result in seconds.

    Parameters:
        func (callable): The function to be wrapped and for which the execution time will be measured.

    Returns:
        callable: The wrapped function with added execution time measurement.
    """

    def wrapper(*args, **kwargs):
        start_time = time.time()
        result = func(*args, **kwargs)
        end_time = time.time()
        execution_time = end_time - start_time
        print(f"Temps d'exécution de {func.__name__}: {execution_time} secondes")
        return result

    return wrapper


def log_params(func):
    """
    Decorator that logs positional and keyword arguments of the wrapped function.

    This decorator prints the positional and keyword arguments passed to the wrapped
    function, helping to debug and inspect the arguments.

    Parameters:
        func (callable): The function to be wrapped and for which the arguments will be logged.

    Returns:
        callable: The wrapped function with added logging of arguments.
    """

    def wrapper(*args, **kwargs):
        print(f"Paramètres positionnels : {args}")
        print(f"Paramètres nommés : {kwargs}")
        result = func(*args, **kwargs)
        return result

    return wrapper


def execute_medulla_info_update():
    """
    Exécute le script medulla_info_update.py situé dans le répertoire spécifié.

    Ce script est exécuté uniquement si le système d'exploitation est Windows.
    Il utilise le module subprocess pour lancer le script avec l'interpréteur Python.

    Raises:
        subprocess.CalledProcessError: Si le script retourne un code d'erreur non nul.
        FileNotFoundError: Si le fichier medulla_info_update.py n'existe pas à l'emplacement spécifié.
    """
    if platform.system() == "Windows":
        script_path = r"C:\Program Files\Medulla\bin\medulla_info_update.py"
        try:
            # Exécuter le script en utilisant l'interpréteur Python
            subprocess.run(
                ["c:\Program Files\Python3\python.exe", script_path], check=True
            )
            logger.info("Le script medulla_info_update.py a été exécuté avec succès.")
        except subprocess.CalledProcessError as e:
            logger.debug(f"Erreur lors de l'exécution du script : {e}")
        except FileNotFoundError:
            logger.error(
                "Le fichier medulla_info_update.py n'existe pas à l'emplacement spécifié."
            )
    else:
        logger.warning(
            "Ce programme est destiné à être exécuté uniquement sur Windows."
        )


def log_details(func):
    """
    Decorator that logs detailed information about the wrapped function.

    This decorator prints the name of the wrapped function, the file name, line number,
    positional, and keyword arguments passed to the function.

    Parameters:
        func (callable): The function to be wrapped and for which detailed information will be logged.

    Returns:
        callable: The wrapped function with added logging of details.
    """

    def wrapper(*args, **kwargs):
        frame = inspect.currentframe().f_back
        filename = frame.f_code.co_filename
        line_number = frame.f_lineno
        function_name = func.__name__
        print(f"Nom de la fonction : {function_name}")
        print(f"Fichier : {filename}, ligne : {line_number}")
        print(f"Paramètres positionnels : {args}")
        print(f"Paramètres nommés : {kwargs}")
        result = func(*args, **kwargs)
        return result

    return wrapper


def log_details_debug_info(func):
    """
    Decorator that logs debug information for the wrapped function.

    This decorator adds logging functionality to the wrapped function, providing debug
    information such as function name, line number, positional arguments, and keyword
    arguments to the console.

    Parameters:
        func (callable): The function to be wrapped and enhanced with logging.

    Returns:
        callable: The wrapped function with added logging capabilities.
    """

    def wrapper(*args, **kwargs):
        frame = inspect.currentframe().f_back
        filename = frame.f_code.co_filename
        line_number = frame.f_lineno
        function_name = func.__name__
        # Configuration du logger
        logger = logging.getLogger(function_name)
        logger.setLevel(logging.INFO)
        # Configuration du format de log
        log_format = f"{function_name} - Ligne {line_number} - %(message)s"
        formatter = logging.Formatter(log_format)
        # Configuration du handler de log vers la console
        console_handler = logging.StreamHandler()
        console_handler.setLevel(logging.INFO)
        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)
        # Log des paramètres passés à la fonction
        logger.info(f"Paramètres positionnels : {args}")
        logger.info(f"Paramètres nommés : {kwargs}")
        result = func(*args, **kwargs)
        return result

    return wrapper


def generate_log_line(message):
    """
    Generate a log line with the provided message, including the filename and line number.

    This function is used to create a log line in the format:
    "[filename:line_number] - message"

    Parameters:
        message (str): The message to be included in the log line.

    Returns:
        str: A log line string in the format "[filename:line_number] - message".
    """
    frame = inspect.currentframe().f_back
    file_name = inspect.getframeinfo(frame).filename
    line_number = frame.f_lineno
    log_line = f"[{file_name}:{line_number}] - {message}"
    return log_line


def display_message_dev(message):
    """
    Display the given message in the log if the global variable 'DEV' is defined and equal to 1.

    If the global variable 'DEV' is defined and its value is 1, this function will log the provided
    message using the 'logging' module to the console.

    Parameters:
        message (str): The message to be displayed in the log.

    Returns:
        None
    """
    try:
        DEV
    except NameError:
        DEV = 0

    if DEV == 1:
        frame = inspect.currentframe().f_back
        file_name = inspect.getframeinfo(frame).filename
        line_number = frame.f_lineno
        logger = logging.getLogger(file_name)
        logger.setLevel(logging.INFO)
        # Configuration du handler de stream (affichage console)
        stream_handler = logging.StreamHandler()
        stream_handler.setLevel(logging.INFO)
        logger.addHandler(stream_handler)
        log_line = generate_log_line(message)
        logger.info(log_line)


def display_message(message):
    """
    Display the given message in the log.

    Parameters:
        message (str): The message to be displayed in the log.

    Returns:
        None
    """
    frame = inspect.currentframe().f_back
    file_name = inspect.getframeinfo(frame).filename
    line_number = frame.f_lineno
    logger = logging.getLogger(file_name)
    logger.setLevel(logging.INFO)
    # Configuration du handler de stream (affichage console)
    stream_handler = logging.StreamHandler()
    stream_handler.setLevel(logging.INFO)
    logger.addHandler(stream_handler)
    log_line = generate_log_line(message)
    logger.info(log_line)


def generer_mot_de_passe(taille):
    """
    Cette fonction permet de generer 1 mot de passe aléatoire
    le parametre taille precise le nombre de caractere du mot de passe
    renvoi le mot de passe

    eg : mot_de_passe = generer_mot_de_passe(32)
    """
    caracteres = string.ascii_letters + string.digits + string.punctuation
    mot_de_passe = "".join(random.choice(caracteres) for _ in range(taille))
    return mot_de_passe


class MotDePasse:
    def __init__(
        self,
        taille,
        temps_validation=60,
        caracteres_interdits=""""()[],%:|`.{}'><\\/^""",
    ):
        self.taille = taille
        self.caracteres_interdits = [x for x in caracteres_interdits]
        self.temps_validation = temps_validation
        self.mot_de_passe = self.generer_mot_de_passe()
        self.date_expiration = self.calculer_date_expiration()

    def generer_mot_de_passe(self):
        caracteres = string.ascii_letters + string.digits + string.punctuation
        for caractere_interdit in self.caracteres_interdits:
            caracteres = caracteres.replace(caractere_interdit, "")
        mot_de_passe = "".join(random.choice(caracteres) for _ in range(self.taille))
        return mot_de_passe

    def calculer_date_expiration(self):
        return datetime.now() + timedelta(seconds=self.temps_validation)

    def verifier_validite(self):
        temps_restant = (self.date_expiration - datetime.now()).total_seconds()
        return temps_restant

    def est_valide(self):
        return datetime.now() < self.date_expiration


class DateTimebytesEncoderjson(json.JSONEncoder):
    """
    Used to handle datetime in json files.
    """

    def default(self, obj):
        if isinstance(obj, datetime):
            encoded_object = obj.isoformat()
        elif isinstance(obj, bytes):
            encoded_object = obj.decode("utf-8")
        else:
            encoded_object = json.JSONEncoder.default(self, obj)
        return encoded_object


def name_random(nb, pref=""):
    a = "abcdefghijklnmopqrstuvwxyz0123456789"
    d = pref
    for t in range(nb):
        d = d + a[random.randint(0, 35)]
    return d


class convert:
    """
    les packages suivant son obligatoire.
    python3-xmltodict python3-dicttoxml python3-yaml json2xml
    pip3 install dict2xml
    Cette class presente des methodes pour convertir simplement des objects.
    elle expose les fonction suivante
        convert_dict_to_yaml(input_dict)
        convert_yaml_to_dict(yaml_data)
        yaml_string_to_dict(yaml_string)
        check_yaml_conformance(yaml_data)
        compare_yaml(yaml_string1, yaml_string2)
        convert_dict_to_json(input_dict_json, indent=None, sort_keys=False)
        check_json_conformance(json_data)
        convert_json_to_dict(json_str)
        xml_to_dict(xml_string)
        compare_xml(xml_file1, xml_file2)
        convert_xml_to_dict(xml_str)
        convert_json_to_xml(input_json)
        convert_xml_to_json(input_xml)
        convert_dict_to_xml(data_dict)
        convert_bytes_datetime_to_string(data)
        compare_dicts(dict1, dict2)
        compare_json(json1, json2)
        convert_to_bytes(input_data)
        compress_and_encode(string)
        decompress_and_encode(string)
        convert_datetime_to_string(input_date)
        encode_to_string_base64(input_data)
        decode_base64_to_string_(input_data)
        check_base64_encoding(input_string)
        taille_string_in_base64(string)
        string_to_int(s)
        int_to_string(n)
        string_to_float(s)
        float_to_string(f)
        list_to_string(lst, separator=', ')
        string_to_list(s, separator=', ')
        list_to_set(lst)
        set_to_list(s)
        dict_to_list(d)
        list_to_dict(lst)
        char_to_ascii(c)
        ascii_to_char(n)
        convert_rows_to_columns(data)
        convert_columns_to_rows(data)
        convert_to_ordered_dict(dictionary)
        generate_random_text(num_words)
        capitalize_words(text)
        compress_data_to_bytes(data)
        decompress_data_to_bytes(data_bytes_compress
        compress_dict_to_dictbytes(dict_data)
        decompress_dictbytes_to_dict(data_bytes_compress)
    """

    # YAML
    @staticmethod
    def convert_dict_to_yaml(input_dict):
        """
        la fonction suivante Python convertit 1 dict python en json.
        """
        if isinstance(input_dict, dict):
            return yaml.dump(convert.convert_bytes_datetime_to_string(input_dict))
        else:
            raise TypeError("L'entrée doit être de type dict.")

    @staticmethod
    def convert_yaml_to_dict(yaml_string):
        return convert.yaml_string_to_dict(yaml_string)

    @staticmethod
    def yaml_string_to_dict(yaml_string):
        try:
            yaml_data = yaml.safe_load(
                convert.convert_bytes_datetime_to_string(yaml_string)
            )
            if isinstance(yaml_data, (dict, list)):
                return yaml_data
            else:
                raise yaml.YAMLError(
                    "Erreur lors de la conversion de la chaîne YAML en dictionnaire."
                )
        except yaml.YAMLError as e:
            raise ValueError(
                "Erreur lors de la conversion de la chaîne YAML en dictionnaire."
            )

    @staticmethod
    def check_yaml_conformance(yaml_data):
        try:
            # Chargement du YAML pour vérifier la conformité
            yaml.safe_load(convert.convert_bytes_datetime_to_string(yaml_data))
            return True
        except yaml.YAMLError:
            return False

    @staticmethod
    def compare_yaml(yaml_string1, yaml_string2):
        """
        Dans cette fonction compare_yaml, nous appelons la fonction yaml_string_to_dict pour convertir chaque chaîne YAML en dictionnaire.
        Si une exception ValueError est levée lors de la conversion, nous affichons l eur et retournons False.
        nous utilisons la fonction compare_dicts pour comparer les dictionnaires obtenus.
        Si les dictionnaires sont égaux, la fonction compare_yaml retourne True, sinon elle retourne False.
        """
        try:
            dict1 = convert.yaml_string_to_dict(yaml_string1)
            dict2 = convert.yaml_string_to_dict(yaml_string2)
            return convert.compare_dicts(dict1, dict2)
        except ValueError as e:
            print(f"Erreur: {str(e)}")
            return False

    # JSON
    @staticmethod
    def convert_dict_to_json(input_dict_json, indent=None, sort_keys=False):
        """
        la fonction suivante Python convertit 1 dict python en json.
        """
        if isinstance(input_dict_json, dict):
            return json.dumps(
                convert.convert_bytes_datetime_to_string(input_dict_json), indent=indent
            )
        else:
            raise TypeError("L'entrée doit être de type dict.")

    @staticmethod
    def check_json_conformance(json_data):
        try:
            json.loads(json_data)
            return True
        except json.JSONDecodeError:
            return False

    @staticmethod
    def convert_json_to_dict(json_str):
        logger.debug(
            "AAAAAAAA convert_json_to_dict **json_str***** data %s" % type(json_str)
        )
        if isinstance(json_str, (dict)):
            return json_str

        logger.debug(
            "AAAAAAAA convert_json_to_dict **************** data %s" % type(json_str)
        )
        stringdata = convert.convert_bytes_datetime_to_string(json_str)
        logger.debug(
            "AAAAAAAA convert_json_to_dict ****stringdata***** data %s"
            % type(stringdata)
        )
        if isinstance(stringdata, (str)):
            try:
                return json.loads(stringdata)
            except json.decoder.JSONDecodeError as e:
                raise
            except Exception as e:
                # Code de gestion d'autres types d'exceptions
                logger.error("convert_json_to_dict %s" % (e))
                raise

    @staticmethod
    def xml_to_dict(xml_string):
        def xml_element_to_dict(element):
            if len(element) == 0:
                return element.text
            result = {}
            for child in element:
                child_dict = xml_element_to_dict(child)
                if child.tag in result:
                    if not isinstance(result[child.tag], list):
                        result[child.tag] = [result[child.tag]]
                    result[child.tag].append(child_dict)
                else:
                    result[child.tag] = child_dict
            return result

        try:
            tree = ET.ElementTree(
                ET.fromstring(convert.convert_bytes_datetime_to_string(xml_string))
            )
            root = tree.getroot()
            return xml_element_to_dict(root)
        except ET.ParseError:
            raise ValueError("Erreur lors de la conversion XML en dictionnaire.")

    @staticmethod
    def compare_xml(xml_file1, xml_file2):
        try:
            dict1 = convert.xml_to_dict(xml_file1)
            dict2 = convert.xml_to_dict(xml_file2)
            return convert.compare_dicts(dict1, dict2)
        except ValueError as e:
            print(f"Erreur: {str(e)}")
            return False

    @staticmethod
    def convert_xml_to_dict(xml_string):
        def _element_to_dict(element):
            result = {}
            for child in element:
                if child.tag not in result:
                    result[child.tag] = []
                result[child.tag].append(_element_to_dict(child))
            if not result:
                return element.text
            return result

        root = ET.fromstring(convert.convert_bytes_datetime_to_string(xml_string))
        return _element_to_dict(root)

    @staticmethod
    def convert_json_to_xml(json_data, root_name="root"):
        def _convert(element, parent):
            if isinstance(element, dict):
                for key, value in element.items():
                    if isinstance(value, (dict, list)):
                        sub_element = ET.SubElement(parent, key)
                        _convert(value, sub_element)
                    else:
                        child = ET.SubElement(parent, key)
                        child.text = str(value)
            elif isinstance(element, list):
                for item in element:
                    sub_element = ET.SubElement(parent, parent.tag[:-1])
                    _convert(item, sub_element)

        root = ET.Element(root_name)
        _convert(json.loads(json_data), root)

        xml_data = ET.tostring(root, encoding="unicode", method="xml")
        return xml_data

    # xml
    @staticmethod
    def convert_xml_to_json(input_xml):
        return json.dumps(xmltodict.parse(input_xml), indent=4)

    @staticmethod
    def convert_dict_to_xml(data_dict):
        xml_str = xmltodict.unparse({"root": data_dict}, pretty=True)
        return xml_str

    @staticmethod
    def convert_bytes_datetime_to_string(data):
        """
        la fonction suivante Python parcourt récursivement un dictionnaire,
        convertit les types bytes en str,
        les objets datetime en chaînes de caractères au format "année-mois-jour heure:minute:seconde"
        si les clés sont de type bytes elles sont convertit en str :
        encodage ('utf-8') est utilise pour le decode des bytes.
        Si 1 chaine est utilisée pour definir FALSE ou True alors c'est convertit en boolean True/false
        Si 1 valeur est None, elle est convertit a ""
        Si key ou valeur ne peut pas etre convertit en str alors 1 exception est leve
        renvoi le dictionnaire serializable
        """
        if isinstance(data, (str)):
            compa = data.lower
            if compa == "true":
                return True
            elif compa == "false":
                return False
            elif compa == "none":
                return ""
            return data
        if isinstance(data, (int, float, bool)):
            return data
        elif isinstance(data, dict):
            return {
                convert.convert_bytes_datetime_to_string(
                    key
                ): convert.convert_bytes_datetime_to_string(value)
                for key, value in data.items()
            }
        elif isinstance(data, list):
            return [convert.convert_bytes_datetime_to_string(item) for item in data]
        elif isinstance(data, bytes):
            return data.decode("utf-8")
        elif isinstance(data, datetime):
            return data.strftime("%Y-%m-%d %H:%M:%S")
        elif data is None:
            return ""
        else:
            try:
                str(data)
                return data
            except Exception as e:
                raise ValueError(
                    "Type %s impossible de convertir en string " % type(data)
                )
        return data

    @staticmethod
    def compare_dicts(dict1, dict2):
        """
        Dans cette fonction, nous commençons par comparer les ensembles des clés des deux dictionnaires (dict1.keys() et dict2.keys()). Si les ensembles des clés sont différents, nous retournons False immédiatement car les dictionnaires ne peuvent pas être égaux.

        Ensuite, nous itérons sur les clés du premier dictionnaire (dict1.keys()) et comparons les valeurs correspondantes dans les deux dictionnaires (value1 et value2).

        Si une valeur est un autre dictionnaire, nous effectuons un appel récursif à la fonction compare_dicts pour comparer les sous-dictionnaires. Si le résultat de l'appel récursif est False, nous retournons False immédiatement.

        Si les valeurs ne sont pas égales et ne sont pas des dictionnaires, nous retournons également False.

        Si toutes les clés et les valeurs correspondent dans les deux dictionnaires, nous retournons True à la fin de la fonction.
        """
        if dict1.keys() != dict2.keys():
            return False

        for key in dict1.keys():
            value1 = dict1[key]
            value2 = dict2[key]

            if isinstance(value1, dict) and isinstance(value2, dict):
                # Si la valeur est un dictionnaire, appel récursif
                if not convert.compare_dicts(value1, value2):
                    return False
            elif value1 != value2:
                # Si les valeurs ne sont pas égales, retourne False
                return False
        return True

    @staticmethod
    def compare_json(json1, json2):
        try:
            dict1 = json.loads(json1)
            dict2 = json.loads(json2)
        except json.JSONDecodeError:
            raise ValueError("Erreur lors de la conversion JSON en dictionnaire.")
        return convert.compare_dicts(dict1, dict2)

    @staticmethod
    def convert_to_bytes(input_data):
        if isinstance(input_data, bytes):
            return input_data
        elif isinstance(input_data, str):
            return input_data.encode("utf-8")
        else:
            raise TypeError("L'entrée doit être de type bytes ou string.")

    # COMPRESS
    @staticmethod
    def compress_and_encode(string):
        # Convert string to bytes
        data = convert.convert_to_bytes(string)
        # Compress the data using zlib
        compressed_data = zlib.compress(data, 9)
        # Encode the compressed data in base64
        encoded_data = base64.b64encode(compressed_data)
        return encoded_data.decode("utf-8")

    @staticmethod
    def decompress_and_encode(string):
        # Convert string to bytes
        data = convert.convert_to_bytes(string)
        decoded_data = base64.b64decode(data)
        # Decompress the data using zlib
        decompressed_data = zlib.decompress(decoded_data)
        # Encode the decompressed data in base64
        return decompressed_data.decode("utf-8")

    # datetime
    @staticmethod
    def convert_datetime_to_string(input_date: datetime):
        if isinstance(input_date, datetime):
            return input_date.strftime("%Y-%m-%d %H:%M:%S")
        else:
            raise TypeError("L'entrée doit être de type datetime.")

    # base64
    @staticmethod
    def encode_to_string_base64(input_data):
        if isinstance(input_data, str):
            input_data_bytes = input_data.encode("utf-8")
        elif isinstance(input_data, bytes):
            input_data_bytes = input_data
        else:
            raise TypeError("L'entrée doit être une chaîne ou un objet bytes.")
        encoded_bytes = base64.b64encode(input_data_bytes)
        encoded_string = encoded_bytes.decode("utf-8")
        return encoded_string

    @staticmethod
    def decode_base64_to_string_(input_data):
        try:
            decoded_bytes = base64.b64decode(input_data)
            decoded_string = decoded_bytes.decode("utf-8")
            return decoded_string
        except base64.binascii.Error:
            raise ValueError("L'entrée n'est pas encodée en base64 valide.")

    @staticmethod
    def check_base64_encoding(input_string):
        try:
            # Décode la chaîne en base64 et vérifie si cela génère une erreur
            base64.b64decode(input_string)
            return True
        except base64.binascii.Error:
            return False

    @staticmethod
    def taille_string_in_base64(string):
        """
        renvoie la taille que prend 1 string en encode en base64.
        """
        taille = len(string)
        return (taille + 2 - ((taille + 2) % 3)) * 4 / 3

    @staticmethod
    def string_to_int(s):
        """
        Conversion de chaînes en entiers
        """
        try:
            return int(s)
        except ValueError:
            return None

    @staticmethod
    def int_to_string(n):
        """
        Conversion d'entiers en chaînes
        """
        return str(n)

    @staticmethod
    def string_to_float(s):
        """
        Conversion de chaînes en nombres à virgule flottante
        """
        try:
            return float(s)
        except ValueError:
            return None

    @staticmethod
    def float_to_string(f):
        """
        Conversion de nombres à virgule flottante en chaînes
        """
        return str(f)

    @staticmethod
    def list_to_string(lst, separator=", "):
        """
        Conversion d'une liste de chaînes en une seule chaîne avec un séparateur
        """
        return separator.join(lst)

    @staticmethod
    def string_to_list(s, separator=", "):
        """
        Conversion d'une chaîne en une liste en utilisant un séparateur
        """
        return s.split(separator)

    @staticmethod
    def list_to_set(lst):
        """
        Conversion d'une liste en un ensemble (élimine les doublons)
        """
        return set(lst)

    @staticmethod
    def set_to_list(s):
        """
        Conversion d'un ensemble en une liste en conservant l'ordre
        """
        return [item for item in s]

    @staticmethod
    def dict_to_list(d):
        """
        Conversion d'un dictionnaire en une liste de tuples clé-valeur
        """
        return list(d.items())

    @staticmethod
    def list_to_dict(lst):
        """
        Conversion d'une liste de tuples clé-valeur en un dictionnaire
        """
        return dict(lst)

    @staticmethod
    def char_to_ascii(c):
        """
        Conversion de caractères en code ASCII
        """
        return ord(c)

    @staticmethod
    def ascii_to_char(n):
        """
        Conversion de code ASCII en caractère :
        """
        return chr(n)

    @staticmethod
    def convert_rows_to_columns(data):
        """
        cette fonction fait la convertion depuis 1 list de dict representant des lignes
        en
        1 list de colonne

        data = [{"id": 1, "name": "mac1", "age": 30},
                {"id": 2, "name": "mac2", "age": 25}]
        to
        [{'age': [30, 25]}, {'name': ['mac1', 'mac2']}, {'id': [1, 2]}]
        """
        # Obtenez les noms de colonnes
        column_names = set()
        for row in data:
            column_names.update(row.keys())
        # Créez un dictionnaire vide pour chaque colonne
        columns = {name: [] for name in column_names}
        # Remplissez les colonnes avec les valeurs correspondantes
        for row in data:
            for column, value in row.items():
                columns[column].append(value)
        # Convertissez les dictionnaires de colonnes en une liste de colonnes
        columns_list = [{name: values} for name, values in columns.items()]
        return columns_list

    @staticmethod
    def convert_columns_to_rows(data):
        """
        Cette fonction fait l'inverse de la conversion réalisée par la fonction convert_rows_to_columns.

        data = [{'age': [30, 25]}, {'name': ['mac1', 'mac2']}, {'id': [1, 2]}]
        to
        [{"id": 1, "name": "mac1", "age": 30},
        {"id": 2, "name": "mac2", "age": 25}]
        """
        # Obtenez tous les noms de colonnes
        rows = []
        s = [list(x.keys())[0] for x in data]
        nbligne = len(data[0][s[0]])
        for t in range(nbligne):
            result = {}
            for z in range(len(s)):
                result[s[z]] = data[z][s[z]][t]
            rows.append(result)
        return rows

    @staticmethod
    def convert_to_ordered_dict(dictionary):
        ordered_dict = OrderedDict()
        for key, value in dictionary.items():
            ordered_dict[key] = value
        return ordered_dict

    @staticmethod
    def generate_random_text(num_words):
        words = []
        for _ in range(num_words):
            word = "".join(
                random.choice(string.ascii_letters) for _ in range(random.randint(3, 8))
            )
            words.append(word)
        return " ".join(words)

    @staticmethod
    def capitalize_words(text):
        """
        renvoi la chaine avec chaque mot commencant par une majuscule et les autres lettres sont en minuscules
        """
        words = text.split()
        capitalized_words = [word.capitalize() for word in words]
        capitalized_text = " ".join(capitalized_words)
        return capitalized_text

    # Fonction de compression gzip
    @staticmethod
    def compress_data_to_bytes(data_string_or_bytes):
        return gzip.compress(convert.convert_to_bytes(data_string_or_bytes))

    # Fonction de décompression gzip
    @staticmethod
    def decompress_data_to_bytes(data_bytes_compress):
        return convert.convert_to_bytes(gzip.decompress(data_bytes_compress))

    @staticmethod
    def serialized_dict_to_compressdictbytes(dict_data):
        json_bytes = json.dumps(
            dict_data, indent=4, cls=DateTimebytesEncoderjson
        ).encode("utf-8")
        return convert.compress_data_to_bytes(json_bytes)

    @staticmethod
    def unserialized_compressdictbytes_to_dict(serialized_dict_bytes_compress):
        json_bytes = gzip.decompress(
            convert.convert_to_bytes(serialized_dict_bytes_compress)
        )
        return json.loads(json_bytes)

    @staticmethod
    def is_multiple_of(s, multiple=4):
        return len(s) % multiple == 0

    @staticmethod
    def is_base64(s):
        if not convert.is_multiple_of(s, multiple=4):
            return False
        decoded = None
        try:
            # Tente de décoder la chaîne en base64
            decoded = base64.b64decode(s)
            # Vérifie si la chaîne d'origine est égale à la chaîne encodée puis décodée
            if base64.b64encode(decoded) == s.encode():
                return decoded
            else:
                return False
        except:
            return False

    @staticmethod
    def header_body(xml_string):
        """
        on supprime l'entete xml
        """
        body = header = ""
        index = xml_string.find("?>")
        if index != -1:
            # Supprimer l'en-tête XML
            body = xml_string[index + 2 :]
            header = xml_string[: index + 2]
        return header, body

    @staticmethod
    def format_xml(xml_string):
        dom = parseString(xml_string)
        formatted_xml = dom.toprettyxml(indent="  ")
        return formatted_xml


class NetworkInfoxmpp:
    def __init__(self, port: int):
        self.port = int(port)
        self.ip_address = self._get_established_ipv4_connection_on_port()
        if self.ip_address:
            self.details = self._get_interface_details()
        else:
            self.details = None

    def _get_established_ipv4_connection_on_port(self) -> str:
        connections = psutil.net_connections(kind="inet")
        for conn in connections:
            if (
                conn.family == socket.AF_INET
                and conn.status == psutil.CONN_ESTABLISHED
                and conn.raddr
                and conn.raddr.port == self.port
            ):
                return conn.laddr.ip
        return None

    def _get_interface_details(self):
        details = {}
        interface_name = None

        # Find the interface for the given IPv4 address
        for interface, addrs in psutil.net_if_addrs().items():
            for addr in addrs:
                if addr.family == socket.AF_INET and addr.address == self.ip_address:
                    interface_name = interface
                    details["ip_address"] = self.ip_address
                    details["netmask"] = addr.netmask
                    details["broadcast"] = addr.broadcast
                    break
            if interface_name:
                break

        if not interface_name:
            return None

        # Calculate network address
        if "ip_address" in details and "netmask" in details:
            ip = int.from_bytes(socket.inet_aton(details["ip_address"]), "big")
            netmask = int.from_bytes(socket.inet_aton(details["netmask"]), "big")
            network = socket.inet_ntoa((ip & netmask).to_bytes(4, "big"))
            details["network"] = network

        # Get the gateway
        gateway = self._get_gateway()
        details["gateway"] = gateway

        # Get the DHCP server and client addresses
        details["dhcp_server"] = None  # Update this for your environment
        details["dhcp_client"] = None  # Update this for your environment
        # Get the MAC address
        details["macnotshortened"] = self._get_mac_address(interface_name)
        details["macaddress"] = self.reduction_mac(details["macnotshortened"])
        return details

    def _get_gateway(self):
        system = platform.system()
        if system == "Windows":
            gateway = (
                os.popen('ipconfig | findstr /C:"Default Gateway"')
                .read()
                .strip()
                .split(":")[-1]
                .strip()
            )
        elif system == "Linux":
            gateway = (
                os.popen("ip route | grep default | awk '{print $3}'").read().strip()
            )
        elif system == "Darwin":  # macOS
            gateway = (
                os.popen("netstat -nr | grep default | awk '{print $2}'").read().strip()
            )
        else:
            gateway = None
        return gateway

    def _get_mac_address(self, interface):
        try:
            mac_address = psutil.net_if_addrs()[interface][0].address
            return mac_address
        except KeyError:
            return None

    def reduction_mac(self, mac):
        mac = mac.lower()
        mac = mac.replace(":", "")
        mac = mac.replace("-", "")
        mac = mac.replace(" ", "")
        return mac


def clean_update_directories():
    """
    Cette fonction vérifie l'existence du fichier BOOL_CLEAN_UPDATE dans le répertoire
    C:\\Program Files\\Python3\\Lib\\site-packages\\pulse_xmpp_agent\\.
    Si le fichier existe, elle recherche les répertoires terminant par la chaîne "update" dans
    C:\\Program Files\\Medulla\\var\\tmp\\packages\\ et les supprime, ainsi que le fichier BOOL_CLEAN_UPDATE.
    Ensuite, elle démonte tous les lecteurs logiques CD-ROM.
    """
    # Chemin du fichier BOOL_CLEAN_UPDATE
    bool_clean_update_path = (
        r"C:\Program Files\Python3\Lib\site-packages\pulse_xmpp_agent\BOOL_CLEAN_UPDATE"
    )

    # Vérifie si le fichier BOOL_CLEAN_UPDATE existe
    if os.path.exists(bool_clean_update_path):
        logger.debug(
            "Le fichier BOOL_CLEAN_UPDATE a été trouvé. Exécution des actions..."
        )

        # Chemin du répertoire cible pour la recherche des répertoires "update"
        target_dir = r"C:\Program Files\Medulla\var\tmp\packages"

        # Recherche des répertoires terminant par "update"
        for root, dirs, files in os.walk(target_dir):
            for dir_name in dirs:
                if dir_name.endswith("update"):
                    dir_path = os.path.join(root, dir_name)
                    logger.debug(f"Suppression du répertoire : {dir_path}")
                    try:
                        shutil.rmtree(dir_path)
                        logger.debug(
                            f"Le répertoire {dir_path} a été supprimé avec succès."
                        )
                    except Exception as e:
                        logger.error(
                            f"Erreur lors de la suppression du répertoire {dir_path}. Message : {e}"
                        )

        # Suppression du fichier BOOL_CLEAN_UPDATE
        try:
            os.remove(bool_clean_update_path)
            logger.debug("Le fichier BOOL_CLEAN_UPDATE a été supprimé avec succès.")
        except Exception as e:
            logger.debug(
                f"Erreur lors de la suppression du fichier BOOL_CLEAN_UPDATE. Message : {e}"
            )

        # Démonter les lecteurs logiques CD-ROM
        eject_cdrom_drives()
    else:
        logger.debug(
            "Le fichier BOOL_CLEAN_UPDATE n'a pas été trouvé. Aucune action n'est requise."
        )

def eject_cdrom_drives():
    """
    Récupère la liste des lecteurs CD/DVD via CIM en utilisant :
        Get-CimInstance -ClassName Win32_CDROMDrive
    Puis tente de les éjecter via l'API Shell.Application.
    """

    # Exécute Get-CimInstance et récupère les données en JSON
    ps_command = [
        "powershell",
        "-NoProfile",
        "-Command",
        "Get-CimInstance -ClassName Win32_CDROMDrive | "
        "Select-Object Drive, Name | "
        "ConvertTo-Json"
    ]

    try:
        result = subprocess.check_output(ps_command, text=True, encoding="utf-8")
    except subprocess.CalledProcessError as e:
        logger.debug(f"Erreur PowerShell : {e}")
        return

    # Parse le JSON PowerShell (peut être un dict ou une liste)
    try:
        cdrom_list = json.loads(result)
    except json.JSONDecodeError:
        logger.debug("Aucun lecteur CD/DVD détecté par Get-CimInstance.")
        return

    # Normalise pour toujours avoir une liste
    if isinstance(cdrom_list, dict):
        cdrom_list = [cdrom_list]

    if not cdrom_list:
        logger.debug("Aucun lecteur CD/DVD trouvé via CIM.")
        return

    pythoncom.CoInitialize()
    try:
        for drive in cdrom_list:
            device_id = drive.get("Drive")
            name = drive.get("Name")

            logger.debug(f"Lecteur trouvé : {device_id} - {name}")

            if not device_id:
                continue

            try:
                shell = win32com.client.Dispatch("Shell.Application")
                cd_drive = shell.Namespace(17).ParseName(device_id)

                if cd_drive:
                    cd_drive.InvokeVerb("Eject")
                    logger.debug(f"Le lecteur {device_id} a été éjecté avec succès.")
                else:
                    logger.debug(f"Impossible de localiser {device_id} via Shell.Application.")

            except Exception as e:
                logger.debug(f"Erreur lors de l'éjection de {device_id} : {e}")

    finally:
        pythoncom.CoUninitialize()
