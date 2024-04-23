#!/usr/bin/python3
# -*- coding: utf-8; -*-
# SPDX-FileCopyrightText: 2016-2023 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-3.0-or-later
import sys

import configparser
from slixmpp import jid
import netifaces
import json
import platform
import os
import logging
from . import utils
import random
from .agentconffile import conffilename

from .agentconffile import directoryconffile
from .utils import ipfromdns
import re

logger = logging.getLogger()


def uniq(input):
    """
    Remove duplicate elements from the input list and return a new list.

    Args:
        input (list): The input list containing elements.

    Returns:
        list: A new list with duplicate elements removed.
    """
    output = []
    for x in input:
        if x not in output:
            output.append(x)
    return output


def changeconfigurationsubtitute(conffile, confsubtitute):
    """
    Modify the machine agent to use substitute by default.

    Args:
        conffile (str): The configuration file to modify.
        confsubtitute (dict): The substitute to add in the configuration file.
    """
    Config = configparser.ConfigParser()
    Config.read(conffile)
    if not Config.has_section("substitute"):
        Config.add_section("substitute")
    for t in confsubtitute["conflist"]:
        uniq_list = uniq(confsubtitute[t])
        Config.set("substitute", t, ",".join(uniq_list))
        logger.info(f"application substitut {uniq_list[0]} for {t}")
    logger.debug("writing parameters of the substitutes")
    with open(conffile, "w") as configfile:
        Config.write(configfile)


def changeconnection(conffile, port, ipserver, jidrelayserver, baseurlguacamole):
    """
    Modify default configuration parameters.

    Args:
        conffile (str): The configuration file to modify.
        port (int): The new port to use (section connection).
        ipserver (str): The new IP of the main server (section connection).
        jidrelayserver (str): The new JID of the relay server (section global).
        baseurlguacamole (str): The URL used for Guacamole (section type).
    """
    Config = configparser.ConfigParser()
    Config.read(conffile)
    domain = jid.JID(jidrelayserver).domain
    if not Config.has_option("configuration_server", "confdomain"):
        logger.warning(
            "The confdomain parameter is missing in the configuration_server section."
        )
        logger.warning(
            'We will force the configuration by using "medulla" for confdomain.'
        )

        Config.set("configuration_server", "confdomain", "medulla")
    Config.set("chat", "domain", domain)
    Config.set("connection", "port", str(port))
    Config.set("connection", "server", ipfromdns(str(ipserver)))
    Config.set("global", "relayserver_agent", str(jidrelayserver))
    Config.set("type", "guacamole_baseurl", str(baseurlguacamole))
    with open(conffile, "w") as configfile:
        Config.write(configfile)


def alternativeclusterconnection(conffile, data):
    """
    Add an alternative cluster to the configuration file.

    Args:
        conffile (str): The configuration file to modify.
        data (list): The information about the alternative cluster.

    Note:
        The `data` parameter should be a list of tuples, where each tuple contains
        the IP address, port, JID, and Guacamole base URL for an alternative server.

    Example:
        alternativeclusterconnection("config.ini", [
            ("192.168.1.2", 8080, "alternative_server1@domain.com", "http://guac.com")
        ])
    """
    logger.debug(f"We write the file {conffile} to handle alternative connections")
    with open(conffile, "w") as configfile:
        if len(data) != 0:
            listalternative = [str(x[2]) for x in data]
            nb_alternativeserver = len(listalternative)
            configfile.write(f"[alternativelist]{os.linesep}")
            configfile.write(f'listars = {",".join(listalternative)}{os.linesep}')
            configfile.write(f"nbserver = {nb_alternativeserver}{os.linesep}")
            configfile.write(f"nextserver = 1{os.linesep}")
            for arsdataconection in data:
                configfile.write(f"[{str(arsdataconection[2])}]{os.linesep}")
                configfile.write(f"port = {str(arsdataconection[1])}{os.linesep}")
                configfile.write(
                    f"server = {ipfromdns(str(arsdataconection[0]))}{os.linesep}"
                )
                configfile.write(
                    f"guacamole_baseurl = {str(arsdataconection[3])}{os.linesep}"
                )
        elif os.path.isfile(conffile):
            os.unlink(conffile)


def nextalternativeclusterconnectioninformation(conffile):
    """
    Retrieve information about the next alternative cluster from the configuration file.

    Args:
        conffile (str): The configuration file containing alternative cluster information.

    Returns:
        dict: A dictionary containing information about the next alternative cluster.

    Example:
        nextalternativeclusterconnectioninformation("config.ini")
    """
    if not os.path.isfile(conffile):
        logger.error(f"file alternatif conf missing {conffile}")
        return {}

    Config = configparser.ConfigParser()
    Config.read(conffile)
    alternatif_conf = {"nextserver": Config.getint("alternativelist", "nextserver")}
    alternatif_conf["nbserver"] = Config.getint("alternativelist", "nbserver")
    alternatif_conf["listars"] = [
        x.strip()
        for x in Config.get("alternativelist", "listars").split(",")
        if x.strip() != ""
    ]

    if len(alternatif_conf["listars"]) != alternatif_conf["nbserver"]:
        logger.error(f"format alternatif file {conffile} : count list ars != nbserver")
        return {}

    if alternatif_conf["nextserver"] > alternatif_conf["nbserver"]:
        alternatif_conf["nextserver"] = 1

    # charge les informations server
    for ars in alternatif_conf["listars"]:
        if not Config.has_section(ars):
            logger.error(f"format alternatif file {conffile} : section {ars} missing")
            return {}

    for ars in alternatif_conf["listars"]:
        if not (
            Config.has_option(ars, "port")
            and Config.has_option(ars, "server")
            and Config.has_option(ars, "guacamole_baseurl")
        ):
            logger.error(
                f"format alternatif file {conffile} : section {ars} farmat error"
            )
            return {}
        else:
            alternatif_conf[ars] = {}
            alternatif_conf[ars]["port"] = Config.getint(ars, "port")
            alternatif_conf[ars]["server"] = Config.get(ars, "server")
            alternatif_conf[ars]["guacamole_baseurl"] = Config.get(
                ars, "guacamole_baseurl"
            )
    return alternatif_conf


def nextalternativeclusterconnection(conffile):
    """
    Move to the next alternative cluster and update the configuration file.

    Args:
        conffile (str): The configuration file to modify.

    Returns:
        list: A list containing information about the next alternative cluster.

    Example:
        nextalternativeclusterconnection("config.ini")
    """
    if not os.path.isfile(conffile):
        return []
    Config = configparser.ConfigParser()
    Config.read(conffile)
    nextserver = Config.getint("alternativelist", "nextserver")
    nbserver = Config.getint("alternativelist", "nbserver")
    listalternative = Config.get("alternativelist", "listars").split(",")

    serverjid = listalternative[nextserver - 1]
    logger.info(f"serverjid {serverjid}")
    port = Config.get(serverjid, "port")
    server = Config.get(serverjid, "server")
    guacamole_baseurl = Config.get(serverjid, "guacamole_baseurl")
    try:
        domain = str(serverjid).split("@")[1].split("/")[0]
    except BaseException:
        domain = str(serverjid)
    nextserver = nextserver + 1
    if nextserver > nbserver:
        nextserver = 1
    logger.info(f"next index alternatif server {nextserver}")
    Config.set("alternativelist", "nextserver", str(nextserver))

    # Writing our configuration file to 'example.cfg'
    with open(conffile, "w") as configfile:
        Config.write(configfile)

    return [serverjid, server, port, guacamole_baseurl, domain, nbserver]


class SingletonDecorator:
    """
    A decorator class to implement the Singleton pattern.

    Usage:
        Use this decorator to ensure that a class has only one instance.

    Example:
        @SingletonDecorator
        class MyClass:
            pass

        obj1 = MyClass()
        obj2 = MyClass()

        print(obj1 is obj2)  # True (obj1 and obj2 refer to the same instance)
    """

    def __init__(self, klass):
        """
        Initialize the SingletonDecorator.

        Args:
            klass: The class to which the singleton pattern will be applied.
        """
        self.klass = klass
        self.instance = None

    def __call__(self, *args, **kwds):
        """
        Call method to create and return the instance of the class.

        Args:
            *args: Variable length argument list.
            **kwds: Arbitrary keyword arguments.

        Returns:
            object: The instance of the class.

        Note:
            If the instance does not exist, it will be created; otherwise, the existing
            instance will be returned.
        """
        if self.instance is None:
            self.instance = self.klass(*args, **kwds)
        return self.instance


def infos_network_packageserver():
    """
    Retrieve information about the package server's network configuration.

    Returns:
        dict: A dictionary containing the port and public IP of the package server.
    """
    namefileconfig = os.path.join(
        "etc", "mmc", "medulla", "package-server", "package-server.ini"
    )
    namefileconfiglocal = os.path.join(
        "etc", "mmc", "medulla", "package-server", "package-server.ini.local"
    )
    public_ip = ipfromdns(loadparameters(namefileconfiglocal, "main", "public_ip"))
    if public_ip == "":
        public_ip = ipfromdns(loadparameters(namefileconfig, "main", "public_ip"))
    port = loadparameters(namefileconfiglocal, "main", "port")
    if port == "":
        port = loadparameters(namefileconfig, "main", "port")
    return {"port": port, "public_ip": public_ip}


def loadparameters(namefile, group, key):
    """
    Obtain the parameter value from the specified group and key in the configuration file.

    Args:
        namefile (str): The configuration file where the information is stored.
        group (str): The group in the config file.
        key (str): The key where the needed information is stored.

    Returns:
        str: The value defined by the group/key couple.

    Example:
        loadparameters("config.ini", "section1", "key1")
    """
    Config = configparser.ConfigParser()
    Config.read(namefile)
    return Config.get("group", "key") if Config.has_option("group", "key") else ""


class substitutelist:
    """
    A class representing a list of substitute values.

    Attributes:
        sub_inventory (list): List of substitute values for inventory.
        sub_subscribe (list): List of substitute values for subscription.
        sub_registration (list): List of substitute values for registration.
        sub_assessor (list): List of substitute values for assessor.
        sub_logger (list): List of substitute values for logger.
        sub_monitoring (list): List of substitute values for monitoring.
        sub_updates (list): List of substitute values for updates.
    """

    def __init__(self):
        """
        Initialize the Substitutelist with default and user-defined substitute values.
        """
        Config = configparser.ConfigParser()
        namefileconfig = conffilename("machine")
        Config.read(namefileconfig)
        if os.path.exists(f"{namefileconfig}.local"):
            Config.read(f"{namefileconfig}.local")
        #################substitute####################

        self.sub_inventory = ["master_inv@medulla"]
        self.sub_subscribe = ["master_subs@medulla"]
        self.sub_registration = ["master_reg@medulla"]
        self.sub_assessor = ["master_asse@medulla"]
        self.sub_logger = ["log@medulla", "maste_log@medulla"]
        self.sub_monitoring = ["master_mon@medulla"]
        self.sub_updates = ["master_upd@medulla"]

        if Config.has_option("substitute", "subscription"):
            sub_subscribelocal = Config.get("substitute", "subscription")
            self.sub_subscribe = [x.strip() for x in sub_subscribelocal.split(",")]

        if Config.has_option("substitute", "inventory"):
            sub_inventorylocal = Config.get("substitute", "inventory")
            self.sub_inventory = [x.strip() for x in sub_inventorylocal.split(",")]

        if Config.has_option("substitute", "registration"):
            sub_registrationlocal = Config.get("substitute", "registration")
            self.sub_registration = [
                x.strip() for x in sub_registrationlocal.split(",")
            ]

        if Config.has_option("substitute", "assessor"):
            sub_assessorlocal = Config.get("substitute", "assessor")
            self.sub_assessor = [x.strip() for x in sub_assessorlocal.split(",")]

        if Config.has_option("substitute", "logger"):
            sub_loggerlocal = Config.get("substitute", "logger")
            self.sub_logger = [x.strip() for x in sub_loggerlocal.split(",")]

        if Config.has_option("substitute", "monitoring"):
            sub_monitoringlocal = Config.get("substitute", "monitoring")
            self.sub_monitoring = [x.strip() for x in sub_monitoringlocal.split(",")]

        if Config.has_option("substitute", "updates"):
            sub_updateslocal = Config.get("substitute", "updates")
            self.sub_updates = [x.strip() for x in sub_updateslocal.split(",")]

    def parameterssubtitute(self):
        """
        Load user-defined substitute values from the configuration file.

        Args:
            Config (ConfigParser): The configuration parser object.
        """
        data = {
            "subscription": self.sub_subscribe,
            "inventory": self.sub_inventory,
            "registration": self.sub_registration,
            "assessor": self.sub_assessor,
            "logger": self.sub_logger,
            "monitoring": self.sub_monitoring,
            "updates": self.sub_updates,
        }
        conflist = list(data)
        data["conflist"] = conflist
        return data


class confParameter:
    def __init__(self, typeconf="machine"):
        Config = configparser.ConfigParser()
        namefileconfig = conffilename(typeconf)
        if not os.path.isfile(namefileconfig):
            logger.error("The configuration file %s is missing" % namefileconfig)

        Config.read(namefileconfig)
        if os.path.exists(namefileconfig + ".local"):
            Config.read(namefileconfig + ".local")
        self.packageserver = {}
        self.Port = Config.get("connection", "port")
        self.Server = ipfromdns(Config.get("connection", "server"))
        self.passwordconnection = Config.get("connection", "password")
        self.nameplugindir = os.path.dirname(namefileconfig)
        self.namefileconfig = namefileconfig
        # parameters AM and kiosk tcp server
        self.am_local_port = 8765
        self.kiosk_local_port = 8766
        if Config.has_option("kiosk", "am_local_port"):
            self.am_local_port = Config.getint("kiosk", "am_local_port")
        if Config.has_option("kiosk", "kiosk_local_port"):
            self.kiosk_local_port = Config.getint("kiosk", "kiosk_local_port")

        self.sub_inventory = ["master_inv@medulla"]
        self.sub_subscribe = ["master_subs@medulla"]
        self.sub_registration = ["master_reg@medulla"]
        self.sub_assessor = ["master_asse@medulla"]
        self.sub_monitoring = ["master_mon@medulla"]
        self.sub_updates = ["master_upd@medulla"]
        self.sub_logger = ["log@medulla", "master_log@medulla"]

        if Config.has_option("substitute", "subscription"):
            sub_subscribelocal = Config.get("substitute", "subscription")
            self.sub_subscribe = [x.strip() for x in sub_subscribelocal.split(",")]

        if Config.has_option("substitute", "inventory"):
            sub_inventorylocal = Config.get("substitute", "inventory")
            self.sub_inventory = [x.strip() for x in sub_inventorylocal.split(",")]

        if Config.has_option("substitute", "registration"):
            sub_registrationlocal = Config.get("substitute", "registration")
            self.sub_registration = [
                x.strip() for x in sub_registrationlocal.split(",")
            ]

        if Config.has_option("substitute", "monitoring"):
            sub_monitoringlocal = Config.get("substitute", "monitoring")
            self.sub_monitoring = [x.strip() for x in sub_monitoringlocal.split(",")]

        if Config.has_option("substitute", "updates"):
            sub_updateslocal = Config.get("substitute", "updates")
            self.sub_updates = [x.strip() for x in sub_updateslocal.split(",")]

        if Config.has_option("substitute", "assessor"):
            sub_assessorlocal = Config.get("substitute", "assessor")
            self.sub_assessor = [x.strip() for x in sub_assessorlocal.split(",")]

        if Config.has_option("substitute", "logger"):
            sub_loggerlocal = Config.get("substitute", "logger")
            self.sub_logger = [x.strip() for x in sub_loggerlocal.split(",")]

        try:
            self.agenttype = Config.get("type", "agent_type")
        except BaseException:
            self.agenttype = "machine"

        if self.agenttype == "machine":
            self.alwaysnetreconf = False
            if Config.has_option("connection", "alwaysnetreconf"):
                self.alwaysnetreconf = Config.getboolean(
                    "connection", "alwaysnetreconf"
                )

            filePath = os.path.abspath(
                os.path.join(os.path.dirname(os.path.realpath(__file__)), "..")
            )
            path_reconf_nomade = os.path.join(filePath, "BOOL_FILE_ALWAYSNETRECONF")
            if self.alwaysnetreconf:
                # We create the bool file that will force the reconfiguration
                if not os.path.exists(path_reconf_nomade):
                    fh = open(path_reconf_nomade, "w")
                    fh.write(
                        "DO NOT REMOVE THIS FILE\n"
                        "The parameter alwaysnetreconf is set to True\n "
                        "The agent will reconfigure the machine at every start"
                    )
                    fh.close()
            else:
                if os.path.exists(path_reconf_nomade):
                    os.remove(path_reconf_nomade)

        if self.agenttype == "relayserver":
            self.syncthing_share = "/var/lib/syncthing-depl/depl_share"
            self.syncthing_home = "/var/lib/syncthing-depl/.config/syncthing"

            self.syncthing_port = 23000
            if Config.has_option("syncthing-deploy", "syncthing_port"):
                self.syncthing_port = Config.getint(
                    "syncthing-deploy", "syncthing_port"
                )

            self.syncthing_gui_port = 8385
            if Config.has_option("syncthing-deploy", "syncthing_gui_port"):
                self.syncthing_gui_port = Config.getint(
                    "syncthing-deploy", "syncthing_gui_port"
                )

            if Config.has_option("syncthing-deploy", "syncthing_share"):
                self.syncthing_share = Config.get("syncthing-deploy", "syncthing_share")
        else:
            self.syncthing_home = "/var/lib/medulla/.config/syncthing"
            self.syncthing_gui_port = 8384

        if Config.has_option("syncthing-deploy", "syncthing_home"):
            self.syncthing_home = Config.get("syncthing-deploy", "syncthing_home")

        if Config.has_option("syncthing", "activation"):
            self.syncthing_on = Config.getboolean("syncthing", "activation")
        else:
            self.syncthing_on = True

        if self.syncthing_on:
            logger.debug("Syncthing have been activated.")
        else:
            logger.debug("Syncthing have not been activated by configuration.")

        self.moderelayserver = "static"
        if Config.has_option("type", "moderelayserver"):
            self.moderelayserver = Config.get("type", "moderelayserver")

        if Config.has_option("updateagent", "updatingplugins"):
            self.updatingplugins = Config.getboolean("updateagent", "updatingplugins")
        else:
            self.updatingplugins = 1

        if Config.has_option("updateagent", "updating"):
            self.updating = Config.getboolean("updateagent", "updating")
        else:
            self.updating = 1

        if Config.has_option("networkstatus", "netchanging"):
            self.netchanging = Config.getint("networkstatus", "netchanging")
        else:
            if sys.platform.startswith("win"):
                self.netchanging = 0
            else:
                self.netchanging = 1

        if Config.has_option("networkstatus", "detectiontime"):
            self.detectiontime = Config.getint("networkstatus", "detectiontime")
        else:
            self.detectiontime = 300

        if self.agenttype == "machine":
            self.time_before_reinscription = 900
            if Config.has_option("global", "time_before_reinscription"):
                try:
                    self.time_before_reinscription = Config.getint(
                        "global", "time_before_reinscription"
                    )
                except Exception as e:
                    logger.warning(
                        "parameter [global]  time_before_reinscription :(%s)" % str(e)
                    )
                    logger.warning(
                        "parameter [global]  time_before_reinscription"
                        " : parameter set to 900"
                    )
                    self.time_before_reinscription = 900

            if self.time_before_reinscription < 30:
                self.time_before_reinscription = 30

        self.parametersscriptconnection = {}

        if self.agenttype == "relayserver":
            self.concurrentdeployments = 10
            if Config.has_option("global", "concurrentdeployments"):
                try:
                    self.concurrentdeployments = Config.getint(
                        "global", "concurrentdeployments"
                    )
                except Exception as e:
                    logger.warning(
                        "parameter [global]  concurrentdeployments :(%s)" % str(e)
                    )
                    logger.warning(
                        "parameter [global]  concurrentdeployments"
                        " : parameter set to 10"
                    )

            if self.concurrentdeployments < 1:
                logger.warning(
                    "parameter [global]  concurrentdeployments "
                    " : parameter must be greater than or equal to 1"
                )
                logger.warning(
                    "parameter [global]  concurrentdeployments " ": parameter set to 10"
                )
                self.concurrentdeployments = 10

            if Config.has_option("connection", "portARSscript"):
                self.parametersscriptconnection["port"] = Config.get(
                    "connection", "portARSscript"
                )
            else:
                self.parametersscriptconnection["port"] = 5001
        else:
            if Config.has_option("connection", "portAMscript"):
                self.parametersscriptconnection["port"] = Config.get(
                    "connection", "portAMscript"
                )
            else:
                self.parametersscriptconnection["port"] = 5000
        #######configuration browserfile#######
        if sys.platform.startswith("win"):
            self.defaultdir = os.path.join(os.environ["TEMP"])
            self.rootfilesystem = os.path.join(os.environ["TEMP"])
        elif sys.platform.startswith("darwin"):
            self.defaultdir = os.path.join("/opt", "Medulla", "tmp")
            self.rootfilesystem = os.path.join("/opt", "Medulla", "tmp")
        else:
            self.defaultdir = os.path.join("/", "tmp")
            self.rootfilesystem = os.path.join("/", "tmp")

        if Config.has_option("browserfile", "defaultdir"):
            self.defaultdir = Config.get("browserfile", "defaultdir")
        if Config.has_option("browserfile", "rootfilesystem"):
            self.rootfilesystem = Config.get("browserfile", "rootfilesystem")
        if self.rootfilesystem[-1] == "\\":
            self.rootfilesystem = self.rootfilesystem[:-1]
        if self.rootfilesystem[-1] == "/" and len(self.rootfilesystem) > 1:
            self.rootfilesystem = self.rootfilesystem[:-1]
        if self.defaultdir[-1] == "\\" or self.defaultdir[-1] == "/":
            self.defaultdir = self.defaultdir[:-1]
        self.listexclude = ""
        if Config.has_option("browserfile", "listexclude"):
            # listexclude=/usr,/etc,/var,/lib,/boot,/run,/proc,/lib64,
            # /bin,/sbin,/dev,/lost+found,/media,/mnt,/opt,/root,/srv,/sys,/vagrant
            self.listexclude = Config.get("browserfile", "listexclude")
        self.excludelist = [
            x.strip() for x in self.listexclude.split(",") if x.strip() != ""
        ]
        #######end configuration browserfile#######
        if self.agenttype == "relayserver":
            packageserver = infos_network_packageserver()
            if packageserver["public_ip"] == "":
                self.packageserver["public_ip"] = self.Server
            if packageserver["port"] == "":
                self.packageserver["port"] = 9990
            else:
                self.packageserver["port"] = int(packageserver["port"])
        self.public_ip = ""
        self.public_ip_relayserver = ""
        self.geoservers = "ifconfig.co, if.siveo.net"
        self.geolocalisation = True

        if Config.has_option("type", "public_ip"):
            self.public_ip = Config.get("type", "public_ip")

        if self.agenttype == "relayserver":
            if Config.has_option("type", "request_type"):
                self.request_type = Config.get("type", "request_type")
                if self.request_type.lower() == "public" and Config.has_option(
                    "type", "public_ip"
                ):
                    self.public_ip_relayserver = ipfromdns(
                        Config.get("type", "public_ip")
                    )
                    self.packageserver["public_ip"] = self.public_ip_relayserver
        else:
            if Config.has_option("type", "request_type"):
                self.request_type = Config.get("type", "request_type")
            else:
                self.request_type = "public"
        if Config.has_option("type", "geolocalisation"):
            self.geolocalisation = Config.getboolean("type", "geolocalisation")

        if Config.has_option("type", "geoservers"):
            self.geoserversstr = Config.get("type", "geoservers")

        pluginlist = Config.get("plugin", "pluginlist").split(",")
        # par convention :
        # la liste des plugins definie dans la section plugin avec la clef pluginlist
        # donne les fichiers .ini a chargé.
        # les fichiers ini des plugins doivent comporter une session parameters.
        # les clef representeront aussi par convention le nom des variables
        # utilisable dans le plugins.
        if Config.has_option("plugin", "pluginlist"):
            pluginlist = Config.get("plugin", "pluginlist").split(",")
            pluginlist = [x.strip() for x in pluginlist]
            for z in pluginlist:
                namefile = "%s.ini" % os.path.join(self.nameplugindir, z)
                if os.path.isfile(namefile):
                    liststuple = self.loadparametersplugins(namefile)
                    for keyparameter, valueparameter in liststuple:
                        setattr(self, keyparameter, valueparameter)
                else:
                    logger.warning("The configuration file: %s is missing" % namefile)
        try:
            self.agentcommand = Config.get("global", "relayserver_agent")
        except BaseException:
            self.agentcommand = ""

        if self.agenttype == "relayserver":
            if Config.has_option("global", "diragentbase"):
                self.diragentbase = Config.get("global", "diragentbase")
            else:
                self.diragentbase = "/var/lib/medulla/xmpp_baseremoteagent/"

        jidsufixetempinfo = os.path.join(
            os.path.dirname(os.path.realpath(__file__)), "INFOSTMP", "JIDSUFFIXE"
        )
        jidsufixe = ""
        if os.path.exists(jidsufixetempinfo):
            jidsufixe = utils.file_get_contents(jidsufixetempinfo)[:3]

        if not jidsufixe.isalnum():
            jidsufixe = utils.getRandomName(3)
            utils.file_put_contents(jidsufixetempinfo, jidsufixe)
        # if aucune interface. il n'y a pas de macs adress. ressource missing
        try:
            ressource = utils.name_jid()
        except BaseException:
            ressource = "missingmac"
            logger.warning("list mac missing")
        # Chatroom
        # Deployment chatroom
        self.NickName = "%s.%s" % (platform.node().split(".")[0], jidsufixe)
        # Chat
        # The jidagent's ressource must be the smallest value in the mac address list.
        # except for the rsmedulla@medulla ressource which is the main relay
        chatserver = Config.get("chat", "domain")

        # Smallest mac address
        username = self.NickName
        domain = Config.get("chat", "domain")

        self.jidagent = "%s@%s/%s" % (username, Config.get("chat", "domain"), ressource)

        if Config.has_option("jid_01", "jidname"):
            self.jidagent = Config.get("jid_01", "jidname")
            username = jid.JID(self.jidagent).user

        if jid.JID(self.jidagent).bare == "rsmedulla@medulla":
            self.jidagent = "rsmedulla@medulla/mainrelay"
        else:
            self.jidagent = "%s@%s/%s" % (username, domain, ressource)
        try:
            self.nbrotfile = Config.getint("global", "nb_rot_file")
        except BaseException:
            self.nbrotfile = 6

        if self.nbrotfile < 1:
            self.nbrotfile = 1

        try:
            self.compress = Config.get("global", "compress")
        except BaseException:
            self.compress = "no"
        self.compress = self.compress.lower()
        if self.compress not in ["zip", "gzip", "bz2", "No"]:
            self.compress = "no"
        defaultnamelogfile = "xmpp-agent-machine.log"
        if self.agenttype == "relayserver":
            defaultnamelogfile = "xmpp-agent-relay.log"
        try:
            self.logfile = Config.get("global", "logfile")
        except BaseException:
            if sys.platform.startswith("win"):
                self.logfile = os.path.join(
                    "c:\\",
                    "progra~1",
                    "Medulla",
                    "var",
                    "log",
                    defaultnamelogfile,
                )
            elif sys.platform.startswith("darwin"):
                self.logfile = os.path.join(
                    "/opt", "Medulla", "var", "log", defaultnamelogfile
                )
            else:
                self.logfile = os.path.join(
                    "/", "var", "log", "medulla", defaultnamelogfile
                )

        if Config.has_option("configuration_server", "confserver"):
            self.confserver = Config.get("configuration_server", "confserver")
            listserver = [
                ipfromdns(x.strip())
                for x in self.confserver.split(",")
                if x.strip() != ""
            ]
            listserver = list(set(listserver))
            self.confserver = listserver[random.randint(0, len(listserver) - 1)]
        if Config.has_option("configuration_server", "confport"):
            self.confport = Config.get("configuration_server", "confport")
        if Config.has_option("configuration_server", "confpassword"):
            self.confpassword = Config.get("configuration_server", "confpassword")
        if Config.has_option("configuration_server", "keyAES32"):
            self.keyAES32 = Config.get("configuration_server", "keyAES32")

        try:
            self.baseurlguacamole = Config.get("type", "guacamole_baseurl")
        except BaseException:
            self.baseurlguacamole = ""

        if self.agenttype == "machine":
            try:
                timeal = Config.get("global", "alternativetimedelta")
                self.timealternatif = [
                    int(x)
                    for x in re.split(
                        r"[a-zA-Z;,\[\(\]\)\{\}\:\=\+\*\\\?\/\#\+\.\&\-\$\|\s]\s*",
                        timeal,
                    )
                    if x.strip() != ""
                ][:2]
                self.timealternatif.sort()
                if len(self.timealternatif) < 2:
                    raise
                else:
                    if self.timealternatif[0] < 2:
                        self.timealternatif[0] = 2
                    if self.timealternatif[1] > 30:
                        self.timealternatif[1] = 30
            except Exception:
                self.timealternatif = [2, 30]
            logger.debug(
                '[Global] Parameter "alternativetimedelta" is %s' % self.timealternatif
            )

        try:
            self.levellog = self._levellogdata(Config.get("global", "log_level"))
        except BaseException:
            # Set to INFO as default
            self.levellog = 20
        try:
            self.log_level_slixmpp = self._levellogdata(
                Config.get("global", "log_level_slixmpp")
            )
        except BaseException:
            # Set to FATAL as default
            self.log_level_slixmpp = 50

        if Config.has_option("configuration_server", "confdomain"):
            self.confdomain = Config.get("configuration_server", "confdomain")
        else:
            self.confdomain = "medulla"

        try:
            self.classutil = Config.get("global", "agent_space")
        except BaseException:
            self.classutil = "both"

        try:
            jidagentsiveo = Config.get("global", "allow_order")
            self.jidagentsiveo = [
                jid.JID(x.strip()).user for x in jidagentsiveo.split(",")
            ]
        except BaseException:
            self.jidagentsiveo = ["agentsiveo"]

        try:
            self.ordreallagent = Config.getboolean("global", "inter_agent")
        except BaseException:
            self.ordreallagent = False

        if self.agenttype == "relayserver":
            self.jidchatroomcommand = self.jidagent
        else:
            self.jidchatroomcommand = str(self.agentcommand)

        self.max_size_stanza_xmpp = 1048576
        if Config.has_option("quick_deploy", "max_size_stanza_xmpp"):
            self.max_size_stanza_xmpp = Config.getint(
                "quick_deploy", "max_size_stanza_xmpp"
            )

        self.nbconcurrentquickdeployments = 10
        if Config.has_option("quick_deploy", "concurrentdeployments"):
            self.nbconcurrentquickdeployments = Config.getint(
                "quick_deploy", "concurrentdeployments"
            )
        # we make sure that the time for the
        # inventories is greater than or equal to 1 hour.
        # if the time for the inventories is 0, it is left at 0.
        # this deactive cycle inventory
        self.inventory_interval = 0
        if Config.has_option("inventory", "inventory_interval"):
            self.inventory_interval = Config.getint("inventory", "inventory_interval")
            if self.inventory_interval != 0 and self.inventory_interval < 3600:
                self.inventory_interval = 36000
        # DEBUG switch_scheduling
        # clean session if ban jid for deploy
        self.sched_remove_ban = True
        self.sched_check_connection = True
        self.sched_quick_deployment_load = True
        # switch exec plugin scheduling
        self.sched_scheduled_plugins = True
        self.sched_update_plugin = True
        self.sched_check_network = True
        self.sched_send_ping_kiosk = True
        # controle si doit installer image
        self.sched_update_agent = True
        self.sched_manage_session = True
        self.sched_reload_deployments = True
        self.sched_check_inventory = True
        self.sched_session_reload = True
        self.sched_check_events = True
        self.sched_check_cmd_file = True
        self.sched_init_syncthing = True
        self.sched_check_syncthing_deployment = True
        self.sched_check_synthing_config = True
        if Config.has_option("switch_scheduling", "sched_remove_ban"):
            self.sched_remove_ban = Config.getboolean(
                "switch_scheduling", "sched_remove_ban"
            )

        if Config.has_option("switch_scheduling", "sched_check_connection"):
            self.sched_check_connection = Config.getboolean(
                "switch_scheduling", "sched_check_connection"
            )

        if Config.has_option("switch_scheduling", "sched_quick_deployment_load"):
            self.sched_quick_deployment_load = Config.getboolean(
                "switch_scheduling", "sched_quick_deployment_load"
            )

        if Config.has_option("switch_scheduling", "sched_scheduled_plugins"):
            self.sched_scheduled_plugins = Config.getboolean(
                "switch_scheduling", "sched_scheduled_plugins"
            )

        if Config.has_option("switch_scheduling", "sched_update_plugin"):
            self.sched_update_plugin = Config.getboolean(
                "switch_scheduling", "sched_update_plugin"
            )

        if Config.has_option("switch_scheduling", "sched_check_network"):
            self.sched_check_network = Config.getboolean(
                "switch_scheduling", "sched_check_network"
            )

        if Config.has_option("switch_scheduling", "sched_send_ping_kiosk"):
            self.sched_send_ping_kiosk = Config.getboolean(
                "switch_scheduling", "sched_send_ping_kiosk"
            )

        if Config.has_option("switch_scheduling", "sched_update_agent"):
            self.sched_update_agent = Config.getboolean(
                "switch_scheduling", "sched_update_agent"
            )

        if Config.has_option("switch_scheduling", "sched_manage_session"):
            self.sched_manage_session = Config.getboolean(
                "switch_scheduling", "sched_manage_session"
            )

        if Config.has_option("switch_scheduling", "sched_reload_deployments"):
            self.sched_reload_deployments = Config.getboolean(
                "switch_scheduling", "sched_reload_deployments"
            )

        if Config.has_option("switch_scheduling", "sched_check_inventory"):
            self.sched_check_inventory = Config.getboolean(
                "switch_scheduling", "sched_check_inventory"
            )

        if Config.has_option("switch_scheduling", "sched_session_reload"):
            self.sched_session_reload = Config.getboolean(
                "switch_scheduling", "sched_session_reload"
            )

        if Config.has_option("switch_scheduling", "sched_check_events"):
            self.sched_check_events = Config.getboolean(
                "switch_scheduling", "sched_check_events"
            )

        if Config.has_option("switch_scheduling", "sched_check_cmd_file"):
            self.sched_check_cmd_file = Config.getboolean(
                "switch_scheduling", "sched_check_cmd_file"
            )

        if Config.has_option("switch_scheduling", "sched_init_syncthing"):
            self.sched_init_syncthing = Config.getboolean(
                "switch_scheduling", "sched_init_syncthing"
            )

        if Config.has_option("switch_scheduling", "sched_check_synthing_config"):
            self.sched_check_synthing_config = Config.getboolean(
                "switch_scheduling", "sched_check_synthing_config"
            )

        if Config.has_option("switch_scheduling", "sched_check_syncthing_deployment"):
            self.sched_check_syncthing_deployment = Config.getboolean(
                "switch_scheduling", "sched_check_syncthing_deployment"
            )

        self.excludedplugins = []
        if Config.has_option("excluded_plugins", "excludedplugins"):
            excludedpluginstmp = Config.get(
                "excluded_plugins", "excludedplugins"
            ).split(",")
            self.excludedplugins = [x.strip() for x in excludedpluginstmp]

        self.excludedscheduledplugins = []
        if Config.has_option("excluded_scheduled_plugins", "excludedscheduledplugins"):
            excludedscheduledpluginstmp = Config.get(
                "excluded_scheduled_plugins", "excludedscheduledplugins"
            ).split(",")
            self.excludedscheduledplugins = [
                x.strip() for x in excludedscheduledpluginstmp
            ]

        self.scheduling_plugin_action = True
        self.plugin_action = True
        if Config.has_option("call_plugin", "scheduling_plugin_action"):
            self.scheduling_plugin_action = Config.getboolean(
                "call_plugin", "scheduling_plugin_action"
            )

        if Config.has_option("call_plugin", "plugin_action"):
            self.plugin_action = Config.getboolean("call_plugin", "plugin_action")
        # ########################## END DEBUG switch_scheduling ##############
        # configuration monitoring
        if self.agenttype == "machine":
            if Config.has_option("monitoring", "monitoring_agent_config_file"):
                self.monitoring_agent_config_file = Config.get(
                    "monitoring", "monitoring_agent_config_file"
                )
            else:
                # Config file not found
                self.monitoring_agent_config_file = ""

        self.information = {}
        self.PlatformSystem = platform.platform()
        self.information["platform"] = self.PlatformSystem
        self.OperatingSystem = platform.system()
        self.information["os"] = self.OperatingSystem
        self.UnameSystem = platform.uname()
        self.information["uname"] = [x for x in self.UnameSystem]
        self.HostNameSystem = platform.node().split(".")[0]
        self.information["hostname"] = self.HostNameSystem
        self.OsReleaseNumber = platform.release()
        self.information["osrelease"] = self.OsReleaseNumber
        self.DetailedVersion = platform.version()
        self.information["version"] = self.DetailedVersion
        self.HardwareType = platform.machine()
        self.information["hardtype"] = self.HardwareType
        self.ProcessorIdentifier = platform.processor()
        self.information["processor"] = self.ProcessorIdentifier
        self.Architecture = platform.architecture()
        self.information["archi"] = self.Architecture
        # Http fileviewer server parameters
        self.paths = []
        self.names = []
        self.extensions = []
        self.date_format = "%Y-%m-%d %H:%M:%S"

        if Config.has_option("fileviewer", "sources"):
            self.paths = Config.get("fileviewer", "sources").split(";")

        # The size_paths drive the final size of paths, names and extensions
        # parameters
        size_paths = len(self.paths)

        if Config.has_option("fileviewer", "names"):
            # Get names from ini file
            self.names = Config.get("fileviewer", "names").split(";")

        # If some names are missing, complete display names associated to each
        # paths
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
        if Config.has_option("fileviewer", "extensions"):
            self.extensions = Config.get("fileviewer", "extensions").split(";")

        # If some extensions group are missing, complete the list for each
        # paths
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
            if isinstance(self.extensions[count], list):
                self.extensions[count] = self.extensions[count]
            else:
                self.extensions[count] = self.extensions[count].split(",")
            count += 1

        if Config.has_option("fileviewer", "date_format"):
            self.date_format = Config.get("fileviewer", "date_format")

        self.fv_host = "127.0.0.1"
        if Config.has_option("fileviewer", "host"):
            self.fv_host = Config.get("fileviewer", "host")

        self.fv_port = 52044
        if Config.has_option("fileviewer", "port"):
            self.fv_port = Config.getint("fileviewer", "port")

        if Config.has_option("fileviewer", "maxwidth"):
            self.fv_maxwidth = Config.getint("fileviewer", "maxwidth")
        else:
            self.fv_maxwidth = 800

        if Config.has_option("fileviewer", "minwidth"):
            self.fv_minwidth = Config.getint("fileviewer", "minwidth")
        else:
            self.fv_minwidth = 600

        if self.fv_minwidth > self.fv_maxwidth:
            self.fv_minwidth, self.fv_maxwidth = self.fv_maxwidth, self.fv_minwidth

    def loadparametersplugins(self, namefile):
        Config = configparser.ConfigParser()
        Config.read(namefile)
        if os.path.isfile(namefile + ".local"):
            Config.read(namefile + ".local")
        return Config.items("parameters")

    def _levellogdata(self, levelstring):
        strlevel = levelstring.upper()
        if strlevel in ["CRITICAL", "FATAL"]:
            return 50
        elif strlevel == "ERROR":
            return 40
        elif strlevel in ["WARNING", "WARN"]:
            return 30
        elif strlevel == "INFO":
            return 20
        elif strlevel == "DEBUG":
            return 10
        elif strlevel == "NOTSET":
            return 0
        elif strlevel in ["LOG", "DEBUGPULSE"]:
            return 25
        else:
            return 20

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
            if i == "lo":
                continue
            iface = netifaces.ifaddresses(i).get(netifaces.AF_INET)
            if iface:
                for j in iface:
                    addr = j["addr"]
                    if addr != "127.0.0.1":
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
                if_mac = addrs[netifaces.AF_LINK][0]["addr"]
                if_ip = addrs[netifaces.AF_INET][0]["addr"]
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
    ifconfig = os.popen("/sbin/ifconfig").readlines()
    for line in ifconfig:
        if line.startswith(" ") or line.startswith("\t") and "ether" not in line:
            pass
        else:
            if "ether" not in line:
                ll = line.strip().split(":")[0]
            else:
                lst[ll] = line.split("ether")[1].strip()
    return lst


def listMacAdressWinOs():
    """
    This function return the mac address on MS Windows

    Return:
        it returns the mac address of the windows machine.
    """
    lst = {}
    i = 0
    ifconfig = os.popen("ipconfig /all").readlines()
    for line in ifconfig:
        if line.strip() == "":
            continue
        if "phy" in line.lower() or not (line.startswith("\t") or line.startswith(" ")):
            if "phy" not in line.lower():
                ll = line.split(" ")[0].strip() + "%d" % i
            else:
                lst[ll] = line.split(":")[1].strip()
                i = i + 1
    return lst


def listMacAdressLinuxOs():
    """
    This function return the mac address on GNU/Linux

    Returns:
        it returns the mac address of the linux machine
    """
    lst = {}
    ifconfig = os.popen("/sbin/ifconfig").readlines()
    for line in ifconfig:
        if "hwaddr" in line.lower():
            t = line.strip().split(" ")
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
    if len(listdataconfiguration) > 1 and directoryconffile() is not None:
        fileofconf = os.path.join(directoryconffile(), listdataconfiguration[1])
    else:
        return False
    if listdataconfiguration[0].lower() == "add":
        if len(listdataconfiguration) != 5:
            return False
        if (
            listdataconfiguration[2] != ""
            and listdataconfiguration[3] != ""
            and listdataconfiguration[4] != ""
        ):
            fileconf = configparser.ConfigParser()
            fileconf.read(fileofconf)
            # test si section existe.
            if not listdataconfiguration[2] in fileconf.sections():
                fileconf.add_section(listdataconfiguration[2])
            fileconf.set(
                listdataconfiguration[2],
                listdataconfiguration[3],
                listdataconfiguration[4],
            )
            with open(fileofconf, "w") as configfile:
                fileconf.write(configfile)
            return True
        else:
            return False
    elif listdataconfiguration[0].lower() == "del":
        if len(listdataconfiguration) < 4:
            return False
        fileconf = configparser.ConfigParser()
        fileconf.read(fileofconf)
        if listdataconfiguration[2] != "" and fileconf.has_section(
            listdataconfiguration[2]
        ):
            if len(fileconf.options(listdataconfiguration[2])) == 0:
                fileconf.remove_section(listdataconfiguration[2])
                with open(fileofconf, "w") as configfile:
                    fileconf.write(configfile)
                return True
            if listdataconfiguration[3] != "" and fileconf.has_option(
                listdataconfiguration[2], listdataconfiguration[3]
            ):
                fileconf.remove_option(
                    listdataconfiguration[2], listdataconfiguration[3]
                )
                if len(fileconf.options(listdataconfiguration[2])) == 0:
                    fileconf.remove_section(listdataconfiguration[2])
                with open(fileofconf, "w") as configfile:
                    fileconf.write(configfile)
                return True
            else:
                return False
        else:
            return False
    else:
        return False
