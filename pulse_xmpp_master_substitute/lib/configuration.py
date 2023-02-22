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
# file /pulse_xmpp_master_substitute/lib/configuration.py
import sys
import os
import logging
import configparser
from configparser import NoOptionError
import random
from lib.utils import ipfromdns

# Singleton/SingletonDecorator.py


class SingletonDecorator:
    def __init__(self, klass):
        self.klass = klass
        self.instance = None

    def __call__(self, *args, **kwds):
        if self.instance is None:
            self.instance = self.klass(*args, **kwds)
        return self.instance


@SingletonDecorator
class confParameter:
    # dbport = None
    # dbsslenable = False

    # check_db_enable = False
    # check_db_interval = 300

    # filter_on = None

    # state section
    # orange = 10
    # red = 35

    # computer_list section
    # complete list: ['cn', 'description', 'os', 'type', 'user', 'inventorynumber', 'state', 'entity', 'location', 'model', 'manufacturer']
    ##
    #
    # ordered = False

    # antivirus section
    # av_false_positive = []

    # manufacturer section
    # manufacturerWarrantyUrl = {}
    # webservices = {
    # 'purge_machine': 0
    # }

    def __init__(self, namefileconfig):
        self.pathdirconffile = os.path.dirname(os.path.realpath(namefileconfig))
        Config = configparser.ConfigParser()
        Config.read(namefileconfig)
        if os.path.exists(namefileconfig + ".local"):
            Config.read(namefileconfig + ".local")
        self.packageserver = {}
        # CONNECTION XMPP
        self.Port = "5222"
        if Config.has_option("connection", "port"):
            self.Port = Config.get("connection", "port")

        self.Server = "pulse"
        if Config.has_option("connection", "server"):
            self.Server = ipfromdns(Config.get("connection", "server"))

        self.passwordconnection = "secret"
        if Config.has_option("connection", "password"):
            self.passwordconnection = Config.get("connection", "password")

        self.jidmaster = "master@pulse"
        if Config.has_option("connection", "jidmaster"):
            self.jidmaster = Config.get("connection", "jidmaster")

        self.sub_logger = "log@pulse"
        if Config.has_option("connection", "logger"):
            self.sub_logger = Config.get("connection", "logger")

        self.jidmastersubstitute = ""
        if Config.has_option("connection", "jidmastersubstitute"):
            self.jidmastersubstitute = Config.get("connection", "jidmastersubstitute")
        if self.jidmastersubstitute == "":
            logging.getLogger().error(
                "jidmastersubstitute parameter missing in file config : %s : "
                % namefileconfig
            )
            sys.exit(1)

        self.jidmasterreg = "master_reg@pulse"
        if Config.has_option("connection", "jidreg"):
            self.jidmasterreg = Config.get("connection", "jidreg")

        # GLOBAL CONFIGURATION
        self.levellog = 20
        if Config.has_option("global", "log_level"):
            self.levellog = self._levellogdata(Config.get("global", "log_level"))
        self.log_level_slixmpp = 50
        if Config.has_option("global", "log_level_slixmpp"):
            self.log_level_slixmpp = self._levellogdata(
                Config.get("global", "log_level_slixmpp")
            )

        self.logfile = "/var/log/mmc/master_inv.log"
        if Config.has_option("global", "logfile"):
            self.logfile = Config.get("global", "logfile")

        ################################################################
        # list des noms des plugins start executer au demarage.
        # le code de ces plugins est executé au démarage. il commence par start

        # pluginlist = 'load_plugins_base, load_plugin_base_scheduled,autoupdateagent'
        self.pluginliststart = "loadpluginlistversion, loadpluginschedulerlistversion, loadautoupdate, loadshowregistration"
        if Config.has_option("plugins", "pluginliststart"):
            self.pluginliststart = Config.get("plugins", "pluginliststart")
        self.pluginliststart = [
            x.strip() for x in self.pluginliststart.split(",") if x.strip() != ""
        ]
        ################################################################
        self.dbpoolrecycle = 3600
        self.dbpoolsize = 60
        self.charset = "utf8"
        if Config.has_option("main", "dbpoolrecycle"):
            self.dbpoolrecycle = Config.getint("main", "dbpoolrecycle")
        if Config.has_option("main", "dbpoolsize"):
            self.dbpoolsize = Config.getint("main", "dbpoolsize")
        if Config.has_option("main", "charset"):
            self.charset = Config.get("main", "charset")
        # PLUGIN LIST
        # activate connection to base module
        self.plugins_list = ["xmpp", "glpi", "kiosk"]
        if Config.has_option("global", "activate_plugin"):
            listplugsql = Config.get("global", "activate_plugin")
            self.plugins_list = [
                x.strip().lower() for x in listplugsql.split(",") if x.strip() != ""
            ]

        if "glpi" in self.plugins_list:
            self.readConfglpi(Config)

        if "xmpp" in self.plugins_list:
            self.readConfxmpp(Config)

        if "kiosk" in self.plugins_list:
            self.readConfkiosk(Config)

        if "msc" in self.plugins_list:
            self.readConfmsc(Config)

        if "pkgs" in self.plugins_list:
            self.readConfpkgs(Config)

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

    def readConfkiosk(self, confiobject):
        self.kiosk_dbpooltimeout = 30
        if confiobject.has_option("kioskdatabase", "kiosk_dbpooltimeout"):
            self.kiosk_dbpooltimeout = confiobject.getint(
                "kioskdatabase", "kiosk_dbpooltimeout"
            )

        self.kiosk_dbhost = "localhost"
        if confiobject.has_option("kioskdatabase", "kiosk_dbhost"):
            self.kiosk_dbhost = confiobject.get("kioskdatabase", "kiosk_dbhost")

        self.kiosk_dbport = 3306
        if confiobject.has_option("kioskdatabase", "kiosk_dbport"):
            self.kiosk_dbport = confiobject.getint("kioskdatabase", "kiosk_dbport")

        self.kiosk_dbname = "kiosk"
        if confiobject.has_option("kioskdatabase", "kiosk_dbname"):
            self.kiosk_dbname = confiobject.get("kioskdatabase", "kiosk_dbname")

        self.kiosk_dbuser = "mmc"
        if confiobject.has_option("kioskdatabase", "kiosk_dbuser"):
            self.kiosk_dbuser = confiobject.get("kioskdatabase", "kiosk_dbuser")

        self.kiosk_dbpasswd = "mmc"
        if confiobject.has_option("kioskdatabase", "kiosk_dbpasswd"):
            self.kiosk_dbpasswd = confiobject.get("kioskdatabase", "kiosk_dbpasswd")

        self.kiosk_dbpoolrecycle = 3600
        if confiobject.has_option("kioskdatabase", "kiosk_dbpoolrecycle"):
            self.kiosk_dbpoolrecycle = confiobject.getint(
                "kioskdatabase", "kiosk_dbpoolrecycle"
            )

        self.kiosk_dbpoolsize = 60
        if confiobject.has_option("kioskdatabase", "kiosk_dbpoolsize"):
            self.kiosk_dbpoolsize = confiobject.getint(
                "kioskdatabase", "kiosk_dbpoolsize"
            )

    def readConfmsc(self, confiobject):
        self.msc_dbpooltimeout = 30
        if confiobject.has_option("mscdatabase", "msc_dbpooltimeout"):
            self.msc_dbpooltimeout = confiobject.getint(
                "mscdatabase", "msc_dbpooltimeout"
            )

        self.msc_dbhost = "localhost"
        if confiobject.has_option("mscdatabase", "msc_dbhost"):
            self.msc_dbhost = confiobject.get("mscdatabase", "msc_dbhost")

        self.msc_dbport = 3306
        if confiobject.has_option("mscdatabase", "msc_dbport"):
            self.msc_dbport = confiobject.getint("mscdatabase", "msc_dbport")

        self.msc_dbname = "msc"
        if confiobject.has_option("mscdatabase", "msc_dbname"):
            self.msc_dbname = confiobject.get("mscdatabase", "msc_dbname")

        self.msc_dbuser = "mmc"
        if confiobject.has_option("mscdatabase", "msc_dbuser"):
            self.msc_dbuser = confiobject.get("mscdatabase", "msc_dbuser")

        self.msc_dbpasswd = "mmc"
        if confiobject.has_option("mscdatabase", "msc_dbpasswd"):
            self.msc_dbpasswd = confiobject.get("mscdatabase", "msc_dbpasswd")

        self.msc_dbpoolrecycle = 3600
        if confiobject.has_option("mscdatabase", "msc_dbpoolrecycle"):
            self.msc_dbpoolrecycle = confiobject.getint(
                "mscdatabase", "msc_dbpoolrecycle"
            )

        self.msc_dbpoolsize = 60
        if confiobject.has_option("mscdatabase", "msc_dbpoolsize"):
            self.msc_dbpoolsize = confiobject.getint("mscdatabase", "msc_dbpoolsize")

    def readConfpkgs(self, confiobject):
        self.pkgs_dbpooltimeout = 30
        if confiobject.has_option("pkgsdatabase", "pkgs_dbpooltimeout"):
            self.pkgs_dbpooltimeout = confiobject.getint(
                "pkgsdatabase", "pkgs_dbpooltimeout"
            )

        self.pkgs_dbhost = "localhost"
        if confiobject.has_option("pkgsdatabase", "pkgs_dbhost"):
            self.pkgs_dbhost = confiobject.get("pkgsdatabase", "pkgs_dbhost")

        self.pkgs_dbport = 3306
        if confiobject.has_option("pkgsdatabase", "pkgs_dbport"):
            self.pkgs_dbport = confiobject.getint("pkgsdatabase", "pkgs_dbport")

        self.pkgs_dbname = "pkgs"
        if confiobject.has_option("pkgsdatabase", "pkgs_dbname"):
            self.pkgs_dbname = confiobject.get("pkgsdatabase", "pkgs_dbname")

        self.pkgs_dbuser = "mmc"
        if confiobject.has_option("pkgsdatabase", "pkgs_dbuser"):
            self.pkgs_dbuser = confiobject.get("pkgsdatabase", "pkgs_dbuser")

        self.pkgs_dbpasswd = "mmc"
        if confiobject.has_option("pkgsdatabase", "pkgs_dbpasswd"):
            self.pkgs_dbpasswd = confiobject.get("pkgsdatabase", "pkgs_dbpasswd")

        self.pkgs_dbpoolrecycle = 3600
        if confiobject.has_option("pkgsdatabase", "pkgs_dbpoolrecycle"):
            self.pkgs_dbpoolrecycle = confiobject.getint(
                "pkgsdatabase", "pkgs_dbpoolrecycle"
            )

        self.pkgs_dbpoolsize = 60
        if confiobject.has_option("pkgsdatabase", "pkgs_dbpoolsize"):
            self.pkgs_dbpoolsize = confiobject.getint("pkgsdatabase", "pkgs_dbpoolsize")

    def readConfxmpp(self, confiobject):
        self.xmpp_dbpooltimeout = 30
        if confiobject.has_option("xmppdatabase", "xmpp_dbpooltimeout"):
            self.xmpp_dbpooltimeout = confiobject.getint(
                "xmppdatabase", "xmpp_dbpooltimeout"
            )

        self.xmpp_dbhost = "localhost"
        if confiobject.has_option("xmppdatabase", "xmpp_dbhost"):
            self.xmpp_dbhost = confiobject.get("xmppdatabase", "xmpp_dbhost")

        self.xmpp_dbport = 3306
        if confiobject.has_option("xmppdatabase", "xmpp_dbport"):
            self.xmpp_dbport = confiobject.getint("xmppdatabase", "xmpp_dbport")

        self.xmpp_dbname = "xmppmaster"
        if confiobject.has_option("xmppdatabase", "xmpp_dbname"):
            self.xmpp_dbname = confiobject.get("xmppdatabase", "xmpp_dbname")

        self.xmpp_dbuser = "mmc"
        if confiobject.has_option("xmppdatabase", "xmpp_dbuser"):
            self.xmpp_dbuser = confiobject.get("xmppdatabase", "xmpp_dbuser")

        self.xmpp_dbpasswd = "mmc"
        if confiobject.has_option("xmppdatabase", "xmpp_dbpasswd"):
            self.xmpp_dbpasswd = confiobject.get("xmppdatabase", "xmpp_dbpasswd")

        self.xmpp_dbpoolrecycle = 3600
        if confiobject.has_option("xmppdatabase", "xmpp_dbpoolrecycle"):
            self.xmpp_dbpoolrecycle = confiobject.getint(
                "xmppdatabase", "xmpp_dbpoolrecycle"
            )

        self.xmpp_dbpoolsize = 60
        if confiobject.has_option("xmppdatabase", "xmpp_dbpoolsize"):
            self.xmpp_dbpoolsize = confiobject.getint("xmppdatabase", "xmpp_dbpoolsize")

    def readConfglpi(self, confiobject):
        self.inventory_url = "http://localhost:9999/"
        if confiobject.has_option("glpi", "inventory_server_url"):
            self.inventory_url = confiobject.get("glpi", "inventory_server_url")

        # Configuration sql
        # configuration glpi
        self.glpi_dbpooltimeout = 30
        if confiobject.has_option("glpidatabase", "glpi_dbpooltimeout"):
            self.glpi_dbpooltimeout = confiobject.getint(
                "glpidatabase", "glpi_dbpooltimeout"
            )

        self.glpi_dbhost = "localhost"
        if confiobject.has_option("glpidatabase", "glpi_dbhost"):
            self.glpi_dbhost = confiobject.get("glpidatabase", "glpi_dbhost")

        self.glpi_dbport = 3306
        if confiobject.has_option("glpidatabase", "glpi_dbport"):
            self.glpi_dbport = confiobject.getint("glpidatabase", "glpi_dbport")

        self.glpi_dbname = "glpi"
        if confiobject.has_option("glpidatabase", "glpi_dbname"):
            self.glpi_dbname = confiobject.get("glpidatabase", "glpi_dbname")

        self.glpi_dbuser = "mmc"
        if confiobject.has_option("glpidatabase", "glpi_dbuser"):
            self.glpi_dbuser = confiobject.get("glpidatabase", "glpi_dbuser")

        self.glpi_dbpasswd = "mmc"
        if confiobject.has_option("glpidatabase", "glpi_dbpasswd"):
            self.glpi_dbpasswd = confiobject.get("glpidatabase", "glpi_dbpasswd")

        self.glpi_dbpoolrecycle = 3600
        if confiobject.has_option("glpidatabase", "glpi_dbpoolrecycle"):
            self.glpi_dbpoolrecycle = confiobject.getint(
                "glpidatabase", "glpi_dbpoolrecycle"
            )

        self.glpi_dbpoolsize = 60
        if confiobject.has_option("glpidatabase", "glpi_dbpoolsize"):
            self.glpi_dbpoolsize = confiobject.getint("glpidatabase", "glpi_dbpoolsize")

        try:
            self.activeProfiles = confiobject.get("glpi", "active_profiles").split(" ")
        except Exception:
            # put the GLPI default values for actives profiles
            logging.getLogger().warning(
                "Apply default parameters for GLPI active profiles"
            )
            self.activeProfiles = ["Super-Admin", "Admin", "Supervisor", "Technician"]

        self.ordered = 1
        if confiobject.has_option("computer_list", "ordered"):
            self.ordered = confiobject.getint("computer_list", "ordered")

        filter = "state="
        if confiobject.has_option("glpi", "filter_on"):
            filter = confiobject.get("glpi", "filter_on")
        self.filter_on = self._parse_filter_on(filter)

        self.orange = 10
        self.red = 35
        if confiobject.has_option("state", "orange"):
            self.orange = confiobject.getint("state", "orange")
        if confiobject.has_option("state", "red"):
            self.red = confiobject.getint("state", "red")

        # This will be used to configure the machine table from glpi
        # The reg_key_ shown are displayed as reg_key_1 reg_key_2
        self.summary = ["cn", "description", "os", "type", "user", "entity"]
        if confiobject.has_option("computer_list", "summary"):
            self.summary = confiobject.get("computer_list", "summary").split(" ")

        # Registry keys that need to be pushed in an inventory
        ## Format: reg_key_x = path_to_key|key_label_shown_in_mmc
        # eg.:
        # reg_key_1 = HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA|LUAEnabled
        # reg_key_2 = HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\ProductName|WindowsVersion
        ## max_key_index = 2

        # reg_key_1 = HKEY_CURRENT_USER\Software\test\dede|dede
        # reg_key_1 = HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\EnableLUA|LUAEnabled
        # reg_key_2 = HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\ProductName|ProductName
        # max_key_index=2

        self.max_key_index = 50
        if confiobject.has_option("inventory", "max_key_index"):
            self.max_key_index = confiobject.getint("inventory", "max_key_index")
        # create mutex
        self.arraykeys = []
        for index_key in range(1, self.max_key_index + 1):
            if confiobject.has_option("inventory", "reg_key_%s" % index_key):
                self.arraykeys.append(
                    confiobject.get("inventory", "reg_key_%s" % index_key)
                )

        self.max_key_index = len(self.arraykeys)

        self.av_false_positive = []
        if confiobject.has_option("antivirus", "av_false_positive"):
            self.av_false_positive = confiobject.get(
                "antivirus", "av_false_positive"
            ).split("||")

        # associate manufacturer's names to their warranty url
        # manufacturer must have same key in 'manufacturer' and 'manufacturer_warranty_url' sections
        # for adding its warranty url
        self.manufacturerWarranty = {}
        if "" in confiobject.sections():
            logging.getLogger().debug(
                "[GLPI] Get manufacturers and their warranty infos"
            )
            for manufacturer_key in confiobject.options("manufacturers"):
                if confiobject.has_section(
                    "manufacturer_" + manufacturer_key
                ) and confiobject.has_option("manufacturer_" + manufacturer_key, "url"):
                    try:
                        type = confiobject.get(
                            "manufacturer_" + manufacturer_key, "type"
                        )
                    except NoOptionError:
                        type = "get"
                    try:
                        params = confiobject.get(
                            "manufacturer_" + manufacturer_key, "params"
                        )
                    except NoOptionError:
                        params = ""
                    self.manufacturerWarranty[manufacturer_key] = {
                        "names": confiobject.get(
                            "manufacturers", manufacturer_key
                        ).split("||"),
                        "type": type,
                        "url": confiobject.get(
                            "manufacturer_" + manufacturer_key, "url"
                        ),
                        "params": params,
                    }
            logging.getLogger().debug(self.manufacturerWarranty)

    def _parse_filter_on(self, value):
        """
        Parsing of customized filters.

        Returned value will be parsed as a dictionnary with list of values
        for each filter.

        @param value: raw string
        @type value: str

        @return: dictionnary of filters
        @rtype: dict
        """
        try:
            couples = [f.split("=") for f in value.split(" ")]

            filters = dict([(key, values.split("|")) for (key, values) in couples])
            logging.getLogger().debug("will filter machines on %s" % (str(filters)))
            return filters

        except Exception as e:
            logging.getLogger().warning("Parsing on filter_on failed: %s" % str(e))
            return None

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
