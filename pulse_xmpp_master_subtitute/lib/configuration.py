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
from ConfigParser import  NoOptionError, NoSectionError
import utils
import random
from agentconffile import conffilename
from sleekxmpp import jid
from agentconffile import directoryconffile
from utils import ipfromdns

# Singleton/SingletonDecorator.py
class SingletonDecorator:
    def __init__(self, klass):
        self.klass = klass
        self.instance = None

    def __call__(self, *args, **kwds):
        if self.instance == None:
            self.instance = self.klass(*args, **kwds)
        return self.instance

@SingletonDecorator
class confParameter:
    
    #dbport = None
    #dbsslenable = False

    #check_db_enable = False
    #check_db_interval = 300

    #filter_on = None

    ## state section
    #orange = 10
    #red = 35

    ## computer_list section
    ## complete list: ['cn', 'description', 'os', 'type', 'user', 'inventorynumber', 'state', 'entity', 'location', 'model', 'manufacturer']
    ##
    #
    #ordered = False

    ## antivirus section
    #av_false_positive = []

    ## manufacturer section
    #manufacturerWarrantyUrl = {}
    #webservices = {
        #'purge_machine': 0
    #}

    def __init__(self, namefileconfig):
        print namefileconfig
        Config = ConfigParser.ConfigParser()
        #namefileconfig = os.path.join( '/',
                                       #'etc',
                                       #'pulse-xmpp-agent_master_inv',
                                       #'agentmasterinv.ini')
        Config.read(namefileconfig)
        if os.path.exists(namefileconfig + ".local"):
            Config.read(namefileconfig + ".local")
        self.packageserver = {}
        #CONNECTION XMPP
        self.Port = "5222"
        if Config.has_option("connection", "port"):
            self.Port = Config.get('connection', 'port')

        self.Server = "pulse"
        if Config.has_option("connection", "server"):
            self.Server = ipfromdns(Config.get('connection', 'server'))

        self.passwordconnection = "ahsy94heQErA12"
        if Config.has_option("connection", "password"):
            self.passwordconnection = Config.get('connection', 'password')

        self.jidmaster = "master@pulse"
        if Config.has_option("connection", "jidmaster"):
            self.jidmaster = Config.get('connection', 'jidmaster')

        self.jidlog = "log@pulse"
        if Config.has_option("connection", "jidlog"):
            self.jidlog =    Config.get('connection', 'jidlog')

        self.jidmastersubstitute = ""
        if Config.has_option("connection", "jidmastersubstitute"):
            self.jidmastersubstitute = Config.get('connection', 'jidmastersubstitute')
        if self.jidmastersubstitute == "":
            logging.getLogger().error("jidmastersubstitute parameter missing in file config : %s : "%namefileconfig)
            sys.exit(1)

        self.jidmasterreg = "master_reg@pulse"
        if Config.has_option("connection", "jidreg"):
            self.jidmasterreg = Config.get('connection', 'jidreg')

        #GLOBAL CONFIGURATION
        self.debug = "INFO"
        if Config.has_option("global", "log_level"):
            self.debug = Config.get('global', 'log_level')

        self.logfile = "/var/log/mmc/master_inv.log"
        if Config.has_option("global", "log_file"):
            self.logfile = Config.get('global', 'log_file')


        self.dbpoolrecycle = 60
        self.dbpoolsize = 5
        if Config.has_option("main", "dbpoolrecycle"):
            self.dbpoolrecycle = Config.getint('main', 'dbpoolrecycle')
        if Config.has_option("main", "dbpoolsize"):
            self.dbpoolsize = Config.getint('main', 'dbpoolsize')
        #PLUGIN LIST
        # activate connection to base module
        self.plugins_list = ["xmpp","glpi", "kiosk"]
        if Config.has_option("global", "activate_plugin"):
            listplugsql = Config.get('global', 'activate_plugin')
            self.plugins_list = [x for x in listplugsql.split(",") if x.strip() != ""]

        if "glpi" in self.plugins_list:
            self.readConfglpi(Config)

        if "xmpp" in self.plugins_list:
            self.readConfxmpp(Config)

        if "kiosk" in self.plugins_list:
            self.readConfkiosk(Config)

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

    def readConfkiosk(self, confiobject):
        self.kiosk_dbhost = "localhost"
        if confiobject.has_option("kioskdatabase", "kiosk_dbhost"):
            self.kiosk_dbhost = confiobject.get('kioskdatabase', 'kiosk_dbhost')

        self.kiosk_dbport = "3306"
        if confiobject.has_option("kioskdatabase", "kiosk_dbport"):
            self.kiosk_dbport = confiobject.get('kioskdatabase', 'kiosk_dbport')

        self.kiosk_dbname = "kiosk"
        if confiobject.has_option("kioskdatabase", "kiosk_dbname"):
            self.kiosk_dbname = confiobject.get('kioskdatabase', 'kiosk_dbname')

        self.kiosk_dbuser = "root"
        if confiobject.has_option("kioskdatabase", "kiosk_dbuser"):
            self.kiosk_dbuser = confiobject.get('kioskdatabase', 'kiosk_dbuser')

        self.kiosk_dbpasswd = "siveo"
        if confiobject.has_option("kioskdatabase", "kiosk_dbpasswd"):
            self.kiosk_dbpasswd = confiobject.get('kioskdatabase', 'kiosk_dbpasswd')

    def readConfxmpp(self, confiobject):
        self.xmpp_dbhost = "localhost"
        if confiobject.has_option("xmppdatabase", "xmpp_dbhost"):
            self.xmpp_dbhost = confiobject.get('xmppdatabase', 'xmpp_dbhost')

        self.xmpp_dbport = "3306"
        if confiobject.has_option("xmppdatabase", "xmpp_dbport"):
            self.xmpp_dbport = confiobject.get('xmppdatabase', 'xmpp_dbport')

        self.xmpp_dbname = "xmppmaster"
        if confiobject.has_option("xmppdatabase", "xmpp_dbname"):
            self.xmpp_dbname = confiobject.get('xmppdatabase', 'xmpp_dbname')

        self.xmpp_dbuser = "root"
        if confiobject.has_option("xmppdatabase", "xmpp_dbuser"):
            self.xmpp_dbuser = confiobject.get('xmppdatabase', 'xmpp_dbuser')

        self.xmpp_dbpasswd = "siveo"
        if confiobject.has_option("xmppdatabase", "xmpp_dbpasswd"):
            self.xmpp_dbpasswd = confiobject.get('xmppdatabase', 'xmpp_dbpasswd')

    def readConfglpi(self, confiobject):
        self.inventory_url = "http://localhost:9999/"
        if confiobject.has_option("glpi", "urlglpi"):
            self.inventory_url = confiobject.get('glpi', 'urlglpi')

        self.glpi_computer_uri = "http://pulse01/glpi//front/computer.form.php?id="
        if confiobject.has_option("glpi", "glpi_computer_uri"):
            self.glpi_computer_uri = confiobject.get('glpi', 'glpi_computer_uri')

        #Configuration sql
        #configuration glpi
        self.glpi_dbhost = "localhost"
        if confiobject.has_option("glpidatabase", "glpi_dbhost"):
            self.glpi_dbhost = confiobject.get('glpidatabase', 'glpi_dbhost')

        self.glpi_dbport = "3306"
        if confiobject.has_option("glpidatabase", "glpi_dbport"):
            self.glpi_dbport = confiobject.get('glpidatabase', 'glpi_dbport')

        self.glpi_dbname = "glpi"
        if confiobject.has_option("glpidatabase", "glpi_dbname"):
            self.glpi_dbname = confiobject.get('glpidatabase', 'glpi_dbname')

        self.glpi_dbuser = "glpi"
        if confiobject.has_option("glpidatabase", "glpi_dbuser"):
            self.glpi_dbuser = confiobject.get('glpidatabase', 'glpi_dbuser')

        self.glpi_dbpasswd = "siveo"
        if confiobject.has_option("glpidatabase", "glpi_dbpasswd"):
            self.glpi_dbpasswd = confiobject.get('glpidatabase', 'glpi_dbpasswd')

        try:
            self.activeProfiles = confiobject.get('main', 'active_profiles').split(' ')
        except NoOptionError:
            # put the GLPI default values for actives profiles
            self.activeProfiles = ['Super-Admin', 'Admin', 'Supervisor', 'Technician']

        self.ordered = 1 
        if confiobject.has_option("computer_list", "ordered"):
            self.ordered = confiobject.getint("computer_list", "ordered")


        filter = "state="
        if confiobject.has_option("main", "filter_on"):
            filter = confiobject.get("main", "filter_on")
        self.filter_on = self._parse_filter_on(filter)

        self.orange = 10
        self.red = 35
        if confiobject.has_option("state", "orange"):
            self.orange = confiobject.getint("state", "orange")
        if confiobject.has_option("state", "red"):
            self.red = confiobject.getint("state", "red")

        self.summary = ['cn', 'description', 'os', 'type', 'user', 'entity']
        if confiobject.has_option("computer_list", "summary"):
            self.summary = confiobject.get("computer_list", "summary").split(' ')

        self.av_false_positive = []
        if confiobject.has_option("antivirus", "av_false_positive"):
            self.av_false_positive = confiobject.get("antivirus", "av_false_positive").split('||')

        # associate manufacturer's names to their warranty url
        # manufacturer must have same key in 'manufacturer' and 'manufacturer_warranty_url' sections
        # for adding its warranty url
        self.manufacturerWarranty = {}
        if '' in confiobject.sections():
            logging.getLogger().debug('[GLPI] Get manufacturers and their warranty infos')
            for manufacturer_key in confiobject.options('manufacturers'):
                if confiobject.has_section('manufacturer_' + manufacturer_key) and confiobject.has_option('manufacturer_' + manufacturer_key, 'url'):
                    try:
                        type = confiobject.get('manufacturer_' + manufacturer_key, 'type')
                    except NoOptionError:
                        type = "get"
                    try:
                        params = confiobject.get('manufacturer_' + manufacturer_key, 'params')
                    except NoOptionError:
                        params = ""
                    self.manufacturerWarranty[manufacturer_key] = {'names': confiobject.get('manufacturers', manufacturer_key).split('||'),
                                                                   'type': type,
                                                                   'url': confiobject.get('manufacturer_' + manufacturer_key, 'url'),
                                                                   'params': params}
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

        except Exception, e:
            logging.getLogger().warn("Parsing on filter_on failed: %s" % str(e))
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
