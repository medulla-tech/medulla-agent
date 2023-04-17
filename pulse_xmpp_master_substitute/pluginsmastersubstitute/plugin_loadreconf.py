# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2016-2023 Siveo <support@siveo.net> 
# SPDX-License-Identifier: GPL-2.0-or-later 

import json
import os
import logging
from lib.utils import getRandomName
import types
import ConfigParser
from lib.plugins.xmpp import XmppMasterDatabase
import time
import traceback
logger = logging.getLogger()
DEBUGPULSEPLUGIN = 25

# this plugin calling to starting agent

plugin = {"VERSION": "1.1", "NAME": "loadreconf", "TYPE": "substitute"}

def action( objectxmpp, action, sessionid, data, msg, dataerreur):
    logger.debug("=====================================================")
    logger.debug("call %s from %s" % (plugin, msg['from']))
    logger.debug("=====================================================")

    compteurcallplugin = getattr(objectxmpp, "num_call%s" % action)

    if compteurcallplugin == 0:
        read_conf_loadreconf(objectxmpp)
        logger.debug("Configuration remote update")
        objectxmpp.concurentdata = {}
        logger.info("install loadreconf")
        objectxmpp.loadreconf = types.MethodType(loadreconf,
                                                 objectxmpp)
        logger.info("install send_reconf_mach_all_noeud_xmpp")
        objectxmpp.send_reconf_mach_all_noeud_xmpp = types.MethodType(send_reconf_mach_all_noeud_xmpp,
                                                                      objectxmpp)

        logger.info("search list ars")
        objectxmpp.list_ars =  XmppMasterDatabase().get_list_ars()
        logger.info("%s ars used" % len(objectxmpp.list_ars))

        objectxmpp.listconcurentreconf = []

        objectxmpp.schedule('loadreconf',
                            objectxmpp.generate_reconf_interval,
                            objectxmpp.loadreconf,
                            args=(objectxmpp,),
                            repeat=True)

def send_reconf_mach_all_noeud_xmpp(self, list_machine_user):
    ## on envoi a toutes les machines de la liste dans tout les domaines
    try:
        datasend = {"action": "force_setup_agent",
                    "data": "",
                    'ret': 0,
                    'sessionid': getRandomName(5, "loadreconf_")}
        for ars in self.list_ars:
            for mach in list_machine_user:
                jidmachine="%s@%s" % ( mach, ars['domaine'])
                self.send_message(mto=jidmachine,
                                mbody=json.dumps(datasend),
                                mtype='chat')
    except Exception as e:
        logging.getLogger().error("traceback send_reconf_mach_all_noeud_xmpp %s" % traceback.format_exc())

def loadreconf(self, objectxmpp):
    """
        Runs the load fingerprint
    """
    # calcul time entre 2 demandes de reconfiguration.
    t = time.time()
    end = t + objectxmpp.generate_reconf_interval

    datasend = {"action": "force_setup_agent",
                "data": "",
                'ret': 0,
                'sessionid': getRandomName(5, "loadreconf_")}
    list_machine_enabled_reconf = []
    viability = time.time() + objectxmpp.timeout_reconf
    while(time.time() < end):
        # fait tant qu'on est dans le temps du cycle planifier
        listmachine_user_search_on_ars = [x[1].split('.')[0] for x in objectxmpp.listconcurentreconf if x[2] <= t]
        listmachine_timeoutreconf = [x[0] for x in objectxmpp.listconcurentreconf if x[2] <= t]

        if len(listmachine_timeoutreconf) != 0:
            # on supprime les machines qui n'ont pas ete reconfigure dans les temps et on les considere eteintes.
            logger.warning ("The following machines are currently offline and their reconfiguration will be processed later: %s" % listmachine_timeoutreconf)
            # on lance 1 procedure de recherche pour etre certain que la machine n'a pas change de ars.
            # on cree 1 list des users et on apelle tout les ars pour savoir si il n'ont pas cette machine conecter.
            self.send_reconf_mach_all_noeud_xmpp(listmachine_user_search_on_ars)

            # machine pas de retour de reconf on les passe a non presente.
            XmppMasterDatabase().call_set_list_machine(listmachine=listmachine_timeoutreconf)
            # on supprime les non acquites suivant timeout de plus de generate_reconf_interval seconde
            objectxmpp.listconcurentreconf = [x for x in objectxmpp.listconcurentreconf if x[2] > t]

        list_user_machine_need_reconf = [ x[1].split('.')[0] for x in objectxmpp.listconcurentreconf]
        # lists reconf terminate
        if len(list_user_machine_need_reconf) > 0:
            # machine
            resultacquite = XmppMasterDatabase().call_acknowledged_reconficuration(list_user_machine_need_reconf)

            # liste des concurent
            if len(resultacquite) > 0:
                logger.debug ("concurent acquite machines id %s" % resultacquite)
                objectxmpp.listconcurentreconf = [ x for x in objectxmpp.listconcurentreconf \
                                            if  x[1].split('.')[0]  not in resultacquite]



        if len(list_machine_enabled_reconf) == 0:
            # machine presente et reconf demande[[id,jid],...]
            list_machine_enabled_reconf = XmppMasterDatabase().call_reconfiguration_machine(limit=objectxmpp.nbconcurrentreconf)
            if len(list_machine_enabled_reconf) == 0:
                return
        list_updatenopresence = []


        for _ in range(min(objectxmpp.nbconcurrentreconf, objectxmpp.listconcurentreconf)):
            if len(list_machine_enabled_reconf) > 0 and \
                    time.time() < end:
                eltmachine = list_machine_enabled_reconf.pop(0)
                eltmachine.append(viability)
                logger.debug ("ADD  %s " % (eltmachine))
                objectxmpp.listconcurentreconf.append(eltmachine)
                self.send_message(mto=eltmachine[1],
                                mbody=json.dumps(datasend),
                                mtype='chat')
                logger.debug ("SEND RECONFIGURATION %s (%s)" % (eltmachine[1], eltmachine[0]))
                list_updatenopresence.append(eltmachine[0])
            else:
                break

        if len(list_updatenopresence) != 0:
            XmppMasterDatabase().call_set_list_machine(listmachine=list_updatenopresence)
        time.sleep(.2)

def read_conf_loadreconf(objectxmpp):
    namefichierconf = plugin['NAME'] + ".ini"
    pathfileconf = os.path.join( objectxmpp.config.pathdirconffile, namefichierconf )
    if not os.path.isfile(pathfileconf):
        logger.warning("plugin %s\nConfiguration file :"
                       "\n\t%s missing"
                       "\neg conf:\n[parameters]\n"
                       "generate_reconf_interval = 60\n"
                       "concurrentreconf = 240\n"
                       "timeout_reconf = 500" % (plugin['NAME'],
                                                 pathfileconf))
        objectxmpp.generate_reconf_interval = 60
        objectxmpp.nbconcurrentreconf = 240
        objectxmpp.timeout_reconf = 500
    else:
        Config = ConfigParser.ConfigParser()
        Config.read(pathfileconf)
        logger.debug("read file %s"%pathfileconf)
        if os.path.exists(pathfileconf + ".local"):
            Config.read(pathfileconf + ".local")
            logger.debug("read file %s.local" % pathfileconf)
        if Config.has_option("parameters",
                             "generate_reconf_interval"):
            objectxmpp.generate_reconf_interval = Config.getint('parameters',
                                                                'generate_reconf_interval')
        else:
            objectxmpp.generate_reconf_interval = 60

        if Config.has_option("parameters",
                             "concurrentreconf"):
            objectxmpp.nbconcurrentreconf = Config.getint('parameters',
                                                          'concurrentreconf')
        else:
            objectxmpp.nbconcurrentreconf = 240

        if Config.has_option("parameters",
                             "timeout_reconf"):
            objectxmpp.timeout_reconf = Config.getint('parameters',
                                                      'timeout_reconf')
        else:
            objectxmpp.timeout_reconf = 500
    objectxmpp.plugin_loadreconf = types.MethodType(plugin_loadreconf, objectxmpp)

def plugin_loadreconf(self, msg, data):
    # Manage update remote agent
    pass
