# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2016-2023 Siveo <support@siveo.net> 
# SPDX-License-Identifier: GPL-2.0-or-later 

"""
ce plugin install 1 fonction appeler cycliquement
cette fonction a pour charge d'executer les actions creation des packages d'update, de deplacer les packages d'update du flip flop
"""

import os
import logging
import ConfigParser
import shutil
import types
from lib.configuration import confParameter
from datetime import datetime, timedelta
from lib.plugins.xmpp import XmppMasterDatabase
import traceback
from lib.utils import file_put_contents, simplecommandstr, simplecommand
logger = logging.getLogger()

DEBUGPULSEPLUGIN = 25

# this plugin calling to starting agent

plugin = {"VERSION" : "1.0", "NAME" : "loadactionupdate", "TYPE" : "substitute", "LOAD" : "START" }

GLOBALPARAM={"duration" : 30 , "debuglocal" : False}

def action( objectxmpp, action, sessionid, data, msg, dataerreur):
    logger.debug("=====================================================")
    logger.debug("call %s from %s"%(plugin, msg['from']))
    logger.debug("=====================================================")

    compteurcallplugin = getattr(objectxmpp, "num_call%s"%action)
    if compteurcallplugin == 0:
        read_conf_loadactionupdate(objectxmpp)
        # install code dynamique : fonction Action_update ci dessous
        objectxmpp.Action_update = types.MethodType(Action_update, objectxmpp)
        objectxmpp.msg_debug_local = types.MethodType(msg_debug_local, objectxmpp)
        # schedule appel de cette fonction cette fonctions
        objectxmpp.schedule('Action_update', objectxmpp.time_scrutation, objectxmpp.Action_update, repeat=True)
        objectxmpp.Action_update()

def read_conf_loadactionupdate(objectxmpp):
    """
        Read plugin configuration
        The folder holding the config file is in the variable objectxmpp.config.pathdirconffile
    """
    nameconffile = plugin['NAME'] + ".ini"
    pathconffile = os.path.join( objectxmpp.config.pathdirconffile, nameconffile )
    objectxmpp.time_scrutation = GLOBALPARAM["duration"]
    objectxmpp.debuglocal = GLOBALPARAM["debuglocal"]
    if not os.path.isfile(pathconffile):
        logger.error("plugin %s\nConfiguration file missing\n  %s" \
            "\neg conf:\n[parameters]\ntime_scrutation = %s\n" \
                "\ndebuglocal=%s" %(plugin['NAME'], pathconffile, GLOBALPARAM["duration"], GLOBALPARAM["debuglocal"]))
        create_default_config(objectxmpp)
        logger.warning("default value for time_scrutation is %s secondes" % objectxmpp.time_scrutation)
    else:
        Config = ConfigParser.ConfigParser()
        Config.read(pathconffile)
        if os.path.exists(pathconffile + ".local"):
            Config.read(pathconffile + ".local")
        if Config.has_option("parameters", "time_scrutation"):
            objectxmpp.time_scrutation = Config.getint('parameters', 'time_scrutation')
        else:
            # default values parameters
            objectxmpp.time_scrutation = GLOBALPARAM["duration"]
        if Config.has_option("parameters", "debuglocal"):
            objectxmpp.debuglocal = Config.getboolean('parameters', 'debuglocal')
        else:
            # default values parameters
            objectxmpp.debuglocal = GLOBALPARAM["debuglocal"]
        logger.info("%s"%vars(Config)['_sections'])
        # file_get_contents
        logger.info("debuglocal  %s   " % objectxmpp.debuglocal )
        logger.info("time_scrutation  %s   " % objectxmpp.time_scrutation )

def read_debug_conf(objectxmpp):
    """
        Read plugin configuration
        et interprete informatin de debug local
        parametre debuglocal=True
    """
    nameconffile = plugin['NAME'] + ".ini"
    pathconffile = os.path.join( objectxmpp.config.pathdirconffile, nameconffile )
    if os.path.isfile(pathconffile):
        Config = ConfigParser.ConfigParser()
        Config.read(pathconffile)
        if os.path.exists(pathconffile + ".local"):
            Config.read(pathconffile + ".local")
        if Config.has_option("parameters", "debuglocal"):
            objectxmpp.debuglocal = Config.getboolean('parameters', 'debuglocal')


# creation fichier de configuration par default
def create_default_config(objectxmpp):
    nameconffile = plugin['NAME'] + ".ini"
    pathconffile = os.path.join( objectxmpp.config.pathdirconffile, nameconffile )
    if not os.path.isfile(pathconffile):
        logger.warning("Creation default config file %s" % pathconffile)
        Config = ConfigParser.ConfigParser()
        Config.add_section('parameters')
        Config.set('parameters', 'time_scrutation', GLOBALPARAM["duration"])
        Config.set('parameters', 'debuglocal',  GLOBALPARAM["debuglocal"])
        with open(pathconffile, 'w') as configfile:
            Config.write(configfile)

def msg_debug_local(self, msg):
    try:
        if self.debuglocal:
            logger.info(msg)
    except Exception as e:
        logger.error("error localdebug %s" % str(e))

def Action_update(self):
    """
        Runs the log rotation
    """
    try:
        read_debug_conf(self)
        self.msg_debug_local("===================Action_update=====================")
        pidlist = XmppMasterDatabase().get_pid_list_all_Up_action_update_packages()
        if pidlist:
            self.msg_debug_local("Action update pid en cour %s" % pidlist)
            # pid python or bash
            cmd=r"""ps -U root -e | grep python | awk '{print $1}'"""
            self.msg_debug_local("commande list pid possible %s" % cmd)
            rr = simplecommand(cmd)

            if rr['code'] == 0:
                list_pid_bash = [ x.strip() for x in rr['result']]
                self.msg_debug_local("Action update   pid en cour %s" % list_pid_bash)
            pid_finish = [int(x['id']) for x in  pidlist if x['pid_run'] not in list_pid_bash]
            self.msg_debug_local("Action update test list pid finish %s" % pid_finish)
            XmppMasterDatabase().del_Up_action_update_packages_id(pid_finish)
        resultbase = []
        resultbase = XmppMasterDatabase().get_all_Up_action_update_packages()
        if resultbase:
            self.msg_debug_local("Action update list action package %s " % resultbase)
            for t in resultbase:
                cmd = "/usr/sbin/medulla_mysql_exec_update.sh %s" % str(t['action'])
                self.msg_debug_local("call launcher : %s" % cmd)
                rr = simplecommand(cmd)
                if rr['code'] == 0:
                    for ligneresult in rr['result']:
                        if ligneresult.startswith('pid : '):
                            pid_run = int(ligneresult.split(" ")[2].strip())
                            self.msg_debug_local("pid programme launcher : %s" % pid_run)
                            # on met a jour le pid
                            XmppMasterDatabase().update_pid_all_Up_action_update_packages(int(t['id']),
                                                                                          pid_run)
        self.msg_debug_local("===================Action_update=====================")
    except Exception as e:
        logger.error("Plugin %s, we encountered the error %s" % ( plugin['NAME'], str(e)))
        logger.error("We obtained the backtrace %s" % traceback.format_exc())
