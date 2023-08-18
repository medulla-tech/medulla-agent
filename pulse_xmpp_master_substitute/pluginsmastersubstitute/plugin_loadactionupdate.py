# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2016-2023 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-3.0-or-later

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
from lib.plugins.msc import MscDatabase
import traceback
from lib.utils import file_put_contents, simplecommandstr, simplecommand

logger = logging.getLogger()

DEBUGPULSEPLUGIN = 25

# DEBUGSCRIPT = True active fonction debug msg_debug_local
# this plugin calling to starting agent


plugin = {"VERSION" : "1.0", "NAME" : "loadactionupdate", "TYPE" : "substitute", "LOAD" : "START" }  # fmt: skip

GLOBALPARAM={"duration" : 30 , "debuglocal" : False}  # fmt: skip


def action(objectxmpp, action, sessionid, data, msg, dataerreur):
    logger.debug("=====================================================")
    logger.debug("call %s from %s" % (plugin, msg["from"]))
    logger.debug("=====================================================")

    compteurcallplugin = getattr(objectxmpp, "num_call%s" % action)
    if compteurcallplugin == 0:
        read_conf_loadactionupdate(objectxmpp)
        # install code dynamique : fonction Action_update ci dessous
        objectxmpp.Action_update = types.MethodType(Action_update, objectxmpp)
        objectxmpp.msg_debug_local = types.MethodType(msg_debug_local, objectxmpp)
        objectxmpp.create_deploy_for_up_machine_windows = types.MethodType(
            create_deploy_for_up_machine_windows, objectxmpp
        )
        # schedule appel de cette fonction cette fonctions
        objectxmpp.schedule(
            "Action_update",
            objectxmpp.time_scrutation,
            objectxmpp.Action_update,
            repeat=True,
        )
        objectxmpp.Action_update()
        objectxmpp.schedule(
            "Action_luncher_deploy",
            objectxmpp.time_scrutation,
            objectxmpp.create_deploy_for_up_machine_windows,
            repeat=True,
        )


def create_deploy_for_up_machine_windows(objectxmpp):
    try:
        need_to_add = XmppMasterDatabase().pending_up_machine_windows_white()
        for update in need_to_add:
            intervals = update["intervals"] if update["intervals"] is not None else ""
            section = '"section":"update"'
            command = MscDatabase().createcommanddirectxmpp(
                update["update_id"],
                "",
                section,
                update["files_str"],
                "enable",
                "disable",
                update["start_date"],
                update["end_date"],
                "root",
                "root",
                update["title"],
                0,
                28,
                0,
                intervals,
                None,
                None,
                None,
                "none",
                "active",
                "1",
                cmd_type=0,
            )
            try:
                target = MscDatabase().xmpp_create_Target(
                    update["uuidmachine"], update["hostname"]
                )
            except Exception as e:
                logger.error(
                    "Unable to create Msc Target for update %s" % update["update_id"]
                )

            com_on_host = MscDatabase().xmpp_create_CommandsOnHost(
                command.id,
                target["id"],
                update["hostname"],
                command.end_date,
                command.start_date,
            )

            if com_on_host is not None or com_on_host is not False:
                MscDatabase().xmpp_create_CommandsOnHostPhasedeploykiosk(com_on_host.id)

                XmppMasterDatabase().addlogincommand(
                    "root", command.id, "", "", "", "", "", 0, 0, 0, 0, {}
                )
                logger.info(
                    "Update %s will be deployed on %s between %s and %s %s"
                    % (
                        update["update_id"],
                        update["title"],
                        update["start_date"],
                        update["end_date"],
                        intervals,
                    )
                )

            else:
                logger.error(
                    "Unable to create phases for update %s" % (update["title"])
                )
    except Exception as e:
        logger.error(e)


def read_conf_loadactionupdate(objectxmpp):
    """
    Read plugin configuration
    The folder holding the config file is in the variable objectxmpp.config.pathdirconffile
    """
    nameconffile = plugin["NAME"] + ".ini"
    pathconffile = os.path.join(objectxmpp.config.pathdirconffile, nameconffile)
    objectxmpp.time_scrutation = GLOBALPARAM["duration"]
    objectxmpp.debuglocal = GLOBALPARAM["debuglocal"]
    if not os.path.isfile(pathconffile):
        logger.error(
            "plugin %s\nConfiguration file missing\n  %s"
            "\neg conf:\n[parameters]\ntime_scrutation = %s\n"
            "\ndebuglocal=%s"
            % (
                plugin["NAME"],
                pathconffile,
                GLOBALPARAM["duration"],
                GLOBALPARAM["debuglocal"],
            )
        )
        create_default_config(objectxmpp)
        logger.warning(
            "default value for time_scrutation is %s secondes"
            % objectxmpp.time_scrutation
        )
    else:
        Config = ConfigParser.ConfigParser()
        Config.read(pathconffile)
        if os.path.exists(pathconffile + ".local"):
            Config.read(pathconffile + ".local")
        if Config.has_option("parameters", "time_scrutation"):
            objectxmpp.time_scrutation = Config.getint("parameters", "time_scrutation")
        else:
            # default values parameters
            objectxmpp.time_scrutation = GLOBALPARAM["duration"]
        if Config.has_option("parameters", "debuglocal"):
            objectxmpp.debuglocal = Config.getboolean("parameters", "debuglocal")
        else:
            # default values parameters
            objectxmpp.debuglocal = GLOBALPARAM["debuglocal"]
        logger.info("%s" % vars(Config)["_sections"])
        # file_get_contents
        logger.info("debuglocal  %s   " % objectxmpp.debuglocal)
        logger.info("time_scrutation  %s   " % objectxmpp.time_scrutation)


def read_debug_conf(objectxmpp):
    """
    Read plugin configuration
    et interprete informatin de debug local
    parametre debuglocal=True
    """
    nameconffile = plugin["NAME"] + ".ini"
    pathconffile = os.path.join(objectxmpp.config.pathdirconffile, nameconffile)
    if os.path.isfile(pathconffile):
        Config = ConfigParser.ConfigParser()
        Config.read(pathconffile)
        if os.path.exists(pathconffile + ".local"):
            Config.read(pathconffile + ".local")
        if Config.has_option("parameters", "debuglocal"):
            objectxmpp.debuglocal = Config.getboolean("parameters", "debuglocal")


# creation fichier de configuration par default
def create_default_config(objectxmpp):
    nameconffile = plugin["NAME"] + ".ini"
    pathconffile = os.path.join(objectxmpp.config.pathdirconffile, nameconffile)
    if not os.path.isfile(pathconffile):
        logger.warning("Creation default config file %s" % pathconffile)
        Config = ConfigParser.ConfigParser()
        Config.add_section("parameters")
        Config.set("parameters", "time_scrutation", GLOBALPARAM["duration"])
        Config.set("parameters", "debuglocal", GLOBALPARAM["debuglocal"])
        with open(pathconffile, "w") as configfile:
            Config.write(configfile)


def msg_debug_local(self, msg):
    deb = False
    try:
        global DEBUGSCRIPT
        deb = True
    except NameError:
        deb = False
    try:
        if self.debuglocal or deb:
            logger.info(msg)
    except Exception as e:
        logger.error("error localdebug %s" % str(e))


def Action_update(self):
    """
    Runs the log rotation
    """
    try:
        read_debug_conf(self)
        resultbase = XmppMasterDatabase().get_all_Up_action_update_packages()
        if resultbase:
            for t in resultbase:
                cmd = "%s" % (
                    str(t["action"])
                )  # str(t['packages'])/usr/sbin/medulla_mysql_exec_update.sh %s
                self.msg_debug_local("call launcher : %s" % cmd)
                rr = simplecommand(cmd)
            idlist = [x["id"] for x in resultbase]
            XmppMasterDatabase().del_Up_action_update_packages_id(idlist)
    except Exception as e:
        logger.error(
            "Plugin %s, we encountered the error %s" % (plugin["NAME"], str(e))
        )
        logger.error("We obtained the backtrace %s" % traceback.format_exc())
