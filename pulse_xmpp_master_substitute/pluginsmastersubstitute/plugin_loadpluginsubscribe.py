# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2016-2023 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-3.0-or-later

import json
import logging
from lib.utils import name_random
import traceback
import slixmpp
from slixmpp import jid
import types
from lib.plugins.xmpp import XmppMasterDatabase
import os
import time
from lib.utils import file_put_contents, simplecommandstr
import configparser
import asyncio

try:
    from lib.stat import statcallplugin

    statfuncton = True
except:
    statfuncton = False

logger = logging.getLogger()
DEBUGPULSEPLUGIN = 25
plugin = {"VERSION": "1.12", "NAME": "loadpluginsubscribe", "TYPE": "substitute"}  # fmt: skip


def action(objectxmpp, action, sessionid, data, msg, dataerreur):
    logger.debug("=====================================================")
    logger.debug("call %s from %s" % (plugin, msg["from"]))
    logger.debug("=====================================================")

    compteurcallplugin = getattr(objectxmpp, "num_call%s" % action)
    if compteurcallplugin == 0:
        if statfuncton:
            objectxmpp.stat_subcription_agent = statcallplugin(
                objectxmpp, plugin["NAME"]
            )
        read_conf_load_plugin_subscribe(objectxmpp)

        objectxmpp.changed_status = types.MethodType(changed_status, objectxmpp)
        objectxmpp.add_event_handler("changed_status", objectxmpp.changed_status)

        XmppMasterDatabase().update_enable_for_agent_subscription(
            objectxmpp.boundjid.bare
        )  # update down machine substitute manage by self agent

        # add function clean_roster et synchro_count_substitut
        objectxmpp.synchro_count_substitut = types.MethodType(
            synchro_count_substitut, objectxmpp
        )
        objectxmpp.clean_roster = types.MethodType(clean_roster, objectxmpp)

        objectxmpp.schedule("clean_roster", 60, objectxmpp.clean_roster, repeat=True)


def clean_roster(self):
    """
    This function does several actions:
        - removes master@pulse from the roster
        - removes all the unactive machines from the roster ( none none )
        - count how many contacts are in the roster
    """
    try:
        cmd = [
            "ejabberdctl process_rosteritems delete any any %s master@pulse"
            % self.boundjid.bare,
            "ejabberdctl process_rosteritems delete none:to none %s any"
            % str(self.boundjid.bare),
        ]
        for command in cmd:
            simplecommandstr(command)
    except Exception as error_cleaning:
        logger.error(
            "An error occured while cleaning the roster. We got the error %s"
            % str(error_cleaning)
        )
        logger.error("We hit the backtrace: \n%s" % (traceback.format_exc()))
    self.synchro_count_substitut()


def synchro_count_substitut(self):
    """
    This function is used to count the number of contacts in the roster.
    And add them to the database.
    """
    try:
        cmd = (
            "ejabberdctl get_roster %s %s | "
            "awk '{print $3;}' | grep -v out | wc -l "
            % (str(self.boundjid.user), str(self.boundjid.domain))
        )
        result = simplecommandstr(str(cmd))
        cardinal_roster = int(result["result"].strip()) if result else 0
        logger.debug(
            "roster number (%s) %s" % (cardinal_roster, str(self.boundjid.user))
        )

        XmppMasterDatabase().update_count_subscription(
            self.boundjid.bare, cardinal_roster
        )
    except Exception as error_count:
        logger.error(
            "An error occured while counting the roster. We got the error %s"
            % str(error_count)
        )
        logger.error("We hit the backtrace: \n%s" % (traceback.format_exc()))


def read_conf_load_plugin_subscribe(objectxmpp):
    """
    It reads the configuration plugin
    The folder where the configuration file must be is in the objectxmpp.config.pathdirconffile variable.
    """
    namefichierconf = plugin["NAME"] + ".ini"
    objectxmpp.pathfileconf = os.path.join(
        objectxmpp.config.pathdirconffile, namefichierconf
    )
    if not os.path.isfile(objectxmpp.pathfileconf):
        logger.error(
            "plugin %s\nConfiguration file  missing\n  %s"
            % (plugin["NAME"], objectxmpp.pathfileconf)
        )
        dataconfigfile = "[parameters]\ntime_between_checks =  60\n"
        file_put_contents(objectxmpp.pathfileconf, dataconfigfile)
        if statfuncton:
            objectxmpp.stat_subcription_agent.display_param_config(msg="DEFAULT")
        return False
    else:
        Config = configparser.ConfigParser()
        Config.read(objectxmpp.pathfileconf)
        if os.path.exists(objectxmpp.pathfileconf + ".local"):
            Config.read(objectxmpp.pathfileconf + ".local")
        if Config.has_section("parameters"):
            if statfuncton:
                objectxmpp.stat_subcription_agent.load_param_lap_time_stat_(Config)
                objectxmpp.stat_subcription_agent.display_param_config("CONFIG")
        else:
            logger.error(
                "see SECTION [parameters] mising in file : %s "
                % objectxmpp.pathfileconf
            )
            objectxmpp.assessor_agent_errorconf = True
            if statfuncton:
                objectxmpp.stat_subcription_agent.display_param_config("DEFAULT")
            return False
    return True


async def changed_status(self, presence):
    if presence["from"].bare != self.boundjid.bare:
        logger.debug(
            "********* changed_status %s %s" % (presence["from"], presence["type"])
        )
    if statfuncton:
        self.stat_subcription_agent.statutility()
    frommsg = jid.JID(presence["from"])
    logger.debug("Message from %s" % frommsg)
    spresence = str(presence["from"])
    try:
        if frommsg.bare == self.boundjid.bare:
            logger.debug("Message self calling not processed")
            return
    except Exception:
        logger.error("\n%s" % (traceback.format_exc()))
        pass
    try:
        hostname = spresence.split(".", 1)[0]
        jidsubscripbe = spresence.split("/", 1)[0]
        lastevent = XmppMasterDatabase().last_event_presence_xmpp(spresence)
        if presence["type"] == "unavailable":
            if lastevent and lastevent[0]["status"] == 1:
                try:
                    updowntime = time.time() - lastevent[0]["time"]
                except:
                    updowntime = time.time()
                XmppMasterDatabase().setUptime_machine(
                    hostname, spresence, status=0, updowntime=updowntime, date=None
                )
            result = XmppMasterDatabase().getMachinefromjid(spresence)
            if result and result["enabled"] == 0:
                return
            try:
                logger.info("The machine or ARS %s is now Offline" % spresence)
                result = XmppMasterDatabase().initialisePresenceMachine(spresence)
                XmppMasterDatabase().setlogxmpp(
                    "%s offline" % spresence,
                    "info",
                    "",
                    -1,
                    spresence,
                    "",
                    "",
                    "Presence",
                    "",
                    self.boundjid.bare,
                    self.boundjid.bare,
                )
                if result is None or len(result) == 0:
                    return
                if "type" in result and result["type"] == "relayserver":
                    # recover list of cluster ARS
                    listrelayserver = (
                        XmppMasterDatabase().getRelayServerofclusterFromjidars(
                            spresence
                        )
                    )
                    cluster = {
                        "action": "cluster",
                        "sessionid": name_random(5, "cluster"),
                        "data": {
                            "subaction": "initclusterlist",
                            "data": listrelayserver,
                        },
                    }
                    # all Relays server in the cluster are notified.
                    logger.debug("Notify to all ARS, offline ARS %s" % spresence)
                    for ARScluster in listrelayserver:
                        self.send_message(
                            mto=ARScluster, mbody=json.dumps(cluster), mtype="chat"
                        )
                else:
                    obj = XmppMasterDatabase().getcluster_resources(spresence)
                    arscluster = []
                    for t in obj["resource"]:
                        if t["jidmachine"] == spresence:
                            logger.debug(
                                "*** resource recovery on ARS %s for deploy"
                                "sessionid %s on machine  (connection loss) %s "
                                % (t["jidrelay"], t["sessionid"], t["hostname"])
                            )
                            arscluster.append(
                                [
                                    t["jidrelay"],
                                    t["sessionid"],
                                    t["hostname"],
                                    t["jidmachine"],
                                ]
                            )

                            ret = XmppMasterDatabase().updatedeploystate1(
                                t["sessionid"],
                                "DEPLOYMENT PENDING (REBOOT/SHUTDOWN/...)",
                            )
                            if ret and ret >= 1:
                                logger.debug(
                                    "Update deploy Status for Machine OffLine %s"
                                    % t["jidmachine"]
                                )
                                self.xmpplog(
                                    "Freeing deployment resource on ARS %s"
                                    "sessionid %s on machine %s (connection loss)"
                                    % (t["jidrelay"], t["sessionid"], t["hostname"]),
                                    type="deploy",
                                    sessionname=t["sessionid"],
                                    priority=-1,
                                    action="xmpplog",
                                    who="",
                                    how="",
                                    why=t["jidmachine"],
                                    module="Deployment| Notify | Cluster",
                                    date=None,
                                    fromuser="",
                                    touser="",
                                )

                                self.xmpplog(
                                    "Waiting for reboot",
                                    type="deploy",
                                    sessionname=t["sessionid"],
                                    priority=-1,
                                    action="xmpplog",
                                    who=t["jidmachine"],
                                    how="",
                                    why="",
                                    module="Deployment | Error | Terminate | Notify",
                                    date=None,
                                    fromuser="master",
                                    touser="",
                                )
                    if len(arscluster) > 0:
                        listrelayserver = XmppMasterDatabase().getRelayServer(
                            enable=True
                        )
                        cluster = {
                            "action": "cluster",
                            "sessionid": name_random(5, "cluster"),
                            "data": {
                                "subaction": "removeresource",
                                "data": {"jidmachine": spresence},
                            },
                        }

                        for ars in listrelayserver:
                            logger.debug(
                                "We remove the ressource on the ARS %s for the machine %s"
                                % (ars, spresence)
                            )
                            self.send_message(
                                mto=ars["jid"], mbody=json.dumps(cluster), mtype="chat"
                            )
            except Exception as e:
                logger.error("We encountered the error %s" % str(e))
                logger.error("the backtrace is: \n %s" % (traceback.format_exc()))
        elif presence["type"] == "available":
            lastevent = XmppMasterDatabase().last_event_presence_xmpp(spresence)
            if lastevent:
                if lastevent[0]["status"] == 0:
                    try:
                        updowntime = time.time() - lastevent[0]["time"]
                    except:
                        updowntime = time.time()

                    XmppMasterDatabase().setUptime_machine(
                        hostname, spresence, status=1, updowntime=updowntime, date=None
                    )
            else:
                XmppMasterDatabase().setUptime_machine(
                    hostname, spresence, status=1, updowntime=0, date=None
                )
            logger.info("The machine or ARS %s is now Online" % spresence)
            result = XmppMasterDatabase().initialisePresenceMachine(
                spresence, presence=1
            )
            if result is None or len(result) == 0:
                return
            if "type" in result and result["type"] == "machine":
                try:
                    if "reconf" in result and result["reconf"] == 1:
                        result1 = self.iqsendpulse(
                            presence["from"],
                            {
                                "action": "information",
                                "data": {
                                    "listinformation": ["force_reconf"],
                                    "param": {},
                                },
                            },
                            5,
                        )
                except Exception:
                    pass
                try:
                    XmppMasterDatabase().updateMachinereconf(spresence)
                except Exception:
                    logger.error("\n%s" % (traceback.format_exc()))

            XmppMasterDatabase().setlogxmpp(
                "%s online" % spresence,
                "info",
                "",
                -1,
                spresence,
                "",
                "",
                "Presence",
                "",
                self.boundjid.bare,
                self.boundjid.bare,
            )
    except Exception:
        logger.error("\n%s" % (traceback.format_exc()))
