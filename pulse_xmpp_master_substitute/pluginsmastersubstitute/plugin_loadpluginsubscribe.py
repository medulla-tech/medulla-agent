# -*- coding: utf-8 -*-
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

# file pluginsmastersubstitute/plugin_loadpluginsubscribe.py

import json
import logging
from lib.utils import name_random
import traceback
from sleekxmpp import jid
import types
from lib.plugins.xmpp import XmppMasterDatabase

import time

logger = logging.getLogger()
DEBUGPULSEPLUGIN = 25

# this plugin calling to starting agent

plugin = {"VERSION": "1.10", "NAME": "loadpluginsubscribe", "TYPE": "substitute"}


def action(objectxmpp, action, sessionid, data, msg, dataerreur):
    logger.debug("=====================================================")
    logger.debug("call %s from %s" % (plugin, msg["from"]))
    logger.debug("=====================================================")

    compteurcallplugin = getattr(objectxmpp, "num_call%s" % action)
    if compteurcallplugin == 0:
        read_conf_load_plugin_subscribe(objectxmpp)
        objectxmpp.add_event_handler("changed_status", objectxmpp.changed_status)

        XmppMasterDatabase().update_enable_for_agent_subscription(
            objectxmpp.boundjid.bare
        )  # update down machine substitute manage by self agent

        # self.add_event_handler('presence_unavailable', objectxmpp.presence_unavailable)
        # self.add_event_handler('presence_available', objectxmpp.presence_available)

        # self.add_event_handler('presence_subscribe', objectxmpp.presence_subscribe)
        # self.add_event_handler('presence_subscribed', objectxmpp.presence_subscribed)

        # self.add_event_handler('presence_unsubscribe', objectxmpp.presence_unsubscribe)
        # self.add_event_handler('presence_unsubscribed', objectxmpp.presence_unsubscribed)

        # self.add_event_handler('changed_subscription', objectxmpp.changed_subscription)


def read_conf_load_plugin_subscribe(objectxmpp):
    """
    It reads the configuration plugin
    The folder where the configuration file must be is in the objectxmpp.config.pathdirconffile variable.
    """
    objectxmpp.changed_status = types.MethodType(changed_status, objectxmpp)


def changed_status(self, presence):
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
                XmppMasterDatabase().setUptime_machine(
                    hostname,
                    spresence,
                    status=0,
                    updowntime=time.time() - lastevent[0]["time"],
                    date=None,
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
                            if ret >= 1:
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
                    XmppMasterDatabase().setUptime_machine(
                        hostname,
                        spresence,
                        status=1,
                        updowntime=time.time() - lastevent[0]["time"],
                        date=None,
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
