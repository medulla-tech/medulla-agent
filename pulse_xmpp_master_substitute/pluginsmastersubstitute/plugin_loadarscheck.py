# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2021-2023 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-3.0-or-later

"""
    Plugin used to check if the ARS of the Ejabberd server are running
    correctly.
"""

import traceback
import os
import logging
from lib.plugins.xmpp import XmppMasterDatabase
from lib.utils import name_random
import configparser
import types
import time
from slixmpp import jid
from slixmpp.exceptions import IqError, IqTimeout

logger = logging.getLogger()
plugin = {"VERSION": "1.3", "NAME": "loadarscheck", "TYPE": "substitute"}  # fmt: skip


def action(objectxmpp, action, sessionid, data, msg, ret):
    """
    Used to configure/start the plugin
    """
    try:
        logger.debug("=====================================================")
        logger.debug("call %s from %s" % (plugin, msg["from"]))
        logger.debug("=====================================================")
        compteurcallplugin = getattr(objectxmpp, "num_call%s" % action)

        if compteurcallplugin == 0:
            read_conf_loadarscheck(objectxmpp)
    except Exception as e:
        logger.error("Plugin loadarscheck, we encountered the error %s" % str(e))
        logger.error("We obtained the backtrace %s" % traceback.format_exc())


def arscheck(self):
    """
    This function is used to ping the ARS regularly.
    The check_ars_scan_interval variable define how much this is done.
    check_ars_by_ping
    """
    sessionid = name_random(5, "monitoring_check_ars")

    if not self.ressource_scan_available:
        logger.debug("The ressource is not available.")
        return
    try:
        self.ressource_scan_available = False

        list_ars_search = XmppMasterDatabase().getRelayServer()
        enabled_ars = [x for x in list_ars_search if x["enabled"]]
        disabled_ars = [x for x in list_ars_search if not x["enabled"]]
        logger.debug("disable %s" % len(disabled_ars))
        logger.debug("enable %s" % len(enabled_ars))

        self.ars_server_list_status = []
        listaction = []
        for ars in enabled_ars:
            arsstatus = self.ping_ejabberd_and_relay(ars["jid"])
            self.ars_server_list_status.append(arsstatus)
            if (
                arsstatus["server"]["presence"] == 0
                or arsstatus["ars"]["presence"] == 0
            ):
                listaction.append(ars["jid"])

        if logger.level == 10 and self.ars_server_list_status:
            self.display_server_status()

        logger.debug("listaction %s" % listaction)

        # We give some time for the relay server, to be correctly/fully started
        for jidaction in listaction:
            logger.error("jidaction %s" % jidaction)
            time.sleep(1)
            arsstatus = self.ping_ejabberd_and_relay(jidaction)
            if (
                arsstatus["server"]["presence"] == 0
                or arsstatus["ars"]["presence"] == 0
            ):
                if self.update_table:
                    # Update relay and machine table.

                    XmppMasterDatabase().update_Presence_Relay(jidaction)

                    self.xmpplog(
                        "update on ping ars %s" % jidaction,
                        type="Monitoring",
                        sessionname=sessionid,
                        priority=-1,
                        action="xmpplog",
                        why=self.boundjid.bare,
                        module="Notify | Substitut | Monitoring",
                        date=None,
                        fromuser=jidaction,
                    )
                    if self.monitoring_message_on_machine_no_presence:
                        logger.warning("The Ars %s is down" % jidaction)
                        self.message_datas_to_monitoring_loadarscheck(
                            jidaction,
                            "The Ars %s is down" % jidaction,
                            informationaction="ack",
                        )
                    if self.action_reconf_ars_machines:
                        # update machine for reconf
                        self.xmpplog(
                            "Reconfigure all the machines belonging to the ars %s"
                            % jidaction,
                            type="Monitoring",
                            sessionname=sessionid,
                            priority=-1,
                            action="xmpplog",
                            why=self.boundjid.bare,
                            module="Notify | Substitut | Monitoring",
                            date=None,
                            fromuser=jidaction,
                        )
                        XmppMasterDatabase().is_machine_reconf_needed(jidaction)

        for ars in disabled_ars:
            arsstatus = self.ping_ejabberd_and_relay(ars["jid"])
            if (
                arsstatus["server"]["presence"] == 1
                and arsstatus["ars"]["presence"] == 1
            ):
                self.xmpplog(
                    "The ARS %s is online" % ars["jid"],
                    type="Monitoring",
                    sessionname=sessionid,
                    priority=-1,
                    action="xmpplog",
                    why=self.boundjid.bare,
                    module="Notify | Substitut | Monitoring",
                    date=None,
                    fromuser=ars["jid"],
                )
                XmppMasterDatabase().update_Presence_Relay(ars["jid"], presence=1)
    except Exception as e:
        logger.error("We failed to check the ARS Status")
        logger.error("The backtrace of this error is \n %s" % traceback.format_exc())
    finally:
        self.ressource_scan_available = True


def message_datas_to_monitoring_loadarscheck(
    self, ars, message, informationaction="ack"
):
    # status// "ready", "disable", "busy", "warning", "error"
    logger.debug(
        "message_datas_to_monitoring_loadarscheck( %s,%s) "
        % (message, informationaction)
    )
    sessionid = name_random(5, "monitoring_check_ars")
    self.xmpplog(
        message,
        type="Monitoring",
        sessionname=sessionid,
        priority=-1,
        action="xmpplog",
        why=self.boundjid.bare,
        module="Notify | Substitut | Monitoring",
        date=None,
        fromuser=ars,
    )


def ping_ejabberd_and_relay(self, jid_client):
    """
    Used to test both the relayserver and the ejabberd server
    to determine which one is not functionnal.
    Args:
        jid_client: jid of the relay
    """
    server_jid = str(jid.JID(jid_client).domain)
    name_ars_jid = str(jid.JID(jid_client).user)

    rep = {
        "server": {"jid": server_jid, "presence": 1},
        "ars": {"jid": name_ars_jid, "presence": 1},
    }
    result = self.send_ping_relay(jid_client, self.check_timeout_ping)

    if result == 1:
        pass
    elif result == -1:
        rep["ars"]["presence"] = 2
        rep["server"]["presence"] = 2
    else:
        rep["ars"]["presence"] = 0
        result = self.send_ping_relay(server_jid, self.check_timeout_ping)
        if result == 1:
            pass
        elif result == -1:
            rep["server"]["presence"] = 2
        else:
            rep["server"]["presence"] = 0

    return rep


def send_ping_relay(self, jid, timeout=5):
    """
    Send ping to the relay using the XEP 0199.
    ref: https://xmpp.org/extensions/xep-0199.html
    Args:
        jid: jid of the relay to ping
        timeout: time before a timeout of the IQ
    """
    logger.debug("send ping to %s " % jid)
    result = False
    try:
        result = self["xep_0199"].send_ping(jid, timeout=timeout)
        logger.debug("ars present %s" % (jid))
        return 1
    except IqError as e:
        logger.error("test presence  %s :[%s]" % (jid, e.iq["error"]["text"]))
        return 0
    except IqTimeout:
        logger.error("No response from server.")
        return -1


def display_server_status(self):
    """
    Display the status of both ejabberd and ARS.
    """
    logger.info("+-------------------------+-+-------------------------+-+")
    logger.info("|         EJABBERD        |S|           ARS           |S|")
    logger.info("+-------------------------+-+-------------------------+-+")
    for status_ars in self.ars_server_list_status:
        if status_ars["ars"]["presence"] == 0:
            logger.warning(
                "|%25s|%1s|%25s|%1s|"
                % (
                    status_ars["server"]["jid"],
                    status_ars["server"]["presence"],
                    status_ars["ars"]["jid"],
                    status_ars["ars"]["presence"],
                )
            )
        else:
            logger.info(
                "|%25s|%1s|%25s|%1s|"
                % (
                    status_ars["server"]["jid"],
                    status_ars["server"]["presence"],
                    status_ars["ars"]["jid"],
                    status_ars["ars"]["presence"],
                )
            )
    logger.info("+-------------------------+-+-------------------------+-+")


def read_conf_loadarscheck(objectxmpp):
    """
    Define all the variables and functions used in the plugin
    Args:
        objectxmpp: Permit to acces to all xmpp mecanism.
    """
    logger.debug("Initialisation plugin : %s " % plugin["NAME"])
    namefichierconf = plugin["NAME"] + ".ini"
    # objectxmpp.ars_server_list_status = []
    # for _ in range(15): logger.info("read_conf_loadarscheck")

    pathfileconf = os.path.join(objectxmpp.config.pathdirconffile, namefichierconf)
    objectxmpp.ressource_scan_available = True
    objectxmpp.ars_server_list_status = []

    if not os.path.isfile(pathfileconf):
        # not config files
        objectxmpp.check_ars_scan_interval = 600
        objectxmpp.check_timeout_ping = 5
        objectxmpp.update_table = True
        objectxmpp.action_reconf_ars_machines = True
        objectxmpp.monitoring_message_on_machine_no_presence = True
        objectxmpp.monitor_agent = "master_mon@pulse"
    else:
        ars_config = configparser.ConfigParser()
        ars_config.read(pathfileconf)

        if os.path.exists(pathfileconf + ".local"):
            ars_config.read(pathfileconf + ".local")

        if ars_config.has_option("parameters", "check_ars_scan_interval"):
            objectxmpp.check_ars_scan_interval = ars_config.getint(
                "parameters", "check_ars_scan_interval"
            )
        else:
            # default values parameters
            objectxmpp.check_ars_scan_interval = 30

        if ars_config.has_option("parameters", "check_timeout_ping"):
            objectxmpp.check_timeout_ping = ars_config.getint(
                "parameters", "check_timeout_ping"
            )
        else:
            # default values parameters
            objectxmpp.check_timeout_ping = 15

        logger.debug(
            "check_ars_scan_interval = %s" % objectxmpp.check_ars_scan_interval
        )
        logger.debug("check_timeout_ping = %s" % objectxmpp.check_timeout_ping)
        logger.debug(
            "ressource_scan_available = %s" % objectxmpp.ressource_scan_available
        )

        if ars_config.has_option("parameters", "update_table"):
            objectxmpp.update_table = ars_config.getboolean(
                "parameters", "update_table"
            )
        else:
            # default values parameters
            objectxmpp.update_table = True

        if ars_config.has_option("parameters", "action_reconf_ars_machines"):
            objectxmpp.action_reconf_ars_machines = ars_config.getboolean(
                "parameters", "action_reconf_ars_machines"
            )
        else:
            # default values parameters
            objectxmpp.action_reconf_ars_machines = False

        if ars_config.has_option(
            "parameters", "monitoring_message_on_machine_no_presence"
        ):
            objectxmpp.monitoring_message_on_machine_no_presence = (
                ars_config.getboolean(
                    "parameters", "monitoring_message_on_machine_no_presence"
                )
            )
        else:
            # default values parameters
            objectxmpp.monitoring_message_on_machine_no_presence = False

        if ars_config.has_option("parameters", "monitor_agent"):
            objectxmpp.monitor_agent = ars_config.get("parameters", "monitor_agent")
        else:
            # default values parameters
            objectxmpp.monitor_agent = "master_mon@pulse"

    logger.debug(
        "parameter loadarscheck : check_ars_scan_interval = %s"
        % objectxmpp.check_ars_scan_interval
    )
    logger.debug(
        "parameter loadarscheck : check_timeout_ping = %s"
        % objectxmpp.check_timeout_ping
    )
    logger.debug("parameter loadarscheck : update_table = %s" % objectxmpp.update_table)

    if objectxmpp.update_table:
        logger.debug(
            "parameter loadarscheck : action_reconf_ars_machines = %s"
            % objectxmpp.action_reconf_ars_machines
        )
        logger.debug(
            "parameter monitoring_message_on_machine_no_presence : "
            "   monitoring_message_on_machine_no_presence = %s"
            % objectxmpp.check_ars_scan_interval
        )
        logger.debug(
            "parameter loadarscheck : monitor_agent = %s" % objectxmpp.monitor_agent
        )
    logger.debug(
        "lock ressource_scan_available = %s" % objectxmpp.ressource_scan_available
    )

    # declaration function message_datas_to_monitoring_loadarscheck in object
    # xmpp
    objectxmpp.message_datas_to_monitoring_loadarscheck = types.MethodType(
        message_datas_to_monitoring_loadarscheck, objectxmpp
    )

    # declaration function ping_ejabberd_and_relay in object xmpp
    objectxmpp.ping_ejabberd_and_relay = types.MethodType(
        ping_ejabberd_and_relay, objectxmpp
    )

    # declaration function send_ping_relay in object xmpp
    objectxmpp.send_ping_relay = types.MethodType(send_ping_relay, objectxmpp)

    # declaration function arscheck in object xmpp
    objectxmpp.arscheck = types.MethodType(arscheck, objectxmpp)

    # declaration function display_server_status in object xmpp
    objectxmpp.display_server_status = types.MethodType(
        display_server_status, objectxmpp
    )

    # schedule function arscheck
    objectxmpp.schedule(
        "check_ars_by_ping",
        objectxmpp.check_ars_scan_interval,
        objectxmpp.arscheck,
        repeat=True,
    )
