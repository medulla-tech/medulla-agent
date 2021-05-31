# -*- coding: utf-8 -*-
#
# (c) 2021 siveo, http://www.siveo.net
#
# $Id$
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


"""
    Plugin used to check if the ARS of the Ejabberd server are running
    correctly.
"""

import traceback
import os
import logging
import ConfigParser
import types
import time
from sleekxmpp import jid
from sleekxmpp.exceptions import IqError, IqTimeout
from lib.plugins.xmpp import XmppMasterDatabase

logger = logging.getLogger()


plugin = {"VERSION": "1.2", "NAME": "loadarscheck", "TYPE": "substitute"}

def action(objectxmpp, action, sessionid, data, msg, ret):
    """
        Used to configure/start the plugin
    """
    try:
        logger.debug("=====================================================")
        logger.debug("call %s from %s" % (plugin, msg['from']))
        logger.debug("=====================================================")
        compteurcallplugin = getattr(objectxmpp, "num_call%s"%action)

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
    if not self.ressource_scan_available:
        logger.debug("The ressource is not available.")
        return
    try:
        self.ressource_scan_available = False
        list_ars_search = XmppMasterDatabase().getRelayServer()
        enabled_ars = [x for x in list_ars_search if x['enabled']]
        disabled_ars = [x for x in list_ars_search if not x['enabled']]
        logger.debug("disable %s" % len(disabled_ars))
        logger.debug("enable %s" % len(enabled_ars))

        self.ars_server_list_status = []
        listaction = []
        for ars in enabled_ars:
            arsstatus = self.ping_ejabberd_and_relay(ars['jid'])
            self.ars_server_list_status.append(arsstatus)
            if arsstatus['server']['presence'] == 0 or \
                    arsstatus['ars']['presence'] == 0:
                listaction.append(ars['jid'])

        if logger.level == 10 and self.ars_server_list_status:
            self.display_server_status()

        logger.debug("listaction %s" % listaction)

        # We give some time for the relay server, to be correctly/fully started
        for jidaction in listaction:
            time.sleep(1)
            arsstatus = self.ping_ejabberd_and_relay(jidaction)
            if arsstatus['server']['presence'] == 0 or \
                arsstatus['ars']['presence'] == 0:
                if self.update_table:
                    XmppMasterDatabase().update_Presence_Relay(jidaction['jid'], presence=0)
                    logger.debug("MISE A JOUR %s" % ars['jid'])
                    #logger.debug("update ARS %s" % enabled_ars)
                    #if self.action_reconf_ars_machines:
                        ## update machine for reconf
                        #XmppMasterDatabase().is_machine_reconf_needed(jidaction['jid'])
                        ##logger.error("Update reconf %s" % jidaction['jid'])

        for ars in disabled_ars:
            arsstatus = self.ping_ejabberd_and_relay(ars['jid'])
            if arsstatus['server']['presence'] == 1 and \
                    arsstatus['ars']['presence'] == 1:
                XmppMasterDatabase().update_Presence_Relay(ars['jid'], presence=1)

    finally:
        self.ressource_scan_available = True

def ping_ejabberd_and_relay(self, jid_client):
    """
        Used to test both the relayserver and the ejabberd server
        to determine which one is not functionnal.
        Args:
            jid_client: jid of the relay
    """
    server_jid = str(jid.JID(jid_client).domain)
    name_ars_jid = str(jid.JID(jid_client).user)

    rep = {'server': {'jid': server_jid, 'presence': 1},
           'ars': {'jid': name_ars_jid, 'presence': 1}}
    result = self.send_ping_relay(jid_client, self.check_timeout_ping)

    if result == 1:
        pass
    elif result == -1:
        rep['ars']['presence'] = 2
        rep['server']['presence'] = 2
    else:
        rep['ars']['presence'] = 0
        result = self.send_ping_relay(server_jid, self.check_timeout_ping)
        if result == 1:
            pass
        elif  result == -1:
            rep['server']['presence'] = 2
        else:
            rep['server']['presence'] = 0

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
        result = self['xep_0199'].send_ping(jid, timeout=timeout)
        logger.debug("ars present %s" % (jid))
        return 1
    except IqError as e:
        logger.error("test presence  %s :[%s]" % (jid, e.iq['error']['text']))
        return 0
    except IqTimeout:
        logger.error("No response from server.")
        return -1

def display_server_status(self):
    """
        Display the status of both ejabberd and ARS.
    """
    logger.debug("+-------------------------+-+-------------------------+-+")
    logger.debug("|         EJABBERD        |S|           ARS           |S|")
    logger.debug("+-------------------------+-+-------------------------+-+")
    for status_ars in self.ars_server_list_status:
        logger.debug("|%25s|%1s|%25s|%1s|" % (status_ars['server']['jid'],
                                              status_ars['server']['presence'],
                                              status_ars['ars']['jid'],
                                              status_ars['ars']['presence']))
    logger.debug("+-------------------------+-+-------------------------+-+")


def read_conf_loadarscheck(objectxmpp):
    """
        Define all the variables and functions used in the plugin
        Args:
            objectxmpp: Permit to acces to all xmpp mecanism.
    """
    logger.debug("Initialisation plugin : %s " % plugin["NAME"])
    namefichierconf = plugin['NAME'] + ".ini"
    # objectxmpp.ars_server_list_status = []
    # for _ in range(15): logger.info("read_conf_loadarscheck")

    pathfileconf = os.path.join(objectxmpp.config.pathdirconffile, namefichierconf)
    objectxmpp.ressource_scan_available = True
    objectxmpp.ars_server_list_status = []

    if not os.path.isfile(pathfileconf):
        # not config files
        objectxmpp.check_ars_scan_interval = 20
        objectxmpp.check_timeout_ping = 1
        objectxmpp.update_table = True
        objectxmpp.action_reconf_ars_machines = True
    else:
        ars_config = ConfigParser.ConfigParser()
        ars_config.read(pathfileconf)
        if ars_config.has_option("parameters", "check_ars_scan_interval"):
            objectxmpp.check_ars_scan_interval = ars_config.getint('parameters',
                                                                   'check_ars_scan_interval')
        else:
            # default values parameters
            objectxmpp.check_ars_scan_interval = 30

        if ars_config.has_option("parameters", "check_timeout_ping"):
            objectxmpp.check_timeout_ping = ars_config.getint('parameters', 'check_timeout_ping')
        else:
            # default values parameters
            objectxmpp.check_timeout_ping = 15
    logger.info("check_ars_scan_interval = %s" % objectxmpp.check_ars_scan_interval)
    logger.info("check_timeout_ping = %s" % objectxmpp.check_timeout_ping)
    logger.info("ressource_scan_available = %s" % objectxmpp.ressource_scan_available)

    # declaration function ping_ejabberd_and_relay in object xmpp
    objectxmpp.ping_ejabberd_and_relay = types.MethodType(ping_ejabberd_and_relay, objectxmpp)

    # declaration function send_ping_relay in object xmpp
    objectxmpp.send_ping_relay = types.MethodType(send_ping_relay, objectxmpp)

    # declaration function arscheck in object xmpp
    objectxmpp.arscheck = types.MethodType(arscheck, objectxmpp)

    # declaration function display_server_status in object xmpp
    objectxmpp.display_server_status = types.MethodType(display_server_status, objectxmpp)

    # schedule function arscheck
    objectxmpp.schedule('check_ars_by_ping',
                        objectxmpp.check_ars_scan_interval,
                        objectxmpp.arscheck,
                        repeat=True)
