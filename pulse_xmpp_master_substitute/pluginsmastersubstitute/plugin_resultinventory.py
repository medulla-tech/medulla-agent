#!/usr/bin/python3
# -*- coding: utf-8; -*-
#
# (c) 2016-2017 siveo, http://www.siveo.net
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
# file pluginsmastersubstitute/plugin_resultinventory.py

import zlib
import base64
import traceback
import urllib.request
import urllib.error
import urllib.parse
import time
import json
import logging
from lib.plugins.xmpp import XmppMasterDatabase
from lib.plugins.glpi import Glpi

logger = logging.getLogger()

plugin = {"VERSION": "1.12", "NAME": "resultinventory", "TYPE": "substitute"}


def action(xmppobject, action, sessionid, data, msg, ret, dataobj):
    HEADER = {
        "Pragma": "no-cache",
        "User-Agent": "Proxy:FusionInventory/Pulse2/GLPI",
        "Content-Type": "application/x-compress",
    }
    try:
        logger.debug("=====================================================")
        logger.debug("call %s from %s" % (plugin, msg["from"]))
        logger.debug("=====================================================")
        logger.info(
            "Received inventory from %s in inventory substitute agent" % (msg["from"])
        )
        try:
            url = xmppobject.config.inventory_url
        except Exception:
            url = "http://localhost:9999/"
        inventory = zlib.decompress(base64.b64decode(data["inventory"]))
        request = urllib.request.Request(url, inventory, HEADER)

        try:
            response = urllib.request.urlopen(request)
            logger.debug(
                "inject intentory to %s code wed %s" % (url, response.getcode())
            )
        except urllib.error.URLError:
            logger.info(
                "The inventory server is not reachable. Please check pulse2-inventory-server service"
            )

        machine = XmppMasterDatabase().getMachinefromjid(msg["from"])
        if not machine:
            logger.error("machine missing in table %s" % (msg["from"]))
            return

        nbsize = len(inventory)
        XmppMasterDatabase().setlogxmpp(
            "Received inventory from machine %s" % msg["from"],
            "Inventory",
            "",
            0,
            msg["from"],
            "",
            "",
            "QuickAction |Inventory | Inventory requested",
            "",
            xmppobject.boundjid.bare,
            xmppobject.boundjid.bare,
        )
        if nbsize < 250:
            XmppMasterDatabase().setlogxmpp(
                '<span class="log_warn">Inventory XML size: %s byte</span>' % nbsize,
                "Inventory",
                "",
                0,
                msg["from"],
                "",
                "",
                "Inventory | Notify",
                "",
                xmppobject.boundjid.bare,
                xmppobject.boundjid.bare,
            )
        time.sleep(15)
        uuidglpi = XmppUpdateInventoried(msg["from"], machine)
        if uuidglpi == -1:
            logger.error(
                "After injection of the inventory, no inventory is found for the address Macs."
            )
            XmppMasterDatabase().setlogxmpp(
                '<span class="log_err">Injection of inventory for machine %s failed</span>'
                % (msg["from"]),
                "Inventory",
                "",
                0,
                msg["from"],
                "",
                "",
                "Inventory | Notify | Error",
                "",
                xmppobject.boundjid.bare,
                xmppobject.boundjid.bare,
            )

        # save registry inventory
        try:
            reginventory = json.loads(base64.b64decode(data["reginventory"]))
        except Exception:
            reginventory = False
        # send inventory to inventory server

        XmppMasterDatabase().setlogxmpp(
            "Sending inventory to inventory server",
            "Inventory",
            "",
            0,
            msg["from"],
            "",
            "",
            "QuickAction | Inventory | Inventory requested",
            "",
            xmppobject.boundjid.bare,
            xmppobject.boundjid.bare,
        )

        if reginventory:
            counter = 0
            while True:
                time.sleep(counter)
                if machine["id"] or counter >= 10:
                    break
            logger.debug("Computers ID: %s" % machine["id"])
            nb_iter = int(reginventory["info"]["max_key_index"]) + 1
            for num in range(1, nb_iter):
                reg_key_num = "reg_key_" + str(num)
                try:
                    reg_key = reginventory[reg_key_num]["key"].strip('"')
                    reg_key_value = reginventory[reg_key_num]["value"].strip('"')
                    key_name = reg_key.split("\\")[-1]
                    logger.debug("Registry information:")
                    logger.debug("  reg_key_num: %s" % reg_key_num)
                    logger.debug("  reg_key: %s" % reg_key)
                    logger.debug("  reg_key_value: %s" % reg_key_value)
                    logger.debug("  key_name: %s" % key_name)
                    registry_id = Glpi().getRegistryCollect(reg_key)
                    logger.debug("  registry_id: %s" % registry_id)
                    XmppMasterDatabase().setlogxmpp(
                        "Inventory Registry information: [machine :  %s][reg_key_num : %s]"
                        "[reg_key: %s][reg_key_value : %s]"
                        "[key_name : %s]"
                        % (msg["from"], reg_key_num, reg_key, reg_key_value, key_name),
                        "Inventory",
                        "",
                        0,
                        msg["from"],
                        "",
                        "",
                        "QuickAction |Inventory | Inventory requested",
                        "",
                        xmppobject.boundjid.bare,
                        xmppobject.boundjid.bare,
                    )
                    # Glpi().addRegistryCollectContent(machine['id'], registry_id, key_name, reg_key_value)
                    if uuidglpi != -1:
                        Glpi().addRegistryCollectContent(
                            uuidglpi, registry_id, key_name, reg_key_value
                        )
                except Exception as e:
                    logger.error(
                        "getting key: %s\n%s" % (str(e), traceback.format_exc())
                    )
                    pass
        # time.sleep(25)
        # restart agent
        # xmppobject.restartAgent(msg['from'])
    except Exception as e:
        logger.error("%s\n%s" % (str(e), traceback.format_exc()))


def getComputerByMac(mac):
    ret = Glpi().getMachineByMacAddress("imaging_module", mac)
    if isinstance(ret, list):
        if len(ret) != 0:
            return ret[0]
        else:
            return None
    return ret


def getMachineByUuidSetup(uuidsetupmachine):
    if uuidsetupmachine is None or uuidsetupmachine == "":
        logger.warning("Setup uuid machine missing in inventory xmpp")
        return {}
    machine_result = Glpi().getMachineByUuidSetup(uuidsetupmachine)
    if machine_result:
        logger.debug("machine for setup uuid machine %s" % machine_result)
    return machine_result


def XmppUpdateInventoried(jid, machine):
    """search id glpi for machine
    search on uuid setup machine is exist.
    if not exit search on macadress"""
    if (
        machine["uuid_serial_machine"] is not None
        and machine["uuid_serial_machine"] != ""
    ):
        # search on uuid setup

        setupuuid = getMachineByUuidSetup(machine["uuid_serial_machine"])
        if setupuuid:
            logger.debug("** search id glpi on uuid setup machine")
            uuid = "UUID" + str(setupuuid["id"])
            if machine["uuid_inventorymachine"] == uuid:
                logger.debug(
                    "correct uuid_inventorymachine "
                    "in table machine id(%s) uuid_inventorymachine(%s)"
                    % (machine["id"], machine["uuid_inventorymachine"])
                )
                return setupuuid["id"]
            XmppMasterDatabase().updateMachineidinventory(uuid, machine["id"])
            XmppMasterDatabase().replace_Organization_ad_id_inventory(
                machine["uuid_inventorymachine"], uuid
            )
            return setupuuid["id"]
    # update on mac address
    try:
        result = XmppMasterDatabase().listMacAdressforMachine(machine["id"])
        results = result[0].split(",")
        logger.debug("listMacAdressforMachine   %s" % results)
        uuid = ""
        for t in results:
            logger.debug("Processing mac address")
            computer = getComputerByMac(t)
            if computer is not None:
                uuid = "UUID" + str(computer.id)
                logger.debug(
                    "** Update uuid %s for machine %s " % (uuid, machine["jid"])
                )
                if (
                    machine["uuid_inventorymachine"] != ""
                    and machine["uuid_inventorymachine"] is not None
                ):
                    logger.debug(
                        "** Update in Organization_ad uuid %s to %s "
                        % (machine["uuid_inventorymachine"], uuid)
                    )
                    XmppMasterDatabase().replace_Organization_ad_id_inventory(
                        machine["uuid_inventorymachine"], uuid
                    )
                    XmppMasterDatabase().updateMachineidinventory(uuid, machine["id"])
                return computer.id
    except KeyError:
        logger.error(
            "An error occurred on machine %s and we did not receive any inventory,"
            "make sure fusioninventory is running correctly" % machine
        )
    except Exception:
        logger.error(
            "** Update error on inventory %s\n%s" % (jid, traceback.format_exc())
        )
    return -1
