# -*- coding: utf-8 -*-
#
# (c) 2016-2020 siveo, http://www.siveo.net
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
#
# plugin register machine dans presence table xmpp.
# file pulse_xmpp_master_substitute/pluginsmastersubstitute/plugin_registeryagent.py
#
import base64
import traceback
import os
import json
import logging
from lib.plugins.xmpp import XmppMasterDatabase
from lib.plugins.glpi import Glpi
from lib.plugins.kiosk import KioskDatabase
from lib.manageRSAsigned import MsgsignedRSA
from slixmpp import jid
from lib.utils import getRandomName
import re
from distutils.version import LooseVersion
import configparser
import netaddr

# this import will be used later
# import types

logger = logging.getLogger()
plugin = {"VERSION": "1.55", "NAME": "registeryagent", "TYPE": "substitute"}  # fmt: skip

# function comment for next feature
# this functions will be used later
# def function_dynamique_declaration_plugin(xmppobject):
# xmppobject.changestatusin_plugin = types.MethodType(changestatusin_plugin, xmppobject)

# def changestatusin_plugin(self, msg_changed_status):
# logger.debug("chang status for %s"%msg_changed_status['from'])
# pass


def action(xmppobject, action, sessionid, data, msg, ret, dataobj):
    try:
        logger.debug("=====================================================")
        logger.debug("call %s from %s" % (plugin, msg["from"]))
        logger.debug("=====================================================")
        compteurcallplugin = getattr(xmppobject, "num_call%s" % action)

        if compteurcallplugin == 0:
            read_conf_remote_registeryagent(xmppobject)
            if xmppobject.registeryagent_showinfomachine:
                logger.debug(
                    "Including debug information for list jid %s"
                    % (xmppobject.registeryagent_showinfomachine)
                )
            # return
            # function comment for next feature
            # this functions will be used later
            # add function for event change staus des autre agent
            # function_dynamique_declaration_plugin(xmppobject)
            # intercepte event change status call function
        showinfobool = False
        listupt = [x.upper() for x in xmppobject.registeryagent_showinfomachine]
        for x in listupt:
            if x in str(msg["from"]).upper():
                logger.info(
                    "We will show detailled information for the machine %s"
                    % (str(msg["from"]))
                )
                showinfobool = True
                break
            else:
                showinfobool = False
        if "ALL" in listupt:
            showinfobool = True
        if "action" in data and data["action"] == "infomachine":
            if showinfobool:
                logger.info("The machine %s is sending a mini inventory" % msg["from"])
            if "completedatamachine" in data:
                info = json.loads(base64.b64decode(data["completedatamachine"]))
                data["information"] = info
                if not xmppobject.use_uuid:
                    data["uuid_serial_machine"] = ""
                    if showinfobool:
                        logger.info(
                            "The parameter use_uuid is set to False"
                            "The uuid_serial_machine information will not be used"
                        )
                if "uuid_serial_machine" not in data:
                    data["uuid_serial_machine"] = ""
                    if showinfobool:
                        logger.info("** uuid setup_machine missing")
                else:
                    if showinfobool:
                        logger.info(
                            "The uuid_setup_machine is  %s"
                            % data["uuid_serial_machine"]
                        )
                interfacedata = []
                interfaceblacklistdata = []
                for interface in data["information"]["listipinfo"]:
                    # exclude mac address from table network
                    if test_mac_address_black_list(
                        interface["macnotshortened"],
                        xmppobject.blacklisted_mac_addresses,
                        showinfobool=showinfobool,
                    ):
                        interfaceblacklistdata.append(interface)
                    else:
                        interfacedata.append(interface)

                data["information"]["listipinfo"] = interfacedata
                if showinfobool:
                    logger.info("For the machine %s" % str(msg["from"]))
                    if len(data["information"]["listipinfo"]):
                        logger.info("The actives interfaces are:")
                        logger.info("|   macaddress|      ip address|")
                        for interface in data["information"]["listipinfo"]:
                            logger.info(
                                "|%s|%15s|"
                                % (interface["macaddress"], interface["ipaddress"])
                            )
                    if interfaceblacklistdata:
                        logger.warning("The interface below are blacklisted")
                        for interface in interfaceblacklistdata:
                            logger.warning("|   macaddress|      ip address|")
                            logger.warning(
                                "|%s|%15s|"
                                % (interface["macaddress"], interface["ipaddress"])
                            )

                logger.info("We are registering the machine %s" % data["from"])
                XmppMasterDatabase().setlogxmpp(
                    "Registering machine %s" % data["from"],
                    "info",
                    sessionid,
                    -1,
                    msg["from"],
                    "",
                    "",
                    "Registration",
                    "",
                    xmppobject.boundjid.bare,
                    xmppobject.boundjid.bare,
                )
            if "oldjid" in data:
                logger.debug(
                    "The hostname changed from %s to %s"
                    % (data["oldjid"], data["from"])
                )
                XmppMasterDatabase().delPresenceMachinebyjiduser(
                    jid.JID(data["oldjid"]).user
                )
            machine = XmppMasterDatabase().getMachinefromjid(data["from"])
            if machine:
                if (
                    "regcomplet" in data
                    and data["regcomplet"] is True
                    or str(jid.JID(data["from"]).domain)
                    != str(jid.JID(str(machine["jid"])).domain)
                ):
                    if showinfobool:
                        logger.info(
                            "We are performing a complete re-registration of the machine %s"
                            % msg["from"]
                        )
                        logger.info(
                            "We are deleting machine %s in the machines table"
                            % msg["from"]
                        )
                    XmppMasterDatabase().delPresenceMachinebyjiduser(msg["from"].user)
                    machine = {}

            if showinfobool:
                if len(machine) != 0:
                    logger.info("The machine %s already exists in base" % msg["from"])
                else:
                    logger.info("The machine %s does not exist in base" % msg["from"])
            if len(machine) != 0:
                # We look if the network table is coherent.
                try:
                    result = XmppMasterDatabase().listMacAdressforMachine(
                        machine["id"], infomac=showinfobool
                    )
                    macadresssort = sorted(
                        [
                            x["macnotshortened"]
                            for x in data["information"]["listipinfo"]
                        ]
                    )
                    macadressstr = ",".join(macadresssort)
                    if showinfobool:
                        logger.info(
                            "The mac addresses on the machine: %s " % macadressstr
                        )

                    if result[0] is None or result[0] != macadressstr:
                        if result[0] is not None:
                            logger.warning(
                                "mac adress diff :\n\t %s : %s\n\t "
                                "network table : %s"
                                % (data["agenttype"], macadressstr, result[0])
                            )
                        raise
                    machine["enabled"] = 1
                except Exception:
                    # There is an incoherence in the mac tables between the machine list and the network list.
                    # So we need to delete the machine from the table and proceed to a new registration
                    logger.warning(
                        "We detected and incoherence in the mac tables between the machine list and the network list for the machine %s. \n"
                        "We need to delete the machine and proceed a new registration"
                        % data["from"]
                    )

                    machine["enabled"] = 0
                    XmppMasterDatabase().delPresenceMachinebyjiduser(msg["from"].user)
                    logger.warning(
                        "We are proceeding at the full reinscription of %s %s"
                        % (msg["from"].user, data["agenttype"])
                    )

                    XmppMasterDatabase().setlogxmpp(
                        "Full reinscription of "
                        "the %s %s" % (msg["from"].user, data["agenttype"]),
                        "info",
                        sessionid,
                        -1,
                        msg["from"],
                        "",
                        "",
                        "Registration | Notify",
                        "",
                        xmppobject.boundjid.bare,
                        xmppobject.boundjid.bare,
                    )
                if machine["enabled"] == 1:
                    logger.debug(
                        "The machine %s registered with the id: %s"
                        % (msg["from"], machine["id"])
                    )
                    XmppMasterDatabase().setlogxmpp(
                        "The machine %s registered with %s"
                        % (msg["from"], machine["id"]),
                        "info",
                        sessionid,
                        -1,
                        msg["from"],
                        "",
                        "",
                        "Registration | Notify",
                        "",
                        xmppobject.boundjid.bare,
                        xmppobject.boundjid.bare,
                    )

                    if showinfobool:
                        logger.info(
                            "The machine %s is now Online in the machine table."
                            % data["from"]
                        )
                    pluginfunction = [
                        str("plugin_%s" % x) for x in xmppobject.pluginlistregistered
                    ]
                    if showinfobool:
                        logger.info("We are loading the plugins for online machines")
                    for function_plugin in pluginfunction:
                        try:
                            if hasattr(xmppobject, function_plugin):
                                if showinfobool:
                                    logger.info("Calling plugin %s" % function_plugin)
                                getattr(xmppobject, function_plugin)(msg, data)
                            else:
                                if showinfobool:
                                    logger.warning(
                                        "The %s plugin is not called" % function_plugin
                                    )
                                    logger.warning(
                                        "Check why plugin %s"
                                        " does not have function %s"
                                        % (function_plugin, function_plugin)
                                    )
                        except Exception:
                            logger.error(
                                "An error occured while loading plugins for online machines."
                            )
                            logger.error(
                                "We hit this backtrace: i\n%s"
                                % (traceback.format_exc())
                            )

                    if showinfobool:
                        logger.debug(
                            "The machine %s already exists in the database"
                            % str(msg["from"])
                        )
                        logger.debug("We will update it's uuid_inventory_machine")
                    if (
                        data["from"] != machine["jid"]
                        or data["baseurlguacamole"] != machine["urlguacamole"]
                        or data["deployment"] != machine["groupdeploy"]
                    ):
                        if showinfobool:
                            # TODO: Make it more userfriendly
                            logger.debug(
                                "Update machine id %s\njid %s\n"
                                "urlguacamole %s\n"
                                "groupdeploy %s\nto\n"
                                "jid %s\n"
                                "urlguacamole %s\n"
                                "groupdeploy %s"
                                % (
                                    machine["id"],
                                    machine["jid"],
                                    machine["urlguacamole"],
                                    machine["groupdeploy"],
                                    data["from"],
                                    data["baseurlguacamole"],
                                    data["deployment"],
                                )
                            )
                        machine["jid"] = data["from"]
                        machine["urlguacamole"] = data["baseurlguacamole"]
                        machine["groupdeploy"] = data["deployment"]
                        XmppMasterDatabase().updateMachinejidGuacamoleGroupdeploy(
                            machine["jid"],
                            machine["urlguacamole"],
                            machine["groupdeploy"],
                            machine["id"],
                        )
                    # on regarde si le UUID associe a hostname machine correspond au hostname dans glpi.
                    # on fait cette verification si patametre config
                    # check_uuidinventory est vrai
                    if (
                        xmppobject.check_uuidinventory
                        and "uuid_inventorymachine" in machine
                        and machine["uuid_inventorymachine"] is not None
                    ):
                        # on regarde si le UUID associe a hostname machine
                        # correspond au hostname dans glpi.
                        hostname = None
                        if showinfobool:
                            logger.info(
                                "We are looking if there is incoherences between "
                                "xmpp and glpi for the uuid %s"
                                % machine["uuid_inventorymachine"]
                            )
                        try:
                            # TODO: Use a SQL request quicker/smaller
                            ret = Glpi().getLastMachineInventoryFull(
                                machine["uuid_inventorymachine"]
                            )
                            for t in ret:
                                if t[0] == "name":
                                    hostname = t[1]
                                    break

                            # We verify that the hostname in the database and the one provided
                            # by the inventory are the same.
                            # If not we will update by a new full registration
                            if (
                                hostname
                                and "hostname" in data
                                and hostname != data["hostname"]
                            ):
                                machine["uuid_inventorymachine"] = None
                                if showinfobool:
                                    logger.warning(
                                        "When there is an incoherence between "
                                        "xmpp and glpi uuid, we restore the uuid from glpi"
                                    )
                                    logger.warning(
                                        "The hostname in the database and the one provided by the"
                                        ""
                                    )
                            else:
                                # la correspondance existe.
                                # mais il se peut que la machine ne soit pas configuré pour guacamole.
                                # si la machine n'est pas configuré pour
                                # guacamole, alors on refait l'enregistrement
                                # complet.
                                ret = XmppMasterDatabase().getGuacamoleidforUuid(
                                    machine["uuid_inventorymachine"], "configured"
                                )
                                if not ret:
                                    machine["uuid_inventorymachine"] = None
                                    if showinfobool:
                                        logger.warning(
                                            "When guacamole is not configured,"
                                            " we restore the uuid from glpi"
                                        )
                        except Exception:
                            machine["uuid_inventorymachine"] = None
                        if machine["uuid_inventorymachine"] is not None:
                            if showinfobool:
                                logger.info("Coherence True for hostname %s" % hostname)
                    if (
                        "uuid_inventorymachine" not in machine
                        or machine["uuid_inventorymachine"] is None
                        or not machine["uuid_inventorymachine"]
                    ):
                        if data["agenttype"] != "relayserver":
                            listmacadress = result[0].split(",")
                            nbelt = len(listmacadress)
                            listmacadress = set(listmacadress)
                            nbelt1 = len(listmacadress)
                            if nbelt != nbelt1:
                                if showinfobool:
                                    logger.warning(
                                        "%s duplicate in the network table "
                                        "for machine [%s] id %s"
                                        % (nbelt - nbelt1, data["from"], machine["id"])
                                    )
                                    logger.warning(
                                        "Mac address list (without duplicate)"
                                        " for machine %s : %s"
                                        % (machine["id"], listmacadress)
                                    )
                                else:
                                    logger.debug(
                                        "Mac address list for machine %s : %s"
                                        % (machine["id"], listmacadress)
                                    )
                            listmacadress = result[0].split(",")
                            if showinfobool:
                                logger.info(
                                    "Mac address list for machine %s : %s"
                                    % (machine["id"], listmacadress)
                                )
                            uuid = ""
                            btestfindcomputer = False
                            # for testinventaireremonte in range(20):
                            if showinfobool:
                                logger.info(
                                    "Finding uuid from GLPI computer id for mac address"
                                )
                            (
                                btestfindcomputer,
                                idglpimachine,
                            ) = test_consolidation_inventory(
                                xmppobject,
                                sessionid,
                                data,
                                showinfobool,
                                msg,
                                machine["id"],
                            )
                            if showinfobool:
                                if btestfindcomputer:
                                    logger.info(
                                        "The consolidation of the inventory for the machine with the glpi id %s passed"
                                        % idglpimachine
                                    )
                                else:
                                    logger.info(
                                        "The consolidation of the inventory for the machine with the glpi id %s failed"
                                        % idglpimachine
                                    )

                            if not btestfindcomputer:
                                # pas trouver inventaire dans glpi
                                if showinfobool:
                                    logger.info(
                                        "No computer found in glpi for %s"
                                        % (data["from"])
                                    )
                                if showinfobool:
                                    logger.info(
                                        "** Calling inventory on %s" % msg["from"]
                                    )
                                callinventory(xmppobject, data["from"])
                                if showinfobool:
                                    logger.info(
                                        "Wait until the machine inventory [%s] "
                                        "is processed for registration....."
                                        % (data["from"])
                                    )
                            else:
                                if showinfobool:
                                    logger.info(
                                        "machine registerd [%s] " % (data["from"])
                                    )
                            return
                    else:
                        # il faut verifier si guacamole est initialisé.
                        # logger.debug("UUID is %s"%uuid_inventorymachine)
                        if showinfobool:
                            logger.info("Machine %s already exists" % data["from"])
                            logger.info("Verifying existence of jid %s" % msg["from"])

                        if XmppMasterDatabase().getPresencejid(msg["from"]):
                            if showinfobool:
                                logger.info("Correct jid: %s" % msg["from"])
                            return
                        else:
                            # The registration of the machine in database must
                            # be deleted, so it is updated.
                            if showinfobool:
                                logger.info(
                                    "jid %s does not exist in base cf domain change"
                                    % msg["from"]
                                )
                            XmppMasterDatabase().delPresenceMachinebyjiduser(
                                msg["from"].user
                            )
                            # on reenregistre la machine cas 2
            # ----------------------------------------------
            # Registering Machine non exist in table machine
            # ----------------------------------------------
            """ Check machine information from agent """
            if showinfobool:
                logger.info(
                    "** Machine %s reports offline in machines table" % data["from"]
                )
                logger.info(
                    "** Registering machine %s with information from agent."
                    % data["from"]
                )
            data["information"] = info
            if data["adorgbymachine"] is not None and data["adorgbymachine"] != "":
                try:
                    data["adorgbymachine"] = base64.b64decode(data["adorgbymachine"])
                except TypeError:
                    pass
            if data["adorgbyuser"] is not None and data["adorgbyuser"] != "":
                try:
                    data["adorgbyuser"] = base64.b64decode(data["adorgbyuser"])
                except TypeError:
                    pass
            if "keysyncthing" not in data:
                if "information" in data and "keysyncthing" in data["information"]:
                    data["keysyncthing"] = data["information"]["keysyncthing"]
                else:
                    data["keysyncthing"] = ""
            if data["agenttype"] == "relayserver" and "syncthing_port" not in data:
                data["syncthing_port"] = 23000
            publickeybase64 = info["publickey"]
            is_masterpublickey = info["is_masterpublickey"]
            del info["publickey"]
            del info["is_masterpublickey"]
            RSA = MsgsignedRSA("master")
            if not is_masterpublickey:
                # Send public key if the machine agent does not have one
                if showinfobool:
                    logger.info(
                        "** Machine %s key master public missing" % data["from"]
                    )
                    logger.info(
                        "** call install key public master on Machine %s" % data["from"]
                    )
                datasend = {
                    "action": "installkeymaster",
                    "keypublicbase64": RSA.loadkeypublictobase64(),
                    "ret": 0,
                    "sessionid": getRandomName(5, "publickeymaster"),
                }
                xmppobject.send_message(
                    mto=msg["from"], mbody=json.dumps(datasend), mtype="chat"
                )
            useradd, listedatageolocalisation = adduserdatageolocalisation(
                xmppobject, data, msg, sessionid, showinfobool
            )
            # if useradd == -1 or useradd == None:
            # return

            # Add relayserver or update status in database

            if data["agenttype"] == "relayserver":
                logger.info(
                    "** Adding relayserver or update status in database %s"
                    % msg["from"]
                )
                data["adorgbyuser"] = ""
                data["adorgbymachine"] = ""
                data["kiosk_presence"] = ""

                if "moderelayserver" in data:
                    moderelayserver = data["moderelayserver"]
                else:
                    moderelayserver = "static"
                XmppMasterDatabase().addServerRelay(
                    data["baseurlguacamole"],
                    data["subnetxmpp"],
                    data["information"]["info"]["hostname"],
                    data["deployment"],
                    data["xmppip"],
                    data["ipconnection"],
                    data["portconnection"],
                    data["portxmpp"],
                    data["xmppmask"],
                    data["from"],
                    listedatageolocalisation["longitude"],
                    listedatageolocalisation["latitude"],
                    True,
                    data["classutil"],
                    data["packageserver"]["public_ip"],
                    data["packageserver"]["port"],
                    moderelayserver=moderelayserver,
                    keysyncthing=data["keysyncthing"],
                    syncthing_port=data["syncthing_port"],
                )
                # Recover list of cluster ARS
                listrelayserver = (
                    XmppMasterDatabase().getRelayServerofclusterFromjidars(
                        str(data["from"])
                    )
                )
                cluster = {
                    "action": "cluster",
                    "sessionid": getRandomName(5, "cluster"),
                    "data": {"subaction": "initclusterlist", "data": listrelayserver},
                }

                # All relays server in the cluster are notified.
                for ARScluster in listrelayserver:
                    xmppobject.send_message(
                        mto=ARScluster, mbody=json.dumps(cluster), mtype="chat"
                    )
            if showinfobool:
                logger.info(
                    "** Adding or updating machine %s in database" % str(msg["from"])
                )
            # Add machine
            ippublic = None
            if "ippublic" in data:
                ippublic = data["ippublic"]
            if ippublic is None:
                ippublic = data["xmppip"]
            kiosk_presence = ""
            if "kiosk_presence" in data and data["kiosk_presence"] != "":
                kiosk_presence = data["kiosk_presence"]
            else:
                kiosk_presence = "False"
            if "lastusersession" not in data:
                data["lastusersession"] = ""
            if showinfobool:
                logger.info("=============")
                logger.info("=============")
                logger.info(
                    "Case 2 : The machine %s does not exist in database"
                    % str(msg["from"])
                )
                logger.info("Creating it and updating it's uuid_inventorymachine")
                logger.info("=============")
                logger.info("=============")
                logger.info("Adding or updating machine presence into machines table")
            for interface in data["information"]["listipinfo"]:
                if interface["macaddress"] == data["xmppmacaddress"]:
                    break
                else:
                    # adress mac exclut alert
                    if len(data["information"]["listipinfo"]):
                        data["xmppmacaddress"] = data["information"]["listipinfo"][0][
                            "macaddress"
                        ]
            if "uuid_serial_machine" not in data:
                if showinfobool:
                    logger.warning("uuid serial machine is missing")
                data["uuid_serial_machine"] = ""

            if showinfobool:
                logger.info("uuid serial machine : %s" % data["uuid_serial_machine"])
            idmachine, msgret = XmppMasterDatabase().addPresenceMachine(
                data["from"],
                data["platform"],
                data["information"]["info"]["hostname"],
                data["information"]["info"]["hardtype"],
                None,
                data["xmppip"],
                data["subnetxmpp"],
                data["xmppmacaddress"],
                data["agenttype"],
                classutil=data["classutil"],
                urlguacamole=data["baseurlguacamole"],
                groupdeploy=data["deployment"],
                objkeypublic=publickeybase64,
                ippublic=ippublic,
                ad_ou_user=data["adorgbyuser"],
                ad_ou_machine=data["adorgbymachine"],
                kiosk_presence=kiosk_presence,
                lastuser=data["lastusersession"],
                keysyncthing=data["keysyncthing"],
                uuid_serial_machine=data["uuid_serial_machine"],
            )

            if msgret.startswith("Update Machine"):
                if showinfobool:
                    logger.info("%s" % msgret)
                XmppMasterDatabase().setlogxmpp(
                    msgret,
                    "warn",
                    sessionid,
                    -1,
                    msg["from"],
                    "",
                    "",
                    "Registration | Notify",
                    "",
                    xmppobject.boundjid.bare,
                    xmppobject.boundjid.bare,
                )
            if idmachine != -1:
                if showinfobool:
                    logger.info(
                        "Calling callInstallConfGuacamole on %s"
                        " for %s machineid %s and ip %s Mach %s"
                        % (
                            data["deployment"],
                            data["information"]["info"]["hostname"],
                            idmachine,
                            data["xmppip"],
                            msg["from"],
                        )
                    )
                callInstallConfGuacamole(
                    xmppobject,
                    data["deployment"],
                    {
                        "hostname": data["information"]["info"]["hostname"],
                        "machine_ip": data["xmppip"],
                        "uuid": -1,
                        "machine_id": idmachine,
                        "remoteservice": data["remoteservice"],
                        "platform": data["platform"],
                        "os": data["information"]["info"]["os"],
                    },
                    showinfobool=showinfobool,
                )
                XmppMasterDatabase().setlogxmpp(
                    "configuration guacamole "
                    "for machine %s" % (data["information"]["info"]["hostname"]),
                    "warn",
                    sessionid,
                    -1,
                    msg["from"],
                    "",
                    "",
                    "Registration | Notify",
                    "",
                    xmppobject.boundjid.bare,
                    xmppobject.boundjid.bare,
                )
                if showinfobool:
                    logger.info("Machine %s added to machines table" % idmachine)

                if useradd != -1:
                    XmppMasterDatabase().hasmachineusers(useradd, idmachine)
                else:
                    logger.warning("** No user found for the machine %s" % msg["from"])
                    XmppMasterDatabase().setlogxmpp(
                        "Machine %s not registered. No user found" % msg["from"],
                        "info",
                        sessionid,
                        -1,
                        msg["from"],
                        "",
                        "",
                        "Registration | Notify | Error | Alert",
                        "",
                        xmppobject.boundjid.bare,
                        xmppobject.boundjid.bare,
                    )
                XmppMasterDatabase().delNetwork_for_machines_id(idmachine)
                for i in data["information"]["listipinfo"]:
                    # exclude mac address from table network
                    try:
                        broadcast = str(
                            netaddr.IPNetwork(
                                "%s/%s" % (i["ipaddress"], i["mask"])
                            ).broadcast
                        )
                    except Exception:
                        broadcast = ""
                    if showinfobool:
                        logger.info(
                            "** Adding interface %s in database for machine %s"
                            % (str(i["macaddress"]), msg["from"])
                        )
                        logger.info(
                            "Adding network card %s to the machine %s id #%s"
                            % (i["macaddress"], msg["from"], idmachine)
                        )
                    XmppMasterDatabase().addPresenceNetwork(
                        i["macaddress"],
                        i["ipaddress"],
                        broadcast,
                        i["gateway"],
                        i["mask"],
                        i["macnotshortened"],
                        idmachine,
                    )
                if data["agenttype"] != "relayserver":
                    uuid = ""
                    btestfindcomputer = False
                    jidrs = ""
                    # Si pulse inject inventory glpi: il faut 1 certain temps pour que celui-ci soit injecter.
                    # par substitute subinv
                    # plugin_resultinventory.py est charge de la mise a jour de
                    # uuid_inventory

                    # search consolidation
                    btestfindcomputer, machineglpiid = test_consolidation_inventory(
                        xmppobject, sessionid, data, showinfobool, msg, idmachine
                    )

                    if btestfindcomputer:
                        # il faut faire 1 appel pour l'inventaire
                        if "countstart" in data and data["countstart"] == 1:
                            if showinfobool:
                                logger.info("** Calling inventory on PXE machine")
                            callinventory(xmppobject, data["from"])
                            return
                        osmachine = Glpi().getComputersOS(str(machineglpiid))
                        if len(osmachine) != 0:
                            if (
                                "Unknown operating system (PXE"
                                in osmachine[0]["OSName"]
                            ):
                                if showinfobool:
                                    logger.info("** Calling inventory on PXE machine")
                                callinventory(xmppobject, data["from"])
                                return
                        else:
                            logger.warning(
                                "information about the operating system is missing for %s"
                                % (msg["from"].bare)
                            )
                        try:
                            xmppobject.listmodulemmc
                        except AttributeError:
                            xmppobject.listmodulemmc = []
                        if "kiosk" in xmppobject.listmodulemmc and kiosk_presence:
                            # send a data message to kiosk when an inventory is
                            # registered
                            handlerkioskpresence(
                                xmppobject,
                                data["from"],
                                idmachine,
                                data["platform"],
                                data["information"]["info"]["hostname"],
                                uuid,
                                data["agenttype"],
                                classutil=data["classutil"],
                                fromplugin=True,
                                showinfobool=showinfobool,
                            )

                        XmppMasterDatabase().setlogxmpp(
                            "Remote Service <b>%s</b>"
                            " : for [machine : %s][RS : %s]"
                            % (
                                data["remoteservice"],
                                data["information"]["info"]["hostname"],
                                jidrs,
                            ),
                            "Master",
                            "",
                            0,
                            data["from"],
                            "auto",
                            "",
                            "Remote_desktop | Guacamole | Service | Auto",
                            "",
                            xmppobject.boundjid.bare,
                            "Master",
                        )
                    else:
                        if showinfobool:
                            logger.info("** Calling inventory on %s" % msg["from"])
                        XmppMasterDatabase().setlogxmpp(
                            "Master ask inventory for registration",
                            "Master",
                            "",
                            0,
                            data["from"],
                            "auto",
                            "",
                            "QuickAction | Inventory | Inventory requested",
                            "",
                            xmppobject.boundjid.bare,
                            "Master",
                        )
                        callinventory(xmppobject, data["from"])
                        if showinfobool:
                            logger.info(
                                "Waiting for inventory from %s" % (data["from"])
                            )
            else:
                # error creation machine
                logger.error(
                    "** Creating or updating machine: Database registration error for machine %s"
                    % msg["from"]
                )
                XmppMasterDatabase().setlogxmpp(
                    "Database registration error for machine %s" % msg["from"],
                    "info",
                    sessionid,
                    -1,
                    msg["from"],
                    "",
                    "",
                    "Registration | Notify | Error | Alert",
                    "",
                    xmppobject.boundjid.bare,
                    xmppobject.boundjid.bare,
                )
                return

            logger.info("Machine %s registered" % msg["from"])
            XmppMasterDatabase().setlogxmpp(
                "Machine %s registered" % msg["from"],
                "info",
                sessionid,
                -1,
                msg["from"],
                "",
                "",
                "Registration | Notify",
                "",
                xmppobject.boundjid.bare,
                xmppobject.boundjid.bare,
            )

            pluginfunction = [
                str("plugin_%s" % x) for x in xmppobject.pluginlistunregistered
            ]

            if showinfobool:
                logger.info("Calling plugin action for machine %s ." % msg["from"])

            for function_plugin in pluginfunction:
                try:
                    if hasattr(xmppobject, function_plugin):
                        if showinfobool:
                            logger.info("Calling plugin %s" % function_plugin)
                        getattr(xmppobject, function_plugin)(msg, data)
                    else:
                        if showinfobool:
                            logger.warning(
                                "The %s plugin is not called" % function_plugin
                            )
                            logger.warning(
                                "Check why plugin %s"
                                " does not have function %s"
                                % (function_plugin, function_plugin)
                            )
                except Exception as e:
                    logger.error(
                        "Error on machine %s : %s\n%s"
                        % (msg["from"], str(e), traceback.format_exc())
                    )
                    XmppMasterDatabase().setlogxmpp(
                        "Error on machine %s : %s" % (msg["from"], str(e)),
                        "info",
                        sessionid,
                        -1,
                        msg["from"],
                        "",
                        "",
                        "Registration | Notify | Error | Alert",
                        "",
                        "",
                        xmppobject.boundjid.bare,
                    )
    except Exception as e:
        logger.error(
            "Error on machine %s : %s\n%s"
            % (msg["from"], str(e), traceback.format_exc())
        )
        XmppMasterDatabase().setlogxmpp(
            "Error on machine %s : %s" % (msg["from"], str(e)),
            "info",
            sessionid,
            -1,
            msg["from"],
            "",
            "",
            "Registration | Notify | Error | Alert",
            "",
            xmppobject.boundjid.bare,
            xmppobject.boundjid.bare,
        )


def test_mac_address_black_list(macaddress, table_reg_for_match, showinfobool=True):
    if showinfobool:
        logger.info("analyse blacklist Mac address %s" % macaddress)
    for regexpmatch in table_reg_for_match:
        if regexpmatch.match(macaddress.lower()):
            if showinfobool:
                logger.info("Blacklist Mac Address  %s" % macaddress)
            return True
    if showinfobool:
        logger.info("No Blacklist Mac Address  %s" % macaddress)
    return False


def getComputerByMac(mac, showinfobool=True):
    if showinfobool:
        logger.info(
            "Function getComputerByMac asking glpi for machine list for mac %s" % mac
        )
    ret = Glpi().getMachineByMacAddress("imaging_module", mac)
    if isinstance(ret, list):
        if len(ret) != 0:
            return ret[0]
        else:
            return None
    if showinfobool:
        logger.info("Function getComputerByMac Glpi returned : %s" % ret)
    return ret


def getMachineByUuidSetup(uuidsetupmachine, showinfobool=True):
    if uuidsetupmachine is None or uuidsetupmachine == "":
        logger.warning("Setup uuid machine missing in inventory xmpp")
        return {}
    machine_result = Glpi().getMachineByUuidSetup(uuidsetupmachine)
    if showinfobool:
        if machine_result:
            logger.debug("machine for setup uuid machine %s" % machine_result)
    return machine_result


def getMachineInformationByUuidSetup(uuidsetupmachine, showinfobool=True):
    if uuidsetupmachine is None or uuidsetupmachine == "":
        logger.warning("Setup uuid machine missing in inventory xmpp")
        return {}
    machine_result = Glpi().getMachineInformationByUuidSetup(uuidsetupmachine)
    if showinfobool:
        if machine_result:
            logger.debug("machine for setup uuid machine %s" % machine_result)
    return machine_result


def getMachineInformationByUuidMachine(idmachine, showinfobool=True):
    if idmachine is None or idmachine == "":
        logger.warning("uuid glpi machine missing")
        return {}
    machine_result = Glpi().getMachineInformationByUuidMachine(idmachine)
    if showinfobool:
        if machine_result:
            logger.debug("machine for uuid glpi %s" % machine_result)
    return machine_result


def callInstallConfGuacamole(xmppobject, torelayserver, data, showinfobool=True):
    if "remoteservice" in data and len(data["remoteservice"]) > 0:
        try:
            body = {
                "action": "guacamoleconf",
                "sessionid": getRandomName(5, "guacamoleconf"),
                "data": data,
            }
            if showinfobool:
                logger.info(
                    "Calling callInstallConfGuacamole on %s for %s"
                    % (torelayserver, data["hostname"])
                )
            xmppobject.send_message(
                mto=torelayserver, mbody=json.dumps(body), mtype="chat"
            )
        except Exception:
            logger.error("\n%s" % (traceback.format_exc()))
    else:
        if showinfobool:
            logger.info(
                "Setting guacamole parameters in base for machine id %s" % data["uuid"]
            )
        XmppMasterDatabase().addlistguacamoleidformachineid(data["machine_id"], {})


def callinventory(xmppobject, to):
    try:
        body = {
            "action": "inventory",
            "sessionid": getRandomName(5, "inventory"),
            "data": {"forced": "forced"},
        }
        xmppobject.send_message(mto=to, mbody=json.dumps(body), mtype="chat")
    except Exception:
        logger.error("\n%s" % (traceback.format_exc()))


def data_struct_message(action, data={}, ret=0, base64=False, sessionid=None):
    if sessionid is None or sessionid == "" or not isinstance(sessionid, str):
        sessionid = action.strip().replace(" ", "")
    return {
        "action": action,
        "data": data,
        "ret": 0,
        "base64": False,
        "sessionid": getRandomName(4, sessionid),
    }


def handlerkioskpresence(
    xmppobject,
    jid,
    id,
    os,
    hostname,
    uuid_inventorymachine,
    agenttype,
    classutil,
    fromplugin=False,
    showinfobool=True,
):
    """
    This function launch the kiosk actions when a prensence machine is active
    """
    if showinfobool:
        logger.info("kiosk handled")
    # print jid, id, os, hostname, uuid_inventorymachine, agenttype, classutil
    # get the profiles from the table machine.
    machine = XmppMasterDatabase().getMachinefromjid(jid)
    structuredatakiosk = get_packages_for_machine(machine, showinfobool=showinfobool)
    datas = {"subaction": "initialisation_kiosk", "data": structuredatakiosk}
    message_to_machine = data_struct_message(
        "kiosk",
        data=datas,
        ret=0,
        base64=False,
        sessionid=getRandomName(6, "initialisation_kiosk"),
    )
    xmppobject.send_message(mto=jid, mbody=json.dumps(message_to_machine), mtype="chat")
    return datas


def test_consolidation_inventory(
    xmppobject, sessionid, data, showinfobool, msg, idmachine
):
    btestfindcomputer = False
    machineglpiid = -1

    if "uuid_serial_machine" in data and data["uuid_serial_machine"]:
        data["uuid_serial_machine"] = data["uuid_serial_machine"].strip()
    else:
        data["uuid_serial_machine"] = ""

    if data["uuid_serial_machine"] != "":
        # cherche machine in glpi on uuid_setup
        if showinfobool:
            logger.info(
                "***** Finding uuid from GLPI computer id for uuis setup machine"
            )
    else:
        if showinfobool:
            logger.info("***** Finding uuid from GLPI computer id for mac address ")

    setupuuid = False
    if data["uuid_serial_machine"] != "":
        try:
            setupuuid = getMachineInformationByUuidSetup(
                data["uuid_serial_machine"], showinfobool
            )
        except Exception:
            logger.error("\n%s" % (traceback.format_exc()))
            setupuuid = {}

    if isinstance(setupuuid, dict) and "count" in setupuuid and setupuuid["count"] != 0:
        if showinfobool:
            logger.info("setupuuid %s" % setupuuid)
        # structure machine de glpi_computer table pour uuid setup .data['uuid_serial_machine']
        # on a 1 setup uuid on consolide xmpp et glpi sur uuid_serial_machine
        uuid = "UUID" + str(setupuuid["data"]["id"][0])
        if showinfobool:
            logger.info(
                "** Calling updateMachineidinventory uuid %s "
                "for machine %s setup uuid %s"
                % (uuid, msg["from"], data["uuid_serial_machine"])
            )
        XmppMasterDatabase().updateMachineGlpiInformationInventory(
            setupuuid, idmachine, data
        )
        btestfindcomputer = True
        machineglpiid = setupuuid["data"]["id"][0]
        if showinfobool:
            logger.info(
                "Machine %s : Finding computer id [%s] from GLPI,"
                " for UUID SETUP MACHINE %s"
                % (
                    setupuuid["data"]["name"][0],
                    setupuuid["data"]["id"][0],
                    data["uuid_serial_machine"],
                )
            )
    else:
        if showinfobool:
            logger.info(
                "Searching list of mac addresses for the machine %s "
                "id #%s for asigning uuid from glpi" % (msg["from"], idmachine)
            )
        result = XmppMasterDatabase().listMacAdressforMachine(
            idmachine, infomac=showinfobool
        )
        try:
            results = result[0].split(",")
        except Exception:
            logger.error(
                "Interface missing on machine %s id %s" % (msg["from"], idmachine)
            )
            logger.error("Check if its mac addresses are not blacklisted")
            macmachine = []
            for j in data["information"]["listipinfo"]:
                macmachine.append(j["macnotshortened"])
            logger.error(
                "List of interfaces on machine %s: %s" % (msg["from"], macmachine)
            )
            logger.error("Registration incomplete for machine %s" % msg["from"])
            XmppMasterDatabase().setlogxmpp(
                "Registration incomplete for machine %s" % msg["from"],
                "warn",
                sessionid,
                -1,
                msg["from"],
                "",
                "",
                "Registration | Notify | Error | Alert",
                "",
                xmppobject.boundjid.bare,
                xmppobject.boundjid.bare,
            )
            return False
        # cherche machine in glpi on macadress
        for t in results:
            if showinfobool:
                logger.info(
                    "Finding the machine which has the specified mac address : %s" % t
                )
            if showinfobool:
                logger.info(
                    "Finding uuid for mac address %s for machine %s" % (t, msg["from"])
                )
            computer = getComputerByMac(t, showinfobool=showinfobool)
            if computer is not None:
                computerid = str(computer.id)
                machineglpiid = computerid
                if showinfobool:
                    logger.info(
                        "UUID found in GLPI : UUID%s for %s on mac %s "
                        % (computer.id, msg["from"], t)
                    )
                jidrs = str(jid.JID(data["deployment"]).user)
                jidm = jid.JID(data["from"]).domain
                jidrs = "%s@%s" % (jidrs, jidm)
                uuid = "UUID" + str(computer.id)
                if showinfobool:
                    logger.info(
                        "** Calling updateMachineidinventory uuid %s for machine %s id %s"
                        % (uuid, msg["from"], idmachine)
                    )
                setupuuid = False
                try:
                    setupuuid = getMachineInformationByUuidMachine(
                        uuid, showinfobool=True
                    )
                except Exception:
                    setupuuid = {}

                if (
                    isinstance(setupuuid, dict)
                    and "count" in setupuuid
                    and setupuuid["count"] != 0
                ):
                    if showinfobool:
                        logger.info("setupuuid %s" % setupuuid)
                    # structure machine de glpi_computer table pour uuid setup .data['uuid_serial_machine']
                    # on a 1 setup uuid on consolide xmpp et glpi sur
                    # uuid_serial_machine
                    uuid = "UUID" + str(setupuuid["data"]["id"][0])
                    if showinfobool:
                        logger.info(
                            "** Calling updateMachineidinventory uuid %s "
                            "for machine %s setup uuid %s"
                            % (uuid, msg["from"], data["uuid_serial_machine"])
                        )
                    XmppMasterDatabase().updateMachineGlpiInformationInventory(
                        setupuuid, idmachine, data
                    )
                    btestfindcomputer = True
                    machineglpiid = setupuuid["data"]["id"][0]
                    if showinfobool:
                        logger.info(
                            "Machine %s : Finding computer id [%s] from GLPI,"
                            " for UUID SETUP MACHINE %s"
                            % (
                                setupuuid["data"]["name"][0],
                                setupuuid["data"]["id"][0],
                                data["uuid_serial_machine"],
                            )
                        )
                btestfindcomputer = True
                break
            else:
                if showinfobool:
                    logger.info(
                        "No computer found for mac address %s for machine %s"
                        % (t, msg["from"])
                    )
    return btestfindcomputer, machineglpiid


def get_packages_for_machine(machine, showinfobool=True):
    """
    Get a list of the packages for the concerned machine.
    Param:
        machine : tuple of the machine datas
    Returns:
        list of the packages
    """
    OUmachine = [
        machine["ad_ou_machine"].replace("\n", "").replace("\r", "").replace("@@", "/")
    ]
    OUuser = [
        machine["ad_ou_user"].replace("\n", "").replace("\r", "").replace("@@", "/")
    ]

    OU = list(set(OUmachine + OUuser))

    # search packages for the applied profiles
    list_profile_packages = KioskDatabase().get_profile_list_for_OUList(OU)
    if list_profile_packages is None:
        # TODO
        # linux and mac os does not have an Organization Unit.
        # For mac os and linux, profile association will be done on the login
        # name.
        return
    list_software_glpi = []
    softwareonmachine = Glpi().getLastMachineInventoryPart(
        machine["uuid_inventorymachine"],
        "Softwares",
        0,
        -1,
        "",
        {"hide_win_updates": True, "history_delta": ""},
    )
    for x in softwareonmachine:
        list_software_glpi.append([x[0][1], x[1][1], x[2][1]])
    # print list_software_glpi  # ordre information
    # [["Vendor","Name","Version"],]
    structuredatakiosk = []

    # Create structuredatakiosk for initialization
    for packageprofile in list_profile_packages:
        structuredatakiosk.append(
            __search_software_in_glpi(
                list_software_glpi, packageprofile, structuredatakiosk
            )
        )
    if showinfobool:
        logger.info("* Initializing kiosk on machine %s" % (machine["hostname"]))
    return structuredatakiosk


def __search_software_in_glpi(list_software_glpi, packageprofile, structuredatakiosk):
    structuredatakioskelement = {
        "name": packageprofile[0],
        "action": [],
        "uuid": packageprofile[6],
        "description": packageprofile[2],
        "version": packageprofile[3],
    }
    patternname = re.compile("(?i)" + packageprofile[0])
    for soft_glpi in list_software_glpi:
        # TODO
        # Into the pulse package provide Vendor information for the software name
        # For now we use the package name which must match with glpi name
        if patternname.match(str(soft_glpi[0])) or patternname.match(str(soft_glpi[1])):
            # Process with this package which is installed on the machine
            # The package could be deleted
            structuredatakioskelement["icon"] = "kiosk.png"
            structuredatakioskelement["action"].append("Delete")
            structuredatakioskelement["action"].append("Launch")
            # verification if update
            # compare the version
            # TODO
            # For now we use the package version.
            # Later the software version will be needed into the pulse package
            if LooseVersion(soft_glpi[2]) < LooseVersion(packageprofile[3]):
                structuredatakioskelement["action"].append("Update")
                logger.debug(
                    "The software version is superior "
                    "to that installed on the machine %s : %s < %s"
                    % (packageprofile[0], soft_glpi[2], LooseVersion(packageprofile[3]))
                )
            break
    if len(structuredatakioskelement["action"]) == 0:
        # The package defined for this profile is absent from the machine:
        if packageprofile[8] == "allowed":
            structuredatakioskelement["action"].append("Install")
        else:
            structuredatakioskelement["action"].append("Ask")
    return structuredatakioskelement


def adduserdatageolocalisation(xmppobject, data, msg, sessionid, showinfobool):
    try:
        tabinformation = {
            "longitude": "unknown",
            "latitude": "unknown",
            "city": "unknown",
            "region_name": "unknown",
            "time_zone": "unknown",
            "zip_code": "unknown",
            "country_iso": "",
            "country": "unknown",
        }
        # Assignment of the user system, if user absent.
        if "users" in data["information"] and len(data["information"]["users"]) == 0:
            data["information"]["users"] = ["system"]

        if "users" in data["information"] and len(data["information"]["users"]) > 0:
            userinfo = ",".join(data["information"]["users"])
            if showinfobool:
                logger.info(
                    "Adding user : %s for machine : %s "
                    % (userinfo, data["information"]["info"]["hostname"])
                )
        if (
            "geolocalisation" in data
            and data["geolocalisation"] is not None
            and len(data["geolocalisation"]) > 0
        ):
            # initialization parameter geolocalisation
            for geovariable in tabinformation:
                try:
                    tabinformation[geovariable] = str(
                        data["geolocalisation"][geovariable]
                    )
                except Exception:
                    pass
            if showinfobool:
                logger.info("parameter geolocalisation : %s" % tabinformation)
        try:
            useradd = XmppMasterDatabase().adduser(
                userinfo,
                data["information"]["info"]["hostname"],
                tabinformation["city"],
                tabinformation["region_name"],
                tabinformation["time_zone"],
                tabinformation["longitude"],
                tabinformation["latitude"],
                tabinformation["zip_code"],
                tabinformation["country_iso"],
                tabinformation["country"],
            )
            try:
                useradd = useradd[0]
            except TypeError:
                pass
            return useradd, tabinformation
        except Exception:
            logger.error("\n%s" % (traceback.format_exc()))
            logger.error(
                "** Impossible to register machine %s. User missing" % msg["from"]
            )
            XmppMasterDatabase().setlogxmpp(
                "Machine %s not registered. No user found" % msg["from"],
                "info",
                sessionid,
                -1,
                msg["from"],
                "",
                "",
                "Registration | Notify | Error | Alert",
                "",
                xmppobject.boundjid.bare,
                xmppobject.boundjid.bare,
            )
            return -1, tabinformation
    except Exception:
        logger.error("\n%s" % (traceback.format_exc()))
        return -1, {}


def read_conf_remote_registeryagent(xmppobject):
    logger.debug("Initializing plugin :% s " % plugin["NAME"])
    namefichierconf = plugin["NAME"] + ".ini"
    pathfileconf = os.path.join(xmppobject.config.pathdirconffile, namefichierconf)
    if not os.path.isfile(pathfileconf):
        logger.error(
            "Plugin %s\nConfiguration file :"
            "\n\t%s missing"
            "\neg conf:\n[parameters]\n"
            "pluginlistregistered = loadpluginlistversion, loadpluginschedulerlistversion,"
            "loadautoupdate, loadshowregistration\n"
            "pluginlistunregistered = loadpluginlistversion, loadpluginschedulerlistversion,"
            "loadautoupdate, loadshowregistration" % (plugin["NAME"], pathfileconf)
        )
        logger.warning(
            "Default value for pluginlistregistered "
            "is loadpluginlistversion, loadpluginschedulerlistversion, loadautoupdate, loadshowregistration"
            "\ndefault value for pluginlistunregistered"
            "is loadpluginlistversion, loadpluginschedulerlistversion, loadautoupdate, loadshowregistration"
        )
        xmppobject.pluginlistregistered = [
            "loadpluginlistversion",
            "loadpluginschedulerlistversion",
            "loadautoupdate",
            "loadshowregistration",
        ]
        xmppobject.pluginlistunregistered = [
            "loadpluginlistversion",
            "loadpluginschedulerlistversion",
            "loadautoupdate",
            "loadshowregistration",
        ]
        xmppobject.check_uuidinventory = False
        xmppobject.blacklisted_mac_addresses = ["00\\:00\\:00\\:00\\:00\\:00"]
        xmppobject.registeryagent_showinfomachine = []
        xmppobject.use_uuid = True
    else:
        Config = configparser.ConfigParser()
        Config.read(pathfileconf)
        logger.debug("Config file %s for plugin %s" % (pathfileconf, plugin["NAME"]))
        if os.path.exists(pathfileconf + ".local"):
            Config.read(pathfileconf + ".local")
            logger.debug("read file %s.local" % pathfileconf)

        if Config.has_option("parameters", "check_uuidinventory"):
            xmppobject.check_uuidinventory = Config.getboolean(
                "parameters", "check_uuidinventory"
            )
        else:
            xmppobject.check_uuidinventory = False

        if Config.has_option("parameters", "use_uuid"):
            xmppobject.use_uuid = Config.getboolean("parameters", "use_uuid")
        else:
            xmppobject.use_uuid = True

        if Config.has_option("parameters", "pluginlistregistered"):
            pluginlistregistered = Config.get("parameters", "pluginlistregistered")
        else:
            pluginlistregistered = (
                "loadpluginlistversion, loadpluginschedulerlistversion,"
                " loadautoupdate, loadshowregistration"
            )
        xmppobject.pluginlistregistered = [
            x.strip() for x in pluginlistregistered.split(",")
        ]

        if Config.has_option("parameters", "pluginlistunregistered"):
            pluginlistunregistered = Config.get("parameters", "pluginlistunregistered")
        else:
            pluginlistunregistered = (
                "loadpluginlistversion, loadpluginschedulerlistversion,"
                "loadautoupdate, loadshowregistration"
            )

        xmppobject.pluginlistunregistered = [
            x.strip() for x in pluginlistunregistered.split(",")
        ]

        xmppobject.blacklisted_mac_addresses = []
        if Config.has_option("parameters", "blacklisted_mac_addresses"):
            blacklisted_mac_addresses = Config.get(
                "parameters", "blacklisted_mac_addresses"
            )
        else:
            blacklisted_mac_addresses = "00\\:00\\:00\\:00\\:00\\:00"

        blacklisted_mac_addresseslist = [
            x.strip() for x in blacklisted_mac_addresses.split(",")
        ]
        # Unique regexp identique
        blacklisted_mac_addresseslist = list(set(blacklisted_mac_addresseslist))

        for regexpconf in blacklisted_mac_addresseslist:
            try:
                logger.info("BUILD REGEXP FOR BLACKLIST MAC ADDRESS -> %s" % regexpconf)
                xmppobject.blacklisted_mac_addresses.append(re.compile(regexpconf))
            except Exception:
                logger.error(
                    "COMPIL REGEXP BLACKLIST MAC ADDRESS -> %s <- [IGNORE THIS REGEXP]"
                    % regexpconf
                )

        if Config.has_section("parameters"):
            if Config.has_option("parameters", "showinfomachine"):
                paramshowinfomachine = Config.get("parameters", "showinfomachine")
                xmppobject.registeryagent_showinfomachine = [
                    str(x.strip())
                    for x in paramshowinfomachine.split(",")
                    if x.strip() != ""
                ]
            else:
                # Default configuration
                xmppobject.registeryagent_showinfomachine = []
                logger.warning("showinfomachine default value is []")

    logger.debug("Plugin list registered is %s" % xmppobject.pluginlistregistered)
    logger.debug("Plugin list unregistered is %s" % xmppobject.pluginlistunregistered)
