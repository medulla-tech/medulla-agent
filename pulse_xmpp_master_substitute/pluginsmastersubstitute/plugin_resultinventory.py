#!/usr/bin/python3
# -*- coding: utf-8; -*-
# SPDX-FileCopyrightText: 2016-2023 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-3.0-or-later

import sys
import os
import gzip
import zlib
import base64
import traceback
import urllib.request
import urllib.error
import time
import json
from lib.plugins.xmpp import XmppMasterDatabase
from lib.plugins.glpi import Glpi
from lib.utils import convert
import re
import inspect
import requests
import shutil
from urllib.parse import urlparse
from datetime import datetime
from requests.packages.urllib3.exceptions import InsecureRequestWarning
import logging
from logging.handlers import RotatingFileHandler
import importlib.util


logger = logging.getLogger()
plugin = {"VERSION": "1.14", "NAME": "resultinventory", "TYPE": "substitute"}  # fmt: skip


class InventoryFix:
    def __init__(
        self, xmlfixplugindir, inventory_xml, xmldumpactive=False, verbose=False
    ):
        self._inventory_content = inventory_xml
        if isinstance(self._inventory_content, bytes):
            self._inventory_content = self._inventory_content.decode("utf-8")
        logger.debug("Initialize the inventory fixer")

        self.xmldumpactive = xmldumpactive
        self.xmlfixplugindir = os.path.abspath(xmlfixplugindir)
        self.xmldumpdir = os.path.join(self.xmlfixplugindir, "xmldumpdir")
        self.verbose = verbose
        if not os.path.exists(self.xmlfixplugindir):
            os.makedirs(self.xmlfixplugindir)
        if not os.path.exists(self.xmldumpdir):
            os.makedirs(self.xmldumpdir)
        self.fixers = []
        self.namefix = []
        self._check_in()
        self._update()

    def _check_in(self):
        """
        Find and pre-check all .py from xmlfixplugindir.
        Checked module must have a calable function named 'xml_fix'.
        """
        for path, dirs, files in os.walk(self.xmlfixplugindir):
            for filename in sorted(files):
                pathname = os.path.join(path, filename)
                if re.match("^.*\\.py$", pathname):
                    mod_name = filename
                    py_mod = fnc = None
                    try:
                        spec = importlib.util.spec_from_file_location(
                            mod_name, pathname
                        )
                        py_mod = importlib.util.module_from_spec(spec)
                        spec.loader.exec_module(py_mod)
                    except ImportError:
                        logger.warning("Cannot load fixing script '%s'" % filename)
                        continue
                    except Exception as e:
                        logger.warning("Unable to run %s script: %s" % (filename, e))
                        continue
                    if hasattr(py_mod, "xml_fix"):
                        fnc = getattr(py_mod, "xml_fix")
                        if hasattr(fnc, "__call__"):
                            self.fixers.append(fnc)
                            self.namefix.append(pathname)
                        else:
                            logger.warn(
                                "module %s : attribute xml_fix is not a function or method"
                                % filename
                            )
                    else:
                        logger.warning(
                            "Unable to run %s script: missing xml_fix() function"
                            % filename
                        )

    def _update(self):
        """Aply the script on inventory"""
        # Logging pre-modified xml to temp file

        if self.xmldumpactive:
            dumpdir = self.xmldumpdir
            timestamp = str(int(time.time()))
            f = open(dumpdir + "/inventorylog-pre-" + timestamp + ".xml", "w")
            f.write(convert.convert_bytes_datetime_to_string(self._inventory_content))
            f.close()

        for index, fnc in enumerate(self.fixers):
            try:
                if self.verbose:
                    logger.debug("Exec fix plugin %s %s" % (index, fnc.__module__))
                if isinstance(self._inventory_content, bytes):
                    self._inventory_content = self._inventory_content.decode("utf-8")
                self._inventory_content = fnc(self._inventory_content)
                logger.debug("Inventory fixed by '%s' script" % fnc.__module__)
            except BaseException:
                info = sys.exc_info()
                for fname, linenumber, fnc_name, text in traceback.extract_tb(info[2]):
                    args = (fname, linenumber, fnc_name)
                    logger.error("module: %s line: %d in function: %s" % args)
                    logger.error("Failed on: %s" % text)

        # Logging the post modified xml file
        if self.xmldumpactive:
            dumpdir = self.xmldumpdir
            f = open(dumpdir + "/inventorylog-post-" + timestamp + ".xml", "w")
            f.write(convert.convert_bytes_datetime_to_string(self._inventory_content))
            f.close()

    def get(self):
        """get the fixed inventory"""
        return self._inventory_content


def send_content(
    url, content, verbose=False, user_agent="siveo-injector", inventory_plugin_name=""
):
    """
    send inventaire to plugin fusion inventory

    """
    # Check if the glpi plugin is enabled
    if inventory_plugin_name != "":
        check_plugin = Glpi().get_plugin_inventory_state(inventory_plugin_name)
        plugin_in_result = True if inventory_plugin_name in check_plugin else False

        # If the plugin is missing or disabled
        if (
            plugin_in_result is False
            or plugin_in_result is True
            and check_plugin[inventory_plugin_name]["state"] == "disabled"
        ):
            logger.warning(
                "The plugin %s is disabled or not installed, the inventory will be sent but not saved"
                % inventory_plugin_name
            )

    headers = {
        "User-Agent": user_agent,
        "Pragma": "no-cache",
        "Content-Type": "Application/x-gzip",
    }
    if verbose:
        logger.info("Send content to url : %s" % url)

    compressed_content = convert.convert_to_bytes(content)
    Content_Type = ["Application/x-compress"]
    try:
        compressed_content = gzip.compress(
            convert.convert_to_bytes(content), compresslevel=9
        )
        Content_Type = ["Application/x-gzip"]
    except:
        logger.error("erreur compression de content")
        compressed_content = convert.convert_to_bytes(content)
    reponsequery = ""
    reponsecode = 400
    for mine in Content_Type:
        headers["Content-Type"] = mine
        if verbose:
            logger.info("headers is : %s" % headers)
        response = requests.post(url, headers=headers, data=compressed_content)
        reponsecode = response.status_code
        try:
            reponsequery = gzip.decompress(response.content)
        except:
            reponsequery = response.content

        if response.status_code == 200:
            if verbose:
                logger.info("OK")
                logger.info(response.headers["Content-Type"])
                logger.info(reponsequery)
        else:
            logger.error(response.status_code)
            logger.error(reponsequery)
    return reponsecode, reponsequery


def action(xmppobject, action, sessionid, data, msg, ret, dataobj):
    if "inventory" not in data:
        payload_keys = sorted(data.keys()) if isinstance(data, dict) else []
        error_detail = ""
        if isinstance(data, dict):
            error_detail = data.get("msg") or data.get("error_detail") or ""
            if not error_detail and "error" in data:
                try:
                    error_detail = json.dumps(data.get("error"))
                except Exception:
                    error_detail = str(data.get("error"))

        error_msg = "inventory on machine %s (missing key 'inventory') keys=%s" % (
            msg["from"],
            payload_keys,
        )
        if error_detail:
            error_msg = "%s : %s" % (error_msg, error_detail)
        logger.error(error_msg)
        return
    try:
        logger.debug("=====================================================")
        logger.debug("call %s from %s" % (plugin, msg["from"]))
        logger.debug("=====================================================")
        logger.info(
            "Received inventory from %s in inventory substitute agent" % (msg["from"])
        )
        content = convert.convert_bytes_datetime_to_string(
            zlib.decompress(base64.b64decode(data["inventory"]))
        )
        if xmppobject.config.inventory_enable_forward:
            list_url_to_forward = [
                x.strip() for x in xmppobject.config.url_to_forward.split(",")
            ]
            QUERY = "FAILS"
            DEVICEID = ""
            try:
                QUERY = re.search(r"<QUERY>([\w-]+)</QUERY>", content).group(1)
            except AttributeError as e:
                logger.warn("Could not get any QUERY section in inventory")
                QUERY = "FAILS"
            try:
                DEVICEID = re.search(r"<DEVICEID>([\w-]+)</DEVICEID>", content).group(1)
            except AttributeError as e:
                logger.warn("Could not get any DEVICEID section in inventory")
                DEVICEID = ""
            if xmppobject.config.inventory_verbose:
                logger.info(
                    "################################################################"
                )
                logger.info(
                    "####################### DETAIL INVENTORY #######################"
                )
                logger.info(
                    "################################################################"
                )
                logger.info("inventory QUERY %s : " % QUERY)
                logger.info("inventory DEVICEID %s : " % DEVICEID)
                logger.info(
                    "################################################################"
                )
                logger.info("%s\n...\n...\n%s" % (content[:150], content[-150:]))
                logger.info(
                    "######################## INVENTORY FIX #########################"
                )
                logger.info(
                    "Execution des fonctions 'def xml_fix(contenu_xml_inventory)' in tout les fichiers .py du repertoire : %s "
                    % xmppobject.config.xmlfixplugindir
                )
                logger.info(
                    "les fonctions xml_fix(contenu_xml_inventory) de chaque fichiers doivent renvoyés 1 xml conforme en string"
                )
                logger.info(
                    "################################################################"
                )
            # on modifie le xml suivant les fix pluging contenu dans xmppobject.config.xmlfixplugindir
            invfix = InventoryFix(
                xmppobject.config.xmlfixplugindir,
                content,
                xmldumpactive=xmppobject.config.xmldumpactive,
                verbose=xmppobject.config.inventory_verbose,
            )
            content = invfix.get()
            if xmppobject.config.inventory_verbose:
                logger.info(
                    "################################################################"
                )
                logger.info(content[:150])
                # fix contenue xml pour qu'il soit conforme OCS comme fusioninventory
                logger.info(
                    "################################################################"
                )
            for url in list_url_to_forward:
                codeerror, reponse = send_content(
                    url,
                    content,
                    verbose=xmppobject.config.inventory_verbose,
                    user_agent=xmppobject.config.user_agent,
                    inventory_plugin_name=xmppobject.config.inventory_plugin,
                )
        inventory = content
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

       # message de warning si aucune machine n'est trouvée

def XmppUpdateInventoried(jid, machine):
    """
    Synchronise et corrige l'identifiant d'inventaire (UUID) d'une machine XMPP
    avec les données présentes dans GLPI.

    Cette fonction tente d'identifier la machine dans GLPI selon deux méthodes :

    1. Par UUID de setup (prioritaire)
       - Si `uuid_serial_machine` est présent, recherche la machine correspondante dans GLPI.
       - Si trouvé :
           - Vérifie si l'UUID actuel est déjà correct.
           - Sinon, met à jour l'UUID dans la base XMPP.
           - Met également à jour les références associées (Organization_ad.id_inventory).

    2. Par adresse(s) MAC (fallback)
       - Récupère les adresses MAC associées à la machine XMPP.
       - Normalise les formats (aa:bb:cc:dd:ee:ff).
       - Recherche une machine correspondante dans GLPI pour chaque MAC.
       - Si trouvé :
           - Met à jour l'UUID dans la base XMPP.
           - Met à jour les références associées.

    Cas d'échec :
       - Aucun UUID valide ou aucune correspondance MAC trouvée.
       - Données d'inventaire manquantes ou incohérentes.
       - Machine non encore inventoriée dans GLPI.

    Args:
        jid (str): Identifiant XMPP de la machine.
        machine (dict): Dictionnaire contenant les informations de la machine,
                        incluant notamment :
                        - id (int): ID interne XMPP
                        - uuid_serial_machine (str, optionnel)
                        - uuid_inventorymachine (str, optionnel)
                        - jid (str)

    Returns:
        int: ID GLPI de la machine si trouvée et synchronisée.
        -1 : En cas d'erreur ou si aucune correspondance n'est trouvée.

    Logs:
        - DEBUG : étapes détaillées de recherche et normalisation
        - WARNING : données manquantes ou non correspondance
        - ERROR : erreurs critiques (base de données, exceptions)

    Notes:
        - La recherche par UUID est prioritaire sur la recherche par MAC.
        - Les adresses MAC invalides sont ignorées.
        - La fonction modifie directement la base XMPP via XmppMasterDatabase().
    """

    # Search by UUID setup
    if machine.get("uuid_serial_machine"):
        logger.debug(f"Searching machine by UUID setup: {machine['uuid_serial_machine']}")
        setupuuid = getMachineByUuidSetup(machine["uuid_serial_machine"])
        if setupuuid:
            uuid = f"UUID{setupuuid['id']}"
            if machine.get("uuid_inventorymachine") == uuid:
                logger.debug(f"UUID already correct: {uuid}")
                return setupuuid["id"]

            logger.debug("Updating UUID in XMPP database")
            try:
                XmppMasterDatabase().updateMachineidinventory(uuid, machine["id"])
                if machine.get("uuid_inventorymachine"):
                    ret = XmppMasterDatabase().replace_Organization_ad_id_inventory(
                        machine["uuid_inventorymachine"], uuid
                    )
                    if ret == -1:
                        logger.error("Failed to update Organization_ad.id_inventory")
                        return -1
                return setupuuid["id"]
            except Exception as e:
                logger.error(f"Error updating UUID: {str(e)}")
                return -1

    # Search by MAC addresses
    try:
        result = XmppMasterDatabase().listMacAdressforMachine(machine["id"])
        if not result or not result[0] or not result[0].strip():
            logger.warning(f"No MAC addresses found for machine ID: {machine['id']}")
            return -1

        results = result[0].split(",")
        logger.debug(f"MAC addresses to process: {results}")

        for mac in results:
            logger.debug(f"Processing raw MAC: {mac}")

            # Normalize MAC address
            mac = mac.strip().lower().replace("-", ":").replace("_", ":").replace(" ", "")
            if len(mac) == 12 and ":" not in mac:
                mac = ":".join([mac[i:i+2] for i in range(0, 12, 2)])

            if len(mac) != 17 or mac.count(":") != 5:
                logger.warning(f"Invalid MAC format: {mac}")
                continue

            logger.debug(f"Querying machine by normalized MAC: {mac}")
            computer = getComputerByMac(mac)
            if not computer:
                logger.warning(f"No machine found for MAC: {mac}")
                continue

            uuid = f"UUID{computer.id}"
            if machine.get("uuid_inventorymachine") == uuid:
                logger.debug(f"UUID already correct: {uuid}")
                return computer.id

            try:
                if machine.get("uuid_inventorymachine"):
                    ret = XmppMasterDatabase().replace_Organization_ad_id_inventory(
                        machine["uuid_inventorymachine"], uuid
                    )
                    if ret == -1:
                        logger.error("Failed to update Organization_ad.id_inventory")
                        return -1

                XmppMasterDatabase().updateMachineidinventory(uuid, machine["id"])
                logger.debug(f"Successfully updated machine UUID to: {uuid}")
                return computer.id

            except Exception as e:
                logger.error(f"Error during UUID update: {str(e)}")
                return -1

        logger.warning(
            f"No machine found with the provided MAC addresses for machine {machine['jid']}. "
            "Possible reasons: "
            "1. The inventory may not have been injected or processed yet in GLPI. "
            "2. The machine may not be registered in GLPI. "
            "3. The MAC address may be excluded (blacklisted) or not associated with this machine."
        )

    except KeyError as e:
        logger.error(
            f"KeyError for machine {machine}: missing inventory data. "
            f"Check if FusionInventory is running correctly. Error: {str(e)}"
        )
    except Exception as e:
        logger.error(
            f"Unexpected error for inventory {jid}: {str(e)}\n"
            f"Traceback: {traceback.format_exc()}"
        )

    logger.warning(f"No valid UUID or MAC address found for machine: {jid}")
    return -1
