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
import logging
from lib.plugins.xmpp import XmppMasterDatabase
from lib.plugins.glpi import Glpi
from lib.utils import convert
import re
import inspect
import requests
import gzip
import shutil
from urllib.parse import urlparse
from datetime import datetime
from requests.packages.urllib3.exceptions import InsecureRequestWarning
import zlib
import logging
from logging.handlers import RotatingFileHandler
import importlib.util


from urllib.parse import urlparse
from datetime import datetime

logger = logging.getLogger()
plugin = {"VERSION": "1.12", "NAME": "resultinventory", "TYPE": "substitute"}  # fmt: skip


class InventoryFix:
    def __init__(
        self, xmlfixplugindir, inventory_xml, xmldumpactive=False, verbose=False
    ):
        self._inventory_content = inventory_xml
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
                        # py_mod = imp.load_source(mod_name, pathname)
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
            # for fnc in self.fixers:
            try:
                if self.verbose:
                    logger.debug("Exec fix plugin %s %s" % (index, fnc.__module__))
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


def send_content(url, content, verbose=False, user_agent="siveo-injector"):
    """
    send inventaire to plugin fusion inventory

    """
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
        reponsequery = gzip.decompress(response.content)

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
