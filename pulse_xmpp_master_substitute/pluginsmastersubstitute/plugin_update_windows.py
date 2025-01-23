# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2016-2023 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-3.0-or-later

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

plugin = {"VERSION": "2.0", "NAME": "update_windows", "TYPE": "substitute"}  # fmt: skip

# function comment for next feature
# this functions will be used later
# def function_dynamique_declaration_plugin(xmppobject):
# xmppobject.changestatusin_plugin = types.MethodType(changestatusin_plugin, xmppobject)


def action(xmppobject, action, sessionid, data, msg, ret, dataobj):
    """
    This function processes the action.

    Args:
        xmppobject (object): The XMPP object used in the function.
        action (str): The action to be performed.
        sessionid (str): Session ID.
        data (dict): Data to be processed.
        msg (object): Message object.
        ret (str): Return value.
        dataobj (object): Data object.

    """

    try:
        logger.debug("=====================================================")
        logger.debug("call %s from %s" % (plugin, msg["from"]))
        logger.debug("=====================================================")

        compteurcallplugin = getattr(xmppobject, "num_call%s" % action)
        if compteurcallplugin == 0:
            try:
                xmppobject.registeryagent_showinfomachine
            except:
                xmppobject.registeryagent_showinfomachine = []
            read_conf_remote_update_windows(xmppobject)
            logger.debug(
                "Including debug information for list jid %s"
                % (xmppobject.registeryagent_showinfomachine)
            )

            xmppobject.list_produits = []
            xmppobject.list_produits = XmppMasterDatabase().list_produits()

        showinfobool = True
        traitement_update(xmppobject, action, sessionid, data, msg, ret)

    except Exception:
        logger.error("\n%s" % (traceback.format_exc()))


def exclude_update_in_select(msg, exclude_update, list_update):
    """
    Exclude updates from selection.

    Args:
        msg (object): Message object.
        exclude_update (dict): Excluded updates.
        list_update (list): List of updates.

    Returns:
        list: Excluded updates.

    """
    res = []
    for upd in list_update:
        if (
            upd["kb"] in exclude_update["kb"]
            or upd["updateid"] in exclude_update["update_id"]
        ):
            # exclution suivant les regles definie
            continue
        else:
            logger.debug(
                "Adding update %s, %s, %s, %s %s"
                % (
                    msg["from"],
                    upd["kb"],
                    upd["updateid"],
                    upd["title"],
                    upd["msrcseverity"],
                )
            )
            res.append(
                {
                    "kb": upd["kb"],
                    "updateid": upd["updateid"],
                    "title": upd["title"],
                    "tableproduct": upd["tableproduct"],
                    "msrcseverity": upd["msrcseverity"],
                }
            )
    return res


def traitement_update(xmppobject, action, sessionid, data, msg, ret):
    logger.debug("PROCESSING UPDATES FOR %s " % msg["from"])
    logger.debug(json.dumps(data, indent=4))
    logger.debug(
        "Enabled products (xmppobject.list_produits):  %s" % xmppobject.list_produits
    )
    # suivant type de windows exclude list produit

    list_table_product_select = list_products_on(
        xmppobject, data, xmppobject.list_produits
    )
    logger.debug(
        "For machine %s only the following tables will be updated:  %s"
        % (msg["from"], list_table_product_select)
    )
    machine = XmppMasterDatabase().getId_UuidFromJid(msg["from"])
    if not machine:
        logger.warning("Machine %s is not yet registered" % msg["from"])
        return

    if not xmppobject.exclude_history_list:
        logger.debug("Checking against KB history list")
        kblistexclde = []
        history_list_kb = XmppMasterDatabase().history_list_kb(
            data["system_info"]["history_package_uuid"]
        )
        if history_list_kb:
            kblistexclde.extend(history_list_kb)
        kb_installed = [
            x["HotFixID"].replace("KB", "") for x in data["system_info"]["kb_installed"]
        ]
        kblistexclde.extend(kb_installed)
        lkbe = '"%s"' % ",".join(kblistexclde)
        data["system_info"]["kb_list"] = lkbe
    logger.debug("Installed KB list: %s" % data["system_info"]["kb_list"])
    list_update = exclude_update = res_update = []
    exclude_update = XmppMasterDatabase().test_black_list(msg["from"])
    logger.debug("Excluding updates for %s: %s" % (msg["from"], exclude_update))
    for t in list_table_product_select:
        if t == "up_packages_Win_Malicious_X64":
            # le traitement de cette mise a jour est dependante de la version renvoyee par la machine du logiciel.
            # le kb n'est pas modifiee.
            continue
        list_update = []
        logger.debug(
            "Looking for product %s (%s)"
            % (t["name_procedure"], data["system_info"]["kb_list"])
        )

        list_update = XmppMasterDatabase().search_update_by_products(
            tableproduct=t, str_kb_list=data["system_info"]["kb_list"]
        )
        logger.debug("list_update search is %s: " % list_update)
        res_update.extend(exclude_update_in_select(msg, exclude_update, list_update))
    # autre methode attribution des update
    # list_update = XmppMasterDatabase().search_kb_windows1( "", product=data['system_info']['platform_info']['type'],
    # version =data['system_info']['infobuild']['DisplayVersion'],
    # sevrity="Critical",
    # archi=data['system_info']['platform_info']['machine'],
    # kb_list=lkbe)
    # res_update.extend(exclude_update_in_select( msg, exclude_update, list_update ))

    if "up_packages_Win_Malicious_X64" in list_table_product_select:
        if (
            "malicious_software_removal_tool" in data["system_info"]
            and "FileMajorPart"
            in data["system_info"]["malicious_software_removal_tool"]
            and "FileMinorPart"
            in data["system_info"]["malicious_software_removal_tool"]
            and data["system_info"]["malicious_software_removal_tool"]["FileMajorPart"]
            != ""
            and data["system_info"]["malicious_software_removal_tool"]["FileMinorPart"]
            != ""
        ):
            list_update = []
            # search malicious_software_removal_tool
            list_update = (
                XmppMasterDatabase().search_update_windows_malicious_software_tool(
                    data["system_info"]["platform_info"]["type"],
                    data["system_info"]["platform_info"]["machine"],
                    data["system_info"]["malicious_software_removal_tool"][
                        "FileMajorPart"
                    ],
                    data["system_info"]["malicious_software_removal_tool"][
                        "FileMinorPart"
                    ],
                )
            )
            res_update.extend(
                exclude_update_in_select(msg, exclude_update, list_update)
            )

    # update les updates windows a installer
    # delete les mise a jour faites ou a reactualise
    upd_machine = [x["updateid"] for x in res_update]
    XmppMasterDatabase().del_all_Up_machine_windows(machine["id"], upd_machine)
    for t in res_update:
        logger.info(
            "Enabling update %s: %s - %s"
            % (
                t["updateid"],
                t["title"],
                t["kb"],
            )
        )
        XmppMasterDatabase().setUp_machine_windows(
            machine["id"],
            t["updateid"],
            kb=t["kb"],
            deployment_intervals=xmppobject.deployment_intervals,
            msrcseverity=t["msrcseverity"],
        )
        # on add ou update le kb dans la gray list
        XmppMasterDatabase().setUp_machine_windows_gray_list(
            t["updateid"], t["tableproduct"]
        )

    logger.error("JFK traitement_update")
    if ("system_info" in data and
        "infobuild" in data["system_info"] and
        "DisplayVersion" in data["system_info"]["infobuild"] and
        "major_version" in data["system_info"]["infobuild"] and
        "code_lang_iso" in data["system_info"]["infobuild"] and
        "update_major" in data["system_info"]["infobuild"]):
            logger.error("JFK traitement_update")
            # package_name = f"win{data['system_info']['infobuild']['major_version']}upd_{data['system_info']['infobuild']['code_lang_iso']}"
            # package_name_id = f"9514859a-{package_name}bqbowfj6h9update"
            # windows 10 majeur update
            if str(data["system_info"]["infobuild"]["major_version"]) == "10":
                if data["system_info"]["infobuild"]["DisplayVersion"] == "22H2":
                    package_name_id = XmppMasterDatabase().setUp_machine_windows_gray_list_major_version(data, validity_day=10)
                    logger.error("JFK traitement_update")
                    if package_name_id:
                        XmppMasterDatabase().del_all_Up_machine_windows(machine["id"], [package_name_id])
                        logger.error("add JFK traitement_update")

                        XmppMasterDatabase().setUp_machine_windows(
                                                                    machine["id"],
                                                                    package_name_id,
                                                                    kb= package_name_id[9:20],
                                                                    deployment_intervals=xmppobject.deployment_intervals,
                                                                    msrcseverity="major update",)
                        logger.error("add JFK traitement_update")

                else:
                    # mise a jour de win 10 to win 11 decomenter a prevoir 1 parametre
                    # il y a aussi les verification a faire
                    # tpm2.0
                    # boot secure.
                    # memoire, espace disk, et processeur.
                    # data["system_info"]["infobuild"]["major_version"] = "11"
                    pass
            if str(data["system_info"]["infobuild"]["major_version"]) == "11":
                if data["system_info"]["infobuild"]["DisplayVersion"] == "24H2":
                    package_name_id = XmppMasterDatabase().setUp_machine_windows_gray_list_major_version(data, validity_day=10)
                    if package_name_id:
                        XmppMasterDatabase().del_all_Up_machine_windows(machine["id"], [package_name_id])
                        XmppMasterDatabase().setUp_machine_windows(
                                                                    machine["id"],
                                                                    package_name_id,
                                                                    kb= package_name_id[9:19],
                                                                    deployment_intervals=xmppobject.deployment_intervals,
                                                                    msrcseverity="major update",)
            if int(data["system_info"]["infobuild"]["major_version"]) > 11:
                logger.debug("update major  '%s' pas pris encore en compte%" % (data["system_info"]["infobuild"]["DisplayVersion"]))
            if int(data["system_info"]["infobuild"]["major_version"]) > 11:
                logger.debug("update major  '%s' pas pris encore en compte%" % (data["system_info"]["infobuild"]["DisplayVersion"]))


def list_products_on(xmppobject, data, list_produits):
    """
    Filter the list of products based on the type of operating system.

    Args:
        xmppobject (object): The XMPP object used in the function.
        data (dict): A dictionary containing information about the operating system.
        list_produits (list): A list of products to filter.

    Returns:
        list: A filtered list of products.

    Important Notes:
        - Adding new OS tables may require modification of this function.
    """
    logger.debug(
        "exclud table pas du TYPE =   %s "
        % data["system_info"]["platform_info"]["type"]
    )
    listpack = []

    def del_element(x):
        if x in listpack:
            listpack.remove(x)

    for t in list_produits:
        listpack.append(t["name_procedure"])
    logger.debug("listin fonction  selectionne package  %s  " % list_produits)
    if data["system_info"]["platform_info"]["machine"] == "x64":
        if data["system_info"]["platform_info"]["type"] == "Windows 10":
            # deselectionne les windows 11
            del_element("up_packages_Win11_X64")
            del_element("up_packages_Win11_X64_21H2")
            del_element("up_packages_Win11_X64_22H2")
            del_element("up_packages_Win11_X64_23H2")
            del_element("up_packages_Win11_X64_24H2")
            if data["system_info"]["infobuild"]["DisplayVersion"] == "21H2":
                del_element("up_packages_Win10_X64_1903")
                del_element("up_packages_Win10_X64_21H1")
                del_element("up_packages_Win10_X64_22H2")
            elif data["system_info"]["infobuild"]["DisplayVersion"] == "21H1":
                del_element("up_packages_Win10_X64_21H2")
                del_element("up_packages_Win10_X64_1903")
                del_element("up_packages_Win10_X64_22H2")
            elif data["system_info"]["infobuild"]["DisplayVersion"] == "22H2":
                del_element("up_packages_Win10_X64_1903")
                del_element("up_packages_Win10_X64_21H1")
                del_element("up_packages_Win10_X64_21H2")
            else:
                del_element("up_packages_Win10_X64_21H1")
                del_element("up_packages_Win10_X64_22H2")
                del_element("up_packages_Win10_X64_21H2")
        elif "windows 11" in data["system_info"]["platform_info"]["type"]:
            # deselectionne les windows 10
            del_element("up_packages_Win10_X64_21H1")
            del_element("up_packages_Win10_X64_21H2")
            del_element("up_packages_Win10_X64_1903")
            del_element("up_packages_Win10_X64_22H2")
            if data["system_info"]["infobuild"]["DisplayVersion"] == "21H2":
                del_element("up_packages_Win11_X64_22H2")
                del_element("up_packages_Win11_X64_23H2")
                del_element("up_packages_Win11_X64_24H2")
            elif data["system_info"]["infobuild"]["DisplayVersion"] == "22H2":
                del_element("up_packages_Win11_X64_21H2")
                del_element("up_packages_Win11_X64_23H2")
                del_element("up_packages_Win11_X64_24H2")
            elif data["system_info"]["infobuild"]["DisplayVersion"] == "23H2":
                del_element("up_packages_Win11_X64_21H2")
                del_element("up_packages_Win11_X64_22H2")
                del_element("up_packages_Win11_X64_24H2")
            elif data["system_info"]["infobuild"]["DisplayVersion"] == "24H2":
                del_element("up_packages_Win11_X64_21H2")
                del_element("up_packages_Win11_X64_22H2")
                del_element("up_packages_Win11_X64_23H2")
            else:
                # on conserve seulement la window 11 generique up_packages_Win11_X64
                del_element("up_packages_Win11_X64_21H2")
                del_element("up_packages_Win11_X64_22H2")
                del_element("up_packages_Win11_X64_23H2")
                del_element("up_packages_Win11_X64_24H2")
        else:
            del_element("up_packages_Win10_X64_21H1")
            del_element("up_packages_Win10_X64_21H2")
            del_element("up_packages_Win10_X64_1903")
            del_element("up_packages_Win10_X64_22H2")
            del_element("up_packages_Win11_X64_21H2")
            del_element("up_packages_Win11_X64_22H2")
            del_element("up_packages_Win11_X64_23H2")
    else:
        # we don't look at x64 updates
        liste_a_supprimer = [
            "up_packages_Win10_X64_21H1",
            "up_packages_Win10_X64_21H2",
            "up_packages_Win10_X64_1903",
            "up_packages_Win11_X64",
            "up_packages_Win11_X64_21H2",
            "up_packages_Win11_X64_22H2",
            "up_packages_Win11_X64_23H2",
            "up_packages_Win11_X64_24H2",
            "up_packages_Win_Malicious_X64",
            "up_packages_office_2003_64bit",
            "up_packages_office_2007_64bit",
            "up_packages_office_2010_64bit",
            "up_packages_office_2013_64bit",
            "up_packages_office_2016_64bit",
        ]
        listpack = [element for element in listpack if element not in liste_a_supprimer]
    prds = [{"name_procedure": element} for element in listpack if element != ""]
    return prds


def read_conf_remote_update_windows(xmppobject):
    """
    Read configuration for remote Windows update.

    Args:
        xmppobject (object): The XMPP object used in the function.

    """
    xmppobject.exclude_history_list = True
    try:
        logger.debug("Initializing plugin :% s " % plugin["NAME"])
        namefichierconf = plugin["NAME"] + ".ini"
        pathfileconf = os.path.join(xmppobject.config.pathdirconffile, namefichierconf)

        if not os.path.isfile(pathfileconf):
            logger.error(
                "Plugin %s\nConfiguration file :"
                "\n\t%s missing"
                "\neg conf:\n[parameters]"
                "\exclude_history_list= True\n" % (plugin["NAME"], pathfileconf)
            )
            xmppobject.pluginlistregistered = []
            xmppobject.pluginlistunregistered = []
        else:
            Config = configparser.ConfigParser()
            Config.read(pathfileconf)
            logger.debug(
                "Config file %s for plugin %s" % (pathfileconf, plugin["NAME"])
            )
            if os.path.exists(pathfileconf + ".local"):
                Config.read(pathfileconf + ".local")
                logger.debug("read file %s.local" % pathfileconf)

            if Config.has_option("parameters", "exclude_history_list"):
                xmppobject.exclude_history_list = Config.getboolean(
                    "parameters", "exclude_history_list"
                )
            else:
                xmppobject.exclude_history_list = True
    except Exception:
        logger.error("\n%s" % (traceback.format_exc()))

    xmppobject.deployment_intervals = ""
    if Config.has_option("parameters", "deployment_intervals"):
        xmppobject.deployment_intervals = Config.get(
            "parameters", "deployment_intervals"
        )
