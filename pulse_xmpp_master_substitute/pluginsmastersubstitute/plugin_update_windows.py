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
from lib.plugins.pkgs import PkgsDatabase
from slixmpp import jid
from lib.utils import getRandomName
import re
from distutils.version import LooseVersion
import configparser
import netaddr

# this import will be used later
# import types

logger = logging.getLogger()

plugin = {"VERSION": "2.1", "NAME": "update_windows", "TYPE": "substitute"}  # fmt: skip

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

            data['list_produits'] = []
            data['list_produits'] = XmppMasterDatabase().list_produits()
            data['display_version_usuel'] = ['1983',
                                             '21H1',
                                             '21H2',
                                             '22H2',
                                             '23H2',
                                             '24H2',
                                             '25H2',
                                             '26H2',
                                             '2003',
                                             '2008',
                                             '2012',
                                             '2019']
            # MSOS Microsoft Server Operating System
            # WS Window Server
            data['excluded_prefixes_os'] = ["Win10","Win11","MSOS", "WS"]
            data['ARCHI_os'] = ["X64", "AMD64", "X86", "I386", "ARM64"]
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
    """
    Traite les mises à jour en fonction des informations système envoyées par une machine.

    Args:
        xmppobject: Objet XMPP contenant les informations de connexion et les paramètres globaux.
        action: Action demandée (non utilisée dans ce code).
        sessionid: ID de session pour la requête XMPP.
        data: Dictionnaire contenant les informations système de la machine.
        msg: Message XMPP contenant les informations sur l'expéditeur.
        ret: Valeur de retour (non utilisée dans ce code).
    """

    def package_name_major(data):
        """
        Génère un identifiant unique pour une mise à jour majeure en fonction de la version et de la langue du système.

        Args:
            data (dict): Dictionnaire contenant les informations système.

        Returns:
            str | None: Identifiant du package de mise à jour ou None si les informations requises sont absentes.
        """
        if (
            "system_info" in data
            and "infobuild" in data["system_info"]
            and "major_version" in data["system_info"]["infobuild"]
            and "code_lang_iso" in data["system_info"]["infobuild"]
        ):
            package_name = "win%supd_%s" % (
                data["system_info"]["infobuild"]["major_version"],
                data["system_info"]["infobuild"]["code_lang_iso"],
            )
            return f"9514859a-{package_name}bqbowfj6h9update"
        return None

    def verifier_exist_package(package_name_update):
        """
        Vérifie si un package existe à l'emplacement spécifié.

        Le chemin du package est construit en combinant le chemin de base
        '/var/lib/pulse2/packages/sharing/winupdates' avec le nom du UUID du package.

        Paramètres :
        package_name_update (str) : Le nom du UUID du package à vérifier.

        Retourne :
        bool : True si le package existe, False sinon.
        """
        chemin_package = os.path.join(
            "/var/lib/pulse2/packages/sharing/winupdates", package_name_update
        )
        return os.path.isdir(chemin_package)

    logger.debug(
        "Enabled products (list_produits):  %s" % data['list_produits']
    )
    # suivant type de windows exclude list produit

    list_table_product_select = list_products_on(
        xmppobject, data, data['list_produits']
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
        if t['name_procedure'] == "up_packages_Win_Malicious_X64":
            # le traitement de cette mise a jour est dependante de la version renvoyee par la machine du logiciel.
            # le kb n'est pas modifiee.
            if (
                "malicious_software_removal_tool" in data["system_info"]
                ):

                if "FileMinorPart" in data["system_info"]["malicious_software_removal_tool"]:
                    FileMinorPart = data["system_info"]["malicious_software_removal_tool"]["FileMinorPart"]
                else:
                    FileMinorPart = ""

                if "FileMajorPart" in data["system_info"]["malicious_software_removal_tool"]:
                    FileMajorPart = data["system_info"]["malicious_software_removal_tool"]["FileMajorPart"]
                else:
                    FileMajorPart = ""

                list_update = []
                # search malicious_software_removal_tool
                list_update = (
                    XmppMasterDatabase().search_update_windows_malicious_software_tool(
                        data["system_info"]["platform_info"]["type"],
                        data["system_info"]["platform_info"]["machine"],
                        FileMajorPart,
                        FileMinorPart,
                    )
                )
                res_update.extend(
                    exclude_update_in_select(msg, exclude_update, list_update)
                )
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
        # on ajoute le deploiement si le package exist iniquement
        exist_package_base = PkgsDatabase().verifier_exist_uuid(t["updateid"])
        exist_package_physique = verifier_exist_package(t["updateid"])
        if not exist_package_base:
            logger.warning("package update '%s' missing in base pkgs" % t["updateid"])
        if not exist_package_physique:
            logger.warning(
                "package update '%s' missing in base files /var/lib/pulse2/packages/sharing/winupdate"
                % t["updateid"]
            )
        # if exist_package_base and exist_package_physique:
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

def list_products_on(xmppobject, data, list_produits):
    """
    Filter the list of products based on the type of operating system. and sur les
        produit sur lesquel il faut prendre en compte.

    Args:
        xmppobject (object): The XMPP object used in the function.
        data (dict): A dictionary containing information about the operating system.
        list_produits (list): A list of products (dicts with name_procedure).

    Returns:
        list: A filtered list of products.

    Logic:
        - Removes all OS-specific packages (Win10, Win11, MSOS).
        - Keeps all other products (Office, VStudio, etc.).
        - Adds only the correct OS package for the current machine.
    """
    # On commence par recopier tous les produits SAUF ceux liés aux OS

    # Construction de la liste des procédures filtrées :
    # - On exclut les procédures dont le nom commence par "up_packages_<OS>"
    basepack = [
        p["name_procedure"]
        for p in list_produits
        # Vérification que le nom ne commence par aucun des préfixes exclus
        if not any(
            p["name_procedure"].startswith(f"up_packages_{os_prefix}")
            for os_prefix in data['excluded_prefixes_os']
        )
    ]
    # En cas d'erreur, on retourne la liste des table mise à jour sous forme de dictionnaires
    try:
        system_info = data.get("system_info")
        platform_type = system_info["platform_info"]["type"]
        # Récupération de la valeur de machine_arch
        machine_arch = system_info["platform_info"]["machine"]
        # Vérification et transformation en majuscules
        if machine_arch:
            machine_arch = machine_arch.upper()
        display_version = system_info["infobuild"].get("DisplayVersion")
    except KeyError as e:
        logger.error("Clé manquante dans data: %s", e)
        prds = [{"name_procedure": element} for element in basepack if element]
        return prds
    except Exception as e:
        logger.error("Erreur inattendue lors de la lecture des infos système: %s", e)
        prds = [{"name_procedure": element} for element in basepack if element]
        return prds

    # Normalisation du nom d'OS
    os_name = None
    if "Windows 10" in platform_type:
        os_name = "Win10"
    elif "Windows 11" in platform_type:
        os_name = "Win11"
    elif "MSOS" in platform_type:
        os_name = "MSOS"
    elif "WS" in platform_type:
        os_name = "WS"

    # Construction du package attendu
    selected_os_pkg = None
    if os_name:
        if display_version in data['display_version_usuel']:# exemple : up_packages_Win10_X64_21H2
            selected_os_pkg = f"up_packages_{os_name}_{machine_arch}_{display_version}"
        else:  # fallback générique (ex: up_packages_Win11_X64)
            logger.warning( f"display_version '{display_version}' inconnue. "
                            f"Valeur : {display_version}")
            selected_os_pkg = f"up_packages_{os_name}_{machine_arch}" # (ex cas: up_packages_Win11_X64)

    # Vérifie si ce package existe dans la table des produits
    if selected_os_pkg and any(p["name_procedure"] == selected_os_pkg for p in list_produits):
        # on ajoute les mise a jour a prendre en compte pour cette machine
        basepack.append(selected_os_pkg)
        logger.debug("Selected OS package: %s", selected_os_pkg)
    else:
        logger.debug("No matching OS package found for %s", selected_os_pkg)

    # Transformation finale en liste de dicts
    prds = [{"name_procedure": element} for element in basepack if element]
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
