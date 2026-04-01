# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2016-2023 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-3.0-or-later
"""
file : pulse_xmpp_master_substitute/pluginsmastersubstitute/plugin_update_windows.py
============================
"""
import base64
import traceback
import os
import json
import logging
from lib.plugins.xmpp import XmppMasterDatabase
from lib.plugins.glpi import Glpi
from lib.plugins.kiosk import KioskDatabase
from lib.plugins.msc import MscDatabase

from lib.manageRSAsigned import MsgsignedRSA
from lib.plugins.pkgs import PkgsDatabase
from slixmpp import jid
from lib.utils import getRandomName, name_randomplus
import re
from distutils.version import LooseVersion
import configparser
import netaddr

import datetime
import time
import pytz
import types
from lib.managepackage import managepackage
from lib.create_deploy_builder import InstantDeployBuilder

from lib.utils import (
    name_random,
    file_put_contents,
    file_get_contents,
    utc2local,
)

# this import will be used later
# import types

logger = logging.getLogger()

plugin = {"VERSION": "2.6", "NAME": "update_windows", "TYPE": "substitute"}  # fmt: skip


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
        if not isinstance(data, dict):
            logger.error(
                "[%s] action ignored: invalid payload type=%s sessionid=%s from=%s",
                plugin["NAME"],
                type(data).__name__,
                sessionid,
                msg.get("from"),
            )
            return

        sender = str(msg.get("from", ""))
        logger.debug(
            "[%s] action start action=%s sessionid=%s from=%s payload_keys=%s",
            plugin["NAME"],
            action,
            sessionid,
            sender,
            sorted(data.keys()),
        )

        data["hostname"], data["bare_jid"] = parse_jid(sender)
        if not data["bare_jid"]:
            logger.warning(
                "[%s] action ignored: unable to parse sender from=%s sessionid=%s",
                plugin["NAME"],
                sender,
                sessionid,
            )
            return
        logger.debug(
            "[%s] parsed jid bare_jid=%s hostname=%s",
            plugin["NAME"],
            data["bare_jid"],
            data["hostname"],
        )


        # Le plugin initialise certains attributs une seule fois au premier appel.
        compteurcallplugin = getattr(xmppobject, "num_call%s" % action, 0)
        if compteurcallplugin == 0:
            try:
                xmppobject.registeryagent_showinfomachine
            except:
                xmppobject.registeryagent_showinfomachine = []
            read_conf_remote_update_windows(xmppobject)
            
            
            logger.debug(
                "[%s] plugin initialized registered_debug_targets=%s",
                plugin["NAME"],
                len(xmppobject.registeryagent_showinfomachine),
            )

        data['list_produits'] = []
        

        # Windows 11
        # dernière Windows 11 25H2 (Octobre 2025).
        # Windows 11 25H2	26200	1 Octobre 2025
        # Windows 11 24H2	26100	8 Octobre 2024
        # Windows 11 23H2	22631	23 Septembre 2023
        # Windows 11 22H2	22621	21 Septembre 2022
        # Windows 11 21H2	22000	5 octobre 2021


        data['display_version_usuel'] =['1983',
                                        '21H1',
                                        '21H2',
                                        '22H2',
                                        '23H2',
                                        '24H2',
                                        '25H2',
                                        '26H1',
                                        '26H2',
                                        '2003',
                                        '2008',
                                        '2012',
                                        '2019',
                                        '2022',
                                        '2025',
                                        '2026']
        # MSOS Microsoft Server Operating System
        # WS Window Server
        data['excluded_prefixes_os'] = ["Win10", "Win11", "MSOS", "WS"]
        data['ARCHI_os'] = ["X64", "AMD64", "X86", "I386", "ARM64"]
        traitement_update(xmppobject, action, sessionid, data, msg, ret)

    except Exception:
        logger.error(
            "[%s] action failed action=%s sessionid=%s from=%s\n%s",
            plugin["NAME"],
            action,
            sessionid,
            msg.get("from"),
            traceback.format_exc(),
        )


def parse_jid(jid: str):
    """
    Parse a JID string into hostname and bare JID (without resource).

    Example:
        Input:  pc-win11pro-3.nnx@pulse/54aebc3162c5
        Output:
            hostname = pc-win11pro-3
            jid = pc-win11pro-3.nnx@pulse

    Args:
        jid (str): Full JID string including optional resource.

    Returns:
        tuple: (hostname, bare_jid)
    """

    if not jid:
        return "", ""

    # Remove resource part
    bare_jid = jid.split('/')[0]

    # Extract localpart (before @)
    localpart = bare_jid.split('@')[0]

    # Hostname is the part before the first dot
    hostname = localpart.split('.')[0]

    return hostname, bare_jid



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
            logger.debug(
                "Excluding update for %s kb=%s updateid=%s (blacklist)",
                msg["from"],
                upd["kb"],
                upd["updateid"],
            )
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

    # Mapping JID -> machine inventaire, necessaire pour retrouver l'entite et ses regles.
    system_info = data.get("system_info")
    if not isinstance(system_info, dict):
        logger.warning(
            "Missing or invalid system_info for machine=%s sessionid=%s",
            msg.get("from"),
            sessionid,
        )
        return

    machine = XmppMasterDatabase().getIdsEntityMachineInventaireFromJid(msg["from"])
    if not machine or 'entity_id' not in machine:
        logger.warning("Machine %s is not yet registered" % msg["from"])
        return
    #logger.debug("Machine %s" % (machine))
    #logger.debug("data %s" % (data))   
       
    
    entity_id = machine.get('entity_id')
    data['entityid']=entity_id
    logger.debug(
        "Resolved machine context jid=%s machine_id=%s entity_id=%s",
        msg["from"],
        machine.get("id"),
        entity_id,
    )
    # ajoute en base si il n'existe pas les regles pour faire 1 gestion
    # automatique des mise a jour en fonction de entity.
    XmppMasterDatabase().ensure_auto_approve_rules_for_entity(entity_id)

    data['list_produits'] = XmppMasterDatabase().list_produits_entity(entity_id)
    logger.debug(
        "Products configured for entity_id=%s count=%s",
        entity_id,
        len(data['list_produits']) if data['list_produits'] else 0,
    )
    # logger.debug("Machine %s \n liste produit %s" % (msg["from"], data['list_produits']))
    if not data['list_produits']:
        logger.warning(f"Pas de produits windows sélectionnés pour l'entité {entity_id}")
        return
    # on recuperer la table produit windows 1 seule doit conserner ce windows.
    list_table_product_select = list_products_on(xmppobject, data)



    if not list_table_product_select:
         logger.warning(
        "No matching update table for machine=%s entity_id=%s (products=%s)"
        % (msg["from"], entity_id, list_table_product_select)
    )
         return

    logger.debug(
        "Selected product tables for machine=%s count=%s",
        msg["from"],
        len(list_table_product_select),
    )

    # si on prend en compte l'historique des mises à jours on ajoute a la liste des kb installer la list des kb historique. history_list_kb
    # Si active, on fusionne historique + KB installees pour eviter de reproposer
    # des updates deja appliquees par le passe.
    kb_list_value = system_info.get("kb_list", "")
    if not kb_list_value:
        kb_installed = [
            x.get("HotFixID", "").replace("KB", "")
            for x in system_info.get("kb_installed", [])
            if x.get("HotFixID")
        ]
        kb_list_value = '"%s"' % ",".join(kb_installed)
        system_info["kb_list"] = kb_list_value

    if not xmppobject.exclude_history_list:
        logger.debug("Checking against KB history list")
        kblistexclde = []
        history_list_kb = XmppMasterDatabase().history_list_kb(
            system_info.get("history_package_uuid", [])
        )
        if history_list_kb:
            kblistexclde.extend(history_list_kb)
        kb_installed = [
            x["HotFixID"].replace("KB", "") for x in system_info.get("kb_installed", []) if x.get("HotFixID")
        ]
        kblistexclde.extend(kb_installed)
        lkbe = '"%s"' % ",".join(kblistexclde)
        system_info["kb_list"] = lkbe
    logger.debug(
        "Installed KB list prepared for %s (chars=%s)",
        msg["from"],
        len(system_info["kb_list"]) if system_info.get("kb_list") else 0,
    )

    list_update = []
    exclude_update = {}
    res_update = []

    # on exclut les mise à jour se trouvant en liste noire en fonction de  l'entite.
    exclude_update = XmppMasterDatabase().test_black_list(msg["from"], entity_id)
    logger.debug(
        "Blacklist loaded entity_id=%s machine=%s kb_count=%s update_count=%s",
        entity_id,
        msg["from"],
        len(exclude_update.get("kb", [])),
        len(exclude_update.get("update_id", [])),
    )
    
    list_deinstall_update = []
    for t in list_table_product_select:
        
        if t['name_procedure'] == "up_packages_Win_Malicious_X64":
            # cas pour le traitement des mise à jour pour malveillant (malware) détecté ou catégorisé.
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
            else:
                logger.debug(
                    "Skipping malicious tool lookup for %s: no malicious_software_removal_tool in system_info",
                    msg["from"],
                )
            continue
        list_update = []
        logger.debug(
            "Looking for product %s (%s)"
            % (t["name_procedure"], system_info["kb_list"])
        )
        # on cherche si il y a des mise à jour pour cette machine en fonction des kb renvoye et de la table produit
        list_update = XmppMasterDatabase().search_update_by_products(
            tableproduct=t, str_kb_list=system_info["kb_list"]
        )

        list_deinstall = XmppMasterDatabase().select_updatepackageid_produit_table(
            tableproduct=t,
            str_kb_list=system_info["kb_list"],
        )
        logger.debug(
            "Candidate updates table=%s install_count=%s uninstall_count=%s",
            t["name_procedure"],
            len(list_update),
            len(list_deinstall),
        )
        if list_deinstall:
            list_deinstall_update.extend(list_deinstall)
        # on recupere la liste des mise a jour a faire sur la machine en tenant cimpte des mise a jour que l'on a exclut'
        res_update.extend(exclude_update_in_select(msg, exclude_update, list_update))
        logger.debug("Accumulated install candidates for %s: %s", msg["from"], len(res_update))
       
    
    
    # update les updates windows a installer
    # delete les mise a jour faites ou a reactualise
    # on deinstall pour la machine les kb que l'on a installer ou proscrit
    # list_deinstall_update est la liste des package a deinstaller pour cette machine.

    
    upd_machine = [x["updateid"] for x in res_update]
    logger.debug(
        "Final update selection for machine_id=%s: install_count=%s uninstall_count=%s",
        machine["id"],
        len(upd_machine),
        len(list_deinstall_update),
    )
    # Supprime les enregistrements de la table 'Up_machine_windows' qui sont maintenant installé.
    # on met a jour up_machine_windows en fonction de la demande et si la mise à jour est traite ou a traite
    XmppMasterDatabase().del_all_Up_machine_windows(machine["id"], entity_id, upd_machine)
  
    for t in res_update:
        logger.info(
            "Enabling update %s: %s - %s"
            % (
                t["updateid"],
                t["title"],
                    t["kb"],
                )
            )
        # on ajoute le deploiement si le package exist uniquement
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
        # Crée ou met à jour un enregistrement de mise à jour Windows (update) pour une machine donnée.
        # table Up_machine_windows
        XmppMasterDatabase().setUp_machine_windows(
            machine["id"],
            t["updateid"],
            entity_id,
            kb=t["kb"],
            deployment_intervals=xmppobject.deployment_intervals,
            msrcseverity=t["msrcseverity"],
        )
        
        # on add ou update le kb dans la gray list
        # ajoute la mise jour dans la gray list en fonction de entite
        XmppMasterDatabase().setUp_machine_windows_gray_list(
            entity_id, t["updateid"], t["tableproduct"]
        )
    """
    # Bloc de test temporaire: force un package uninstall de demonstration.
    # Le "return" juste apres court-circuite le flux normal de desinstallation.
    data["uuid"] = "ea1310d2-aaa_v38nuf6d0g85652d7vjsyov"
    data["kb"] = "53000001"
    data["titleuninstall"] = "hoho"
    logger.warning("test uninstall block")
    if XmppMasterDatabase().add_uninstall_kb_machine(
            data["uuid"],
            data["hostname"],
            kb=data["kb"],
            jid=data["bare_jid"],
            entities_id=data["entityid"],
            status="",
        ) > 0:
        logger.warning("test uninstall deployment")
        sessionid = (
            InstantDeployBuilder(xmppobject, msg, data, "uninstall")
            .mark_as_update()
            .deploy()
        )
        logger.warning("test uninstall sessionid: %s" % sessionid)
    return
    """
    for package_deinstll in list_deinstall_update:
        if len(package_deinstll) < 3:
            logger.warning(
                "Skipping uninstall package with invalid payload for machine=%s payload=%s",
                msg["from"],
                package_deinstll,
            )
            continue
        logger.info(
            "uninstall update %s: %s - %s"
            % (
                package_deinstll[0],
                package_deinstll[1],
                package_deinstll[2],
            )
            )

        data["uuid"] = package_deinstll[0]
        data["kb"] = package_deinstll[1]
        data["titleuninstall"] = package_deinstll[2]
        # on ajoute le deploiement si le package exist uniquement
        exist_package_base = PkgsDatabase().verifier_exist_uuid(package_deinstll[0])
        exist_package_physique = verifier_exist_package(package_deinstll[0])

        if not exist_package_base:
            logger.warning(
                "package uninstall update '%s' missing in base pkgs" % package_deinstll[0]
            )
        if not exist_package_physique:
            logger.warning(
                "package uninstall update '%s' missing in base files /var/lib/pulse2/packages/sharing/winupdate"
                % package_deinstll[0]
            )

        uninstall_count = XmppMasterDatabase().add_uninstall_kb_machine(
            data["uuid"],
            data["hostname"],
            kb=data["kb"],
            jid=data["bare_jid"],
            entities_id=data["entityid"],
            status="",
        )
        logger.debug(
            "Registered uninstall attempt machine=%s updateid=%s count=%s",
            data["hostname"],
            data["uuid"],
            uninstall_count,
        )

        if uninstall_count == 1:
            deployuninstall(data, msg, xmppobject, "uninstall")
        else:
            logger.info(
                "Skipping duplicate uninstall deployment machine=%s updateid=%s count=%s",
                data["hostname"],
                data["uuid"],
                uninstall_count,
            )

def list_products_on(xmppobject, data):
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

    list_produits = data.get("list_produits", None)
    if not list_produits:
        logger.warning("pas de liste produits de selectionner" )
        return
    basepack = []
    #     p["name_procedure"]
    #     for p in list_produits
    #     # Vérification que le nom ne commence par aucun des préfixes exclus
    #     if not any(
    #         p["name_procedure"].startswith(f"up_packages_{os_prefix}")
    #         for os_prefix in data['excluded_prefixes_os']
    #     )
    # ]
    # En cas d'erreur, on retourne la liste des table mise à jour sous forme de dictionnaires
    try:
        system_info = data.get("system_info")
        if not isinstance(system_info, dict):
            raise ValueError("system_info absent ou invalide")
        # platform_type = system_info["platform_info"].get("type", None)
        platform_type = system_info.get("platform_info", {}).get("type", "").lower()
        # Récupération de la valeur de machine_arch
        machine_arch = system_info.get("platform_info", {}).get("machine", None)
        ProductName =  system_info.get("infobuild", {}).get("ProductName", None)
        DisplayVersion = system_info.get("infobuild", {}).get("DisplayVersion", None)
        logger.debug(
            "system_info summary platform_type=%s machine_arch=%s product_name=%s display_version=%s",
            platform_type,
            machine_arch,
            ProductName,
            DisplayVersion,
        )

        if "office" in system_info:
            office_info = system_info["office"]
            # Construction des noms de packages pour Office et Visual Studio
            produitbrute= [p["name_procedure"] for p in list_produits]
            packageofficename = None
            OfficeVersion = office_info.get("version")
            if OfficeVersion and "year" in office_info:
                packageofficename = f"up_packages_office_{office_info['year']}_{machine_arch}"
                if packageofficename in produitbrute:
                    basepack.append(packageofficename)
        if "visual" in system_info:
            visual_info = system_info["visual"]
            # Vérification et transformation en majuscules
            produitbrute= [p["name_procedure"] for p in list_produits]
            packageVisualStudioname = None
            VisualStudioVersion = visual_info.get("version")
            if VisualStudioVersion and "year" in visual_info:
                packageVisualStudioname = f"up_packages_Vstudio_{visual_info['year']}"
                if packageVisualStudioname in produitbrute:
                    basepack.append(packageVisualStudioname)

        if not (machine_arch and ProductName and platform_type):
            raise ValueError(
                f"Version de produit inconnue pour traitement: "
                f"ProductName: {ProductName}, machine_arch: {machine_arch}, platform_type: {platform_type}"
            )

        machine_arch = machine_arch.upper()

        # Normalisation du nom d'OS
        os_name = None

        # Normalisation des serveurs:
        # - MSOS quand DisplayVersion est fournie
        # - WS + mapping manuel pour anciennes generations sinon
        if 'microsoft windows server' in platform_type:
            if DisplayVersion:
                # on a des packages MSO
                os_name  = "MSOS"
            else:
                os_name = "WS"
                if '2003' in ProductName :
                    DisplayVersion = '2003'
                elif '2008' in ProductName :
                    DisplayVersion = '2008'
                elif '2012' in ProductName :
                    DisplayVersion = '2012'
                elif '2019' in ProductName :
                    DisplayVersion = '2019'
                elif '2022' in ProductName :
                    DisplayVersion = '2022'
                elif '2025' in ProductName :
                    DisplayVersion = '2025'
                else:
                    raise ValueError(
                        f"Version inconnue pour ProductName: {ProductName}, "
                        f"platform_type: {platform_type}, arch: {machine_arch}, "
                        f"DisplayVersion: {DisplayVersion}"
                    )
        elif "windows 10" in platform_type:
            os_name = "Win10"
        elif "windows 11" in platform_type:
            os_name = "Win11"
        else:
            raise ValueError(
                f"Version inconnue pour ProductName: {ProductName}, "
                f"platform_type: {platform_type}, arch: {machine_arch}, "
                f"DisplayVersion: {DisplayVersion}"
            )

        logger.debug(
            "Normalized system info product_name=%s platform_type=%s arch=%s display_version=%s os_name=%s",
            ProductName,
            platform_type,
            machine_arch,
            DisplayVersion,
            os_name,
        )

    except KeyError as e:
        logger.error(
            "Clé manquante dans data pour selection produit: %s\n%s",
            e,
            traceback.format_exc(),
        )
        prds = [{"name_procedure": element} for element in basepack if element]
        return prds
    except Exception as e:
        logger.error(
            "Erreur inattendue lors de la lecture des infos système: %s\n%s",
            e,
            traceback.format_exc(),
        )
        prds = [{"name_procedure": element} for element in basepack if element]
        return prds


    # Construction du package OS attendu dans la table des produits.
    # Format nominal: up_packages_<OS>_<ARCH>_<DisplayVersion>
    selected_os_pkg = None
    if os_name:
        if DisplayVersion in data['display_version_usuel']:# exemple : up_packages_Win10_X64_21H2
            selected_os_pkg = f"up_packages_{os_name}_{machine_arch}_{DisplayVersion}"
        else:  # fallback générique (ex: up_packages_Win11_X64)
            logger.warning( f"DisplayVersion '{DisplayVersion}' inconnue. "
                            f"Valeur : {DisplayVersion}")
            selected_os_pkg = f"up_packages_{os_name}_{machine_arch}" # (ex cas: up_packages_Win11_X64)

        logger.debug("Selected OS table candidate: %s", selected_os_pkg)


    # Vérifie si ce package existe dans la table des produits
    if selected_os_pkg and any(p["name_procedure"] == selected_os_pkg for p in list_produits):
        # on ajoute les mise a jour a prendre en compte pour cette machine
        basepack.append(selected_os_pkg)
        logger.debug("Selected OS package: %s", selected_os_pkg)
    else:
        logger.warning("No matching OS package found for %s", selected_os_pkg)

    # Transformation finale en liste de dicts
    prds = [{"name_procedure": element} for element in basepack if element]
    return prds


def deployuninstall(data, message, xmppobject, sectionname=None):
    builder = InstantDeployBuilder(xmppobject, message, data, sectionname)
    return builder.deploy()



def read_conf_remote_update_windows(xmppobject):
    """
    Read configuration for remote Windows update.

    Args:
        xmppobject (object): The XMPP object used in the function.

    """
    xmppobject.exclude_history_list = True
    xmppobject.deployment_intervals = ""
    Config = None
    try:
        logger.debug("Initializing plugin :% s " % plugin["NAME"])
        namefichierconf = plugin["NAME"] + ".ini"
        pathfileconf = os.path.join(xmppobject.config.pathdirconffile, namefichierconf)

        if not os.path.isfile(pathfileconf):
            logger.error(
                "Plugin %s\nConfiguration file :"
                "\n\t%s missing"
                "\neg conf:\n[parameters]"
                "\nexclude_history_list= True\n" % (plugin["NAME"], pathfileconf)
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
        logger.error(
            "Erreur lecture configuration plugin %s\n%s",
            plugin["NAME"],
            traceback.format_exc(),
        )

    if Config and Config.has_option("parameters", "deployment_intervals"):
        xmppobject.deployment_intervals = Config.get(
            "parameters", "deployment_intervals"
        )
    logger.debug(
        "Plugin config loaded exclude_history_list=%s deployment_intervals=%s",
        xmppobject.exclude_history_list,
        xmppobject.deployment_intervals,
    )
