# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2016-2023 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-3.0-or-later

"""
file : pulse_xmpp_master_substitute/pluginsmastersubstitute/plugin_load_send_Segment_file.py

Ce plugin installe une fonction appelée cycliquement.
Cette fonction a pour charge d'envoyer des fichiers à des machines.
"""

import re
import json
import os
import logging
import configparser
import shutil
import types
from lib.configuration import confParameter
from datetime import datetime, timedelta
from lib.plugins.xmpp import XmppMasterDatabase
from lib.plugins.msc import MscDatabase
import traceback
from lib.utils import file_put_contents, simplecommandstr, simplecommand, getRandomName

logger = logging.getLogger()

DEBUGPULSEPLUGIN = 25

plugin = {"VERSION": "1.0", "NAME": "load_send_Segment_file", "TYPE": "substitute", "LOAD": "START"}  # fmt: skip

var_file_zipper = "/var/lib/pulse2/zip_transfert"


def action(objectxmpp, action, sessionid, data, msg, dataerreur):
    """
    Fonction principale du plugin, appelée lors de l'exécution du plugin.

    Args:
        objectxmpp (object): L'objet XMPP.
        action (str): L'action à exécuter.
        sessionid (str): L'ID de la session.
        data (dict): Les données associées à l'action.
        msg (dict): Le message XMPP.
        dataerreur (dict): Les données d'erreur.

    Returns:
        None
    """
    logger.debug("=====================================================")
    logger.debug("call %s from %s" % (plugin, msg["from"]))
    logger.debug("=====================================================")
    logger.debug("data %s" % json.dumps(data, indent=4))

    compteurcallplugin = getattr(objectxmpp, "num_call%s" % action)
    if compteurcallplugin == 0:
        read_conf_load_send_Segment_file(objectxmpp)
        # Installer le code dynamique : fonction de transfert de fichier
        objectxmpp.transfert_segment_file = types.MethodType(
            transfert_segment_file, objectxmpp
        )
        # Planifier l'appel de cette fonction
        scedule_call_plugin_in_seconde = 15
        objectxmpp.schedule(
            "transfert_segment_file",
            scedule_call_plugin_in_seconde,
            objectxmpp.transfert_segment_file,
            repeat=True,
        )


def transfert_segment_file(self):
    """
    Fonction de transfert de fichiers vers les machines présentes.
    cette fonction est scheduler a
    Args:
        self (object): L'objet XMPP.

    Returns:
        None
    """
    type_transfert = "backup"
    location = None
    transfert_de_fichier_a_nb_machine_simultanement = 10
    repertoires_uuid = lister_repertoires_uuid(var_file_zipper)[
        :transfert_de_fichier_a_nb_machine_simultanement
    ]
    # Envoyer les fichiers tronqués.
    for dir_uuid_machine in repertoires_uuid:
        # dir est un répertoire mais le nom du répertoire est le UUID de la machine cible.
        # Si la machine est présente.

        machine = XmppMasterDatabase().getMachinefromuuidsetup(str(dir_uuid_machine))

        if machine:
            if not machine["enabled"]:
                # La machine n'est pas présente, on ne peut pas lui envoyer des fichiers.
                logger.debug(
                    "Machine %s eteinte : on ne peut pas transferer de fichiers a cette machine"
                    % machine["hostname"]
                )
                logger.debug(
                    "tout les demande de transfert pour la machine %s sont annuler"
                    % machine["hostname"]
                )
                supprimer_repertoire(os.path.join(var_file_zipper, dir_uuid_machine))
                continue
            logger.debug(
                "TRANSFERT SEGMENT FILE to machine %s " % (machine["hostname"])
            )
            # La machine est présente. On peut lui envoyer les fichiers.
            list_repertoire_to_file_for_send = get_uuid_directories(
                os.path.join(var_file_zipper, dir_uuid_machine)
            )
            for repertoire_file_seg in list_repertoire_to_file_for_send:
                sessionid = getRandomName(5, "transfert_file")
                file_list_to_send = lister_fichiers(repertoire_file_seg)
                # logger.debug("REPERTOIRE DES FICHIERS %s \n file_list_to_send %s " % (repertoire_file_seg, file_list_to_send))

                if len(file_list_to_send) < 2:
                    # Le fichier n'est pas encore segmenté ou il y a une erreur
                    continue

                # Le premier fichier de la liste doit être un fichier .manif pour manifeste.
                if file_list_to_send[0].endswith(".manif"):
                    manifeste = lire_fichier_json(file_list_to_send[0])
                    if len(file_list_to_send) != manifeste["nb_total"] + 1:
                        # Pas encore préparé
                        continue

                    # logger.debug("contenue fichier manifeste : %s " % json.dumps(manifeste, indent=4))
                    # logger.debug("repertoire_file_seg : %s " % repertoire_file_seg)

                    if not manifeste:
                        # Le manifeste n'est pas un JSON correct
                        # Donc on considère que le transfert ne peut pas se faire.
                        supprimer_repertoire(repertoire_file_seg)
                        continue

                else:
                    continue

                indexfile = 0
                for filesend in file_list_to_send:
                    # logger.debug("*********************************")
                    # logger.debug("filesend %s  " % (filesend))
                    # logger.debug("*********************************")

                    if indexfile == 0:
                        data = manifeste
                    else:
                        data = lire_fichier_json(filesend)
                        data["namefile"] = manifeste["namefile"]

                    data["segment"] = indexfile
                    data["dir_uuid_machine"] = dir_uuid_machine
                    data["dir_segment"] = os.path.basename(repertoire_file_seg)
                    msg_send = {
                        "sessionid": sessionid,
                        "data": data,
                        "action": "recombine_file",
                        "ret": 0,
                    }
                    indexfile = indexfile + 1
                    # C'est la machine qui reçoit les segments qui doit recombiner le fichier.
                    self.send_message(
                        mto=machine["jid"], mbody=json.dumps(msg_send), mtype="chat"
                    )

                supprimer_repertoire(repertoire_file_seg)
        supprimer_repertoire(os.path.join(var_file_zipper, dir_uuid_machine))


def supprimer_repertoire(chemin_repertoire):
    """
    Supprime un répertoire et tout son contenu.

    Paramètres:
    chemin_repertoire (str): Chemin du répertoire à supprimer.

    Retourne:
    bool: True si le répertoire a été supprimé avec succès, False sinon.
    """
    try:
        shutil.rmtree(chemin_repertoire)
        # logger.debug(f"Le répertoire {chemin_repertoire} a été supprimé avec succès.")
        return True
    except FileNotFoundError:
        logger.debug(f"Le répertoire {chemin_repertoire} n'existe pas.")
        return False
    except PermissionError:
        logger.debug(
            f"Vous n'avez pas les permissions nécessaires pour supprimer le répertoire {chemin_repertoire}."
        )
        return False
    except Exception as e:
        logger.debug(
            f"Une erreur s'est produite lors de la suppression du répertoire {chemin_repertoire}: {e}"
        )
        return False


def lire_fichier_json(chemin_fichier):
    """
    Lit le contenu d'un fichier JSON et le stocke dans un dictionnaire.

    Paramètres:
    chemin_fichier (str): Chemin du fichier JSON à lire.

    Retourne:
    dict: Le contenu du fichier JSON sous forme de dictionnaire.
    """
    try:
        with open(chemin_fichier, "r", encoding="utf-8") as fichier:
            contenu = json.load(fichier)
        return contenu
    except FileNotFoundError:
        logger.debug(f"Le fichier {chemin_fichier} n'existe pas.")
        return None
    except json.JSONDecodeError:
        logger.debug(f"Erreur de décodage JSON dans le fichier {chemin_fichier}.")
        return None
    except Exception as e:
        logger.debug(f"Erreur lors de la lecture du fichier {chemin_fichier}: {e}")
        return None


def get_uuid_directories(base_directory):
    """
    Renvoie les répertoires dans un répertoire de base dont le nom commence par 10 chiffres.

    Args:
    base_directory (str): Le chemin du répertoire de base.

    Returns:
    list: Une liste des chemins des répertoires qui correspondent.
    """
    matching_dirs = []

    # Expression régulière pour 10 chiffres au début du nom
    pattern = re.compile(
        r"^\d{10}_[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
    )

    # Parcourt les fichiers et répertoires dans le répertoire de base
    for dir_name in os.listdir(base_directory):
        # Vérifie si c'est un répertoire et si son nom commence par 10 chiffres
        dir_path = os.path.join(base_directory, dir_name)
        if os.path.isdir(dir_path) and pattern.match(dir_name):
            matching_dirs.append(dir_path)

    return matching_dirs


def lister_fichiers(repertoire):
    """
    Lit tous les fichiers dans un répertoire donné et renvoie une liste triée des fichiers.

    Paramètres:
    repertoire (str): Chemin du répertoire.

    Retourne:
    list: Une liste triée des noms de fichiers dans le répertoire.
    """
    # logger.debug(f"cherche file repertoire {repertoire}")
    try:
        # Obtenir la liste des fichiers et des répertoires dans le répertoire donné
        contenu = os.listdir(repertoire)
        # logger.debug(f"CONTENU {contenu}")
        # Filtrer pour ne conserver que les fichiers
        fichiers = [
            os.path.join(repertoire, f)
            for f in contenu
            if os.path.isfile(os.path.join(repertoire, f))
        ]
        # logger.debug(f"fichiers {fichiers}")
        # Trier la liste des fichiers
        fichiers.sort()

        return fichiers
    except Exception as e:
        logger.debug(f"Erreur lors de la lecture du répertoire {repertoire}: {e}")
        return []


def lire_contenu_fichier(chemin_fichier):
    """
    Lit le contenu texte d'un fichier et le stocke dans une variable.

    Paramètres:
    chemin_fichier (str): Chemin du fichier à lire.

    Retourne:
    str: Le contenu texte du fichier.
    """
    try:
        with open(chemin_fichier, "r", encoding="utf-8") as fichier:
            contenu = fichier.read()
        return contenu
    except Exception as e:
        logger.debug(f"Erreur lors de la lecture du fichier {chemin_fichier}: {e}")
        return None


def lister_repertoires_uuid(repertoire_principal):
    """
    Renvoie une liste de tous les répertoires dans le répertoire principal qui ont un nom de la forme UUID.

    Paramètres:
    repertoire_principal (str): Chemin du répertoire principal.

    Retourne:
    list: Une liste des répertoires ayant un nom de la forme UUID.
    """
    # Expression régulière pour vérifier le format UUID
    uuid_pattern = re.compile(
        r"^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$"
    )
    # Liste pour stocker les répertoires UUID
    repertoires_uuid = []
    # Parcourir les éléments dans le répertoire principal
    for item in os.listdir(repertoire_principal):
        item_path = os.path.join(repertoire_principal, item)
        if os.path.isdir(item_path) and uuid_pattern.match(item):
            repertoires_uuid.append(item)
    return repertoires_uuid


def read_conf_load_send_Segment_file(objectxmpp):
    """
    Lire la configuration du plugin.
    Le dossier contenant le fichier de configuration est dans la variable objectxmpp.config.pathdirconffile.

    Args:
        objectxmpp (object): L'objet XMPP.

    Returns:
        None
    """
    nameconffile = plugin["NAME"] + ".ini"
    pathconffile = os.path.join(objectxmpp.config.pathdirconffile, nameconffile)
    if not os.path.isfile(pathconffile):
        logger.info("pas de fichiers de configuration  %s " % pathconffile)
    else:
        # Implémentez la configuration
        # Config = configparser.ConfigParser()
        # Config.read(pathconffile)
        # if os.path.exists(pathconffile + ".local"):
        #     Config.read(pathconffile + ".local")
        pass
