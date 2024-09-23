# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2016-2023 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-3.0-or-later
# file: pulse_xmpp_agent/pluginsrelay/plugin_backup_restore.py
# file: pulse_xmpp_agent/pluginsmachine/plugin_backup_restore.py
import logging
import traceback
import time
from threading import Lock
from threading import Condition
import os
import hashlib

logger = logging.getLogger()

plugin = {"VERSION": "1.0", "NAME": "backup_restore", "TYPE": "all"}  # fmt: skip

# Verrou pour la synchronisation de la configuration
# config_lock = Lock()

config_condition = Condition()

def action(objectxmpp, action, sessionid, data, message, dataerreur):
    """
    Fonction principale du plugin "backup_restore" qui gère l'action de restauration.

    Cette fonction est appelée par le système XMPP avec les paramètres appropriés pour effectuer des
    actions spécifiques de restauration. Elle vérifie si la configuration du plugin
    a déjà été effectuée et attend que cette configuration soit terminée avant d'exécuter ce a quoi le plugin est cree.

    Args:
        objectxmpp (object): L'objet XMPP représentant l'agent en cours d'exécution.
        action (str): L'action à réaliser, ici 'plugin_backup_restore'.
        sessionid (str): Identifiant unique de la session en cours.
        data (dict): Données fournies pour l'exécution du plugin, telles que la liste des répertoires et fichiers.
        message (dict): Message contenant les informations sur l'émetteur.
        dataerreur (dict): dict message pour repondre aa l'appelant d'une des erreurs lors de l'exécution.

    Returns:
        None
    """
    logger.debug("###################################################")
    logger.debug("call %s from %s" % (plugin, message["from"]))
    logger.debug("###################################################")
    compteurcallplugin = getattr(objectxmpp, f"num_call{action}", None)
    if compteurcallplugin is None:
        logger.error(f"num_call attribute for action {action} not found on objectxmpp")
        return

    with config_condition:
        # Si c'est le premier appel du plugin, on configure
        if compteurcallplugin == 0:
            if not hasattr(objectxmpp, 'configuration_done') or not objectxmpp.configuration_done:
                logger.debug("Starting initial configuration")
                read_conf_plugin_backup_restore(objectxmpp)
                objectxmpp.configuration_done = True
                config_condition.notify_all()
                logger.debug("Configuration done")
        else:
            # Si la configuration n'est pas encore faite, attendre sa fin
            while not hasattr(objectxmpp, 'configuration_done') or not objectxmpp.configuration_done:
                config_condition.wait()

    # Exécution du corps du plugin une fois la configuration terminée
    if 'directorylist' in data and data['directorylist']:
        for directory in data['directorylist']:
            logger.debug(f"Processing directory: {directory}")

def read_conf_plugin_backup_restore(objectxmpp):
    """
    Fonction pour lire et charger la configuration spécifique au plugin "backup_restore".

    Gère les exceptions liées à l'accès aux fichiers de configuration et au parsing.

    Args:
        objectxmpp (object): L'objet XMPP représentant l'agent en cours d'exécution.

    Returns:
        None
    """
    try:
        if objectxmpp.config.agenttype in ["machine"]:
            configfilename = os.path.join(directoryconffile(), "backup_restore.ini")
        elif objectxmpp.config.agenttype in ["relayserver"]:
            configfilename = os.path.join(directoryconffile(), "backup_restore.ini")
        else:
            logger.error(
                "The %s agenttype is not supported in this function, it must be machine or relayserver."
                % objectxmpp.config.agenttype
            )
            return

        if os.path.isfile(configfilename):
            Config = configparser.ConfigParser()
            Config.read(configfilename)
            if os.path.isfile(configfilename + ".local"):
                Config.read(configfilename + ".local")
            logger.debug(f"Loaded configuration from {configfilename}")
        else:
            logger.warning(f"Configuration file {configfilename} not found.")
    except Exception as e:
        logger.error(f"Error reading configuration: {str(e)}")
        traceback.print_exc()

class FileHasher:
    def __init__(self, file_path):
        self.file_path = file_path

    def calculate_hash(self):
        hash_md5 = hashlib.md5()
        with open(self.file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_md5.update(chunk)
        return hash_md5.hexdigest()

