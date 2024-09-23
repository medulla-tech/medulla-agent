# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2016-2023 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-3.0-or-later

# file: pulse_xmpp_agent/[pluginsrelay | pluginsmachine]/plugin_backup_restore.py
# file: pulse_xmpp_agent/pluginsmachine/plugin_backup_restore.py

import logging
import traceback
from threading import Condition
import os
import sys

import psutil
import socket
import ipaddress

import hashlib

from lib.agentconffile import (
    directoryconffile,
)
# from lib.networkinfo import find_common_addresses, get_CIDR_ipv4_addresses
import subprocess
from lib.utils import pulseuser_useraccount_mustexist, pulseuser_profile_mustexist, create_idrsa_on_client, getHomedrive, simplecommand
import platform
import configparser
import json
from pathlib import PurePosixPath, Path

if sys.platform.startswith("linux") or sys.platform.startswith("darwin"):
    import pwd

logger = logging.getLogger()

remote_host = None

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

    :param objectxmpp: The XMPP object.
    :param action: The action to be performed.
    :param sessionid: The session ID.
    :param data: The data containing IP list, file list, directory list, etc.
    :param message: The message object.
    :param dataerreur: Error data.
    """
    logger.debug("###################################################")
    logger.debug("call %s from %s" % (plugin, message["from"]))
    logger.debug("###################################################")
    # logger.debug("MESSAGE")
    logger.debug("%s" % json.dumps(data, indent=4))
    # strjidagent = str(objectxmpp.boundjid.bare)


    compteurcallplugin = getattr(objectxmpp, f"num_call{action}", None)
    if compteurcallplugin is None:
        logger.error(f"num_call attribute for action {action} not found on objectxmpp")
        return

    with config_condition:
        # Si c'est le premier appel du plugin, on configure
        # tant que pas configurer les concurant attentent pour profiter de la conf aussi.
        # et pas provoquer des erreurs par manque de configuration
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

    # Execution du corps du plugin une fois la configuration terminee
    # logger.debug("corp plugin")

    try:
        server_ip_networks = data["ip_list"]
        client_ip_networks = get_ip_and_netmask_linux()
        remote_host = find_best_server_address(server_ip_networks, client_ip_networks)
        if not remote_host:
            logger.error("le serveur urbackup n'est pas dans le reseau de la machine.")
            logger.error("SERVEUR IP : %s", server_ip_networks)
            logger.error("CLIENT IP : %s", client_ip_networks )
            return
    except Exception as e:
        logger.error("termine plugin %s" % (traceback.format_exc()))
        return
    logger.debug("IP serveur CONNECT. %s" % remote_host)

    try:
        # Make sure user account and profile exists
        result, message = pulseuser_useraccount_mustexist(
            objectxmpp.username
        )
        if result is False:
            logger.error(f"{message}")
            return
        logger.debug(f"{message}")
        result, message = pulseuser_profile_mustexist(objectxmpp.username)
        if result is False:
            logger.error(f"{message}")
            return
        logger.debug(f"{message}")
        result, message = create_idrsa_on_client(
            objectxmpp.username,
            data['key_private']
        )
        if result is False:
            logger.error(f"{message}")
            return
        logger.debug(f"{message}")
    except Exception as e:
        logger.error(f"{e}")
        return

    id_rsa_path = os.path.join(getHomedrive(), ".ssh", objectxmpp.private_name_key)

    copy_files_and_directories(objectxmpp.remote_user,
                               remote_host,
                               data['filelist'],
                               data['directorylist'],
                               data['base_path'],
                               private_key_path=id_rsa_path,
                               restore_to_backup_location = objectxmpp.restore_to_backup_location)

def read_conf_plugin_backup_restore(objectxmpp):
    """
    Reads and loads the configuration for the backup_restore plugin.
    If the configuration file `backup_restore.ini` does not exist, it is created with default values.

    :param objectxmpp: The XMPP object to which the configuration values will be assigned.
    :type objectxmpp: object
    """
    try:
        # Vérification de l'agenttype pour déterminer le fichier de configuration
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

        Config = configparser.ConfigParser()

        # Si le fichier de configuration n'existe pas, le créer avec un contenu par défaut
        if not os.path.isfile(configfilename):
            logger.warning(f"Configuration file {configfilename} not found. Creating it...")

            config_content = """[backup_restore]
remote_user = urbackup

# La clé privée est normalement celle de reverse_ssh.
# La clé publique id_rsa.pub de reverse_ssh doit être inscrite dans /var/urbackup/authorized_keys afin de permettre l'authentification de la machine locale vers le serveur de sauvegarde.
# Sur la machine locale,
# on donne un autre nom à la même clé que id_rsa de reverse_ssh, par exemple pulseuser_backup_id_rsa.
# pulseuser_backup_id_rsa est réinstallée à chaque demande de transfert de sauvegarde en locale.
# Elle est en fait une copie de la clé privée id_rsa de reverse_ssh.
# Cela permet de diminuer le risque de corruption de la copie de la clé en cas d'erreur de plugin.

private_name_key = pulseuser_backup_id_rsa

username = pulseuser
# on utilise le profil de pulseuser pour inscrire la clef privet

# restore_to_backup_location 'True' signifie que les fichiers récupérés seront placés dans le répertoire de sauvegarde :
# C:\\Program Files\\Medulla\\var\\backup_files pour Windows
# /var/lib/pulse2/backup_files pour Darwin ou Linux
restore_to_backup_location = True
"""
            # Écrire le fichier de configuration avec le contenu par défaut
            with open(configfilename, 'w') as configfile:
                configfile.write(config_content)

            logger.info(f"Configuration file {configfilename} has been created with default content.")

        # Charger les valeurs du fichier de configuration
        Config.read(configfilename)
        if os.path.isfile(configfilename + ".local"):
            Config.read(configfilename + ".local")
        logger.debug(f"Loaded configuration from {configfilename}")

        # Récupérer les valeurs de configuration ou les valeurs par défaut
        objectxmpp.remote_user = Config.get('backup_restore', 'remote_user', fallback='urbackup')
        objectxmpp.private_name_key = Config.get('backup_restore', 'private_name_key', fallback='pulseuser_backup_id_rsa')
        objectxmpp.username = Config.get('backup_restore', 'username', fallback='pulseuser')
        objectxmpp.restore_to_backup_location = Config.getboolean('backup_restore', 'restore_to_backup_location', fallback=True)

        logger.debug(f"Configuration values set: remote_user={objectxmpp.remote_user}, "
                     f"private_name_key={objectxmpp.private_name_key}, "
                     f"username={objectxmpp.username}, "
                     f"restore_to_backup_location={objectxmpp.restore_to_backup_location}")

    except Exception as e:
        logger.error(f"Error reading or creating configuration: {str(e)}")
        logger.error("\n%s" % (traceback.format_exc()))


def copy_files_and_directories(remote_user,
                               remote_host,
                               files,
                               directories,
                               base_path,
                               private_key_path=None,
                               restore_to_backup_location=True):
    """
    Copies files and directories from a remote host to the local machine.

    :param remote_user: The remote user for SSH.
    :param remote_host: The remote host.
    :param files: List of files to copy.
    :param directories: List of directories to copy.
    :param base_path: The base path for the backup.
    :param private_key_path: The path to the private key for SSH.
    :param restore_to_backup_location: Whether to restore files to the backup location.
    """
    if private_key_path is None:
        private_key_path = os.path.join(getHomedrive(), ".ssh", "id_rsa")

    if restore_to_backup_location:
        # on etablie la base ou vont etre mis les backups recuperer.
        # rappel que ce plugin et pour recuperer des fichiers sur 1 autre machine.
        # il y a trop de risque de placer les fichier directement a l'emplacement de depart.
        # mais la hierachi est respecter depuis cette basse backup_path
        backup_path = get_backup_path()

    # Determiner le systeme d'exploitation
    system = platform.system()
    # Chemins des executables
    if system == 'Windows':
        rsync_path = r'C:\Windows\SysWOW64\rsync.exe'
        ssh_path = r'C:\Progra~1\OpenSSH\ssh.exe'
        scp_path = r'C:\Progra~1\OpenSSH\scp.exe'
    else:  # Linux
        rsync_path = 'rsync'
        ssh_path = 'ssh'
        scp_path = 'scp'
    # Verifier si rsync est disponible que pour windows

    # cette ligne sera a decomenter
    rsync_available = False
    # rsync_available = os.path.exists(rsync_path) if system == 'Windows' else True


    # quand on poura ectire la commande rsync en windows. avec clef ssh
    # C:\Windows\SysWOW64\rsync.exe -L -z --rsync-path=rsync
    #                               -e "C:/Program Files/OpenSSH/ssh.exe
    #                                               -o IdentityFile=c:/users/pulseuser/.ssh/pulseuser_backup_id_rsa
    #                                               -o UserKnownHostsFile=/dev/null
    #                                               -o StrictHostKeyChecking=no
    #                                               -o Batchmode=yes
    #                                               -o PasswordAuthentication=no
    #                                               -o ServerAliveInterval=10
    #                                               -o CheckHostIP=no
    #                                               -o LogLevel=ERROR
    #                                               -o ConnectTimeout=10"
    #       -av --chmod=777
    #       urbackup@10.10.0.100:/media/BACKUP/urbackup/amu-win-6/240916-1727/Users/desktop.ini
    #       "C:/Program Files/Medulla/var/backup_files/C_0/Users/desktop.ini

    cmd = (
        """%s -r -p -C "-o IdentityFile=%s" "-o UserKnownHostsFile=/dev/null" "-o StrictHostKeyChecking=no" "-o Batchmode=yes" "-o PasswordAuthentication=no" "-o ServerAliveInterval=10" "-o CheckHostIP=no" "-o LogLevel=ERROR" "-o ConnectTimeout=10" """
        % (
            scp_path,
            private_key_path,
        )
    )
    if rsync_available:
        cmd = (
            """%s -L -z --rsync-path=rsync -e "%s -o IdentityFile=%s -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no -o Batchmode=yes -o PasswordAuthentication=no -o ServerAliveInterval=10 -o CheckHostIP=no -o LogLevel=ERROR -o ConnectTimeout=10" -av --chmod=777 """
            % (
                rsync_path,
                ssh_path,
                private_key_path,
            )
        )

    # Copier les fichiers
    for src, dest in files:
        # le serveur urbackup est sur linux on determine depuis 1 machine windows le chemin dans linux
        # Utiliser PurePosixPath pour construire un chemin specifique e Linux
        logger.debug(f"base_path: {base_path}")
        if restore_to_backup_location:
            modified_path_dest = modify_backup_path(backup_path, dest)
        else:
            modified_path_dest = dest
        linux_path = PurePosixPath(base_path) / src
        # Convertir le chemin en une chaine de caracteres
        srcfile = str(linux_path)
        logger.debug(f"srcfile: {srcfile}")
        remotesrc = """%s@%s:%s """ % (remote_user, remote_host, srcfile)
        # remotesrc = "urbackup@10.10.0.100:/media/BACKUP/urbackup/amu-win-6/240916-1727/Users/desktop.ini"
        create_directories(get_directory_path(modified_path_dest))
        # dest = ' C:/Users/blablabla.txt'
        command = cmd + remotesrc + '"'+modified_path_dest+'"'

        # command = cmd + remotesrc + modified_path_dest
        logger.debug(f"Command: {command}")
        obj = simplecommand(command)
        logger.warning(f"Transfer file : {obj['code']} {obj['result']}")

        if obj['code'] == 1:
            logger.warning(f"Transfer mais link non creer : { obj['code']}")
            logger.warning(f"nb link {len(obj['result'])}")
            logger.warning("liste link")
            for linelogresult in obj['result']:
                logger.warning("{ linelogresult.strip()}")
        elif obj['code'] != 0:
            logger.error(f"Transfer error: { obj['code']}")
            logger.error(f"Transfer error: sur nb file : {len(obj['result'])}")

        else:
            if len(obj['result']) > 0:
                for linelogresult in obj['result']:
                    logger.debug("Transfer successful")
                    logger.debug("{ linelogresult.strip()}")
            else:
                logger.warning("Transfer successful")

    # Copier les repertoires
    for src, dest in directories:
        # le serveur urbackup est sur linux on determine depuis 1 machine windows le chemin dans linux
        # Utiliser PurePosixPath pour construire un chemin specifique e Linux
        logger.debug(f"src dest: {src} {dest}")
        logger.debug(f"base_path: {base_path}")
        if restore_to_backup_location:
            modified_path_dest = modify_backup_path(backup_path, dest)
        else:
            modified_path_dest = dest
        logger.debug(f"dest: {modified_path_dest}")
        linux_path = PurePosixPath(base_path) / src
        # Convertir le chemin en une chaene de caracteres
        srcdirectory = str(linux_path)
        logger.debug(f"srcdirectory: {srcdirectory}")
        remotesrc = """%s@%s:"%s" """ % (remote_user, remote_host, srcdirectory)
        # create_directories(modified_path_dest)
        create_directories(get_directory_path(modified_path_dest))
        command = cmd + remotesrc + '"'+modified_path_dest+'"'
        logger.debug(f"Command: {command}")
        obj = simplecommand(command)
        if rsync_available:
            if obj['code'] != 0:
                logger.error(f"Transfer error code error: { obj['code']}")
                logger.error(f"error message : {obj['result']}")
            else:
                logger.debug("Transfer successful")
        else:
            if obj['code'] == 1:
                logger.warning(f"Transfer mais link non creer : { obj['code']}")
                logger.warning(f"nb link {len(obj['result'])}")
                logger.warning("liste link from serveur %s" % base_path)
                if restore_to_backup_location:
                    logger.warning("to %s" % backup_path)
                backup_path_slach_linux = str(backup_path).replace("\\", "/")
                logger.warning("to %s" % backup_path_slach_linux)
                stringmessage = scp_path + ": Download of file " + base_path
                # Remplacement de stringmessage dans chaque élément de la liste
                for linelogresult in obj['result']:
                    linestr = linelogresult.replace(stringmessage, "").strip()
                    # if restore_to_backup_location:
                    linestr1 = linestr.replace( backup_path_slach_linux, "")
                    linestr1 = linestr1.replace(str(scp_path), "")
                    logger.warning(f"{linestr1}")
            elif obj['code'] != 0:
                logger.error(f"Transfer error: { obj['code']}")
                logger.error(f"Transfer error: sur nb file : {len(obj['result'])}")
            else:
                if len(obj['result']) > 0:
                    for linelogresult in obj['result']:
                        logger.debug("Transfer successful")
                        logger.debug(f"{linelogresult.strip()}")
                else:
                    logger.warning("Transfer successful")

def get_ip_and_netmask_linux(exclude_local=True):
    """
    Retrieves the IP addresses and netmasks of the local machine.

    :param exclude_local: Whether to exclude local addresses.
    :type exclude_local: bool
    :return: List of tuples containing IP addresses and netmasks.
    :rtype: list of tuples
    """
    ip_netmask_list = []
    # Parcours de toutes les interfaces reseau
    for interface, addrs in psutil.net_if_addrs().items():
        for addr in addrs:
            if addr.family == socket.AF_INET:  # Ne prend que les adresses IPv4
                ip = addr.address
                netmask = addr.netmask

                # Exclure les adresses locales si exclude_local est True
                if exclude_local:
                    ip_obj = ipaddress.ip_address(ip)
                    if ip_obj.is_loopback or ip_obj.is_link_local:
                        continue  # On passe e l'iteration suivante si c'est une adresse locale
                ip_netmask_list.append((ip, netmask))
    return ip_netmask_list

def find_best_server_address(server_addresses, client_addresses):
    """
    Finds the best server address that is in the same network as the client.

    :param server_addresses: List of server IP addresses and netmasks.
    :type server_addresses: list of tuples
    :param client_addresses: List of client IP addresses and netmasks.
    :type client_addresses: list of tuples
    :return: The best server IP address or None if no common network is found.
    :rtype: str or None
    """
    for client_ip, client_netmask in client_addresses:
        client_network = ipaddress.IPv4Network(f"{client_ip}/{client_netmask}", strict=False)
        for server_ip, server_netmask in server_addresses:
            server_network = ipaddress.IPv4Network(f"{server_ip}/{server_netmask}", strict=False)
            # Verifie si le client et le serveur sont dans le meme reseau
            if client_network.overlaps(server_network):
                return server_ip  # Retourne l'adresse du serveur dans le meme reseau que le client
    return None  # Aucun reseau commun trouve

def get_backup_path():
    """
    Determines the backup path based on the operating system.

    :return: The backup path.
    :rtype: Path
    """
    # Déterminer le système d'exploitation
    system = platform.system()

    # Définir le chemin du répertoire de sauvegarde en fonction du système d'exploitation
    if system == "Windows":
        backup_path = Path("C:/Program Files/Medulla/var/backup_files")
    elif system in ["Linux", "Darwin"]:
        backup_path = Path("/var/lib/pulse2/backup_files")
    else:
        raise OSError(f"Système d'exploitation non pris en charge: {system}")

    # Créer le répertoire s'il n'existe pas
    backup_path.mkdir(parents=True, exist_ok=True)

    return backup_path

def modify_backup_path(base_dir, restore_path):
    """
    Modifies the backup path to include the drive letter.

    :param base_dir: The base directory for the backup.
    :param restore_path: The restore path.
    :return: The modified backup path.
    :rtype: str
    """
    # Convertir le chemin de restauration en chemin absolu
    drive_letter = restore_path.replace(':', '_0')
    modified_path = os.path.join(base_dir, drive_letter)
    modified_path =  modified_path.replace('\\', '/')
    return modified_path

def create_directories(path):
    """
    Creates the necessary directories.

    :param path: The path to create directories for.
    :type path: str
    """
    # Créer les répertoires nécessaires
    os.makedirs(path, exist_ok=True)

def get_directory_path(file_path):
    """
    Gets the directory path from a file path.

    :param file_path: The file path.
    :type file_path: str
    :return: The directory path.
    :rtype: str
    """
    # Récupérer le chemin du répertoire sans le nom du fichier
    directory_path = os.path.dirname(file_path)
    return directory_path

class FileHasher:
    """
    A class to calculate the MD5 hash of a file.
    """
    def __init__(self, file_path):
        """
        Initializes the FileHasher with the file path.

        :param file_path: The path to the file.
        :type file_path: str
        """
        self.file_path = file_path

    def calculate_hash(self):
        """
        Calculates the MD5 hash of the file.

        :return: The MD5 hash of the file.
        :rtype: str
        """
        hash_md5 = hashlib.md5()
        with open(self.file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_md5.update(chunk)
        return hash_md5.hexdigest()
