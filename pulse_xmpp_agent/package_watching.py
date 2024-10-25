#!/usr/bin/python3
# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2016-2023 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-3.0-or-later

# """
# This module is dedicated to monitoring events related to the creation, deletion, and modification of package files
# and notifying the package system that the modifications have been made.
# """
# file pulse_xmpp_agent/package_watching.py

# API information http://seb.dbzteam.org/pyinotify/

import socket
import pyinotify
import os
import json
import random
import sys
import configparser
import logging
from logging.handlers import RotatingFileHandler
import getopt
import threading
from lib.utils import simplecommandstr, decode_strconsole, getRandomName
import traceback
import os
import hashlib
from datetime import datetime
import zipfile
import uuid
import time
import re
import base64
import shutil

# Configuration du logger
logger = logging.getLogger()
logger.setLevel(logging.DEBUG)

conf = {}

inifile = "/etc/pulse-xmpp-agent/package_watching.ini"
pidfile = "/var/run/package_watching.pid"
# Configuration de base pour le logging
log_file = "/var/log/pulse/pulse-package-watching.log"
# parametre for logging rotation
max_bytes = 10 * 1024 * 1024  # 10 Mo
backup_count = 5  # Nombre de fichiers de log à conserver

# Configuration du handler pour la rotation des fichiers de log
file_handler = RotatingFileHandler(log_file, maxBytes=max_bytes, backupCount=backup_count)
file_handler.setLevel(logging.DEBUG)
formatter = logging.Formatter("%(asctime)s %(levelname)s %(message)s")
file_handler.setFormatter(formatter)
logger.addHandler(file_handler)

# Fonction pour ajouter un gestionnaire de logging pour la console
def add_console_handler():
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logging.DEBUG)
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)


class configerror(Exception):
    """Exception raised for errors in the file configuration.

    Attributes:
        expr -- input expression in which the error occurred
        msg  -- explanation of the error
    """

    def __init__(self, expr="Error Config", msg=""):
        self.expr = expr
        self.msg = msg


# Fonction pour valider une adresse IPv4
def is_valid_ipv4(ip):
    if ip == "localhost":
        return True
    ipv4_pattern = re.compile(r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\$')
    return ipv4_pattern.match(ip) is not None

# Fonction pour valider un port
def is_valid_port(port):
    return 1 <= port <= 65535

def conf_information(conffile):
    Config = configparser.ConfigParser()
    Config.read(conffile)
    Config.read(f"{conffile}.local")

    section_file_de_conf=['global', 'watchingfile', 'network_agent', 'notifyars', 'rsynctocdn', 'segment_package']
    for sectioni_in_ini in section_file_de_conf:
        if not Config.has_section(sectioni_in_ini):
            Config.add_section(sectioni_in_ini)

    # creation et initialisation network informations de confoguration
    configdata = {
        "ip_ars": Config.get("network_agent", "ip_ars", fallback="localhost"),
        "port_ars": Config.getint("network_agent", "port_ars", fallback=8765)
    }

    # Vérifier que ip_ars est une adresse IPv4 valide
    if not is_valid_ipv4(configdata["ip_ars"]):
        logger.warning(f"L'adresse IP {configdata['ip_ars']} n'est pas une adresse IPv4 valide. on applique localhost")
        configdata["ip_ars"] = "localhost"

    # Vérifier que port_ars est un port valide
    if not is_valid_port(configdata["port_ars"]):
        logger.warning(f"Le port {configdata['port_ars']} n'est pas un port valide. on applique 8765")
        configdata['port_ars'] = 8765

    level = Config.get('global', 'log_level', fallback="INFO")

    # Mise à jour en fonction du niveau de logs spécifiés
    if level == "CRITICAL":
        configdata['log_level'] = logging.CRITICAL
    elif level == "ERROR":
        configdata['log_level'] = logging.ERROR
    elif level == "WARNING":
        configdata['log_level'] = logging.WARNING
    elif level == "INFO":
        configdata['log_level'] = logging.INFO
    elif level == "DEBUG":
        configdata['log_level'] = logging.DEBUG
    elif level == "NOTSET":
        configdata['log_level'] = logging.NOTSET
    else:
        # utiliser un niveau par défaut
        configdata['log_level'] = logging.DEBUG

    filelist = Config.get('watchingfile', 'filelist', fallback="/var/lib/pulse2/packages")
    if filelist == "":
        filelist="/var/lib/pulse2/packages"
        logger.warning(f"le parametre filelist pour watchingfile est vide. on applique /var/lib/pulse2/packages")

    configdata["filelist"] = filelist.split(",")

    excludelist = Config.get('watchingfile', 'excludelist', fallback=None)
    if excludelist is not None and len(excludelist) != 0:
        configdata["excludelist"] = excludelist.split(",")
    else:
        configdata["excludelist"] = None

    configdata["notifyars_enable"] = Config.getboolean('notifyars', 'enable', fallback=True)
    configdata["rsynctocdn_enable"] = Config.getboolean("rsynctocdn", "enable", fallback=False)
    if configdata["rsynctocdn_enable"]:
        configdata["rsynctocdn_localfolder"] = Config.get("rsynctocdn", "localfolder", fallback="/var/lib/pulse2/packages/sharing")
        configdata["rsynctocdn_rsync_options"] = Config.get("rsynctocdn", "rsync_options", fallback='--archive --del --exclude ".stfolder"')
        configdata["rsynctocdn_ssh_privkey_path"] = Config.get("rsynctocdn", "ssh_privkey_path", fallback="/root/.ssh/id_rsa")
        configdata["rsynctocdn_ssh_options"] = Config.get("rsynctocdn", "ssh_options",
                                                        fallback="-oBatchMode=yes -oServerAliveInterval=5 -oCheckHostIP=no -oLogLevel=ERROR -oConnectTimeout=40 -oHostKeyAlgorithms=+ssh-dss")
        configdata["rsynctocdn_ssh_remoteuser"] = Config.get("rsynctocdn", "ssh_remoteuser", fallback=None)
        if not configdata["rsynctocdn_ssh_remoteuser"]:
            raise configerror(msg="ssh_remoteuser is not defined")

        configdata["rsynctocdn_ssh_servername"] = Config.get("rsynctocdn", "ssh_servername", fallback=None)
        if not configdata["rsynctocdn_ssh_servername"]:
            raise configerror(msg="ssh_servername is not defined")

        configdata["rsynctocdn_ssh_destpath"] = Config.get("rsynctocdn", "ssh_destpath", fallback=None)
        if not configdata["rsynctocdn_ssh_destpath"]:
            raise configerror(msg="ssh_destpath is not defined")
    return configdata



def getRandomName(nb, pref=""):
    a = "abcdefghijklnmopqrstuvwxyz0123456789"
    d = pref
    for _ in range(nb):
        d = d + a[random.randint(0, 35)]
    return d


def send_agent_data(datastrdata, conf):
    logger.debug(f"string for send agent : {datastrdata}")
    # Convertir la chaîne en bytes
    datastrdata_bytes = datastrdata.encode("utf-8")
    # Encoder les bytes en base64
    EncodedString = base64.b64encode(datastrdata_bytes)
    logger.debug(f"send base64 string  : {EncodedString}")
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_address = (conf["ip_ars"], int(conf["port_ars"]))
    logger.debug(f"send address {conf['ip_ars']}:{conf['port_ars']}")
    try:
        sock.connect(server_address)
        sock.sendall(EncodedString)
        sock.recv(4096)
        logger.debug("send to ARS event")
    except Exception as e:
        logger.error(str(e))
    finally:
        sock.close()

def rsync_to_cdn(conf):
    if not conf["rsynctocdn_localfolder"].endswith(os.sep):
        localfolder = conf["rsynctocdn_localfolder"] + os.sep
    else:
        localfolder = conf["rsynctocdn_localfolder"]
    if not conf["rsynctocdn_ssh_destpath"].endswith(os.sep):
        remotefolder = conf["rsynctocdn_ssh_destpath"] + os.sep
    else:
        remotefolder = conf["rsynctocdn_ssh_destpath"]
    rsync_cmd = 'rsync %s -e "ssh -i %s %s" %s %s@%s:%s' % (
        conf["rsynctocdn_rsync_options"],
        conf["rsynctocdn_ssh_privkey_path"],
        conf["rsynctocdn_ssh_options"],
        localfolder,
        conf["rsynctocdn_ssh_remoteuser"],
        conf["rsynctocdn_ssh_servername"],
        remotefolder,
    )
    logger.debug("rsync command: %s" % rsync_cmd)
    objcmd = simplecommandstr(rsync_cmd)
    logger.debug("rsync command result: %s" % objcmd["result"])
    if objcmd["code"] != 0:
        logger.error(
            "Error synchronizing packages to CDN" % decode_strconsole(objcmd["result"])
        )

def pathlist(watch):
    return [watch[z].path for z in watch]


def listdirfile(rootdir):
    file_paths = []
    for folder, subs, files in os.walk(rootdir):
        dd = [os.path.join(folder, x) for x in subs]
        file_paths = file_paths + dd
    return file_paths


class MyEventHandler(pyinotify.ProcessEvent):

    def __init__(self, config, wm, mask):
        self.config = config
        self.wm = wm
        self.mask = mask


    def find_directory_with_criteria(self, path):
        """
        Recherche un répertoire dans le chemin donné qui commence par un nom de 36 caractères
        avec un tiret (`-`) au 9ème caractère.

        Args:
            path (str): Chemin de base où commencer la recherche.

        Returns:
            str or None: Nom du premier répertoire trouvé qui correspond au motif, ou None si aucun n'est trouvé.
        """
        # Diviser le chemin en composants
        components = path.split(os.sep)

        # Parcourir chaque composant du chemin
        for component in components:
            # Vérifier si la longueur est de 36 caractères et si le 9ème caractère est un tiret "-"
            if len(component) == 36 and component[8] == '-':
                return component

        # Si aucun répertoire n'est trouvé, retourner None
        return None


    def msg_structure(self):
        return {
            "action": "notifysyncthing",
            # "sessionid" : getRandomName(6, "syncthing"),
            "data": "",
        }

    def process_IN_ACCESS(self, event):
        typefile = "directory" if event.dir else "file"
        logger.debug(f"IN_ACCESS {typefile} : {event.pathname}")


    def process_IN_ATTRIB(self, event):
        typefile = "directory" if event.dir else "file"
        logger.debug(f"IN_ATTRIB {typefile} : {event.pathname}")


    def process_IN_CLOSE_NOWRITE(self, event):
        typefile = "directory" if event.dir else "file"
        logger.debug(f"IN_CLOSE_NOWRITE {typefile} : {event.pathname}")


    def process_IN_CLOSE_WRITE(self, event):
        typefile = "directory" if event.dir else "file"
        logger.debug(f"IN_CLOSE_WRITE {typefile} : {event.pathname}")


    def process_IN_OPEN(self, event):
        typefile = "directory" if event.dir else "file"
        logger.debug(f"IN_OPEN {typefile} : {event.pathname}")

    def process_IN_MOVED_TO(self, event):
        if event.dir:
            return
        if self.config["notifyars_enable"]:
            datasend = self.msg_structure()
            difffile = [os.path.dirname(event.pathname)]
            datasend["data"] = {
                "MotifyFile": event.pathname,
                "notifydir": difffile,
                "packageid": os.path.basename(os.path.dirname(event.pathname)),
            }
            datasendstr = json.dumps(datasend, indent=4)
            logger.debug(f"Msg : {datasendstr}")
            send_agent_data(datasendstr, self.config)
        if self.config["rsynctocdn_enable"]:
            # Run rsync command
            rsync_to_cdn(self.config)

    def process_IN_MODIFY(self, event):
        typefile = "directory" if event.dir else "file"
        logger.debug(f"MODIFY {typefile} : {event.pathname}")
        if self.config["notifyars_enable"]:
            namefile = str(os.path.basename(event.pathname))
            if namefile.startswith(".syncthing"):
                return
            datasend = self.msg_structure()
            difffile = [os.path.dirname(event.pathname)]
            datasend["data"] = {
                "difffile": event.pathname,
                "notifydir": difffile,
                "packageid": os.path.basename(os.path.dirname(event.pathname)),
            }
            datasendstr = json.dumps(datasend, indent=4)
            logger.debug(f"Msg : {datasendstr}")
            send_agent_data(datasendstr, self.config)
        if self.config["rsynctocdn_enable"]:
            # Run rsync command
            rsync_to_cdn(self.config)

    def process_IN_DELETE(self, event):
        # Supprimez l'observateur pour le fichier ou répertoire supprimé
        self.wm.rm_watch(event.pathname, rec=True)
        typefile = "directory" if event.dir else "file"
        logger.debug(f"DELETE {typefile} : {event.pathname}")
        if self.config["notifyars_enable"]:
            datasend = self.msg_structure()
            if not event.dir:
                return
            disupp = [os.path.dirname(event.pathname)]
            datasend["data"] = {
                "suppdir": event.pathname,
                "notifydir": disupp,
                "packageid": os.path.basename(event.pathname),
            }
            datasendstr = json.dumps(datasend, indent=4)
            logger.debug(f"Msg : {datasendstr}")
            send_agent_data(datasendstr, self.config)
        if self.config["rsynctocdn_enable"]:
            # Run rsync command
            rsync_to_cdn(self.config)

    def process_IN_CREATE(self, event):
        # Ajoutez un observateur pour le nouveau fichier ou répertoire
        self.wm.add_watch(event.pathname,
                          pyinotify.IN_MODIFY | pyinotify.IN_CREATE | pyinotify.IN_DELETE,
                          rec=True)
        typefile = "directory" if event.dir else "file"
        logger.debug(f"CREATE {typefile} : {event.pathname}")
        if self.config["notifyars_enable"]:
            datasend = self.msg_structure()
            if event.dir:
                directory_added = [os.path.dirname(event.pathname)]
                datasend["data"] = {
                    "adddir": event.pathname,
                    "notifydir": directory_added,
                    "packageid": os.path.basename(event.pathname),
                }
                datasendstr = json.dumps(datasend, indent=4)
                logger.debug(f"Msg : {datasendstr}")
                send_agent_data(datasendstr, self.config)
        if self.config["rsynctocdn_enable"]:
            # Run rsync command
            rsync_to_cdn(self.config)

class WatchingFilePartage :
    """
    A class to watch for file changes in specified directories using inotify.

    Attributes:
        config (dict): Configuration dictionary containing 'filelist' and 'excludelist'.
        stop_event (threading.Event): An event to signal the watcher to stop.
        wm (pyinotify.WatchManager): The Watch Manager instance.
        mask (int): The event mask for inotify.
        handler (MyEventHandler): The event handler for inotify events.
        notifier (pyinotify.ThreadedNotifier): The notifier for handling inotify events.

    Methods:
        __init__(self, config, stop_event): Initializes the WatchingFilePartage instance.
        run(self): Starts the file watching process.
        stop(self): Stops the file watching process.
    """

    def __init__(self, config, stop_event):
        """
        Initializes the WatchingFilePartage instance.

        Args:
            config (dict): Configuration dictionary containing 'filelist' and 'excludelist'.
            stop_event (threading.Event): An event to signal the watcher to stop.
        """
        self.config = config
        self.stop_event = stop_event
        logger.info("install inotify")
        listdirectory = [x for x in config["filelist"] if os.path.isdir(x)]
        startlistdirectory = [x for x in config["filelist"] if os.path.isdir(x)]
        for t in startlistdirectory:
            listdirectory = listdirectory + listdirfile(t)
        listdirectory = list(set(listdirectory))
        self.wm = pyinotify.WatchManager()  # Watch Manager
        self.mask = (
            pyinotify.IN_CREATE
            | pyinotify.IN_MODIFY
            | pyinotify.IN_DELETE
            | pyinotify.IN_MOVED_TO
        )  # | pyinotify.IN_CLOSE_WRITE

        self.handler = MyEventHandler(self.config, self.wm, self.mask)
        if config["excludelist"] is not None:
            excl = pyinotify.ExcludeFilter(config["excludelist"])
            self.wm.add_watch(listdirectory, self.mask, rec=True, exclude_filter=excl)
        else:
            self.wm.add_watch(listdirectory, self.mask, rec=True)

    def run(self):
        """
        Starts the file watching process.
        """
        self.notifier = pyinotify.ThreadedNotifier(self.wm, self.handler)
        self.notifier.start()
        while not self.stop_event.is_set():
            time.sleep(1)
        self.notifier.stop()

    def stop(self):
        """
        Stops the file watching process.
        """
        self.notifier.stop()


def schedule_action(stop_event):
    while not stop_event.is_set():
        # action cyclque
        time.sleep(5)



def close_file_descriptors():
    """Close standard file descriptors to detach the daemon."""
    sys.stdin.close()
    sys.stdout.close()
    sys.stderr.close()


def daemonize():
    try:
        pid = os.fork()
        if pid > 0:
            sys.exit(0)  # Exit parent process
        os.setsid()  # Start a new session
    except OSError as e:
        logging.error(f"Fork failed: {e.errno} ({e.strerror})")
        sys.exit(1)

    # Detach from the parent environment
    close_file_descriptors()
    os.chdir("/")

if __name__ == "__main__":
    logger.info("Start package watching server")
    cp = None

    # Événement pour signaler l'arrêt du thread
    stop_event = threading.Event()
    try:
        opts, suivarg = getopt.getopt(sys.argv[1:], "f:dh")
    except getopt.GetoptError:
        sys.exit(2)
    daemonize_service = True
    for option, argument in opts:
        if option == "-f":
            inifile = argument
        elif option == "-d":
            logger.info("console mode log level en debug")
            daemonize_service = False
            logger.setLevel(logging.DEBUG)
            add_console_handler()  # Ajouter le gestionnaire de logging pour la console
            logger.debug("pid file: %d\n" % os.getpid())
            logger.debug(f"kill -9 {os.getpid()}")
        elif option == "-h":
            print(
                "Configure in file '%s' \n[network_agent]\nip_ars=???\nport_ars=???"
                % inifile
            )
            print("\t[-d <mode debug>]\n\t[-d] debug mode no daemonized")
            sys.exit(0)

    if not os.path.exists(inifile):
        logger.debug("configuration File missing '%s' does not exist." % inifile)
        sys.exit(3)

    conf = conf_information(inifile)

    if daemonize_service:
        daemonize()
        logger.setLevel(conf["log_level"])
    else:
        logger.setLevel(logging.DEBUG)

    try:
        logger.info("start program")
        logger.info(
            "----------------------------------------------------------------"
        )
        logger.info(conf)
        pidrun = os.getpid()
        # Écrire le PID dans le fichier
        with open(pidfile, 'w') as f:
            f.write(str(pidrun))
        os.system(f"echo {str(pidrun)} > {pidfile}")
        logger.debug("If in debug mode, you can stop the program by ussing CTRL+Z then one of")
        logger.debug("the following commands")
        logger.debug("kill -9 $(cat %s)" % pidfile)
        logger.debug("or")
        logger.debug("killall -9 package_watching.py")
        logger.debug("or")
        logger.debug("kill %1")
        logger.debug("or")
        logger.debug("kill -9 %s" % os.getpid())
        logger.info(f"PID file : {str(pidrun)} in file {pidfile}")
        logger.info("kill -9 $(cat %s)" % pidfile)
        logger.info("killall package_watching.py")
        logger.info(
            "----------------------------------------------------------------"
        )
        # Créer et démarrer les threads
        watching_thread = threading.Thread(target=WatchingFilePartage(conf, stop_event).run)
        # schedule_action = threading.Thread(target=schedule_action, args=(stop_event,))
        watching_thread.start()
        # schedule_action.start()

        # Attendre l'arrêt des threads
        watching_thread.join()
        # schedule_action.join()

    except KeyboardInterrupt:
        logger.debug("interruption")
        stop_event.set()
        watching_thread.join()
        # schedule_action.join()
        sys.exit(3)

