#!/usr/bin/python3
# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2016-2023 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-3.0-or-later


# """
# This module is dedicated to analyse inventories sent by a Pulse 2 Client.
# The original inventory is sent using one line per kind of
# """

# API information http://seb.dbzteam.org/pyinotify/
from __future__ import print_function

import socket
import pyinotify
import os
import json
import random
import sys
import configparser
import logging
import getopt
import base64
from lib.utils import simplecommandstr, decode_strconsole

conf = {}


logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s %(levelname)s %(message)s",
    filename="/var/log/pulse/pulse-package-watching.log",
    filemode="a",
)


def writeStdErr(message):
    if sys.version_info >= (3, 0):
        print(message, file=sys.stderr)
    else:
        sys.stderr.write(message)


class configerror(Exception):
    """Exception raised for errors in the file configuration.

    Attributes:
        expr -- input expression in which the error occurred
        msg  -- explanation of the error
    """

    def __init__(self, expr="Error Config", msg=""):
        self.expr = expr
        self.msg = msg


def conf_information(conffile):
    Config = configparser.ConfigParser()
    Config.read(conffile)
    Config.read(f"{conffile}.local")
    configdata = {
        "ip_ars": (
            Config.get("network_agent", "ip_ars")
            if Config.has_option("network_agent", "ip_ars")
            else "localhost"
        )
    }
    if Config.has_option("network_agent", "ip_ars"):
        configdata["port_ars"] = Config.getint("network_agent", "port_ars")
    else:
        configdata["port_ars"] = "8765"

    if Config.has_option("watchingfile", "filelist"):
        filelist = Config.get("watchingfile", "filelist")
    else:
        filelist = "/var/lib/pulse2/packages"

    if filelist == "":
        raise configerror(msg="filelist is empty")

    configdata["filelist"] = filelist.split(",")

    if Config.has_option("watchingfile", "excludelist"):
        excludelist = Config.get("watchingfile", "excludelist")
    else:
        excludelist = None

    if excludelist is not None and len(excludelist) != 0:
        configdata["excludelist"] = excludelist.split(",")
    else:
        configdata["excludelist"] = None

    configdata["filelist"] = filelist.split(",")

    if Config.has_option("notifyars", "enable"):
        configdata["notifyars_enable"] = Config.getboolean("notifyars", "enable")
    else:
        configdata["notifyars_enable"] = True

    if Config.has_option("rsynctocdn", "enable"):
        configdata["rsynctocdn_enable"] = Config.getboolean("rsynctocdn", "enable")
    else:
        configdata["rsynctocdn_enable"] = False
    if Config.has_option("rsynctocdn", "localfolder"):
        configdata["rsynctocdn_localfolder"] = Config.get("rsynctocdn", "localfolder")
    else:
        configdata["rsynctocdn_localfolder"] = "/var/lib/pulse2/packages/sharing"
    if Config.has_option("rsynctocdn", "rsync_options"):
        configdata["rsynctocdn_rsync_options"] = Config.get(
            "rsynctocdn", "rsync_options"
        )
    else:
        configdata["rsynctocdn_rsync_options"] = '--archive --del --exclude ".stfolder"'
    if Config.has_option("rsynctocdn", "ssh_privkey_path"):
        configdata["rsynctocdn_ssh_privkey_path"] = Config.get(
            "rsynctocdn", "ssh_privkey_path"
        )
    else:
        configdata["rsynctocdn_ssh_privkey_path"] = "/root/.ssh/id_rsa"
    if Config.has_option("rsynctocdn", "ssh_options"):
        configdata["rsynctocdn_ssh_options"] = Config.get("rsynctocdn", "ssh_options")
    else:
        configdata["rsynctocdn_ssh_options"] = (
            "-oBatchMode=yes -oServerAliveInterval=5 -oCheckHostIP=no -oLogLevel=ERROR -oConnectTimeout=40 -oHostKeyAlgorithms=+ssh-dss"
        )
    if Config.has_option("rsynctocdn", "ssh_remoteuser"):
        configdata["rsynctocdn_ssh_remoteuser"] = Config.get(
            "rsynctocdn", "ssh_remoteuser"
        )
    elif configdata["rsynctocdn_enable"]:
        raise configerror(msg="ssh_remoteuser is not defined")
    if Config.has_option("rsynctocdn", "ssh_servername"):
        configdata["rsynctocdn_ssh_servername"] = Config.get(
            "rsynctocdn", "ssh_servername"
        )
    elif configdata["rsynctocdn_enable"]:
        raise configerror(msg="ssh_servername is not defined")
    if Config.has_option("rsynctocdn", "ssh_destpath"):
        configdata["rsynctocdn_ssh_destpath"] = Config.get("rsynctocdn", "ssh_destpath")
    elif configdata["rsynctocdn_enable"]:
        raise configerror(msg="ssh_destpath is not defined")

    return configdata


def getRandomName(nb, pref=""):
    a = "abcdefghijklnmopqrstuvwxyz0123456789"
    d = pref
    for _ in range(nb):
        d = d + a[random.randint(0, 35)]
    return d


def send_agent_data(datastrdata, conf):
    logging.getLogger().debug(f"string for send agent : {datastrdata}")
    # Convertir la chaîne en bytes
    datastrdata_bytes = datastrdata.encode("utf-8")
    # Encoder les bytes en base64
    EncodedString = base64.b64encode(datastrdata_bytes)
    logging.getLogger().debug(f"send base64 string  : {EncodedString}")
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_address = (conf["ip_ars"], int(conf["port_ars"]))
    try:
        sock.connect(server_address)
        sock.sendall(EncodedString)
        sock.recv(4096)
        logging.getLogger().debug("send to ARS event")
    except Exception as e:
        logging.getLogger().error(str(e))
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
    logging.getLogger().debug("rsync command: %s" % rsync_cmd)
    objcmd = simplecommandstr(rsync_cmd)
    logging.getLogger().debug("rsync command result: %s" % objcmd["result"])
    if objcmd["code"] != 0:
        logging.getLogger().error(
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

    def msg_structure(self):
        return {
            "action": "notifysyncthing",
            # "sessionid" : getRandomName(6, "syncthing"),
            "data": "",
        }

    def process_IN_ACCESS(self, event):
        pass

    def process_IN_ATTRIB(self, event):
        pass

    def process_IN_CLOSE_NOWRITE(self, event):
        pass

    def process_IN_CLOSE_WRITE(self, event):
        pass

    def process_IN_OPEN(self, event):
        pass

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
            logging.getLogger().debug(f"Msg : {datasendstr}")
            send_agent_data(datasendstr, self.config)
        if self.config["rsynctocdn_enable"]:
            # Run rsync command
            rsync_to_cdn(self.config)

    def process_IN_MODIFY(self, event):
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
            logging.getLogger().debug(f"Msg : {datasendstr}")
            send_agent_data(datasendstr, self.config)
        if self.config["rsynctocdn_enable"]:
            # Run rsync command
            rsync_to_cdn(self.config)

    def process_IN_DELETE(self, event):
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
            logging.getLogger().debug(f"Msg : {datasendstr}")
            send_agent_data(datasendstr, self.config)
        if self.config["rsynctocdn_enable"]:
            # Run rsync command
            rsync_to_cdn(self.config)

    def process_IN_CREATE(self, event):
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
                logging.getLogger().debug(f"Msg : {datasendstr}")
                send_agent_data(datasendstr, self.config)
        if self.config["rsynctocdn_enable"]:
            # Run rsync command
            rsync_to_cdn(self.config)


class watchingfilepartage:
    def __init__(self, config):
        self.config = config
        logging.getLogger().info("install inotify")
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
        self.notifier = pyinotify.ThreadedNotifier(self.wm, self.handler)
        self.notifier.start()

    def stop(self):
        self.notifier.stop()


if __name__ == "__main__":
    logging.getLogger().info("Start package watching server")
    inifile = "/etc/pulse-xmpp-agent/package_watching.ini"
    pidfile = "/var/run/package_watching.pid"
    cp = None
    try:
        opts, suivarg = getopt.getopt(sys.argv[1:], "f:dh")
    except getopt.GetoptError:
        sys.exit(2)
    daemonize = True
    for option, argument in opts:
        if option == "-f":
            inifile = argument
        elif option == "-d":
            logging.getLogger().info("logger mode debug")
            daemonize = False
            logging.getLogger().setLevel(logging.DEBUG)
            print("pid file: %d\n" % os.getpid())
            print(f"kill -9 {os.getpid()}")
        elif option == "-h":
            print(
                "Configure in file '%s' \n[network_agent]\nip_ars=???\nport_ars=???"
                % inifile
            )
            print("\t[-d <mode debug>]\n\t[-d] debug mode no daemonized")
            sys.exit(0)

    if not os.path.exists(inifile):
        print("configuration File missing '%s' does not exist." % inifile)
        sys.exit(3)
    conf = conf_information(inifile)

    if daemonize:
        try:
            pid = os.fork()
            if pid > 0:
                # exit first parent
                sys.exit(0)
        except OSError as e:
            writeStdErr("Fork #1 failed: %d (%s)" % (e.errno, e.strerror))
            sys.exit(1)
        # dissociate from parent environment
        os.close(sys.stdin.fileno())
        os.close(sys.stdout.fileno())
        os.close(sys.stderr.fileno())
        os.chdir("/")
        os.setsid()
        # do second fork
        try:
            pid = os.fork()
            if pid > 0:
                # exit from second parent, print eventual PID before
                # print "Daemon PID %d" % pid
                # print "kill -9 $(cat %s)"%pidfile
                logging.getLogger().info("Daemon PID %d" % pid)
                os.seteuid(0)
                os.setegid(0)
                # logging.getLogger().info("PID file" + str(pid) + " > " + pidfile)
                # logging.getLogger().info("kill -9 $(cat %s)"%pidfile)
                # os.system("echo " + str(pid) + " > " + pidfile)
                # print "echo " + str(pid) + " > " + pidfile
                sys.exit(0)
        except OSError as e:
            writeStdErr("fork #2 failed: %d (%s)" % (e.errno, e.strerror))
            print("fork #2 failed: %d (%s)" % (e.errno, e.strerror), file=sys.stderr)
            sys.exit(1)
    else:
        logging.getLogger().setLevel(logging.DEBUG)

    try:
        logging.getLogger().info("start program")
        logging.getLogger().info(
            "----------------------------------------------------------------"
        )
        logging.getLogger().info(conf)
        pidrun = os.getpid()
        os.system(f"echo {str(pidrun)} > {pidfile}")
        print("If in debug mode, you can stop the program by ussing CTRL+Z then one of")
        print("the following commands")
        print("kill -9 $(cat %s)" % pidfile)
        print("or")
        print("killall -9 package_watching.py")
        print("or")
        print("kill %1")
        print("or")
        print("kill -9 %s" % os.getpid())
        logging.getLogger().info(f"PID file : {str(pidrun)} in file {pidfile}")
        logging.getLogger().info("kill -9 $(cat %s)" % pidfile)
        logging.getLogger().info("killall package_watching.py")
        logging.getLogger().info(
            "----------------------------------------------------------------"
        )
        a = watchingfilepartage(conf)
        a.run()
    except KeyboardInterrupt:
        print("interruption")
        a.stop()
        sys.exit(3)
