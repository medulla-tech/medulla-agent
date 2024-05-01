# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2016-2023 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-3.0-or-later

import sys
import os
from subprocess import Popen
import shlex
import json
import subprocess
from lib import utils
from lib.agentconffile import (
    conffilename,
    medullaPath,
    directoryconffile,
    pulseTempDir,
    conffilenametmp,
    rotation_file,
)
import logging
import time

if sys.platform.startswith("win"):
    import win32security
    import ntsecuritycon
    import win32net
    import win32api

logger = logging.getLogger()
plugin = {"VERSION": "3.2", "NAME": "reverse_ssh_on", "TYPE": "all"}  # fmt: skip


def checkresult(result):
    if result["codereturn"] != 0:
        if len(result["result"]) == 0:
            result["result"][0] = ""
        logger.error("error : %s" % result["result"][-1])
    return result["codereturn"] == 0


def runProcess(cmd, shell=False, envoption=os.environ):
    logger.debug("START COMMAND %s" % cmd)
    args = shlex.split(cmd)
    return Popen(args, env=envoption, shell=shell).pid


def action(objectxmpp, action, sessionid, data, message, dataerreur):
    logger.debug("###################################################")
    logger.debug("call %s from %s" % (plugin, message["from"]))
    logger.debug("%s" % (json.dumps(data, indent=4)))
    logger.debug("###################################################")
    returnmessage = dataerreur
    returnmessage["ret"] = 0
    if objectxmpp.config.agenttype in ["relayserver"]:
        # Make sure reversessh account and keys exist
        msg = []
        username = "reversessh"
        result, msglog = utils.reversessh_useraccount_mustexist_on_relay(username)
        if result is False:
            logger.error(msglog)
        msg.append(msglog)
        result, msglog = utils.reversessh_keys_mustexist_on_relay(username)
        if result is False:
            logger.error(msglog)
        msg.append(msglog)
        # Write message to logger
        for line in msg:
            objectxmpp.xmpplog(
                line,
                type="noset",
                sessionname=sessionid,
                priority=-1,
                action="xmpplog",
                who=objectxmpp.boundjid.bare,
                how="",
                why="",
                module="Notify | Packaging | Reversessh",
                date=None,
                fromuser="",
                touser="",
            )

        if hasattr(objectxmpp.config, "reverseserver_ssh_port"):
            reversessh_server_port = int(objectxmpp.config.reverseserver_ssh_port)
        else:
            reversessh_server_port = "22"

        logger.debug("PROCESSING RELAYSERVER")
        if message["from"] == "console" or message["from"] == "master@pulse/MASTER":
            if "request" not in data:
                objectxmpp.send_message_agent("console", dataerreur)
                return
            if data["request"] == "askinfo":
                logger.debug("Processing of request askinfo")
                returnmessage["data"] = data
                returnmessage["data"]["fromplugin"] = plugin["NAME"]
                returnmessage["data"]["typeinfo"] = "info_xmppmachinebyuuid"
                returnmessage["data"]["sendother"] = "data@infos@jid"
                returnmessage["data"]["sendemettor"] = True
                returnmessage["data"]["relayserverip"] = objectxmpp.ipconnection
                returnmessage["data"]["reversessh_server_port"] = reversessh_server_port
                returnmessage["data"]["key"] = utils.get_relayserver_reversessh_idrsa(
                    "reversessh"
                )
                returnmessage["data"]["keypub"] = utils.get_relayserver_pubkey(
                    "reversessh"
                )
                returnmessage["data"]["keypubroot"] = utils.get_relayserver_pubkey(
                    "root"
                )
                returnmessage["ret"] = 0
                returnmessage["action"] = "askinfo"
                del returnmessage["data"]["request"]
                logger.debug("Send master this data")
                logger.debug("%s" % json.dumps(returnmessage, indent=4))
                objectxmpp.send_message_agent(
                    "master@pulse/MASTER", returnmessage, mtype="chat"
                )
                objectxmpp.send_message_agent("console", returnmessage)
                return
        if message["from"].bare == message["to"].bare:
            if "request" not in data:
                objectxmpp.send_message_agent(message["to"], dataerreur)
                return
            if data["request"] == "askinfo":
                logger.debug("Processing of request askinfo")
                returnmessage["data"] = data
                returnmessage["data"]["fromplugin"] = plugin["NAME"]
                returnmessage["data"]["typeinfo"] = "info_xmppmachinebyuuid"
                returnmessage["data"]["sendother"] = "data@infos@jid"
                returnmessage["data"]["sendemettor"] = True
                returnmessage["data"]["relayserverip"] = objectxmpp.ipconnection
                returnmessage["data"]["reversessh_server_port"] = reversessh_server_port
                returnmessage["data"]["key"] = utils.get_relayserver_reversessh_idrsa(
                    "reversessh"
                )
                returnmessage["data"]["keypub"] = utils.get_relayserver_pubkey(
                    "reversessh"
                )
                returnmessage["data"]["keypubroot"] = utils.get_relayserver_pubkey(
                    "root"
                )
                returnmessage["ret"] = 0
                returnmessage["action"] = "askinfo"
                returnmessage["sessionid"] = sessionid
                del returnmessage["data"]["request"]
                logger.debug("Send relayagent this data")
                logger.debug("%s" % json.dumps(returnmessage, indent=4))
                objectxmpp.send_message_agent(
                    "master@pulse/MASTER", returnmessage, mtype="chat"
                )
                return
    else:
        logger.debug("PROCESSING MACHINE")
        objectxmpp.xmpplog(
            "REVERSE SSH",
            type="noset",
            sessionname=sessionid,
            priority=-1,
            action="xmpplog",
            who=objectxmpp.boundjid.bare,
            how="",
            why="",
            module="Notify | Packaging | Reversessh",
            date=None,
            fromuser="",
            touser="",
        )

        if data["options"] == "createreversessh":
            # Add the keys to pulseuser account
            username = "pulseuser"
            result, msglog = utils.create_idrsa_on_client(username, data["key"])
            if result is False:
                logger.error(msglog)
            objectxmpp.xmpplog(
                msglog,
                type="noset",
                sessionname=sessionid,
                priority=-1,
                action="xmpplog",
                who=objectxmpp.boundjid.bare,
                how="",
                why="",
                module="Notify | Packaging | Reversessh",
                date=None,
                fromuser="",
                touser="",
            )
            try:
                reversetype = data["reversetype"]
            except Exception:
                reversetype = "R"
            try:
                remoteport = data["remoteport"]
            except Exception:
                remoteport = 22
            try:
                reversessh_server_port = data["reversessh_server_port"]
            except Exception:
                reversessh_server_port = 22

            objectxmpp.xmpplog(
                "Creating reverse ssh tunnel from machine : %s "
                "[type: %s / port :%s]" % (message["to"], reversetype, data["port"]),
                type="noset",
                sessionname=sessionid,
                priority=-1,
                action="xmpplog",
                who=objectxmpp.boundjid.bare,
                how="",
                why="",
                module="Notify | Packaging | Reversessh",
                date=None,
                fromuser="",
                touser="",
            )

            if sys.platform.startswith("linux"):
                filekey = os.path.join(
                    os.path.expanduser("~pulseuser"), ".ssh", "id_rsa"
                )
                dd = """#!/bin/bash
                /usr/bin/ssh -t -t -%s %s:localhost:%s -o StrictHostKeyChecking=no -i "%s" -l reversessh %s -p %s&
                """ % (
                    reversetype,
                    data["port"],
                    remoteport,
                    filekey,
                    data["relayserverip"],
                    reversessh_server_port,
                )
                reversesshsh = os.path.join(
                    os.path.expanduser("~pulseuser"), "reversessh.sh"
                )
                utils.file_put_contents(reversesshsh, dd)
                os.chmod(reversesshsh, 0o700)
                args = shlex.split(reversesshsh)
                if "persistence" not in data:
                    data["persistence"] = "no"
                if "persistence" in data and data["persistence"].lower() != "no":
                    if data["persistence"] in objectxmpp.reversesshmanage:
                        logger.info(
                            "Closing reverse ssh tunnel %s"
                            % str(objectxmpp.reversesshmanage[data["persistence"]])
                        )
                        cmd = "kill -9 %s" % str(
                            objectxmpp.reversesshmanage[data["persistence"]]
                        )
                        logger.info(cmd)
                        utils.simplecommandstr(cmd)
                        objectxmpp.xmpplog(
                            "Closing reverse ssh tunnel %s"
                            % str(objectxmpp.reversesshmanage[data["persistence"]]),
                            type="noset",
                            sessionname=sessionid,
                            priority=-1,
                            action="xmpplog",
                            who=objectxmpp.boundjid.bare,
                            how="",
                            why="",
                            module="Notify | Reversessh",
                            date=None,
                            fromuser="",
                            touser="",
                        )
                result = subprocess.Popen(args)
                if "persistence" in data and data["persistence"].lower() != "no":
                    objectxmpp.reversesshmanage[data["persistence"]] = str(result.pid)
                else:
                    objectxmpp.reversesshmanage["other"] = str(result.pid)
                logger.info("creation reverse ssh pid = %s" % str(result.pid))
                objectxmpp.xmpplog(
                    "Creating reverse ssh tunnel from machine : %s "
                    "[type: %s / port :%s]"
                    % (message["to"], reversetype, data["port"]),
                    type="noset",
                    sessionname=sessionid,
                    priority=-1,
                    action="xmpplog",
                    who=objectxmpp.boundjid.bare,
                    how="",
                    why="",
                    module="Notify | Packaging | Reversessh",
                    date=None,
                    fromuser="",
                    touser="",
                )
            elif sys.platform.startswith("win"):
                ################# win reverse #################
                try:
                    win32net.NetUserGetInfo("", "pulseuser", 0)
                    filekey = os.path.join(
                        "C:\\", "Users", "pulseuser", ".ssh", "id_rsa"
                    )
                except BaseException:
                    filekey = os.path.join(medullaPath(), ".ssh", "id_rsa")
                # Define the permissions depending on the user running the
                # agent (admin or system)
                utils.apply_perms_sshkey(filekey, private=True)

                sshexec = os.path.join("c:\\", "progra~1", "OpenSSH", "ssh.exe")
                reversesshbat = os.path.join(medullaPath(), "bin", "reversessh.bat")

                linecmd = []
                cmd = (
                    """\\"%s\\" -t -t -%s %s:localhost:%s -o StrictHostKeyChecking=no -i \\"%s\\" -l reversessh %s -p %s"""
                    % (
                        sshexec,
                        reversetype,
                        data["port"],
                        remoteport,
                        filekey,
                        data["relayserverip"],
                        reversessh_server_port,
                    )
                )
                linecmd.append("""@echo off""")
                linecmd.append(
                    """for /f "tokens=2 delims==; " %%%%a in (' wmic process call create "%s" ^| find "ProcessId" ') do set "$PID=%%%%a" """
                    % cmd
                )
                linecmd.append("""echo %$PID%""")
                linecmd.append(
                    """echo %$PID% > C:\\progra~1\\Medulla\\bin\\%$PID%.pid"""
                )
                dd = "\r\n".join(linecmd)

                if not os.path.exists(os.path.join(medullaPath(), "bin")):
                    os.makedirs(os.path.join(medullaPath(), "bin"))
                utils.file_put_contents(reversesshbat, dd)
                if "persistence" not in data:
                    data["persistence"] = "no"
                # clear tout les reverse ssh
                searchreversesshprocess = os.path.join(medullaPath(), "bin")
                for f in [
                    os.path.join(medullaPath(), "bin", x)
                    for x in os.listdir(searchreversesshprocess)
                    if x[-4:] == ".pid"
                ]:
                    pid = utils.file_get_contents(f).strip(" \n\r\t")
                    cmd = "taskkill /F /PID %s" % str(pid)
                    logger.info(cmd)
                    utils.simplecommand(cmd)
                    os.remove(f)
                    objectxmpp.xmpplog(
                        "Closing reverse ssh tunnel [PID : %s]" % str(f),
                        type="deploy",
                        sessionname=sessionid,
                        priority=-1,
                        action="xmpplog",
                        who=objectxmpp.boundjid.bare,
                        how="",
                        why="",
                        module="Notify | Reversessh",
                        date=None,
                        fromuser="",
                        touser="",
                    )
                result = subprocess.Popen(reversesshbat)
                time.sleep(2)
                for f in [
                    os.path.join(medullaPath(), "bin", x)
                    for x in os.listdir(searchreversesshprocess)
                    if x[-4:] == ".pid"
                ]:
                    pidnumber = ""
                    try:
                        pidnumber = f.split("\\")[-1][:-4]
                    except BaseException:
                        pass
                    if "persistence" in data and data["persistence"].lower() != "no":
                        os.remove(f)
                        msg = (
                            "Creating reverse ssh tunnel [persistence: yes PID : %s]\nscript : %s"
                            % (pidnumber, str(dd))
                        )
                    else:
                        msg = (
                            "Creating reverse ssh tunnel [persistence: no PID : %s]\nscript :%s"
                            % (pidnumber, str(dd))
                        )
                    objectxmpp.xmpplog(
                        msg,
                        type="deploy",
                        sessionname=sessionid,
                        priority=-1,
                        action="xmpplog",
                        who=objectxmpp.boundjid.bare,
                        how="",
                        why="",
                        module="Notify | Reversessh",
                        date=None,
                        fromuser="",
                        touser="",
                    )
            elif sys.platform.startswith("darwin"):
                filekey = os.path.join(
                    os.path.expanduser("~pulseuser"), ".ssh", "id_rsa"
                )
                dd = """#!/bin/bash
                /usr/bin/ssh -t -t -%s %s:localhost:%s -o StrictHostKeyChecking=no -i "%s" -l reversessh %s -p %s&
                """ % (
                    reversetype,
                    data["port"],
                    remoteport,
                    filekey,
                    data["relayserverip"],
                    reversessh_server_port,
                )
                reversesshsh = os.path.join(
                    os.path.expanduser("~pulseuser"), "reversessh.sh"
                )
                utils.file_put_contents(reversesshsh, dd)
                os.chmod(reversesshsh, 0o700)
                args = shlex.split(reversesshsh)
                if "persistence" not in data:
                    data["persistence"] = "no"
                if "persistence" in data and data["persistence"].lower() != "no":
                    if data["persistence"] in objectxmpp.reversesshmanage:
                        logger.info(
                            "Closing reverse ssh tunnel %s"
                            % str(objectxmpp.reversesshmanage[data["persistence"]])
                        )
                        cmd = "kill -9 %s" % str(
                            objectxmpp.reversesshmanage[data["persistence"]]
                        )
                        logger.info(cmd)
                        utils.simplecommandstr(cmd)
                        objectxmpp.xmpplog(
                            "Closing reverse ssh tunnel %s"
                            % str(objectxmpp.reversesshmanage[data["persistence"]]),
                            type="noset",
                            sessionname=sessionid,
                            priority=-1,
                            action="xmpplog",
                            who=objectxmpp.boundjid.bare,
                            how="",
                            why="",
                            module="Notify | Reversessh",
                            date=None,
                            fromuser="",
                            touser="",
                        )
                result = subprocess.Popen(args)
                if "persistence" in data and data["persistence"].lower() != "no":
                    objectxmpp.reversesshmanage[data["persistence"]] = str(result.pid)
                else:
                    objectxmpp.reversesshmanage["other"] = str(result.pid)
                    data["persistence"] = "no"
                logger.info("creation reverse ssh pid = %s" % str(result.pid))
                objectxmpp.xmpplog(
                    "Creating reverse ssh tunnel [PID : %s]" % str(result.pid),
                    type="noset",
                    sessionname=sessionid,
                    priority=-1,
                    action="xmpplog",
                    who=objectxmpp.boundjid.bare,
                    how="",
                    why="",
                    module="Notify | Reversessh",
                    date=None,
                    fromuser="",
                    touser="",
                )
            else:
                logger.warning("os not supported in plugin%s" % sys.platform)
        elif data["options"] == "stopreversessh":
            if sys.platform.startswith("win"):
                # voir cela powershell.exe "Stop-Process -Force
                # (Get-NetTCPConnection -LocalPort 22).OwningProcess"

                cmd = "wmic path win32_process Where \"Commandline like '%reversessh%'\" Call Terminate"
                subprocess.Popen(cmd)
            else:
                os.system(
                    "lpid=$(ps aux | grep reversessh | grep -v grep | awk '{print $2}');kill -9 $lpid"
                )
                objectxmpp.reversessh = None

        returnmessage = dataerreur
        returnmessage["data"] = data
        returnmessage["ret"] = 0
