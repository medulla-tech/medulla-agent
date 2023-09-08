#!/usr/bin/python3
# -*- coding: utf-8; -*-
# SPDX-FileCopyrightText: 2016-2023 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-3.0-or-later

import os
import sys
import platform
import json
import logging
import time
import shlex
from .utils import (
    shellcommandtimeout,
    file_put_contents,
    file_get_contents,
    decode_strconsole,
    encode_strconsole,
    keypub,
    restartsshd,
    pulseuser_useraccount_mustexist,
    pulseuser_profile_mustexist,
    create_idrsa_on_client,
    add_key_to_authorizedkeys_on_client,
)
import socket
from .agentconffile import directoryconffile
import zlib
import re
import base64
import traceback
import subprocess
from lib.managepackage import managepackage
from lib.update_remote_agent import Update_Remote_Agent
from .utils_psutil import (
    sensors_battery,
    winservices,
    clone_ps_aux,
    disk_usage,
    sensors_fans,
    mmemory,
    ifconfig,
    cpu_num,
    netstat,
)
from lib.update_remote_agent import agentinfoversion

if sys.platform.startswith("win"):
    import win32net
    import win32security
    import win32serviceutil

DEBUGPULSE = 25
logger = logging.getLogger()


def callXmppFunctionIq(functionname, *args, **kwargs):
    logger.debug(f"**call function {functionname} {args} {kwargs}")
    return getattr(functionsynchroxmpp, functionname)(*args, **kwargs)


def dispach_iq_command(xmppobject, jsonin):
    """
    this function doit retourner un json string
    """
    data = json.loads(jsonin)

    # functions synch list
    listactioncommand = [
        "xmppbrowsing",
        "test",
        "remotefile",
        "remotecommandshell",
        "listremotefileedit",
        "remotefileeditaction",
        "remotexmppmonitoring",
        "keypub",
        "information",
        "keyinstall",
        "packageslist",
        "reversesshqa",
        "get_id_rsa",
    ]
    if data["action"] in listactioncommand:
        logging.log(DEBUGPULSE, f'call function {data["action"]} ')
        result = callXmppFunctionIq(data["action"], xmppobject=xmppobject, data=data)
        if not isinstance(result, str):
            logging.getLogger().warning(
                f'function {data["action"]} not return str json'
            )
        return result
    else:
        logging.log(
            DEBUGPULSE,
            f'function {data["action"]} missing in list listactioncommand',
        )
        return ""


def logdeploymsg(xmppobject, msg, sessionid):
    xmppobject.xmpplog(
        msg,
        type="deploy",
        sessionname=sessionid,
        priority=-1,
        action="xmpplog",
        who=xmppobject.boundjid.bare,
        module="Deployment | Cluster | Notify",
        date=None,
    )


class functionsynchroxmpp:
    """
    this function must return json string
    """

    @staticmethod
    def xmppbrowsing(xmppobject, data):
        logger.debug("iq xmppbrowsing")
        return json.dumps(data)

    @staticmethod
    def test(xmppobject, data):
        logger.debug("iq test")
        return json.dumps(data)

    @staticmethod
    def get_id_rsa(xmppobject, data):
        private_key_ars = os.path.join(
            os.path.expanduser("~reversessh"), ".ssh", "id_rsa"
        )
        result = {"private_key_ars": file_get_contents(private_key_ars)}
        result["public_key_ars"] = file_get_contents(f"{private_key_ars}.pub")
        return json.dumps(result)

    @staticmethod
    def reversesshqa(xmppobject, data):
        """
        call directement plugin reverse ssh
        """
        datareverse = data["data"]
        portproxy = datareverse["portproxy"]
        remoteport = datareverse["remoteport"]
        if "private_key_ars" in datareverse:
            private_key_ars = datareverse["private_key_ars"].strip(" \t\n\r")
            create_idrsa_on_client("pulseuser", private_key_ars)
        if sys.platform.startswith("linux"):
            filekey = os.path.join(os.path.expanduser("~pulseuser"), ".ssh", "id_rsa")
            dd = """#!/bin/bash
            /usr/bin/ssh -t -t -%s 0.0.0.0:%s:%s:%s -o StrictHostKeyChecking=no -i "%s" -l reversessh %s -p %s&
            """ % (
                datareverse["type_reverse"],
                datareverse["portproxy"],
                datareverse["ipAM"],
                datareverse["remoteport"],
                filekey,
                datareverse["ipARS"],
                datareverse["port_ssh_ars"],
            )
            reversesshsh = os.path.join(
                os.path.expanduser("~pulseuser"), "reversessh.sh"
            )
            file_put_contents(reversesshsh, dd)
            os.chmod(reversesshsh, 0o700)
            args = shlex.split(reversesshsh)
            result = subprocess.Popen(args)
            logger.debug(f"Command reversessh {dd}")
            # /usr/bin/ssh -t -t -R 36591:localhost:22 -o StrictHostKeyChecking=no -i /var/lib/pulse2/.ssh/id_rsa -l reversessh 212.83.136.107 -p 22
        elif sys.platform.startswith("win"):
            ################# win reverse #################
            try:
                win32net.NetUserGetInfo("", "pulseuser", 0)
                filekey = os.path.join("C:\\", "Users", "pulseuser", ".ssh", "id_rsa")
            except Exception:
                filekey = os.path.join(
                    "c:", "progra~1", "pulse", ".ssh", "id_rsa"
                )

            sshexec = os.path.join("c:", "progra~1", "OpenSSH", "ssh.exe")
            reversesshbat = os.path.join(
                "c:", "progra~1", "Pulse", "bin", "reversessh.bat"
            )
            cmd = (
                """\\"%s\\" -t -t -%s 0.0.0.0:%s:%s:%s -o StrictHostKeyChecking=no -i \\"%s\\" -l reversessh %s -p %s"""
                % (
                    sshexec,
                    datareverse["type_reverse"],
                    datareverse["portproxy"],
                    datareverse["ipAM"],
                    datareverse["remoteport"],
                    filekey,
                    datareverse["ipARS"],
                    datareverse["port_ssh_ars"],
                )
            )
            linecmd = [
                """@echo off""",
                """for /f "tokens=2 delims==; " %%%%a in (' wmic process call create "%s" ^| find "ProcessId" ') do set "$PID=%%%%a" """
                % cmd,
                """echo %$PID%""",
                """echo %$PID% > C:\\progra~1\\Pulse\\bin\\%$PID%.pid""",
            ]
            cmd = "\r\n".join(linecmd)

            if not os.path.exists(
                os.path.join("c:", "progra~1", "Pulse", "bin")
            ):
                os.makedirs(os.path.join("c:", "progra~1", "Pulse", "bin"))
            file_put_contents(reversesshbat, cmd)
            result = subprocess.Popen(reversesshbat)
            time.sleep(2)
        elif sys.platform.startswith("darwin"):
            filekey = os.path.join(os.path.expanduser("~pulseuser"), ".ssh", "id_rsa")
            cmd = """#!/bin/bash
            /usr/bin/ssh -t -t -%s 0.0.0.0:%s:%s:%s -o StrictHostKeyChecking=no -i "%s" -l reversessh %s -p %s&
            """ % (
                datareverse["type_reverse"],
                datareverse["portproxy"],
                datareverse["ipAM"],
                datareverse["remoteport"],
                filekey,
                datareverse["ipARS"],
                datareverse["port_ssh_ars"],
            )
            reversesshsh = os.path.join(
                os.path.expanduser("~pulseuser"), "reversessh.sh"
            )
            file_put_contents(reversesshsh, cmd)
            os.chmod(reversesshsh, 0o700)
            args = shlex.split(reversesshsh)
            result = subprocess.Popen(args)
        else:
            logger.warning(f"os not supported in plugin{sys.platform}")
        return json.dumps(data)

    @staticmethod
    def remotefilesimple(xmppobject, data):
        logger.debug("iq remotefilesimple")
        datapath = data["data"]
        if isinstance(datapath, str):
            datapath = str(data["data"])
            filesystem = xmppobject.xmppbrowsingpath.listfileindir(datapath)
            data["data"] = filesystem
        return json.dumps(data)

    @staticmethod
    def remotefile(xmppobject, data):
        logger.debug("iq remotefile")
        datapath = data["data"]
        if not isinstance(datapath, str):
            return ""
        datapath = str(data["data"])
        filesystem = xmppobject.xmppbrowsingpath.listfileindir(datapath)
        data["data"] = filesystem
        try:
            datastr = json.dumps(data)
        except Exception as e:
            try:
                datastr = json.dumps(data, encoding="latin1")
            except Exception as e:
                logging.getLogger().error(
                    f"synchro xmpp function remotefile : {str(e)}"
                )
                return ""
        try:
            result = base64.b64encode(zlib.compress(datastr, 9))
        except Exception as e:
            logging.getLogger().error(
                f"synchro xmpp function remotefile encoding: {str(e)}"
            )
        return result

    @staticmethod
    def remotecommandshell(xmppobject, data):
        logger.debug("iq remotecommandshell")
        result = shellcommandtimeout(
            encode_strconsole(data["data"]), timeout=data["timeout"]
        ).run()
        re = [decode_strconsole(x).strip(os.linesep) + "\n" for x in result["result"]]
        result["result"] = re
        return json.dumps(result)

    @staticmethod
    def keypub(xmppobject, data):
        logger.debug("iq keypub")
        # verify relayserver
        try:
            result = {"result": {"key": keypub()}, "error": False, "numerror": 0}
        except Exception:
            result = {"result": {"key": ""}, "error": True, "numerror": 2}
        return json.dumps(result)

    @staticmethod
    def keyinstall(xmppobject, data):
        restartsshd()
        try:
            if "keyinstall" not in data["action"]:
                logger.error("error format message : %s" % (json.dumps(data, indent=4)))
                data["action"] = "resultkeyinstall"
                data["ret"] = 20
                data["data"]["msg_error"] = ["error format message"]
                return json.dumps(data, indent=4)
            # Make sure user account and profile exists
            username = "pulseuser"
            result, msglog = pulseuser_useraccount_mustexist(username)
            if result is False:
                logger.error(msglog)
            msgaction = [msglog]
            result, msglog = pulseuser_profile_mustexist(username)
            if result is False:
                logger.error(msglog)
            msgaction.append(msglog)

            # Add the keys to pulseuser account
            if "keyreverseprivatssh" in data["data"]:
                result, msglog = create_idrsa_on_client(
                    username, data["data"]["keyreverseprivatssh"]
                )
                if result is False:
                    logger.error(msglog)
                msgaction.append(msglog)
            result, msglog = add_key_to_authorizedkeys_on_client(
                username, data["data"]["key"]
            )
            if result is False:
                logger.error(msglog)
            msgaction.append(msglog)

            # Send logs to logger
            for line in msgaction:
                xmppobject.xmpplog(
                    line,
                    type="deploy",
                    sessionname=data["data"]["sessionid"],
                    priority=-1,
                    action="xmpplog",
                    who=xmppobject.boundjid.bare,
                    how="",
                    why="",
                    module="Deployment | Notify",
                    date=None,
                    fromuser="",
                    touser="",
                )

            data["action"] = "resultkeyinstall"
            data["ret"] = 0
            data["data"] = {"msg_action": msgaction}
            return json.dumps(data, indent=4)
        except Exception:
            data["action"] = "resultkeyinstall"
            data["ret"] = 255
            msgaction.append(f"{traceback.format_exc()}")
            data["data"]["msg_error"] = msgaction
            resltatreturn = json.dumps(data, indent=4)
            logger.error(f"iq install key {resltatreturn}")
            return resltatreturn

    @staticmethod
    def information(xmppobject, data):
        logger.debug("iq information")
        result = {"result": {"informationresult": {}}, "error": False, "numerror": 0}
        for info_ask in data["data"]["listinformation"]:
            try:
                if info_ask == "add_proxy_port_reverse":
                    if "param" in data["data"] and "proxyport" in data["data"]["param"]:
                        if xmppobject.config.agenttype in ["relayserver"]:
                            xmppobject.manage_persistence_reverse_ssh.add_port(
                                data["data"]["param"]["proxyport"]
                            )
                elif info_ask == "battery":
                    result["result"]["informationresult"][info_ask] = decode_strconsole(
                        sensors_battery()
                    )
                elif info_ask == "clean_reverse_ssh":
                    if xmppobject.config.agenttype in ["relayserver"]:
                        # on clean les reverse ssh non utiliser
                        xmppobject.manage_persistence_reverse_ssh.terminate_reverse_ssh_not_using()
                elif info_ask == "clone_ps_aux":
                    result["result"]["informationresult"][info_ask] = decode_strconsole(
                        clone_ps_aux()
                    )
                elif info_ask == "cpu_num":
                    result["result"]["informationresult"][info_ask] = decode_strconsole(
                        cpu_num()
                    )
                elif info_ask == "disk_usage":
                    result["result"]["informationresult"][info_ask] = decode_strconsole(
                        disk_usage()
                    )
                elif info_ask == "folders_packages":
                    result["result"]["informationresult"][
                        info_ask
                    ] = managepackage.packagedir()
                elif info_ask == "force_reconf":
                    filedata = ["BOOLCONNECTOR", "action_force_reconfiguration"]
                    for filename in filedata:
                        file = open(
                            os.path.join(
                                os.path.dirname(os.path.realpath(__file__)),
                                "..",
                                filename,
                            ),
                            "w",
                        )
                        file.close()
                        # xmppobject.networkMonitor()
                        xmppobject.reconfagent()
                    result["result"]["informationresult"][info_ask] = (
                        "action force " "reconfiguration for" % xmppobject.boundjid.bare
                    )
                elif info_ask == "get_ars_key_id_rsa":
                    private_key_ars = os.path.join(
                        os.path.expanduser("~reversessh"), ".ssh", "id_rsa"
                    )
                    result["result"]["informationresult"][info_ask] = file_get_contents(
                        private_key_ars
                    )
                elif info_ask == "get_ars_key_id_rsa_pub":
                    public_key_ars = os.path.join(
                        os.path.expanduser("~reversessh"), ".ssh", "id_rsa.pub"
                    )
                    result["result"]["informationresult"][info_ask] = file_get_contents(
                        public_key_ars
                    )
                elif info_ask == "get_free_tcp_port":
                    tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    tcp.bind(("", 0))
                    addr, port = tcp.getsockname()
                    tcp.close()
                    result["result"]["informationresult"][info_ask] = port
                elif info_ask == "ifconfig":
                    result["result"]["informationresult"][info_ask] = decode_strconsole(
                        ifconfig()
                    )
                elif info_ask == "invent_xmpp":
                    result["result"]["informationresult"][
                        info_ask
                    ] = xmppobject.seachInfoMachine()
                elif info_ask == "keypub":
                    result["result"]["informationresult"][info_ask] = keypub()
                elif info_ask == "mmemory":
                    result["result"]["informationresult"][info_ask] = decode_strconsole(
                        mmemory()
                    )
                elif info_ask == "netstat":
                    result["result"]["informationresult"][info_ask] = decode_strconsole(
                        netstat()
                    )
                elif info_ask == "os":
                    result["result"]["informationresult"][info_ask] = sys.platform
                elif info_ask == "os_version":
                    result["result"]["informationresult"][
                        info_ask
                    ] = platform.platform()
                elif info_ask == "profiluserpulse":
                    result["result"]["informationresult"][info_ask] = "pulseuser"
                elif info_ask == "sensors_fans":
                    result["result"]["informationresult"][info_ask] = decode_strconsole(
                        sensors_fans()
                    )
                elif info_ask == "winservices":
                    result["result"]["informationresult"][info_ask] = decode_strconsole(
                        winservices()
                    )
            except Exception:
                result["result"]["informationresult"][info_ask] = ""
        return json.dumps(result)

    @staticmethod
    def listremotefileedit(xmppobject, data):
        logger.debug("iq listremotefileedit")
        listfileedit = [
            x for x in os.listdir(directoryconffile()) if x.endswith(".ini")
        ]
        data["data"] = {"result": listfileedit}
        return json.dumps(data)

    @staticmethod
    def remotexmppmonitoring(xmppobject, data):
        logger.debug("iq remotexmppmonitoring")
        result = ""
        if data["data"] == "battery":
            result = decode_strconsole(sensors_battery())
        elif data["data"] == "winservices":
            result = decode_strconsole(winservices())
        elif data["data"] == "clone_ps_aux":
            result = decode_strconsole(clone_ps_aux())
        elif data["data"] == "disk_usage":
            result = decode_strconsole(disk_usage())
        elif data["data"] == "sensors_fans":
            result = decode_strconsole(sensors_fans())
        elif data["data"] == "mmemory":
            result = decode_strconsole(mmemory())
        elif data["data"] == "ifconfig":
            result = decode_strconsole(ifconfig())
        elif data["data"] == "cpu_num":
            result = decode_strconsole(cpu_num())
        elif data["data"] == "agentinfos":
            # on doit verifie que l'image existe.
            descriptorimage = Update_Remote_Agent(xmppobject.img_agent)
            result = decode_strconsole(agentinfoversion(xmppobject))
        elif data["data"] == "netstat":
            result = decode_strconsole(netstat())
            result = re.sub("[ ]{2,}", "@", result)
        else:
            datastruct = json.loads(data["data"])
            if "subaction" in datastruct:
                result = functionsynchroxmpp.__execfunctionmonitoringparameter(
                    datastruct, xmppobject
                )
        result = base64.b64encode(zlib.compress(result, 9))
        data["result"] = result
        return json.dumps(data)

    @staticmethod
    def __execfunctionmonitoringparameter(data, xmppobject):
        result = ""
        try:
            if data["subaction"] == "cputimes":
                func = getattr(sys.modules[__name__], data["subaction"])
                return decode_strconsole(
                    json.dumps(func(*data["args"], **data["kwargs"]))
                )
            elif data["subaction"] == "litlog":
                func = getattr(
                    sys.modules[__name__], "showlinelog"
                )  # call showlinelog from util
                data["kwargs"]["logfile"] = xmppobject.config.logfile
                return decode_strconsole(
                    json.dumps(func(*data["args"], **data["kwargs"]))
                )
            else:
                return ""
        except Exception as e:
            logger.error(f"{str(e)}")
            logger.error(f"{traceback.format_exc()}")
            return ""

    @staticmethod
    def remotefileeditaction(xmppobject, data):
        logger.debug("iq remotefileeditaction")
        if "data" in data and "action" in data["data"]:
            if data["data"]["action"] == "loadfile":
                if "file" in data["data"]:
                    filename = os.path.join(directoryconffile(), data["data"]["file"])
                    if os.path.isfile(filename):
                        filedata = file_get_contents(filename)
                        data["data"] = {
                            "result": filedata,
                            "error": False,
                            "numerror": 0,
                        }
                        return json.dumps(data)
                    else:
                        data["data"] = {
                            "result": "error file missing",
                            "error": True,
                            "numerror": 128,
                        }
                else:
                    data["data"] = {"result": "error name file missing"}
            elif data["data"]["action"] == "create":
                if (
                    "file" in data["data"]
                    and data["data"]["file"] != ""
                    and "content" in data["data"]
                ):
                    filename = os.path.join(directoryconffile(), data["data"]["file"])
                    file_put_contents(filename, data["data"]["content"])
                    data["data"] = {
                        "result": f"create file {filename}",
                        "error": False,
                        "numerror": 0,
                    }
                    return json.dumps(data)
                else:
                    data["data"] = {
                        "result": "error create file : name file missing",
                        "error": True,
                        "numerror": 129,
                    }
            elif data["data"]["action"] == "save":
                if (
                    "file" in data["data"]
                    and data["data"]["file"] != ""
                    and "content" in data["data"]
                ):
                    filename = os.path.join(directoryconffile(), data["data"]["file"])
                    if os.path.isfile(filename):
                        file_put_contents(filename, data["data"]["content"])
                        data["data"] = {
                            "result": f"save file {filename}",
                            "error": False,
                            "numerror": 0,
                        }
                        return json.dumps(data)
                    else:
                        data["data"] = {
                            "result": f"error save config file {filename} missing",
                            "error": True,
                            "numerror": 130,
                        }
            elif data["data"]["action"] == "listconfigfile":
                listfileedit = [
                    x
                    for x in os.listdir(directoryconffile())
                    if (x.endswith(".ini") or x.endswith(".ini.local"))
                ]
                data["data"] = {"result": listfileedit, "error": False, "numerror": 0}
                return json.dumps(data)
            else:
                data["data"] = {
                    "result": "error the action parameter is not correct ",
                    "error": True,
                    "numerror": 131,
                }
        else:
            data["data"] = {
                "result": "error action remotefileeditaction parameter incorrect",
                "error": True,
                "numerror": 132,
            }
        return json.dumps(data)

    @staticmethod
    def packageslist(xmppobject, data):
        packages_path = os.path.join("/", "var", "lib", "pulse2", "packages")
        packages_list = {"total": 0, "datas": []}
        total = 0
        for folder, sub_folders, files in os.walk(packages_path):
            size_bytes = 0
            if (
                files
                and os.path.isfile(os.path.join(folder, "conf.json"))
                or os.path.isfile(os.path.join(folder, "xmppdeploy.json"))
            ):
                total += 1
                _files = []
                count_files = 0
                for f in files:
                    count_files += 1
                    path = os.path.join(folder, f)
                    size_bytes += os.stat(path).st_size
                    _files.append((f, os.stat(path).st_size))

                name = folder.split("/")[-1]
                licenses = ""
                metagenerator = ""
                description = ""
                version = ""
                targetos = ""
                methodtransfer = ""
                try:
                    with open(os.path.join(folder, "conf.json"), "r") as conf_file:
                        conf_json = json.load(conf_file)
                        if "licenses" in conf_json:
                            licenses = conf_json["licenses"]
                except BaseException:
                    pass

                try:
                    with open(
                        os.path.join(folder, "xmppdeploy.json"), "r"
                    ) as deploy_file:
                        deploy_json = json.load(deploy_file)
                        if "metagenerator" in deploy_json["info"]:
                            metagenerator = deploy_json["info"]["metagenerator"]
                        if "name" in deploy_json["info"]:
                            name = deploy_json["info"]["name"]
                        if "description" in deploy_json["info"]:
                            description = deploy_json["info"]["description"]
                        if "version" in deploy_json["info"]:
                            version = deploy_json["info"]["version"]
                        if "methodtransfer" in deploy_json["info"]:
                            methodtransfer = deploy_json["info"]["methodetransfert"]
                        if "os" in deploy_json["metaparameter"]:
                            targetos = ", ".join(deploy_json["metaparameter"]["os"])
                except BaseException:
                    pass
                packages_list["datas"].append(
                    {
                        "uuid": folder,
                        "size": size_bytes,
                        "targetos": targetos,
                        "version": version,
                        "description": description,
                        "metagenerator": metagenerator,
                        "licenses": licenses,
                        "name": name,
                        "methodtransfer": methodtransfer,
                        "files": _files,
                        "count_files": count_files,
                    }
                )

        packages_list["total"] = total
        return json.dumps(packages_list, indent=4)
