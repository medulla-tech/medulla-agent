# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2016-2023 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-3.0-or-later

from xml.etree import ElementTree
from lib import utils
from lib.utils import convert
import os
import sys
import platform
import time
import zlib
import base64
import traceback
import json
import logging
import subprocess
import shutil
import lxml.etree as ET
from lib.agentconffile import (
    conffilename,
    medullaPath,
    directoryconffile,
    pulseTempDir,
    conffilenametmp,
    rotation_file,
)

_import_update_linux_error = None
_import_update_linux_traceback = None
UpdateLinux = None
if sys.platform.startswith("linux"):
    try:
        from lib.update_linux import UpdateLinux
    except Exception as exc_lib:
        _import_update_linux_error = exc_lib
        _import_update_linux_traceback = traceback.format_exc()
        try:
            from update_linux import UpdateLinux
        except Exception as exc_local:
            _import_update_linux_error = exc_local
            _import_update_linux_traceback = traceback.format_exc()

import hashlib

logger = logging.getLogger()
if sys.platform.startswith("win"):
    from lib import registerwindows
    import winreg
from slixmpp import jid

DEBUGPULSEPLUGIN = 25
ERRORPULSEPLUGIN = 40
WARNINGPULSEPLUGIN = 30
plugin = {"VERSION": "4.5", "NAME": "inventory", "TYPE": "machine"}  # fmt: skip


@utils.set_logging_level
def action(xmppobject, action, sessionid, data, message, dataerreur):
    logger.debug("###################################################")
    logger.debug("call %s from %s" % (plugin, message["from"]))
    logger.debug("###################################################")
    strjidagent = str(xmppobject.boundjid.bare)
    try:
        xmppobject.sub_inventory
    except:
        xmppobject.sub_inventory = jid.JID("master_inv@pulse")
    try:
        xmppobject.sub_updates
    except:
        xmppobject.sub_updates = jid.JID("master_upd@pulse")
    if sys.platform.startswith("win"):
        try:
            send_plugin_update_windows(xmppobject)
        except Exception as e:
            logger.error("An error occured while calling the plugin:  %s" % str(e))
            logger.error("We got the backtrace\n%s" % (traceback.format_exc()))
    elif sys.platform.startswith("linux"):
        try:
            send_plugin_update_linux(xmppobject)
        except Exception as e:
            logger.error("An error occured while calling the plugin:  %s" % str(e))
            logger.error("We got the backtrace\n%s" % (traceback.format_exc()))

    boolchange = True
    namefilexml = ""
    if hasattr(xmppobject.config, "via_xmpp"):
        if xmppobject.config.via_xmpp == "False":
            if not hasattr(xmppobject.config, "urlinventory"):
                logger.error(
                    "urlinventory must be defined in inventory.ini if via_xmpp is False"
                )
                xmppobject.xmpplog(
                    "urlinventory must be defined in inventory.ini if via_xmpp is False",
                    type="deploy",
                    sessionname=sessionid,
                    priority=-1,
                    action="xmpplog",
                    who=strjidagent,
                    module="Notify | Inventory | Error",
                    date=None,
                )
                return
    else:
        xmppobject.config.via_xmpp = "True"
    if hasattr(xmppobject.config, "json_file_extend_inventory"):
        if os.path.exists(xmppobject.config.json_file_extend_inventory):
            dd = extend_xmlfile(xmppobject)
            root = ET.fromstring(dd)
            strxml = """<?xml version="1.0" encoding="UTF-8" ?>\n%s""" % (
                ET.tostring(root, pretty_print=True)
            )
            namefilexml = xmppobject.config.json_file_extend_inventory + ".xml"
            utils.file_put_contents_w_a(namefilexml, strxml)

    # Enrichissement avec les extensions navigateurs et add-ins Office.
    # Si active (inventory_browser_extensions = True), produit un XML <SOFTWARES>
    # fusionne avec l'enrichissement eventuel ci-dessus, injecte via
    # --additional-content dans l'inventaire envoye a GLPI.
    namefilexml = collect_browser_extensions(xmppobject, namefilexml)
    try:
        compteurcallplugin = getattr(xmppobject, "num_call%s" % action)
        if compteurcallplugin == 0:
            logger.debug("configure plugin %s" % action)
    except BaseException:
        pass
    try:
        xmppobject.sub_inventory
    except BaseException:
        xmppobject.sub_inventory = xmppobject.agentmaster

    agent = "fusioninventory"

    if hasattr(xmppobject.config, "agent"):
        if xmppobject.config.agent == "glpiagent":
            agent = xmppobject.config.agent

    resultaction = "result%s" % action
    result = {}
    result["action"] = resultaction
    result["ret"] = 0
    result["sessionid"] = sessionid
    result["base64"] = False
    result["data"] = {}
    dataerreur["action"] = resultaction
    dataerreur["data"]["msg"] = "ERROR : %s" % action
    dataerreur["sessionid"] = sessionid
    timeoutfusion = 120
    msg = []
    executed_commands = []

    if not len(data):
        data = {"forced": "forced"}
    elif "forced" not in data:
        data["forced"] = "forced"
    elif data["forced"] is True:
        data["forced"] = "forced"
    elif data["forced"] is False:
        data["forced"] = "noforced"

    if sys.platform.startswith("linux"):
        inventoryfile = os.path.join("/tmp", "inventory.txt")
    elif sys.platform.startswith("win") or sys.platform.startswith("darwin"):
        inventoryfile = os.path.join(pulseTempDir(), "inventory.txt")
    else:
        logger.error("undefined OS")
        xmppobject.xmpplog(
            "undefined OS",
            type="deploy",
            sessionname=sessionid,
            priority=-1,
            action="xmpplog",
            who=strjidagent,
            module="Notify | Inventory | Error",
            date=None,
        )
        return

    if os.path.exists(inventoryfile):
        if os.path.exists("%s.back" % inventoryfile):
            os.remove("%s.back" % inventoryfile)
        os.rename(inventoryfile, "%s.back" % inventoryfile)

    if sys.platform.startswith("linux"):
        if agent == "glpiagent":
            agent_candidates = ["glpi-agent", "fusioninventory-agent"]
        else:
            agent_candidates = ["fusioninventory-agent", "glpi-agent"]

        # Resolve executable robustly for service environments where PATH can
        # differ from interactive shells. If preferred binary is unavailable,
        # fallback to the alternate inventory agent.
        agent_cmd = None
        agent_bin = None
        for candidate_bin in agent_candidates:
            candidate_cmd = shutil.which(candidate_bin)
            if not candidate_cmd:
                known_locations = [
                    "/usr/bin/%s" % candidate_bin,
                    "/usr/local/bin/%s" % candidate_bin,
                    "/bin/%s" % candidate_bin,
                    "/snap/bin/%s" % candidate_bin,
                ]
                for candidate_path in known_locations:
                    if os.path.isfile(candidate_path) and os.access(candidate_path, os.X_OK):
                        candidate_cmd = candidate_path
                        break
            if candidate_cmd:
                agent_bin = candidate_bin
                agent_cmd = candidate_cmd
                break

        if not agent_cmd:
            raise Exception(
                "Inventory agent binary not found: candidates=%s (PATH=%s)"
                % (agent_candidates, os.environ.get("PATH", ""))
            )

        if agent_bin != agent_candidates[0]:
            logger.warning(
                "Preferred inventory agent '%s' unavailable, fallback to '%s'",
                agent_candidates[0],
                agent_bin,
            )

        logger.debug(
            "Inventory agent executable resolved: candidates=%s selected=%s resolved=%s PATH=%s",
            agent_candidates,
            agent_bin,
            agent_cmd,
            os.environ.get("PATH", ""),
        )
        try:
            for nbcmd in range(1, 4):
                logger.debug("process inventory %s timeout %s" % (nbcmd, timeoutfusion))
                general_options = "--backend-collect-timeout=%s" % timeoutfusion
                if hasattr(xmppobject.config, "inventorytag"):
                    if xmppobject.config.inventorytag:
                        general_options = (
                            general_options + " --tag=%s" % xmppobject.config.inventorytag
                        )
                location_option = '--local="%s"' % inventoryfile
                if xmppobject.config.via_xmpp == "False":
                    location_option = '--server="%s"' % xmppobject.config.urlinventory
                if namefilexml and os.path.exists(namefilexml):
                    cmd = '"%s" %s %s --additional-content=%s' % (
                        agent_cmd,
                        general_options,
                        location_option,
                        namefilexml,
                    )
                else:
                    cmd = '"%s" %s %s' % (
                        agent_cmd,
                        general_options,
                        location_option,
                    )
                logger.debug("Command: %s" % cmd)
                msg.append(cmd)
                obj = utils.simplecommand(cmd)
                msg.append("Result return code %s: %s" % (obj["code"], obj["result"]))
                executed_commands.append(
                    {
                        "attempt": nbcmd,
                        "timeout": timeoutfusion,
                        "command": cmd,
                        "return_code": obj["code"],
                    }
                )
                if obj["code"] == 0:
                    break
                timeoutfusion = timeoutfusion + 60
            for mesg in msg:
                logger.debug(mesg)
                xmppobject.xmpplog(
                    mesg,
                    type="deploy",
                    sessionname=sessionid,
                    priority=-1,
                    action="xmpplog",
                    who=strjidagent,
                    module="Notify | Inventory | Error",
                    date=None,
                )
            msg = []
            if os.path.exists(inventoryfile):
                try:
                    result["data"]["inventory"], boolchange = compact_xml(inventoryfile)
                    result["data"]["inventory"] = convert.compress_and_encode(
                        result["data"]["inventory"]
                    )
                    if boolchange is False:
                        xmppobject.xmpplog(
                            "no significant change in inventory.",
                            type="deploy",
                            sessionname=sessionid,
                            priority=-1,
                            action="xmpplog",
                            who=strjidagent,
                            module="Notify | Inventory",
                            date=None,
                        )
                    else:
                        xmppobject.xmpplog(
                            "inventory changed",
                            type="deploy",
                            sessionname=sessionid,
                            priority=-1,
                            action="xmpplog",
                            who=strjidagent,
                            module="Notify | Inventory",
                            date=None,
                        )
                except Exception as e:
                    logger.error(
                        "An error occured while calling the plugin:  %s" % str(e)
                    )
                    logger.error("We got the backtrace\n%s" % (traceback.format_exc()))
                    xmppobject.xmpplog(
                        "Inventory error %s " % str(e),
                        type="deploy",
                        sessionname=sessionid,
                        priority=-1,
                        action="xmpplog",
                        who=strjidagent,
                        module="Notify | Inventory | Error",
                        date=None,
                    )
                    raise Exception(str(e))
            else:
                logger.warning("The inventory file %s does not exits" % inventoryfile)
                logger.warning(
                    "If the Medulla agent just started, this error is normal"
                )
                logger.warning(
                    "But if it starts for a while please check that %s is correctly installed and working" % agent_bin
                )
                raise Exception(
                    "Inventory file missing after command execution. "
                    "agent_bin=%s agent_cmd=%s inventoryfile=%s commands=%s"
                    % (agent_bin, agent_cmd, inventoryfile, executed_commands[-3:])
                )
        except Exception as e:
            dataerreur["data"]["msg"] = "Plugin inventory error %s : %s" % (
                dataerreur["data"]["msg"],
                str(e),
            )
            dataerreur["data"]["error_type"] = e.__class__.__name__
            dataerreur["data"]["error_detail"] = str(e)
            dataerreur["data"]["command_trace"] = executed_commands[-3:]
            logger.error("An error occured while calling the plugin:  %s" % str(e))
            logger.error("We got the backtrace\n%s" % (traceback.format_exc()))
            logger.error("Send error message\n%s" % dataerreur)
            xmppobject.send_message(
                mto=xmppobject.sub_inventory, mbody=json.dumps(dataerreur), mtype="chat"
            )
            msg.append(dataerreur["data"]["msg"])
            for mesg in msg:
                logger.debug(mesg)
                xmppobject.xmpplog(
                    mesg,
                    type="deploy",
                    sessionname=sessionid,
                    priority=-1,
                    action="xmpplog",
                    who=strjidagent,
                    module="Notify | Inventory | Error",
                    date=None,
                )
            return
    elif sys.platform.startswith("win"):
        try:
            bitness = platform.architecture()[0]
            if bitness == "32bit":
                other_view_flag = winreg.KEY_WOW64_64KEY
            elif bitness == "64bit":
                other_view_flag = winreg.KEY_WOW64_32KEY
            # Set the variables

            if agent == "glpiagent":
                agent_bin = "glpi-agent.bat"
                agent_path = "GLPI-Agent"
            else:
                agent_bin = "fusioninventory-agent.bat"
                agent_path = "FusionInventory-Agent"

            program = os.path.join("c:\\", "progra~1", agent_path, agent_bin)
            general_options = (
                "--config=none --scan-profiles "
                "--backend-collect-timeout=%s" % timeoutfusion
            )
            if hasattr(xmppobject.config, "inventorytag"):
                if xmppobject.config.inventorytag:
                    general_options = (
                        general_options + " --tag=%s" % xmppobject.config.inventorytag
                    )
            location_option = '--local="%s"' % inventoryfile
            if xmppobject.config.via_xmpp == "False":
                location_option = '--server="%s"' % xmppobject.config.urlinventory
            if hasattr(xmppobject.config, "collector"):
                if xmppobject.config.collector == "ocs":
                    # If OCS x64 bits exists use it
                    if os.path.exists(
                        os.path.join(
                            os.environ["ProgramFiles"],
                            "OCS Inventory Agent",
                            "OCSInventory.exe",
                        )
                    ):
                        program = os.path.join(
                            os.environ["ProgramFiles"],
                            "OCS Inventory Agent",
                            "OCSInventory.exe",
                        )
                    else:
                        # Or use OCS x32 bits
                        program = os.path.join(
                            os.environ["ProgramFiles(x86)"],
                            "OCS Inventory Agent",
                            "OCSInventory.exe",
                        )
                    admininfoconf = os.path.join(
                        os.environ["Programdata"],
                        "OCS Inventory NG",
                        "Agent",
                        "admininfo.conf",
                    )
                    if os.path.exists(admininfoconf):
                        tree = ElementTree.parse(admininfoconf)
                        accountinfo = tree.getroot()
                        tag = accountinfo.find("./KEYVALUE").text
                    try:
                        general_options = '/debug /force /tag="%s"' % tag
                    except NameError:
                        general_options = "/debug /force"
                    # /xml option is waiting for a folder path, not a file path
                    # The inventory is generated as machine_name-id-datetime.xml
                    location_option = '/xml="%s" /S' % pulseTempDir()
                    if xmppobject.config.via_xmpp == "False":
                        location_option = (
                            '/server="%s"' % xmppobject.config.urlinventory
                        )

            for nbcmd in range(3):
                if os.path.exists(namefilexml):
                    cmd = """\"%s\" %s %s """ """--additional-content=%s """ % (
                        program,
                        general_options,
                        location_option,
                        namefilexml,
                    )
                else:
                    cmd = """\"%s\" %s %s""" % (
                        program,
                        general_options,
                        location_option,
                    )
                msg.append(cmd)
                logger.debug(cmd)
                obj = utils.simplecommand(cmd)
                # find the .xml or .ocs file into pulseTempDir (C:\Program Files\Medulla\tmp)
                files = os.listdir(pulseTempDir())
                xmlfile = ""
                for file in files:
                    if file.endswith(".xml") or file.endswith(".ocs"):
                        xmlfile = file
                        break
                if xmlfile != "":
                    try:
                        # a file has been found: try to rename it
                        os.rename(os.path.join(pulseTempDir(), xmlfile), inventoryfile)
                    except:
                        # The file already exists, means the previous inventory has not been renamed in .back
                        pass
                msg.append("Result return code %s: %s" % (obj["code"], obj["result"]))
                if obj["code"] == 0:
                    break
                timeoutfusion = timeoutfusion + 60
            for mesg in msg:
                xmppobject.xmpplog(
                    mesg,
                    type="deploy",
                    sessionname=sessionid,
                    priority=-1,
                    action="xmpplog",
                    who=strjidagent,
                    module="Notify | Inventory | Error",
                    date=None,
                )
            msg = []
            if xmppobject.config.via_xmpp == "True":
                if os.path.exists(inventoryfile):
                    try:
                        # read max_key_index parameter to find out the number of keys
                        # Registry keys that need to be pushed in an inventory
                        graine = ""
                        listfinger = []
                        if hasattr(xmppobject.config, "max_key_index"):
                            result["data"]["reginventory"] = {}
                            result["data"]["reginventory"]["info"] = {}
                            result["data"]["reginventory"]["info"]["max_key_index"] = (
                                int(xmppobject.config.max_key_index)
                            )
                            nb_iter = int(xmppobject.config.max_key_index) + 1
                            # get the value of each key and create the json
                            # file
                            for num in range(1, nb_iter):
                                reg_key_num = "reg_key_" + str(num)
                                result["data"]["reginventory"][reg_key_num] = {}
                                registry_key = getattr(xmppobject.config, reg_key_num)
                                result["data"]["reginventory"][reg_key_num][
                                    "key"
                                ] = registry_key
                                hive = registry_key.split("\\")[0].strip('"')
                                sub_key = registry_key.split("\\")[-1].strip('"')
                                path = (
                                    registry_key.replace(hive + "\\", "")
                                    .replace("\\" + sub_key, "")
                                    .strip('"')
                                )
                                if hive == "HKEY_CURRENT_USER":
                                    if hasattr(xmppobject.config, "current_user"):
                                        # Utilisation de PowerShell pour obtenir le SID de l'utilisateur
                                        process = subprocess.Popen(
                                            ["powershell", "-Command",
                                            "$user = Get-LocalUser -Name '" + xmppobject.config.current_user + "'; "
                                            "$sid = $user.SID; Write-Output $sid"],
                                            stdout=subprocess.PIPE,
                                            stderr=subprocess.STDOUT,
                                            shell=True,
                                        )
                                        output, _ = process.communicate()
                                        sid = output.decode("utf-8").strip()
                                        hive = "HKEY_USERS"
                                        path = sid + "\\" + path
                                    else:
                                        logging.log(
                                            DEBUGPULSEPLUGIN,
                                            "HKEY_CURRENT_USER hive defined but current_user config parameter is not",
                                        )

                                logging.log(DEBUGPULSEPLUGIN, "hive: %s" % hive)
                                logging.log(DEBUGPULSEPLUGIN, "path: %s" % path)
                                logging.log(DEBUGPULSEPLUGIN, "sub_key: %s" % sub_key)
                                reg_constants = (
                                    registerwindows.constantregisterwindows()
                                )
                                try:
                                    key = winreg.OpenKey(
                                        reg_constants.getkey(hive),
                                        path,
                                        0,
                                        winreg.KEY_READ | other_view_flag,
                                    )
                                    key_value = winreg.QueryValueEx(key, sub_key)
                                    logging.log(
                                        DEBUGPULSEPLUGIN,
                                        "key_value: %s" % str(key_value[0]),
                                    )
                                    result["data"]["reginventory"][reg_key_num][
                                        "value"
                                    ] = str(key_value[0])
                                    listfinger.append(str(key_value[0]))
                                    winreg.CloseKey(key)
                                except Exception as e:
                                    logger.error(
                                        "An error occured while calling the plugin:  %s"
                                        % str(e)
                                    )
                                    logging.log(
                                        ERRORPULSEPLUGIN,
                                        "Error getting key: %s" % str(e),
                                    )
                                    result["data"]["reginventory"][reg_key_num][
                                        "value"
                                    ] = ""
                                    pass
                            # generate the json and encode
                            logging.log(
                                DEBUGPULSEPLUGIN,
                                "---------- Registry inventory Data ----------",
                            )
                            logging.log(
                                DEBUGPULSEPLUGIN,
                                json.dumps(
                                    result["data"]["reginventory"],
                                    indent=4,
                                    separators=(",", ": "),
                                ),
                            )
                            logging.log(
                                DEBUGPULSEPLUGIN,
                                "---------- End Registry inventory Data ----------",
                            )
                            result["data"]["reginventory"] = base64.b64encode(
                                json.dumps(
                                    result["data"]["reginventory"],
                                    indent=4,
                                    separators=(",", ": "),
                                )
                            )
                            # dans le cas ou il y a des registres, ceux ci seront pris en compte pour le fingerprint.
                            # on est jamais certain de l'ordre d'un dict. donc
                            # on peut pas prendre directement celui-ci dans 1
                            # finger print.
                            listfinger.sort()
                            graine = "".join(listfinger)
                        result["data"]["inventory"], boolchange = compact_xml(
                            inventoryfile, graine=graine
                        )
                        result["data"]["inventory"] = convert.compress_and_encode(
                            result["data"]["inventory"]
                        )

                        if boolchange is False:
                            xmppobject.xmpplog(
                                "no significant change in inventory.",
                                type="deploy",
                                sessionname=sessionid,
                                priority=-1,
                                action="xmpplog",
                                who=strjidagent,
                                module="Notify | Inventory",
                                date=None,
                            )
                        else:
                            xmppobject.xmpplog(
                                "inventory changed",
                                type="deploy",
                                sessionname=sessionid,
                                priority=-1,
                                action="xmpplog",
                                who=strjidagent,
                                module="Notify | Inventory",
                                date=None,
                            )
                    except Exception as e:
                        logger.error(
                            "An error occured while calling the plugin:  %s" % str(e)
                        )
                        logger.error(
                            "We got the backtrace\n%s" % (traceback.format_exc())
                        )
                        xmppobject.xmpplog(
                            "Inventory error %s " % str(e),
                            type="deploy",
                            sessionname=sessionid,
                            priority=-1,
                            action="xmpplog",
                            who=strjidagent,
                            module="Notify | Inventory | Error",
                            date=None,
                        )
                        raise Exception(str(e))
                else:
                    raise Exception("Inventory file does not exist")
            else:
                logger.info(
                    "Inventory sent directly to inventory server %s"
                    % xmppobject.config.urlinventory
                )
        except Exception as e:
            dataerreur["data"]["msg"] = "Plugin inventory error %s : %s" % (
                dataerreur["data"]["msg"],
                str(e),
            )
            dataerreur["data"]["error_type"] = e.__class__.__name__
            dataerreur["data"]["error_detail"] = str(e)
            logger.error("An error occured while calling the plugin:  %s" % str(e))
            logger.error("We got the backtrace\n%s" % (traceback.format_exc()))
            logger.error("Send error message\n%s" % dataerreur)
            xmppobject.send_message(
                mto=xmppobject.sub_inventory, mbody=json.dumps(dataerreur), mtype="chat"
            )
            msg.append(dataerreur["data"]["msg"])
            for mesg in msg:
                logger.debug(mesg)
                xmppobject.xmpplog(
                    mesg,
                    type="deploy",
                    sessionname=sessionid,
                    priority=-1,
                    action="xmpplog",
                    who=strjidagent,
                    module="Notify | Inventory | Error",
                    date=None,
                )
            return
    elif sys.platform.startswith("darwin"):
        try:
            for nbcmd in range(3):
                # Warning: this command has been tested on only 1 Mac
                cmd = (
                    "/opt/fusioninventory-agent/bin/fusioninventory-inventory "
                    "--backend-collect-timeout=%s > %s" % (timeoutfusion, inventoryfile)
                )
                msg.append(cmd)
                logger.debug(cmd)
                obj = utils.simplecommand(cmd)
                msg.append("Result return code %s: %s" % (obj["code"], obj["result"]))
                if obj["code"] == 0:
                    break
                timeoutfusion = timeoutfusion + 60
            for mesg in msg:
                xmppobject.xmpplog(
                    mesg,
                    type="deploy",
                    sessionname=sessionid,
                    priority=-1,
                    action="xmpplog",
                    who=strjidagent,
                    module="Notify | Inventory | Error",
                    date=None,
                )
            msg = []
            if os.path.exists(inventoryfile):
                try:
                    result["data"]["inventory"], boolchange = compact_xml(inventoryfile)
                    result["data"]["inventory"] = convert.compress_and_encode(
                        result["data"]["inventory"]
                    )
                    if boolchange is False:
                        xmppobject.xmpplog(
                            "no significant change in inventory.",
                            type="deploy",
                            sessionname=sessionid,
                            priority=-1,
                            action="xmpplog",
                            who=strjidagent,
                            module="Notify | Inventory",
                            date=None,
                        )
                    else:
                        xmppobject.xmpplog(
                            "inventory changed",
                            type="deploy",
                            sessionname=sessionid,
                            priority=-1,
                            action="xmpplog",
                            who=strjidagent,
                            module="Notify | Inventory",
                            date=None,
                        )
                except Exception as e:
                    logger.error(
                        "An error occured while calling the plugin:  %s" % str(e)
                    )
                    logger.error("We got the backtrace\n%s" % (traceback.format_exc()))
                    xmppobject.xmpplog(
                        "Inventory error %s " % str(e),
                        type="deploy",
                        sessionname=sessionid,
                        priority=-1,
                        action="xmpplog",
                        who=strjidagent,
                        module="Notify | Inventory | Error",
                        date=None,
                    )
                    raise Exception(str(e))
            else:
                raise Exception("The inventory file does not exists")
        except Exception as e:
            dataerreur["data"]["msg"] = "Plugin inventory error %s : %s" % (
                dataerreur["data"]["msg"],
                str(e),
            )
            dataerreur["data"]["error_type"] = e.__class__.__name__
            dataerreur["data"]["error_detail"] = str(e)
            logger.error("An error occured while calling the plugin:  %s" % str(e))
            logger.error("We got the backtrace\n%s" % (traceback.format_exc()))
            logger.error("Send error message\n%s" % dataerreur)
            xmppobject.send_message(
                mto=xmppobject.sub_inventory, mbody=json.dumps(dataerreur), mtype="chat"
            )
            msg.append(dataerreur["data"]["msg"])
            for mesg in msg:
                logger.debug(mesg)
                xmppobject.xmpplog(
                    mesg,
                    type="deploy",
                    sessionname=sessionid,
                    priority=-1,
                    action="xmpplog",
                    who=strjidagent,
                    module="Notify | Inventory | Error",
                    date=None,
                )
            return

    if result["base64"] is True:
        result["data"] = base64.b64encode(json.dumps(result["data"]))

    if "inventory" not in result["data"]:
        dataerreur["data"]["msg"] = "Plugin inventory error %s : missing inventory payload" % (
            dataerreur["data"]["msg"],
        )
        dataerreur["data"]["error_type"] = "MissingInventoryPayload"
        dataerreur["data"]["error_detail"] = (
            "No 'inventory' key in result data after collection workflow"
        )
        if executed_commands:
            dataerreur["data"]["command_trace"] = executed_commands[-3:]
        logger.error("Inventory payload is missing, sending structured error\n%s" % dataerreur)
        xmppobject.send_message(
            mto=xmppobject.sub_inventory, mbody=json.dumps(dataerreur), mtype="chat"
        )
        return

    if data["forced"] == "forced" or boolchange:
        logger.debug("inventory is injected to :  %s" % xmppobject.sub_inventory)
        xmppobject.send_message(
            mto=xmppobject.sub_inventory, mbody=json.dumps(result), mtype="chat"
        )
        xmppobject.xmpplog(
            "inventory is injected",
            type="deploy",
            sessionname=sessionid,
            priority=-1,
            action="xmpplog",
            who=strjidagent,
            module="Notify | Inventory",
            date=None,
        )
        if sessionid.startswith("commandkiosk"):
            # Deadline to ensure that GLPI treatment is completed before requesting the date of inventory
            time.sleep(10)
            xmppobject.send_message_to_master(
                {"action": "resultkiosk", "data": {"subaction": "inventory"}}
            )
    else:
        logger.debug("inventory is not injected")
        xmppobject.xmpplog(
            "inventory is not injected",
            type="deploy",
            sessionname=sessionid,
            priority=-1,
            action="xmpplog",
            who=strjidagent,
            module="Notify | Inventory",
            date=None,
        )


def Setdirectorytempinfo():
    """
    This functions create a temporary directory.

    Returns:
    path directory INFO Temporaly
    """
    dirtempinfo = os.path.abspath(
        os.path.join(
            os.path.dirname(os.path.realpath(__file__)), "..", "lib", "INFOSTMP"
        )
    )
    if not os.path.exists(dirtempinfo):
        os.makedirs(dirtempinfo, mode=0o007)
    return dirtempinfo


def compact_xml(inputfile, graine=""):
    """prepare xml a envoyer et genere 1 finger print"""
    parser = ET.XMLParser(remove_blank_text=True, remove_comments=True)

    if isinstance(inputfile, str):
        inputfile = inputfile.encode(encoding="UTF-8")

    xmlTree = ET.parse(inputfile, parser=parser)
    contentfile = ET.tostring(xmlTree, pretty_print=False).decode("utf-8")
    strinventorysave = '<?xml version="1.0" encoding="UTF-8" ?>' + contentfile
    utils.file_put_contents_w_a(inputfile, strinventorysave)
    # fingerprint
    listxpath = [
        "/REQUEST/CONTENT/ACCESSLOG",
        "/REQUEST/CONTENT/BIOS",
        "/REQUEST/CONTENT/OPERATINGSYSTEM",
        "/REQUEST/CONTENT/ENVS",
        "/REQUEST/CONTENT/PROCESSES",
        "/REQUEST/CONTENT/DRIVES",
        "/REQUEST/CONTENT/HARDWARE",
        "/REQUEST/CONTENT/CONTROLLERS",
        "/REQUEST/CONTENT/CPUS",
        "/REQUEST/CONTENT/VERSIONPROVIDER",
        "/REQUEST/CONTENT/INPUTS",
        "/REQUEST/CONTENT/LOCAL_GROUPS",
        "/REQUEST/CONTENT/LOCAL_USERS",
        "/REQUEST/CONTENT/VERSIONCLIENT",
        "/REQUEST/CONTENT/FIREWALL",
        "/REQUEST/DEVICEID",
        "/REQUEST/QUERY",
    ]
    for searchtag in listxpath:
        p = xmlTree.xpath(searchtag)
        for t in p:
            t.getparent().remove(t)
    strinventory = ET.tostring(xmlTree, pretty_print=True).decode("utf-8")
    # -----debug file compare------
    # namefilecompare = "%s.xml1" % inputfile
    # if os.path.exists(namefilecompare):
    # os.rename(namefilecompare, "%s.back" % namefilecompare)
    # utils.file_put_contents_w_a(namefilecompare, strinventory)
    # -----end debug file compare------
    if not isinstance(graine, str):
        graine = graine.encode(encoding="UTF-8")
    strbytes = strinventory + graine
    fingerprintinventory = hashlib.md5(strbytes.encode("utf-8")).hexdigest()
    # on recupere ancienne fingerprint
    manefilefingerprintinventory = os.path.join(
        Setdirectorytempinfo(), "fingerprintinventory"
    )
    oldfingerprintinventory = ""
    if os.path.exists(manefilefingerprintinventory):
        oldfingerprintinventory = utils.file_get_contents(manefilefingerprintinventory)
    utils.file_put_contents_w_a(manefilefingerprintinventory, fingerprintinventory)
    if fingerprintinventory == oldfingerprintinventory:
        logger.debug("no significant change in inventory.")

        return strinventorysave, False
    logger.debug("inventory is modify.")
    return strinventorysave, True


def merge_additional_content(xml_files, output_file):
    """Fusionne plusieurs XML d'inventaire partiel en un seul fichier.

    fusioninventory/glpi-agent n'accepte qu'un seul `--additional-content`.
    On regroupe donc le contenu de tous les <CONTENT> dans un <REQUEST> unique.

    Args:
        xml_files: liste de chemins de fichiers XML <REQUEST><CONTENT>...
        output_file: chemin du fichier fusionne a ecrire.

    Returns:
        Le chemin du fichier fusionne.
    """
    request = ET.Element("REQUEST")
    content = ET.SubElement(request, "CONTENT")
    for xml_file in xml_files:
        if not xml_file or not os.path.exists(xml_file):
            continue
        try:
            root = ET.parse(xml_file).getroot()
        except Exception as exc:
            logger.error("Cannot parse additional-content %s: %s", xml_file, exc)
            continue
        src_content = root.find("CONTENT") if root.tag == "REQUEST" else root
        if src_content is None:
            continue
        # list() : lxml deplace les noeuds lors de l'append, on fige donc
        # la liste source avant d'iterer.
        for child in list(src_content):
            content.append(child)
    strxml = ET.tostring(request, encoding="utf-8", xml_declaration=True)
    with open(output_file, "wb") as f:
        f.write(strxml)
    return output_file


def collect_browser_extensions(xmppobject, existing_xml=""):
    """Collecte les extensions navigateurs et add-ins Office, et retourne le
    chemin d'un XML <SOFTWARES> destine a l'option `--additional-content`.

    Pilotee par la cle `inventory_browser_extensions = True` de inventory.ini.
    S'appuie sur le script autonome script/inventory-extension.py (stdlib pure,
    multi-OS) lance avec `--format additional-content`.

    Si un XML d'enrichissement est deja present (existing_xml, ex. peripheriques
    USB/imprimantes via json_file_extend_inventory), les deux sont fusionnes en
    un seul fichier puisque l'agent n'accepte qu'un seul --additional-content.

    Returns:
        Le chemin du XML a injecter, ou existing_xml inchange si la collecte
        est desactivee ou echoue.
    """
    enabled = getattr(xmppobject.config, "inventory_browser_extensions", "False")
    logger.debug(
        "[browserext] collect (inventory_browser_extensions=%r)", enabled
    )
    if str(enabled).strip().lower() != "true":
        logger.debug("[browserext] desactive - rien a faire")
        return existing_xml

    script_path = os.path.abspath(
        os.path.join(
            os.path.dirname(os.path.realpath(__file__)),
            "..",
            "script",
            "inventory-extension.py",
        )
    )
    if not os.path.exists(script_path):
        logger.error("[browserext] script introuvable: %s", script_path)
        return existing_xml

    # Interpreteur Python : dans un service Windows, sys.executable vaut souvent
    # medulla.exe / pythonservice.exe (et non un interpreteur capable de lancer
    # un script). On bascule alors sur python.exe situe a cote.
    python_exe = sys.executable
    if sys.platform == "win32" and not os.path.basename(
        python_exe
    ).lower().startswith("python"):
        for cand in (
            os.path.join(os.path.dirname(python_exe), "python.exe"),
            os.path.join(sys.prefix, "python.exe"),
            os.path.join(sys.exec_prefix, "python.exe"),
        ):
            if os.path.exists(cand):
                python_exe = cand
                break
    logger.debug(
        "[browserext] python_exe=%s (sys.executable=%s)", python_exe, sys.executable
    )

    browserext_xml = os.path.join(pulseTempDir(), "browserext_inventory.xml")
    cmd = '"%s" "%s" --format additional-content -o "%s"' % (
        python_exe,
        script_path,
        browserext_xml,
    )
    logger.debug("[browserext] cmd=%s", cmd)
    try:
        obj = utils.simplecommand(cmd)
        logger.debug("[browserext] returncode=%s", obj.get("code"))
    except Exception as exc:
        logger.error("[browserext] echec lancement du script: %s", exc)
        return existing_xml

    if not os.path.exists(browserext_xml):
        logger.warning("[browserext] aucun XML genere: %s", browserext_xml)
        return existing_xml

    logger.debug("[browserext] XML genere: %s", browserext_xml)

    # Fusion avec un eventuel enrichissement deja present (USB/imprimantes...).
    if existing_xml and os.path.exists(existing_xml):
        merged_xml = os.path.join(pulseTempDir(), "additional_content.xml")
        return merge_additional_content(
            [existing_xml, browserext_xml], merged_xml
        )
    return browserext_xml


def extend_xmlfile(xmppobject):
    """
    generation xml extend from json
    """
    datafile = utils.file_get_contents(xmppobject.config.json_file_extend_inventory)
    datafile = datafile.replace("\n", "")
    dataStripped = [x.strip() for x in datafile.split(",") if x.strip() != ""]
    dataFileCleaned = ",".join(dataStripped)
    dataFileCleaned = dataFileCleaned.replace("},]", "}]")
    dataFileCleaned = dataFileCleaned.replace("    ", " ")
    dataFileCleaned = dataFileCleaned.replace("  ", " ")
    logger.debug(
        "The informations that will be loaded by json are: %s", dataFileCleaned
    )
    data = json.loads(dataFileCleaned)
    if "action" in data:
        if data["action"] == "HwInfo":
            """add printer"""
            xmlstring = """
                           <REQUEST>
                           <CONTENT>"""
            if "peripherals" in data and data["peripherals"]:
                # Some peripherals must be added.
                for printer in data["peripherals"]:
                    # add printer
                    xmlstring = xmlstring + usbdevice_string(
                        data["terminal"],
                        "%s@%s@%s@%s@%s"
                        % (
                            data["terminal"],
                            printer["type"],
                            printer["serial"],
                            printer["manufacturer"],
                            printer["model"],
                        ),
                        printer["serial"],
                        printer["manufacturer"],
                        productid=printer["pid"],
                        vendorid=printer["vid"],
                        firmware=printer["firmware"],
                    )

            xmlstring = (
                xmlstring
                + """\n</CONTENT>
            </REQUEST>"""
            )
            return xmlstring


def usbdevice_string(
    terminal,
    name,
    serial,
    manufacturer,
    productid="",
    vendorid="",
    caption=None,
    classname=None,
    subclass=None,
    firmware="",
):
    if caption is None:
        caption = "%s@%s" % (name, terminal)

    if firmware != "":
        caption = "%s@%s" % (caption, firmware)
        name = "%s@%s" % (name, firmware)
    xmlprinter = """\n<USBDEVICES>
    <CAPTION>%s</CAPTION>
    <NAME>%s</NAME>
    <MANUFACTURER>%s</MANUFACTURER>
    <SERIAL>%s</SERIAL>
    <PRODUCTID>%s</PRODUCTID>
    <VENDORID>%s</VENDORID>
    <COMMENT>%s</COMMENT>
    """ % (
        caption.strip(),
        name.strip(),
        manufacturer.strip(),
        serial.strip(),
        productid.strip(),
        vendorid.strip(),
        firmware.strip(),
    )
    if classname is not None:
        xmlprinter = "%s\n<CLASS>%s</CLASS>" % (xmlprinter, classname)
        if subclass is not None:
            xmlprinter = "%s\n<SUBCLASS>%s</SUBCLASS>" % (xmlprinter, subclass)
    return "%s\n</USBDEVICES>" % (xmlprinter)


def printer_string(
    terminal,
    name,
    serial,
    description=None,
    driver=None,
    port="USB",
    network=None,
    printprocessor=None,
    resolution=None,
    shared=None,
    status=None,
    firmware="",
):
    if driver is None:
        driver = "%s@%s" % (name, terminal)
    if description is None:
        description = "%s@%s@%s@%s" % (name, serial, terminal, firmware)
    if firmware != "":
        description = "%s@%s" % (description, firmware)
        driver = "%s@%s" % (driver, firmware)
    xmlprinter = """\n<PRINTERS>
    <DRIVER>%s</DRIVER>
    <NAME>%s</NAME>
    <SERIAL>%s</SERIAL>
    <DESCRIPTION>%s</DESCRIPTION>
    <PORT>%s</PORT>""" % (
        driver,
        name,
        serial,
        description,
        port,
    )
    if network is not None:
        xmlprinter = " %s\n<NETWORK>%s</NETWORK>" % (xmlprinter, network)
    if printprocessor is not None:
        xmlprinter = "%s\n<PRINTPROCESSOR>%s</PRINTPROCESSOR>" % (
            xmlprinter,
            printprocessor,
        )
    if resolution is not None:
        xmlprinter = "%s\n<RESOLUTION>%s</RESOLUTION>" % (xmlprinter, resolution)
    if shared is not None:
        xmlprinter = "%s\n<SHARED>%s</SHARED>" % (xmlprinter, shared)
    if status is not None:
        xmlprinter = "%s\n<STATUS>%s</STATUS>" % (xmlprinter, status)
    return "%s\n</PRINTERS>" % (xmlprinter)


def send_plugin_update_windows(xmppobject):
    sessioniddata = utils.getRandomName(6, "update_windows")
    try:
        update_information = {
            "action": "update_windows",
            "sessionid": sessioniddata,
            "data": {"system_info": utils.offline_search_kb().get()},
            "ret": 0,
            "base64": False,
        }

        xmppobject.send_message(
            mto=xmppobject.sub_updates,
            mbody=json.dumps(update_information),
            mtype="chat",
        )
    except Exception as e:
        logger.error("An error occured while calling the plugin:  %s" % str(e))
        logger.error("We got the backtrace\n%s" % (traceback.format_exc()))


def send_plugin_update_linux(xmppobject):
    if not sys.platform.startswith("linux"):
        logger.debug("send_plugin_update_linux ignored on non-linux platform")
        return

    if UpdateLinux is None:
        logger.warning(
            "Module UpdateLinux indisponible: update_linux non envoye (inventaire principal maintenu). Cause import: %s",
            repr(_import_update_linux_error),
        )
        if _import_update_linux_traceback:
            logger.error(
                "Traceback import UpdateLinux:\n%s",
                _import_update_linux_traceback,
            )
        return

    sessioniddata = utils.getRandomName(6, "update_linux")
    updater = UpdateLinux(
        dry_run=False,            # execution reelle
        intranet_security=False   # depots normaux
    )
    logger.info(f"Distribution detectee : {updater.distro_name}\n")

    # ============================
    # 1. Fetch updates
    # ============================
    logger.info("[1] Recherche des mises a jour...")
    infosys = updater.fetch_updates()
    json_report = updater.to_json(return_dict=True)
    # logger.info(f"[1] Recherche des mises a jour... {json_report}")

    try:
        update_information = {
            "action": "update_linux",
            "sessionid": sessioniddata,
             "data": {"system_info": updater.to_json(base64_encode=True)},
            "ret": 0,
            "base64": False,
        }
        logger.info(f"send_message... {xmppobject.sub_updates}")
        xmppobject.send_message(
            mto=xmppobject.sub_updates,
            mbody=json.dumps(update_information),
            mtype="chat",
        )
    except Exception as e:
        logger.error("An error occured while calling the plugin:  %s" % str(e))
        logger.error("We got the backtrace\n%s" % (traceback.format_exc()))
