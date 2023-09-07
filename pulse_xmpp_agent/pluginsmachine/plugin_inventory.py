# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2016-2023 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-3.0-or-later

from xml.etree import ElementTree
from lib import utils
from lib.utils import convert
import os
import sys
import platform
import zlib
import base64
import traceback
import json
import logging
import subprocess
import lxml.etree as ET

import hashlib

logger = logging.getLogger()
if sys.platform.startswith("win"):
    from lib import registerwindows
    import winreg
from slixmpp import jid

DEBUGPULSEPLUGIN = 25
ERRORPULSEPLUGIN = 40
WARNINGPULSEPLUGIN = 30
plugin = {"VERSION": "3.71", "NAME": "inventory", "TYPE": "machine"}  # fmt: skip


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
    if "forced" not in data:
        data["forced"] = "forced"
    if data["forced"] is True:
        data["forced"] = "forced"
    if data["forced"] is False:
        data["forced"] = "noforced"

    if sys.platform.startswith("linux"):
        inventoryfile = os.path.join("/", "tmp", "inventory.txt")
    elif sys.platform.startswith("darwin"):
        inventoryfile = os.path.join("/opt", "Pulse", "tmp", "inventory.txt")
    elif sys.platform.startswith("win"):
        inventoryfile = os.path.join(
            os.environ["ProgramFiles"], "Pulse", "tmp", "inventory.txt"
        )
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
        try:
            for nbcmd in range(1, 4):
                logger.debug("process inventory %s timeout %s" % (nbcmd, timeoutfusion))
                general_options = "--backend-collect-timeout=%s" % timeoutfusion
                location_option = '--local="%s"' % inventoryfile
                if xmppobject.config.via_xmpp == "False":
                    location_option = '--server="%s"' % xmppobject.config.urlinventory
                if namefilexml and os.path.exists(namefilexml):
                    cmd = "fusioninventory-agent %s %s " "--additional-content=%s" % (
                        general_options,
                        location_option,
                        namefilexml,
                    )
                else:
                    cmd = "fusioninventory-agent %s %s" % (
                        general_options,
                        location_option,
                    )
                logger.debug("Command: %s" % cmd)
                msg.append(cmd)
                obj = utils.simplecommand(cmd)
                msg.append("Result return code %s: %s" % (obj["code"], obj["result"]))
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
                    "But if it starts for a while please check that FusionInventory is correctly installed and working"
                )
        except Exception as e:
            dataerreur["data"]["msg"] = "Plugin inventory error %s : %s" % (
                dataerreur["data"]["msg"],
                str(e),
            )
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

            program = os.path.join(os.environ["ProgramFiles"], agent_path, agent_bin)
            general_options = (
                "--config=none --scan-profiles "
                "--backend-collect-timeout=%s" % timeoutfusion
            )
            location_option = '--local="%s"' % inventoryfile
            if xmppobject.config.via_xmpp == "False":
                location_option = '--server="%s"' % xmppobject.config.urlinventory
            if hasattr(xmppobject.config, "collector"):
                if xmppobject.config.collector == "ocs":
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
                    location_option = '/xml="%s" /S' % inventoryfile
                    if xmppobject.config.via_xmpp == "False":
                        location_option = (
                            '/server="%s"' % xmppobject.config.urlinventory
                        )

            for nbcmd in range(3):
                try:
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
                except Exception:
                    cmd = """\"%s\" %s %s""" % (
                        program,
                        general_options,
                        location_option,
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
                            result["data"]["reginventory"]["info"][
                                "max_key_index"
                            ] = int(xmppobject.config.max_key_index)
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
                                        process = subprocess.Popen(
                                            "wmic useraccount where name = '%s' "
                                            "get sid" % xmppobject.config.current_user,
                                            shell=True,
                                            stdout=subprocess.PIPE,
                                            stderr=subprocess.STDOUT,
                                        )
                                        output = process.stdout.readlines()
                                        sid = output[1].rstrip(" \t\n\r")
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
