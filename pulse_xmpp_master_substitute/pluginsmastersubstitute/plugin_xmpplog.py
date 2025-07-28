# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2016-2023 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-3.0-or-later

import traceback
import os
import json
import logging
from lib.plugins.xmpp import XmppMasterDatabase
from lib.utils import file_put_contents, call_plugin
import re
import configparser

# this import will be used later
# import types

logger = logging.getLogger()
plugin = {"VERSION": "1.1", "NAME": "xmpplog", "TYPE": "substitute"}  # fmt: skip


def action(xmppobject, action, sessionid, data, msg, ret, dataobj):
    logger.debug("=====================================================")
    logger.debug("call %s from %s" % (plugin, msg["from"]))
    logger.debug("=====================================================")
    compteurcallplugin = getattr(xmppobject, "num_call%s" % action)
    if compteurcallplugin == 0:
        xmppobject.compteur_de_traitement = 0
        xmppobject.listconfiguration = []
        xmppobject.simultaneous_processing = 50
        xmppobject.show_queue_status = False
        xmppobject.status_rules = []
        loggerliststatus = XmppMasterDatabase().get_log_status()
        try:
            for t in XmppMasterDatabase().get_log_status():
                t["compile_re"] = re.compile(t["regexplog"])
                xmppobject.status_rules.append(t)
            logger.debug("We initialized to the rule: %s" % xmppobject.status_rules)
        except Exception:
            logger.error("\n%s" % (traceback.format_exc()))
        read_conf_log_agent(xmppobject)
    if xmppobject.compteur_de_traitement >= xmppobject.simultaneous_processing:
        xmppobject.listconfiguration.append(
            {"action": action, "sessionid": sessionid, "data": data, "msg": msg}
        )
        if bool(xmppobject.show_queue_status):
            logger.info(
                "Pending pool counter = %s" % (xmppobject.compteur_de_traitement)
            )
        return
    try:
        xmppobject.compteur_de_traitement = xmppobject.compteur_de_traitement + 1
        dataobj = data
        if "type" in dataobj and dataobj["type"] == "deploy" and "text" in dataobj:
            re_status = searchstatus(xmppobject, dataobj["text"])
            if re_status["status"] != "":
                XmppMasterDatabase().updatedeploytosessionid(
                    re_status["status"], dataobj["sessionid"]
                )
                logging.debug(
                    "We applied the status %s for the sessionid %s"
                    % (re_status["status"], dataobj["sessionid"])
                )
            else:
                logging.debug(
                    "We have not applied any status for the sessionid %s"
                    % (dataobj["sessionid"])
                )
        if data["action"] == "xmpplog":
            createlog(xmppobject, data)
        elif data["action"] == "resultapplicationdeploymentjson":
            logger.debug("log result deployement")
            data["sessionid"] = sessionid
            xmpplogdeploy(xmppobject, data)
        else:
            logger.warning("message bad formated: msg log from %s" % (msg["from"]))
            logger.warning("data msg is \n%s" % (json.dumps(data, indent=4)))
    except Exception as e:
        logging.error("structure Message from %s %s " % (msg["from"], str(e)))
        logger.error("\n%s" % (traceback.format_exc()))
    finally:
        xmppobject.compteur_de_traitement = xmppobject.compteur_de_traitement - 1
        if xmppobject.compteur_de_traitement < 0:
            xmppobject.compteur_de_traitement = 0
        while (
            xmppobject.compteur_de_traitement > 0
            and xmppobject.compteur_de_traitement < xmppobject.simultaneous_processing
            and len(xmppobject.listconfiguration)
        ):
            ## call plugin
            report = xmppobject.listconfiguration.pop(0)
            dataerreur = {
                "action": "result" + plugin["NAME"],
                "data": {"msg": "error plugin : " + plugin["NAME"]},
                "sessionid": report["sessionid"],
                "ret": 255,
                "base64": False,
            }
            if bool(xmppobject.show_queue_status):
                logger.info("Re-call plugin %s" % (plugin["NAME"]))
            call_plugin(
                __file__,
                xmppobject,
                action,
                report["sessionid"],
                report["data"],
                report["msg"],
                0,
                dataerreur,
            )


def createlog(xmppobject, dataobj):
    """
    this function creating log in base from body message xmpp
    """
    try:
        if "text" in dataobj:
            text = dataobj["text"]
        else:
            return
        type = dataobj["type"] if "type" in dataobj else ""
        sessionname = dataobj["sessionid"] if "sessionid" in dataobj else ""
        priority = dataobj["priority"] if "priority" in dataobj else ""
        who = dataobj["who"] if "who" in dataobj else ""
        how = dataobj["how"] if "how" in dataobj else ""
        why = dataobj["why"] if "why" in dataobj else ""
        module = dataobj["module"] if "module" in dataobj else ""
        action = dataobj["action"] if "action" in dataobj else ""
        fromuser = dataobj["fromuser"] if "fromuser" in dataobj else ""
        touser = dataobj["touser"] if "touser" in dataobj else xmppobject.boundjid.bare
        if sessionname.startswith("update"):
            type = "update"
        XmppMasterDatabase().setlogxmpp(
            text,
            type=type,
            sessionname=sessionname,
            priority=priority,
            who=who,
            how=how,
            why=why,
            module=module,
            fromuser=fromuser,
            touser=touser,
            action=action,
        )
    except Exception as e:
        logger.error("Message deploy error  %s %s" % (dataobj, str(e)))
        logger.error("\n%s" % (traceback.format_exc()))


def registerlogxmpp(
    xmppobject,
    text,
    type="noset",
    sessionname="",
    priority=0,
    who="",
    how="",
    why="",
    module="",
    fromuser="",
    touser="",
    action="",
):
    """
    this function for creating log in base
    """
    if sessionname.startswith("update"):
        typelog = "update"
    typelog = "noset"
    XmppMasterDatabase().setlogxmpp(
        text,
        type=typelog,
        sessionname=sessionname,
        priority=priority,
        who=who,
        how=how,
        why=why,
        module=module,
        fromuser=fromuser,
        touser=touser,
        action=action,
    )


def xmpplogdeploy(xmppobject, data):
    """
    this function manage msg deploy log
    """
    try:
        if (
            "text" in data
            and "type" in data
            and "sessionid" in data
            and "priority" in data
            and "who" in data
        ):
            registerlogxmpp(
                xmppobject,
                data["text"],
                type=data["type"],
                sessionname=data["sessionid"],
                priority=data["priority"],
                touser=xmppobject.boundjid.bare,
                who=data["who"],
            )
        elif "action" in data:
            if data["action"] == "resultapplicationdeploymentjson":
                    # Determination of the message according to section
                    section = data.get("advanced", {}).get("paramdeploy", {}).get("section", "").lower()
                    if data["ret"] == 0:
                        if section == "uninstall":
                            message = "UNINSTALL SUCCESS"
                        else:
                            message = "DEPLOYMENT SUCCESS"
                    else:
                        message = "ABORT PACKAGE EXECUTION ERROR"

                    XmppMasterDatabase().updatedeployresultandstate(
                        data["sessionid"],
                        message,
                        json.dumps(data, indent=4, sort_keys=True),
                    )
    except Exception as e:
        logging.error("obj Message deploy error  %s\nerror text : %s" % (data, str(e)))
        logger.error("\n%s" % (traceback.format_exc()))


def read_conf_log_agent(xmppobject):
    xmppobject.simultaneous_processing = 50
    xmppobject.show_queue_status = False
    namefichierconf = plugin["NAME"] + ".ini"
    pathfileconf = os.path.join(xmppobject.config.pathdirconffile, namefichierconf)
    logger.warning("Config file %s for plugin %s" % (pathfileconf, plugin["NAME"]))
    if not os.path.isfile(pathfileconf):
        logger.warning(
            "Plugin %s\nConfiguration file :"
            "\n\t%s missing"
            "\neg conf:\n[parameters]\n"
            "simultaneous_processing = 50" % (plugin["NAME"], pathfileconf)
        )
        logger.warning("create default conf file %s" % pathfileconf)
        file_put_contents(pathfileconf, "[parameters]\nsimultaneous_processing = 50\n")
    else:
        Config = configparser.ConfigParser()
        Config.read(pathfileconf)
        logger.debug("Config file %s for plugin %s" % (pathfileconf, plugin["NAME"]))
        if os.path.exists(pathfileconf + ".local"):
            Config.read(pathfileconf + ".local")
            logger.debug("read file %s.local" % pathfileconf)

        if Config.has_option("parameters", "simultaneous_processing"):
            xmppobject.simultaneous_processing = Config.getint(
                "parameters", "simultaneous_processing"
            )
        else:
            xmppobject.simultaneous_processing = 50

        if Config.has_option("parameters", "show_queue_status"):
            xmppobject.show_queue_status = Config.getboolean(
                "parameters", "show_queue_status"
            )
        else:
            xmppobject.show_queue_status = False


def searchstatus(xmppobject, chaine):
    for t in xmppobject.status_rules:
        if t["compile_re"].match(chaine):
            logger.debug(
                'The string "%s" match for [%s] and return the following status "%s"'
                % (chaine, t["regexplog"], t["status"])
            )
            return {"status": t["status"], "logmessage": chaine}
    return {"status": "", "logmessage": chaine}
