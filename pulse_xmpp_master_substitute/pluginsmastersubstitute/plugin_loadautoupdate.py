# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2016-2023 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-3.0-or-later

import json
import os
import logging
from lib.utils import getRandomName
from lib.update_remote_agent import Update_Remote_Agent
import types
import configparser
from lib.plugins.xmpp import XmppMasterDatabase
from slixmpp import jid
import traceback


logger = logging.getLogger()
DEBUGPULSEPLUGIN = 25
plugin = {"VERSION": "1.4", "NAME": "loadautoupdate", "TYPE": "substitute"}  # fmt: skip


def action(objectxmpp, action, sessionid, data, msg, dataerreur):
    logger.debug("=====================================================")
    logger.debug("call %s from %s" % (plugin, msg["from"]))
    logger.debug("data %s " % json.dumps(data, indent=4))
    logger.debug("=====================================================")

    compteurcallplugin = getattr(objectxmpp, "num_call%s" % action)

    if compteurcallplugin == 0:
        read_conf_remote_update(objectxmpp)
        logger.debug("Configuration remote update")
        objectxmpp.Update_Remote_Agentlist = Update_Remote_Agent(
            objectxmpp.diragentbase, objectxmpp.autoupdate
        )

        objectxmpp.loadfingerprint = types.MethodType(loadfingerprint, objectxmpp)
        objectxmpp.schedule(
            "loadfingerprint",
            objectxmpp.generate_baseagent_fingerprint_interval,
            objectxmpp.loadfingerprint,
            repeat=True,
        )
        if objectxmpp.modeupdating.lower() == "scheduling":
            objectxmpp.schedule(
                "update_agent_tream",
                objectxmpp.modeupdatingfrequence,
                objectxmpp.updatingmachine,
                repeat=True,
            )


def updatingmachine(objectxmpp):
    """
    This is used to monitor the machines that needs to be updated
    Args:
        objectxmpp (MUC) : a reference to the main xmpp object
    """
    try:
        descriptoragent = objectxmpp.Update_Remote_Agentlist.get_md5_descriptor_agent()
        datasend = {
            "action": "updateagent",
            "data": {"subaction": "descriptor", "descriptoragent": descriptoragent},
            "ret": 0,
            "sessionid": getRandomName(5, "updateagent"),
        }
        machines_to_update = XmppMasterDatabase().getUpdate_machine(
            status="ready", nblimit=objectxmpp.modeupdatingnbmachine
        )
        logger.debug("machines_to_update = %s" % machines_to_update)
        for machine in machines_to_update:
            if objectxmpp.autoupdatebyrelay:
                datasend["data"]["ars_update"] = machine[1]
            objectxmpp.send_message(
                machine[0], mbody=json.dumps(datasend), mtype="chat"
            )
    except Exception as e:
        logger.error("\n%s" % (traceback.format_exc()))


def loadfingerprint(objectxmpp):
    """
    Runs the load fingerprint
    Args:
        objectxmpp (MUC) : a reference to the main xmpp object
    """
    objectxmpp.Update_Remote_Agentlist = Update_Remote_Agent(
        objectxmpp.diragentbase, objectxmpp.autoupdate
    )
    logger.debug(
        "load fingerprint: %s"
        % objectxmpp.Update_Remote_Agentlist.get_fingerprint_agent_base()
    )


def read_conf_remote_update(objectxmpp):
    namefichierconf = plugin["NAME"] + ".ini"
    pathfileconf = os.path.join(objectxmpp.config.pathdirconffile, namefichierconf)
    if not os.path.isfile(pathfileconf):
        logger.error(
            "plugin %s\nConfiguration file :"
            "\n\t%s missing"
            "\neg conf:\n[parameters]\n"
            "diragentbase = /var/lib/pulse2/xmpp_baseremoteagent/\n"
            "autoupdate = True" % (plugin["NAME"], pathfileconf)
        )
        logger.warning(
            "default value for diragentbase "
            "is /var/lib/pulse2/xmpp_baseremoteagent/"
            "\ndefault value for autoupdate is True"
        )
        objectxmpp.diragentbase = "/var/lib/pulse2/xmpp_baseremoteagent/"
        objectxmpp.autoupdate = True
        objectxmpp.generate_baseagent_fingerprint_interval = 900
        objectxmpp.autoupdatebyrelay = True
        objectxmpp.modeupdating = "auto"
        objectxmpp.modeupdatingfrequence = 60
        objectxmpp.modeupdatingnbmachine = 100
    else:
        Config = configparser.ConfigParser()
        Config.read(pathfileconf)
        logger.debug("read file %s" % pathfileconf)
        if os.path.exists(pathfileconf + ".local"):
            Config.read(pathfileconf + ".local")
            logger.debug("read file %s.local" % pathfileconf)
        if Config.has_option("parameters", "diragentbase"):
            objectxmpp.diragentbase = Config.get("parameters", "diragentbase")
        else:
            objectxmpp.diragentbase = "/var/lib/pulse2/xmpp_baseremoteagent/"
        if Config.has_option("parameters", "autoupdate"):
            objectxmpp.autoupdate = Config.getboolean("parameters", "autoupdate")
        else:
            objectxmpp.autoupdate = True
        if Config.has_option("parameters", "autoupdatebyrelay"):
            objectxmpp.autoupdatebyrelay = Config.getboolean(
                "parameters", "autoupdatebyrelay"
            )
        else:
            objectxmpp.autoupdatebyrelay = True
        if Config.has_option("parameters", "generate_baseagent_fingerprint_interval"):
            objectxmpp.generate_baseagent_fingerprint_interval = Config.getint(
                "parameters", "generate_baseagent_fingerprint_interval"
            )
        else:
            objectxmpp.generate_baseagent_fingerprint_interval = 900

        if Config.has_option("parameters", "updatemode"):
            objectxmpp.modeupdating = Config.get("parameters", "updatemode")
        else:
            objectxmpp.modeupdating = "auto"

        # Value list for the Permitted Mode Parameter
        permitted_mode_parameter = ["auto", "scheduling"]
        if objectxmpp.modeupdating not in permitted_mode_parameter:
            logger.warning("mode updating incorrect value %s" % objectxmpp.modeupdating)
            logger.warning(
                "mode updating permited value in %s" % permitted_mode_parameter
            )
            logger.warning('applies the value "auto" to the parameter mode updating')
            objectxmpp.modeupdating = "auto"

        # frequence traitement updating
        if Config.has_option("parameters", "updatingfrequence"):
            objectxmpp.modeupdatingfrequence = Config.getint(
                "parameters", "updatingfrequence"
            )
        else:
            objectxmpp.modeupdatingfrequence = 60

        if Config.has_option("parameters", "updatingnbmachine"):
            objectxmpp.modeupdatingnbmachine = Config.getint(
                "parameters", "updatingnbmachine"
            )
        else:
            objectxmpp.modeupdatingnbmachine = 100

    logger.debug("directory base agent is %s" % objectxmpp.diragentbase)
    if objectxmpp.autoupdate is True:
        logger.debug("Autoupdate is enabled")
    else:
        logger.debug("Autoupdate is disabled")
    logger.debug("autoupdate agent is %s" % objectxmpp.autoupdate)
    logger.debug(
        "generate baseagent "
        "fingerprint interval agent is %s"
        % objectxmpp.generate_baseagent_fingerprint_interval
    )
    logger.debug("mode updating is %s" % objectxmpp.modeupdating)
    if objectxmpp.modeupdating != "auto":
        logger.debug(
            "The check for updates will be proceed every %s seconds"
            % objectxmpp.modeupdatingfrequence
        )
    if objectxmpp.modeupdatingnbmachine == 0:
        logger.debug("0 computers will be updated (by configuration)")
    elif objectxmpp.modeupdatingnbmachine == 1:
        logger.debug("Updates will be done one by one (by configuration)")
    else:
        logger.debug(
            "We will update %s machines at the same time"
            % objectxmpp.modeupdatingnbmachine
        )
    objectxmpp.senddescriptormd5 = types.MethodType(senddescriptormd5, objectxmpp)
    objectxmpp.plugin_loadautoupdate = types.MethodType(
        plugin_loadautoupdate, objectxmpp
    )
    objectxmpp.updatingmachine = types.MethodType(updatingmachine, objectxmpp)


def senddescriptormd5(self, to):
    """
    send the agent's figerprint descriptor in database to update the machine
    Update remote agent
    """
    try:
        datasend = {
            "action": "updateagent",
            "data": {
                "subaction": "descriptor",
                "descriptoragent": self.Update_Remote_Agentlist.get_md5_descriptor_agent(),
            },
            "ret": 0,
            "sessionid": getRandomName(5, "updateagent"),
        }
        # Send catalog of files.
        logger.debug("Send descriptor to agent [%s] for update" % to)
        if self.autoupdatebyrelay:
            relayjid = XmppMasterDatabase().groupdeployfromjid(to)
            relayjid = jid.JID(str(relayjid[0])).bare
            datasend["data"]["ars_update"] = relayjid
        self.send_message(to, mbody=json.dumps(datasend), mtype="chat")
    except Exception as e:
        logger.error("\n%s" % (traceback.format_exc()))


def plugin_loadautoupdate(self, msg, data):
    try:
        msgfrom = str(jid.JID(msg["from"]).bare)
        msgmachine = str(jid.JID(msg["from"]).user)
        if (
            self.autoupdate
            and all(
                [
                    x in data.keys()
                    for x in ["information", "deployment", "md5agent", "agenttype"]
                ]
            )
            and self.Update_Remote_Agentlist.get_fingerprint_agent_base()
            != data["md5agent"]
            and data["md5agent"].upper() not in ["DEV", "DEBUG"]
        ):
            # update agent to do
            # Manage update remote agent
            if self.modeupdating.lower() == "auto":
                # send md5 descriptor of the agent for remote update.
                self.senddescriptormd5(msgfrom)
            else:
                # verify key exist
                XmppMasterDatabase().setUpdate_machine(
                    data["information"]["info"]["hostname"],
                    msgfrom,
                    ars=data["deployment"],
                    status="ready",
                    descriptor=data["agenttype"],
                    md5=data["md5agent"],
                )
        else:
            logger.debug(
                "%s already has the latest version of the agent. Nothing to do."
                % msgmachine
            )
    except Exception as e:
        logger.error("\n%s" % (traceback.format_exc()))
