# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2016-2023 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-3.0-or-later

import json
import logging
from lib.utils import getRandomName, call_plugin, data_struct_message
import traceback

logger = logging.getLogger()
DEBUGPULSEPLUGIN = 25
plugin = {"VERSION": "1.1", "NAME": "start", "TYPE": "substitute"}  # fmt: skip


def action(objectxmpp, action, sessionid, data, msg, dataerreur):
    logger.debug("=====================================================")
    logger.debug("call %s from %s" % (plugin, msg["from"]))
    logger.debug("=====================================================")

    compteurcallplugin = getattr(objectxmpp, "num_call%s" % action)
    # send demande module mmc actif sur master
    logger.debug("Looking for installed mmc modules")
    objectxmpp.listmodulemmc = []
    objectxmpp.send_message(
        mto=objectxmpp.agentmaster,
        mbody=json.dumps(data_struct_message("enable_mmc_module")),
        mtype="chat",
    )
    # dirplugin =os.path.dirname(os.path.realpath(__file__))
    for nameplugin in objectxmpp.config.pluginliststart:
        try:
            plugindescriptorparameter = data_struct_message(
                nameplugin, sessionid=getRandomName(6, nameplugin)
            )
            plugindescriptorparametererreur = data_struct_message(
                "resultmsginfoerror",
                data={"msg": "error plugin : " + plugindescriptorparameter["action"]},
                ret=255,
                sessionid=plugindescriptorparameter["sessionid"],
            )
            # call plugin start
            msgt = {
                "from": objectxmpp.boundjid.bare,
                "to": objectxmpp.boundjid.bare,
                "type": "chat",
            }
            module = "%s/plugin_%s.py" % (
                objectxmpp.modulepath,
                plugindescriptorparameter["action"],
            )
            # verify si attribut compteur existe.
            # try:
            # getattr(objectxmpp, "num_call%s"%plugindescriptorparameter["action"])
            # except AttributeError:
            # setattr(objectxmpp, "num_call%s"%plugindescriptorparameter["action"], 0)
            call_plugin(
                module,
                objectxmpp,
                plugindescriptorparameter["action"],
                plugindescriptorparameter["sessionid"],
                plugindescriptorparameter["data"],
                msgt,
                plugindescriptorparametererreur,
            )
        except Exception:
            logger.error("\n%s" % (traceback.format_exc()))
    logger.debug("========= end plugin %s =========" % plugin["NAME"])
