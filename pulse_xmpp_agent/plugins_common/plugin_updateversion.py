# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2016-2023 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-3.0-or-later

import sys
import os
import logging
from lib import utils

logger = logging.getLogger()

DEBUGPULSEPLUGIN = 25
plugin = {"VERSION": "1.1", "NAME": "updateversion", "TYPE": "all"}  # fmt: skip

@set_logging_level
def action(objectxmpp, action, sessionid, data, message, dataerreur):
    logger.debug("###################################################")
    logger.debug("call %s from %s" % (plugin, message["from"]))
    logger.debug("###################################################")
    if objectxmpp.config.agenttype in ["machine"]:
        if sys.platform.startswith("win"):
            # injection version clef de registre
            logger.debug("INJECTION KEY REGISTER VERSION")
            pathversion = os.path.join(objectxmpp.pathagent, "agentversion")
            if os.path.isfile(pathversion):
                version = (
                    utils.file_get_contents(pathversion)
                    .replace("\n", "")
                    .replace("\r", "")
                    .strip()
                )
                if len(version) < 20:
                    logger.debug("Version AGENT is " + version)
                    import _winreg

                    key = _winreg.OpenKey(
                        _winreg.HKEY_LOCAL_MACHINE,
                        "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Medulla Agent\\",
                        0,
                        _winreg.KEY_SET_VALUE | _winreg.KEY_WOW64_64KEY,
                    )
                    _winreg.SetValueEx(
                        key, "DisplayVersion", 0, _winreg.REG_SZ, version
                    )
                    _winreg.CloseKey(key)
        elif sys.platform.startswith("linux"):
            pass
        elif sys.platform.startswith("darwin"):
            pass
    else:
        logger.debug("###################################################")
        logger.debug("##############AGENT RELAY SERVER###################")
        logger.debug("###################################################")
