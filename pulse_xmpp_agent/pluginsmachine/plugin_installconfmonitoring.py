# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2016-2023 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-3.0-or-later

import logging
import json
import base64
import traceback
from lib.utils import set_logging_level

logger = logging.getLogger()
plugin = {"VERSION": "1.1", "NAME": "installconfmonitoring", "TYPE": "machine"}  # fmt: skip

@set_logging_level
def action(objectxmpp, action, sessionid, data, message, dataerreur):
    logger.debug("###################################################")
    logger.debug("call %s from %s" % (plugin, message["from"]))
    logger.debug("###################################################")
    logger.debug("data %s" % (json.dumps(data, indent=4)))
    strjidagent = str(objectxmpp.boundjid.bare)
    dataerreur["ret"] = 255
    dataerreur["action"] = "resultmsginfoerror"

    content = ""
    try:
        objectxmpp.config.monitoring_agent_config_file
        if objectxmpp.config.monitoring_agent_config_file == "":
            dataerreur["data"]["msg"] = (
                "\nmissing configuration path file monitoring config\n"
                "cf agentconf.ini section\n[monitoring]\nmonitoring_agent_config_file = path_file_monitoring_config_consigne"
            )
            objectxmpp.send_message(
                mto=message["from"], mbody=json.dumps(dataerreur), mtype="chat"
            )
            return
    except Exception as e:
        logger.debug("Plugin %s : %s" % (plugin["NAME"], str(e)))
        logger.error("\n%s" % (traceback.format_exc()))

        dataerreur["data"][
            "msg"
        ] = "Error %s [plugin %s ] on machine %s" "\nTRACEBACK INFORMATION\n%s" % (
            str(e),
            plugin["Name"],
            strjidagent,
            traceback.format_exc(),
        )

        objectxmpp.send_message(
            mto=message["from"], mbody=json.dumps(dataerreur), mtype="chat"
        )
        return

    if "content" in data:
        content = base64.b64decode(data["content"])
        if content != "":
            # Installs the monitoring config gile
            try:
                logger.error(
                    "[%s] : install file %s"
                    % (plugin["NAME"], objectxmpp.config.monitoring_agent_config_file)
                )
                fileplugin = open(objectxmpp.config.monitoring_agent_config_file, "w")
                fileplugin.write(str(content))
                fileplugin.close()

            except Exception as e:
                logging.getLogger().debug("error : %s" % str(e))
                dataerreur["data"]["msg"] = "Installing plugin %s on %s : %s" % (
                    data["pluginname"],
                    message["to"].user,
                    str(e),
                )
                objectxmpp.send_message(
                    mto=message["from"], mbody=json.dumps(dataerreur), mtype="chat"
                )
