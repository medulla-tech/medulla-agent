# -*- coding: utf-8 -*-
#
# (c) 2016 siveo, http://www.siveo.net
#
# This file is part of Pulse 2, http://www.siveo.net
#
# Pulse 2 is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# Pulse 2 is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Pulse 2; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
# MA 02110-1301, USA.
# file pluginsmachine/plugin_installconfmonitoring.py

import os
import logging
import json
import base64
import traceback

logger = logging.getLogger()

plugin = {"VERSION": "1.0", "NAME": "installconfmonitoring", "TYPE": "machine"} # fmt: skip


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
