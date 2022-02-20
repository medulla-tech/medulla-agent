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
# file pluginsmachine/plugin_installplugin.py
import os
import logging
import json


plugin = {"VERSION": "1.26", "NAME": "installplugin", "TYPE": "all"}


def action(objectxmpp, action, sessionid, data, message, dataerreur):
    if action == "installplugin":
        if len(data) != 0:
            namefile = os.path.join(objectxmpp.config.pathplugins, data["pluginname"])
            logging.getLogger().info("Installing plugin %s " % data["pluginname"])
            try:
                fileplugin = open(namefile, "w")
                fileplugin.write(str(data["datafile"]))
                fileplugin.close()
                dataerreur["ret"] = 0
                dataerreur["data"]["msg"] = "Installing plugin %s on %s" % (
                    data["pluginname"],
                    message["to"].user,
                )
            except Exception as e:
                logging.getLogger().debug("error : %s" % str(e))
                dataerreur["data"]["msg"] = "Installing plugin %s on %s : %s" % (
                    data["pluginname"],
                    message["to"].user,
                    str(e),
                )
                dataerreur["ret"] = 255
            dataerreur["action"] = "resultmsginfoerror"
            objectxmpp.send_message(
                mto=message["from"], mbody=json.dumps(dataerreur), mtype="chat"
            )
