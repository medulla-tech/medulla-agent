# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2016-2023 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-3.0-or-later

import os
import logging
import json

plugin = {"VERSION": "1.26", "NAME": "installplugin", "TYPE": "all"}  # fmt: skip


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
