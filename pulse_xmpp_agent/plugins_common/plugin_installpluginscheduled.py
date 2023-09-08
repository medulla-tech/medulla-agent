# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2016-2023 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-3.0-or-later

import os


import logging

logger = logging.getLogger()
DEBUGPULSEPLUGIN = 25
plugin = {"VERSION": "1.0", "NAME": "installpluginscheduled", "TYPE": "all"}  # fmt: skip


def action(objetxmpp, action, sessionid, data, message, dataerreur):
    logging.getLogger().debug("###################################################")
    logging.getLogger().debug("########AGENT INSTALL PLUGINS SCHEDULED#############")
    logging.getLogger().debug("###################################################")
    logging.getLogger().debug(f'call {plugin} from {message["from"]}')
    logging.getLogger().debug("###################################################")
    if action == "installpluginscheduled":
        if len(data) != 0:
            namefile = os.path.join(
                objetxmpp.config.pathpluginsscheduled, data["pluginname"]
            )
            print(namefile)
            logging.getLogger().debug(
                "###################################################"
            )
            try:
                with open(namefile, "w") as fileplugin:
                    fileplugin.write(str(data["datafile"]))
            except BaseException:
                print("Error: cannor write on file")
                return
