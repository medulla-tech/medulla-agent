# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2016-2023 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-3.0-or-later

import json
import traceback
import sys
import time
import logging
import os
from lib.utils import set_logging_level

plugin = {"VERSION": "1.21", "NAME": "guacamole", "TYPE": "all"}  # fmt: skip


logger = logging.getLogger()


@set_logging_level
def action(xmppobject, action, sessionid, data, message, dataerreur):
    # print json.dumps(data, indent=4)

    if xmppobject.config.agenttype in ["relayserver"]:
        import MySQLdb

        # Get reversessh remote port and run reverse_ssh_on
        try:
            db = MySQLdb.connect(
                host=xmppobject.config.guacamole_dbhost,
                user=xmppobject.config.guacamole_dbuser,
                passwd=xmppobject.config.guacamole_dbpasswd,
                db=xmppobject.config.guacamole_dbname,
            )
            cursor = db.cursor()
            # First find out if we need to run a reversessh connection
            sql = f""" SELECT parameter_value FROM guacamole_connection_parameter WHERE connection_id = {data["cux_id"]} AND parameter_name = 'hostname';"""
            cursor.execute(sql)
            results = cursor.fetchall()
            hostname = results[0][0]
            if hostname != "localhost":
                # We won't need a reversessh connection. We can safely quit and
                # let guacamole connect directly to machine
                return
            # We need to run a reversessh connection
            sql = f""" SELECT parameter_value FROM guacamole_connection_parameter WHERE connection_id = {data["cux_id"]} AND parameter_name = 'port';"""
            cursor.execute(sql)
            results = cursor.fetchall()
            localport = results[0][0]
            if data["cux_type"] == "SSH":
                remoteport = (
                    int(xmppobject.config.clients_ssh_port)
                    if hasattr(xmppobject.config, "clients_ssh_port")
                    else 22
                )
                reversetype = "R"
            elif data["cux_type"] == "RDP":
                remoteport = 3389
                reversetype = "R"
            elif data["cux_type"] == "VNC":
                remoteport = (
                    int(xmppobject.config.clients_vnc_port)
                    if hasattr(xmppobject.config, "clients_vnc_port")
                    else 5900
                )
                reversetype = "R"

        except Exception as e:
            db.close()
            dataerreur["data"]["msg"] = f"MySQL Error: {str(e)}"
            logger.error("\n%s" % (traceback.format_exc()))
            raise

        datareversessh = {
            "action": "reverse_ssh_on",
            "sessionid": sessionid,
            "data": {
                "request": "askinfo",
                "port": localport,
                "host": data["uuid"],
                "remoteport": remoteport,
                "reversetype": reversetype,
                "options": "createreversessh",
                "persistence": data["cux_type"],
            },
            "ret": 0,
            "base64": False,
        }
        xmppobject.send_message(
            mto=message["to"], mbody=json.dumps(datareversessh), mtype="chat"
        )

        return

    else:
        # Machine plugin

        from lib.utils import simplecommand

        returnmessage = dataerreur
        returnmessage["data"] = data
        returnmessage["ret"] = 0

        # print json.dumps(returnmessage, indent = 4)
