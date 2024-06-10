# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2016-2024 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-3.0-or-later

import json
import traceback
import sys
import time
import logging
import os
from lib.utils import set_logging_level

plugin = {"VERSION": "1.20", "NAME": "guacamole", "TYPE": "all"}  # fmt: skip


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
                # Specific VNC case. We will use a listener
                remoteport = localport
                localport = 5500
                reversetype = "L"

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

        if data["cux_type"] == "VNC" and hostname == "localhost":
            # Wait x seconds until tunnel is established and guacamole is ready
            # 5 seconds for the reversessh connection + 2 seconds for the
            # guacamole connection
            time.sleep(10)

            # Ask machine plugin to start VNC connection
            datavnc = {
                "action": "guacamole",
                "sessionid": sessionid,
                "data": {"options": "vnclistenmode"},
                "ret": 0,
                "base64": False,
            }
            xmppobject.send_message(
                mto=data["jidmachine"], mbody=json.dumps(datavnc), mtype="chat"
            )

        return

    else:
        # Machine plugin

        from lib.utils import simplecommand, simplecommandstr

        if data["options"] == "vnclistenmode":
            if sys.platform.startswith("win"):
                try:
                    logger.info("Start VNC listener")
                    program = os.path.join(
                        "c:\\", "progra~1", "TightVNC", "tvnserver.exe"
                    )
                    # select display for vnc
                    cmd = """\"%s\" -controlservice -disconnectall""" % (program)
                    logger.debug("VNC Listener Command: %s" % cmd)
                    simplecommand(cmd)
                    cmd = """\"%s\" -controlservice -shareprimary""" % (program)
                    logger.debug("VNC Listener Command: %s" % cmd)
                    simplecommand(cmd)
                    cmd = """\"%s\" -controlservice -connect localhost""" % (program)
                    logger.debug("VNC Listener Command: %s" % cmd)
                    simplecommand(cmd)
                    obj = simplecommandstr(
                        f"netstat -an | findstr 5500 | findstr LISTENING"
                    )
                    if "LISTENING" in obj["result"]:
                        logger.info(f"VNC Listener listening on port 5500")
                except Exception as e:
                    logger.error(f"Error starting VNC listener TightVNC: {str(e)}")
                    logger.error("\n%s" % (traceback.format_exc()))
                    raise
            if sys.platform.startswith("darwin"):
                try:
                    simplecommand("pkill OSXvnc-server -connecthost localhost")
                    simplecommand(
                        '"/Applications/Vine Server.app/Contents/MacOS/OSXvnc-server" -connectHost localhost'
                    )
                except Exception as e:
                    logger.error(f"Error start VNC listener OSXvnc-server: {str(e)}")
                    logger.error("\n%s" % (traceback.format_exc()))
                    raise
            else:
                try:
                    simplecommand("vncconfig -nowin -connect localhost")
                except Exception as e:
                    logging.getLogger().error(
                        f"Error start VNC listener vncconfig: {str(e)}"
                    )
                    logger.error("\n%s" % (traceback.format_exc()))
                    raise

        returnmessage = dataerreur
        returnmessage["data"] = data
        returnmessage["ret"] = 0

        # print json.dumps(returnmessage, indent = 4)
