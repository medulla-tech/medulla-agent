# -*- coding: utf-8 -*-
#
# (c) 2016-2020 siveo, http://www.siveo.net
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
#
# plugin register machine dans presence table xmpp.
# file pluginsmachine/plugin___server_tcpip.py
#
import base64
import traceback
import os
import logging
from slixmpp import jid
import re
import configparser

# this import will be used later
import time
import sys
import asyncio

import socket
import select
import threading
import ast
import json
import pickle

from lib.agentconffile import directoryconffile

# file : pluginsmachine/plugin___server_tcpip.py

logger = logging.getLogger()
plugin = {"VERSION": "1.0", "NAME": "__server_tcpip", "TYPE": "code"}  # fmt: skip


def action(xmppobject, action):
    try:
        logger.debug("=====================================================")
        logger.debug("call plugin code %s " % (plugin))
        logger.debug("=====================================================")
        compteurcallplugin = getattr(xmppobject, "num_call%s" % action)

        if compteurcallplugin == 0:
            logger.debug("====================================")
            logger.debug("========== INITIALIZATION ==========")
            logger.debug("====================================")
            read_conf_server_tcpip_agent_machine(xmppobject)
            logger.debug("====================================")

            asyncio.run(run_server(xmppobject))

    except Exception as e:
        logger.error("Plugin load_TCI/IP, we encountered the error %s" % str(e))
        logger.error("We hit the backtrace %s" % traceback.format_exc())


def read_conf_server_tcpip_agent_machine(xmppobject):
    logger.debug("Initializing plugin :% s " % plugin["NAME"])
    configfilename = os.path.join(directoryconffile(), plugin["NAME"] + ".ini")
    if os.path.isfile(configfilename):
        Config = configparser.ConfigParser()
        Config.read(configfilename)
        if os.path.isfile(configfilename + ".local"):
            Config.read(configfilename + ".local")
    else:
        logger.warning(
            "The configuration file for the plugin %s is missing" % plugin["NAME"]
        )
        xmppobject.port_tcp_kiosk = 15555


def client_info(client, show_info=False):
    addresslisten, portlisten = client.getsockname()
    adressrecept, portrecept = client.getpeername()
    adressfamily = str(client.family)
    clienttype = str(client.type)
    proto = client.proto
    if show_info:
        logger.debug("socket Information")
        logger.debug("AddressFamily socket %s" % str(client.family))
        logger.debug("type STREAM socket %s" % str(client.type))
        logger.debug("proto socket %s" % client.proto)
        logger.debug("listen adress %s %s" % (addresslisten, portlisten))
        logger.debug("recept adress %s %s" % (adressrecept, portrecept))

    return {
        "adressfamily": adressfamily,
        "typesocket": clienttype,
        "proto": proto,
        "adress_listen": addresslisten,
        "port_listen": portlisten,
        "adress_recept": adressrecept,
        "port_recept": portrecept,
    }


def _convert_string(data):
    """
    This function convert data bytes received on the socket into an object (dict or string data)
      1 bytes represents 1 json string,
      1 bytes represents 1 pickle object
      1 bytes represents 1 yaml string
      1 bytes represents 1 string
    """
    if isinstance(data, (bytes)):
        try:
            requestdata = pickle.loads(data)
            return requestdata
        except:
            try:
                data = data.decode("utf8", "ignore")
            except:
                return None
    if isinstance(data, (str)):
        try:
            requestdata = ast.literal_eval(data)
            if isinstance(requestdata, (list, dict, tuple, set)):
                return requestdata
        except:
            # Error in the format of the object
            # We look if this is a json string
            try:
                requestdata = json.loads(data)
                return requestdata
            except:
                # Error in the json, maybe in the pickle serialisation
                try:
                    requestdata = yaml.load(data, Loader=yaml.Loader)
                    return requestdata
                except:
                    return data
    return data


async def handle_client(client, xmppobject):
    loop = asyncio.get_event_loop()
    request = None
    try:
        infoclient = client_info(client, show_info=True)
        if infoclient["adress_recept"] != "127.0.0.1":
            logger.error(
                "Only a local client will be allowed to connect to the server."
            )
            return

        while request != "":
            request = await loop.sock_recv(client, 1048576)
            requestobj = _convert_string(request)

            if requestobj is None:
                break

            if isinstance(requestobj, (str)):
                testresult = requestobj[0:4].lower()
                if (
                    requestobj == ""
                    or requestobj == "quit_server_kiosk"
                    or testresult == "quit"
                    or testresult == "exit"
                    or testresult == "end"
                ):
                    logger.debug("Receiving a `connexion end` request")
                    break
                else:
                    logger.warning("Receiving data: %s" % requestobj)
                    break

            if isinstance(requestobj, (dict)):
                # Creating the action
                ErrorCode, result = xmppobject.handle_client_connection(
                    json.dumps(requestobj)
                )
                logger.warning(
                    "Receiving the datas: __%s__ __%s__" % (ErrorCode, result)
                )
                if not ErrorCode or result == "":
                    # Send `end connect` and `close connection`
                    await loop.sock_sendall(client, b"end_connection")
                    break
                if ErrorCode and result:
                    # We receive the result and we close the server
                    # We can keep the connexion open for special messages:
                    # For exemple  a stream of log messages
                    # We may want to look to this later.
                    resultrequest = json.loads(result)
                    await loop.sock_sendall(client, resultrequest.encode("utf8"))
                    break  # suivant type de connexion desire
    except Exception:
        logger.error(
            "We hit a backtrace in the handle_client function \n %s"
            % traceback.format_exc()
        )
    client.close()


async def run_server(xmppobject):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(("localhost", 15555))
    server.listen(8)
    server.setblocking(False)

    loop = asyncio.get_event_loop()

    while True:
        client, client_address = await loop.sock_accept(server)
        loop.create_task(handle_client(client, xmppobject))
