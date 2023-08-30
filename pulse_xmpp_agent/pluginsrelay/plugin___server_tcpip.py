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
# file : plugin___server_tcpip.py
#
import base64
import traceback
import os
import logging
from slixmpp import jid
import re
import configparser

import yaml

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
from lib.utils import DateTimebytesEncoderjson, simplecommand, AESCipher, isBase64

# file : pluginsmachine/plugin___server_tcpip.py

logger = logging.getLogger()
plugin = {"VERSION": "1.0", "NAME": "__server_tcpip", "TYPE": "all", "INFO": "code"}  # fmt: skip


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
    xmppobject.port_tcp_kiosk = 8765
    prefixe_agent = ""
    if xmppobject.config.agenttype in ["relayserver"]:
        prefixe_agent = "ars_"
        if (
            "ars_local_port" in vars(xmppobject.config)
            and xmppobject.config()["ars_local_port"] != None
        ):
            xmppobject.port_tcp_kiosk = xmppobject.config.ars_local_port
            logger.warning(
                "paraneter tcp_ip port in section [kiosk]/ars_local_port in relayconf.ini : %s"
                % xmppobject.port_tcp_kiosk
            )
    elif xmppobject.config.agenttype in ["machine"]:
        prefixe_agent = "am_"
        if (
            "am_local_port" in vars(xmppobject.config)
            and xmppobject.config()["am_local_port"] != None
        ):
            xmppobject.port_tcp_kiosk = xmppobject.config.am_local_port
            logger.warning(
                "paraneter tcp_ip port in section [kiosk]/am_local_port in agentconf.ini : %s"
                % xmppobject.port_tcp_kiosk
            )
    configfilename = os.path.join(
        directoryconffile(), prefixe_agent + plugin["NAME"] + ".ini"
    )
    logger.info(
        "optionel config file local for plugin___server_tcpip is : %s" % configfilename
    )
    if os.path.isfile(configfilename):
        Config = configparser.ConfigParser()
        Config.read(configfilename)
        if os.path.isfile(configfilename + ".local"):
            Config.read(configfilename + ".local")
            if Config.has_option("server_tcpip", "port_tcpip"):
                xmppobject.port_tcp_kiosk = Config.getint("server_tcpip", "port_tcpip")
                logger.warning(
                    "config local redefini paraneter tcp_ip port in section [server_tcpip]/port_tcpip"
                )
    else:
        logger.warning(
            "local file configuration %s of plugin %s no exist"
            % (configfilename, plugin["NAME"])
        )
    logger.warning("port_tcp_kiosk is %s " % xmppobject.port_tcp_kiosk)


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
            # request = (await loop.sock_recv(client, 255)).decode('utf8')
            request = await loop.sock_recv(client, xmppobject.sizebufferrecv)
            if len(request) >= xmppobject.sizebufferrecv:
                logger.warning(
                    'message may be incomplete : size message Recv is egal max size message (%s) :"verify param sizebufferrecv"'
                    % xmppobject.sizebufferrecv
                )
            if xmppobject.encryptionAES and len(xmppobject.config.keyAES32) > 0:
                if not isBase64(request.strip()):
                    logger.warning("message input no encryption")
                else:
                    logger.warning("message input base64")
                cipher = AESCipher(xmppobject.config.keyAES32)
                request = cipher.decrypt(str(request.decode("utf8")))
                logger.warning("request data is %s" % request)
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
                try:
                    # creation action
                    codeerror, result = xmppobject.handle_client_connection(
                        json.dumps(requestobj)
                    )
                    logger.warning(
                        "reception data : __%s__ __%s__" % (codeerror, result)
                    )

                    if not result:
                        await loop.sock_sendall(
                            client, "aucun resultat".encode("utf-8")
                        )
                    if isinstance(result, (list, dict, set, tuple)):
                        await loop.sock_sendall(
                            client,
                            json.dumps(
                                result, cls=DateTimebytesEncoderjson, indent=4
                            ).encode("utf-8"),
                        )
                    elif isinstance(result, (str)):
                        await loop.sock_sendall(client, result.encode("utf-8"))
                    elif isinstance(result, (bytes)):
                        await loop.sock_sendall(client, result)
                    else:
                        try:
                            strdata = str(result).encode("utf-8")
                            await loop.sock_sendall(client, result)
                        except Exception as e:
                            await loop.sock_sendall(client, str(e).encode("utf-8"))

                        logger.warning("type reception data %s" % type(result))
                    break  # suivant type de connexion desire
                except Exception as e:
                    await loop.sock_sendall(client, str(e).encode("utf-8"))
                    break
    except Exception:
        logger.error(
            "We hit a backtrace in the handle_client function \n %s"
            % traceback.format_exc()
        )
    client.close()


async def run_server(xmppobject):
    if sys.platform.startswith("linux") or sys.platform.startswith("darwin"):
        linux_command = (
            'netstat -lnt4p | grep python | grep ":%s"' % xmppobject.port_tcp_kiosk
        )
        logger.warning("linux command : %s" % linux_command)
        result = simplecommand(linux_command)

        if len(result["result"]) > 0:
            logger.debug(
                "The tcp_ip kiosk server is already running locally in the port %s"
                % xmppobject.port_tcp_kiosk
            )
            return
    elif sys.platform.startswith("win"):
        windows_command = (
            'netstat -aof -p TCP | findstr LISTENING | findstr ":%s"'
            % xmppobject.port_tcp_kiosk
        )
        result = simplecommand(windows_command)
        if len(result["result"]) > 0:
            logger.debug(
                "The tcp_ip kiosk server is already running locally in the port %s"
                % xmppobject.port_tcp_kiosk
            )
            return
    else:
        logger.error("We do not support your Operating System %s" % sys.platform)
        return

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        server.bind(("localhost", xmppobject.port_tcp_kiosk))
        server.listen(8)
    except Exception as e:
        logger.error("The run_server function failed with the error %s" % str(e))
        logger.error("We hit the backtrace \n %s" % traceback.format_exc())
        return
    server.setblocking(False)

    loop = asyncio.get_event_loop()

    while True:
        client, client_address = await loop.sock_accept(server)
        loop.create_task(handle_client(client, xmppobject))
