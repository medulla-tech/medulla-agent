# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2016-2023 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-3.0-or-later
"""
plugin register machine dans presence table xmpp.
"""
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

if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

import socket
import select
import threading
import ast
import json
import pickle

from lib.agentconffile import directoryconffile
from lib.utils import (
    DateTimebytesEncoderjson,
    simplecommand,
    AESCipher,
    isBase64,
    set_logging_level,
)

# file : pluginsmachine/plugin___server_tcpip.py

logger = logging.getLogger()
plugin = {"VERSION": "1.1", "NAME": "__server_tcpip", "TYPE": "all", "INFO": "code"}  # fmt: skip


@set_logging_level
def action(xmppobject, action):
    try:
        logger.debug("=====================================================")
        logger.debug(f"call plugin code {plugin} ")
        logger.debug("=====================================================")
        compteurcallplugin = getattr(xmppobject, f"num_call{action}")

        if compteurcallplugin == 0:
            logger.debug("====================================")
            logger.debug("========== INITIALIZATION ==========")
            logger.debug("====================================")
            read_conf_server_tcpip_agent_machine(xmppobject)
            logger.debug("====================================")

            asyncio.run(run_server(xmppobject))

    except Exception as e:
        logger.error(f"Plugin load_TCI/IP, we encountered the error {str(e)}")
        logger.error(f"We hit the backtrace {traceback.format_exc()}")


def read_conf_server_tcpip_agent_machine(xmppobject):
    xmppobject.port_tcp_kiosk = 8765
    prefixe_agent = ""
    if not hasattr(xmppobject, "sizebufferrecv"):
        xmppobject.sizebufferrecv = 1048576
    if not hasattr(xmppobject, "encryptionAES"):
        xmppobject.encryptionAES = False

    if xmppobject.config.agenttype in ["relayserver"]:
        prefixe_agent = "ars_"
        if (
            "ars_local_port" in vars(xmppobject.config)
            and vars(xmppobject.config)["ars_local_port"] != None
        ):
            xmppobject.port_tcp_kiosk = vars(xmppobject.config)["ars_local_port"]
            logger.warning(
                f"paraneter tcp_ip port in section [kiosk]/ars_local_port in relayconf.ini : {xmppobject.port_tcp_kiosk}"
            )
    elif xmppobject.config.agenttype in ["machine"]:
        prefixe_agent = "am_"
        if (
            "am_local_port" in vars(xmppobject.config)
            and vars(xmppobject.config)["am_local_port"] != None
        ):
            xmppobject.port_tcp_kiosk = vars(xmppobject.config)["am_local_port"]
            logger.warning(
                f"paraneter tcp_ip port in section [kiosk]/am_local_port in agentconf.ini : {xmppobject.port_tcp_kiosk}"
            )
    configfilename = os.path.join(
        directoryconffile(), prefixe_agent + plugin["NAME"] + ".ini"
    )
    logger.info(
        f"optionel config file local for plugin___server_tcpip is : {configfilename}"
    )
    if os.path.isfile(configfilename):
        Config = configparser.ConfigParser()
        Config.read(configfilename)
        if os.path.isfile(f"{configfilename}.local"):
            Config.read(f"{configfilename}.local")
            if Config.has_option("server_tcpip", "port_tcpip"):
                xmppobject.port_tcp_kiosk = Config.getint("server_tcpip", "port_tcpip")
                logger.warning(
                    "config local redefini paraneter tcp_ip port in section [server_tcpip]/port_tcpip"
                )
            if Config.has_option("server_tcpip", "sizebufferrecv"):
                xmppobject.sizebufferrecv = Config.getint(
                    "server_tcpip", "sizebufferrecv"
                )
                logger.warning(
                    "config local redefini paraneter (sizebufferrecv size) in section [server_tcpip]/sizebufferrecv"
                )
            if Config.has_option("server_tcpip", "encryptionAES"):
                xmppobject.sizebufferrecv = Config.getboolean(
                    "server_tcpip", "encryptionAES"
                )
                logger.warning(
                    "config local redefini paraneter boolean  encryptionAES in section [server_tcpip]/encryptionAES"
                )
    else:
        logger.warning(
            f'local file configuration {configfilename} of plugin {plugin["NAME"]} no exist'
        )
    logger.warning(f"port_tcp_kiosk is {xmppobject.port_tcp_kiosk} ")


def client_info(client, show_info=False):
    addresslisten, portlisten = client.getsockname()
    adressrecept, portrecept = client.getpeername()
    adressfamily = str(client.family)
    clienttype = str(client.type)
    proto = client.proto
    if show_info:
        logger.debug("socket Information")
        logger.debug(f"AddressFamily socket {str(client.family)}")
        logger.debug(f"type STREAM socket {str(client.type)}")
        logger.debug(f"proto socket {client.proto}")
        logger.debug(f"listen adress {addresslisten} {portlisten}")
        logger.debug(f"recept adress {adressrecept} {portrecept}")

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
            return pickle.loads(data)
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
                    f'message may be incomplete : size message Recv is egal max size message ({xmppobject.sizebufferrecv}) :"verify param sizebufferrecv"'
                )
            if xmppobject.encryptionAES and len(xmppobject.config.keyAES32) > 0:
                if not isBase64(request.strip()):
                    logger.warning("message input no encryption")
                else:
                    logger.warning("message input base64")
                cipher = AESCipher(xmppobject.config.keyAES32)
                request = cipher.decrypt(str(request.decode("utf8")))
                logger.warning(f"request data is {request}")
            requestobj = _convert_string(request)
            if requestobj is None:
                break
            if isinstance(requestobj, (str)):
                testresult = requestobj[:4].lower()
                if (
                    requestobj == ""
                    or requestobj == "quit_server_kiosk"
                    or testresult == "quit"
                    or testresult == "exit"
                    or testresult == "end"
                ):
                    logger.debug("Receiving a `connexion end` request")
                else:
                    logger.warning(f"Receiving data: {requestobj}")
                await loop.sock_sendall(client, "no result".encode("utf-8"))
                break

            if isinstance(requestobj, (dict)):
                try:
                    # creation action
                    codeerror, result = xmppobject.handle_client_connection(
                        json.dumps(requestobj)
                    )
                    logger.warning(f"reception data : __{codeerror}__ __{result}__")

                    if not result or result == "":
                        await loop.sock_sendall(client, "no result".encode("utf-8"))

                    if isinstance(result, (list, dict, set, tuple)):
                        try:
                            _result = json.dumps(
                                result, cls=DateTimebytesEncoderjson, indent=4
                            ).encode("utf-8")
                        except Exception as e:
                            _result = '{"type":"error", "from":"agent-machine", "message":e}'.encode(
                                "utf-8"
                            )
                        finally:
                            await loop.sock_sendall(client, _result)
                    elif isinstance(result, (str)):
                        if result != "":
                            try:
                                await loop.sock_sendall(client, result.encode("utf-8"))
                            except (
                                BrokenPipeError,
                                ConnectionResetError,
                                ConnectionAbortedError,
                            ):
                                logger.warning(
                                    "Client disconnected before sending the response."
                                )
                        else:
                            try:
                                await loop.sock_sendall(
                                    client, "no result".encode("utf-8")
                                )
                            except (
                                BrokenPipeError,
                                ConnectionResetError,
                                ConnectionAbortedError,
                            ):
                                logger.warning(
                                    "Client disconnected before sending the response."
                                )

                    elif isinstance(result, (bytes)):
                        await loop.sock_sendall(client, result)
                    else:
                        try:
                            strdata = str(result).encode("utf-8")
                            try:
                                await loop.sock_sendall(client, result)
                            except (
                                BrokenPipeError,
                                ConnectionResetError,
                                ConnectionAbortedError,
                            ):
                                logger.warning(
                                    "Client disconnected before sending the response."
                                )
                        except Exception as e:
                            try:
                                await loop.sock_sendall(client, str(e).encode("utf-8"))
                            except (
                                BrokenPipeError,
                                ConnectionResetError,
                                ConnectionAbortedError,
                            ):
                                logger.warning(
                                    "Client disconnected before sending the response."
                                )

                        logger.warning(f"type reception data {type(result)}")
                    break  # suivant type de connexion desire
                except Exception as e:
                    try:
                        await loop.sock_sendall(client, str(e).encode("utf-8"))
                    except (
                        BrokenPipeError,
                        ConnectionResetError,
                        ConnectionAbortedError,
                    ):
                        logger.warning(
                            "Client disconnected before sending the response."
                        )
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
            f'netstat -lnt4p | grep python | grep ":{xmppobject.port_tcp_kiosk}"'
        )
        logger.warning(f"linux command : {linux_command}")
        result = simplecommand(linux_command)

        if len(result["result"]) > 0:
            logger.debug(
                f"The tcp_ip kiosk server is already running locally in the port {xmppobject.port_tcp_kiosk}"
            )
            return
    elif sys.platform.startswith("win"):
        windows_command = f'netstat -aof -p TCP | findstr LISTENING | findstr ":{xmppobject.port_tcp_kiosk}"'
        result = simplecommand(windows_command)
        if len(result["result"]) > 0:
            logger.debug(
                f"The tcp_ip kiosk server is already running locally in the port {xmppobject.port_tcp_kiosk}"
            )
            return
    else:
        logger.error(f"We do not support your Operating System {sys.platform}")
        return

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        server.bind(("localhost", xmppobject.port_tcp_kiosk))
        server.listen(8)
    except Exception as e:
        logger.error(f"The run_server function failed with the error {str(e)}")
        logger.error("We hit the backtrace \n %s" % traceback.format_exc())
        return
    server.setblocking(False)

    loop = asyncio.get_event_loop()

    while True:
        client, client_address = await loop.sock_accept(server)
        loop.create_task(handle_client(client, xmppobject))
