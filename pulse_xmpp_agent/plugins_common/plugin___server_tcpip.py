# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2016-2023 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-3.0-or-later
"""
plugin serveur tcp/ip pour les agent machine et relay.
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
    """
    Reads and configures the TCP/IP server settings for the XMPP object.

    This function initializes and configures the TCP/IP server settings for the specified
    XMPP object, based on its agent type and optional configuration files. The settings
    include the server port, buffer size, and AES encryption flag. If a local configuration
    file is present, it overrides the default settings.

    Args:
        xmppobject (object): The XMPP object that holds the server configuration.

    Returns:
        None
    """
    # Set the default TCP/IP port for the kiosk to 8765
    xmppobject.port_tcp_kiosk = 8765
    prefixe_agent = ""

    # Set default buffer size to 1 MB (1048576 bytes) if not already defined
    if not hasattr(xmppobject, "sizebufferrecv"):
        xmppobject.sizebufferrecv = 1048576

    # Disable AES encryption by default if not already defined
    if not hasattr(xmppobject, "encryptionAES"):
        xmppobject.encryptionAES = False

    # Check the agent type and adjust the prefix and port accordingly
    if xmppobject.config.agenttype in ["relayserver"]:
        prefixe_agent = "ars_"
        # If a specific port is defined in the relay server config, use it
        if (
            "ars_local_port" in vars(xmppobject.config)
            and vars(xmppobject.config)["ars_local_port"] is not None
        ):
            xmppobject.port_tcp_kiosk = vars(xmppobject.config)["ars_local_port"]
            logger.warning(
                f"Parameter TCP/IP port in section [kiosk]/ars_local_port in relayconf.ini: {xmppobject.port_tcp_kiosk}"
            )
    elif xmppobject.config.agenttype in ["machine"]:
        prefixe_agent = "am_"
        # If a specific port is defined in the machine config, use it
        if (
            "am_local_port" in vars(xmppobject.config)
            and vars(xmppobject.config)["am_local_port"] is not None
        ):
            xmppobject.port_tcp_kiosk = vars(xmppobject.config)["am_local_port"]
            logger.warning(
                f"Parameter TCP/IP port in section [kiosk]/am_local_port in agentconf.ini: {xmppobject.port_tcp_kiosk}"
            )

    # Construct the configuration file path for the plugin
    configfilename = os.path.join(
        directoryconffile(), prefixe_agent + plugin["NAME"] + ".ini"
    )
    logger.info(
        f"Optional local config file for plugin 'server_tcpip' is: {configfilename}"
    )

    # Check if the configuration file exists
    if os.path.isfile(configfilename):
        # Parse the configuration file
        Config = configparser.ConfigParser()
        Config.read(configfilename)
        # Check for an optional ".local" file and read it if present
        if os.path.isfile(f"{configfilename}.local"):
            Config.read(f"{configfilename}.local")
            # Override port if specified in the config
            if Config.has_option("server_tcpip", "port_tcpip"):
                xmppobject.port_tcp_kiosk = Config.getint("server_tcpip", "port_tcpip")
                logger.warning(
                    "Local config overrides TCP/IP port in section [server_tcpip]/port_tcpip"
                )
            # Override buffer size if specified in the config
            if Config.has_option("server_tcpip", "sizebufferrecv"):
                xmppobject.sizebufferrecv = Config.getint(
                    "server_tcpip", "sizebufferrecv"
                )
                logger.warning(
                    "Local config overrides buffer size in section [server_tcpip]/sizebufferrecv"
                )
            # Override AES encryption flag if specified in the config
            if Config.has_option("server_tcpip", "encryptionAES"):
                xmppobject.encryptionAES = Config.getboolean(
                    "server_tcpip", "encryptionAES"
                )
                logger.warning(
                    "Local config overrides AES encryption flag in section [server_tcpip]/encryptionAES"
                )
    else:
        # Log a warning if the configuration file does not exist
        logger.warning(
            f"Local configuration file {configfilename} for plugin {plugin['NAME']} does not exist"
        )

    # Log the final port that will be used by the TCP/IP kiosk
    logger.warning(f"port_tcp_kiosk is {xmppobject.port_tcp_kiosk}")



def client_info(client, show_info=False):
    """
    Retrieves and returns information about a client socket connection.

    This function gathers details about a given client socket, including the local and remote
    addresses, the socket family, type, and protocol. Optionally, it can log this information
    for debugging purposes.

    Args:
        client (socket): The client's socket object.
        show_info (bool): If True, logs the socket information using the logger. Default is False.

    Returns:
        dict: A dictionary containing the following keys:
            - 'adressfamily': The address family of the socket (e.g., AF_INET).
            - 'typesocket': The type of the socket (e.g., SOCK_STREAM).
            - 'proto': The protocol used by the socket.
            - 'adress_listen': The local address the socket is bound to.
            - 'port_listen': The local port the socket is bound to.
            - 'adress_recept': The remote address the socket is connected to.
            - 'port_recept': The remote port the socket is connected to.
    """
    # Retrieve the local address and port where the socket is listening
    addresslisten, portlisten = client.getsockname()

    # Retrieve the remote address and port to which the socket is connected
    adressrecept, portrecept = client.getpeername()

    # Get the socket's address family (e.g., AF_INET)
    adressfamily = str(client.family)

    # Get the socket's type (e.g., SOCK_STREAM)
    clienttype = str(client.type)

    # Get the protocol used by the socket
    proto = client.proto

    # Optionally log the socket information for debugging purposes
    if show_info:
        logger.debug("Socket Information")
        logger.debug(f"Address Family: {adressfamily}")
        logger.debug(f"Socket Type: {clienttype}")
        logger.debug(f"Protocol: {proto}")
        logger.debug(f"Listening Address: {addresslisten}:{portlisten}")
        logger.debug(f"Remote Address: {adressrecept}:{portrecept}")

    # Return the collected information as a dictionary
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
    Converts data received as bytes or string into a corresponding Python object.

    This function attempts to convert the input data into one of the following formats:
    - If the data is in bytes format:
      - Checks if the data is Base64 encoded. If so, it decodes it.
      - Attempts to deserialize the data using `pickle`.
      - If deserialization fails, tries to decode the bytes as a UTF-8 string.
    - If the data is in string format:
      - Attempts to evaluate the string as a Python literal (e.g., list, dict, tuple, set).
      - If evaluation fails, it tries to parse the string as JSON.
      - If JSON parsing fails, it attempts to parse the string as YAML.

    If all conversion attempts fail, the function returns the original data.

    Args:
        data (bytes or str): The data to be converted.

    Returns:
        object: The converted data, which may be a dict, list, tuple, set, or str, depending on the content.
                If conversion fails, the original data is returned.
    """

    # Vérification et traitement des données de type bytes
    if isinstance(data, bytes):
        # Décodage Base64 si applicable
        if isBase64(data):
            try:
                data = base64.b64decode(data)
                logger.debug(f"Data decoded from Base64, type: {type(data)}")
            except Exception as e:
                logger.error(f"Erreur lors du décodage Base64 : {e}")
                return None

        # Tentative de désérialisation avec pickle
        try:
            return pickle.loads(data)
        except pickle.UnpicklingError as e:
            logger.debug(f"Data is not a pickle object: {e}")
        except Exception as e:
            logger.error(f"Erreur lors de la désérialisation pickle : {e}")
            return None

        # Tentative de décodage en chaîne UTF-8
        try:
            data = data.decode("utf-8")
            logger.debug("Data decoded to UTF-8 string")
        except UnicodeDecodeError as e:
            logger.error(f"Erreur lors du décodage UTF-8 : {e}")
            return None

    # Vérification et traitement des données de type str
    if isinstance(data, str):
        # Tentative d'évaluation littérale (list, dict, tuple, set)
        try:
            requestdata = ast.literal_eval(data)
            if isinstance(requestdata, (list, dict, tuple, set)):
                logger.debug("Data successfully evaluated to Python structure")
                return requestdata
        except (ValueError, SyntaxError) as e:
            logger.debug(f"Data is not a Python literal structure: {e}")

        # Tentative de parsing JSON
        try:
            requestdata = json.loads(data)
            logger.debug("Data successfully parsed as JSON")
            return requestdata
        except json.JSONDecodeError as e:
            logger.debug(f"Data is not a valid JSON string: {e}")

        # Tentative de parsing YAML
        try:
            requestdata = yaml.load(data, Loader=yaml.Loader)
            logger.debug("Data successfully parsed as YAML")
            return requestdata
        except yaml.YAMLError as e:
            logger.debug(f"Data is not a valid YAML string: {e}")

    # Si aucune des tentatives n'a réussi, retourner les données d'origine
    logger.debug("Data could not be converted, returning original")
    return data

async def handle_client(client, xmppobject):
    """
    Handles an individual client connection.

    This function processes requests from a connected client, decrypts data if necessary,
    and converts the received data into a Python object. It then delegates the handling
    of the client request to the `xmppobject`. The response is sent back to the client.

    Args:
        client (socket): The client's socket object.
        xmppobject (object): An object containing configuration and methods for handling the client request.

    Returns:
        None
    """
    loop = asyncio.get_event_loop()  # Get the current event loop
    request = None  # Initialize the request variable

    try:
        # Retrieve and log information about the connected client
        infoclient = client_info(client, show_info=True)

        # Allow only local clients to connect
        if infoclient["adress_recept"] != "127.0.0.1":
            logger.error("Only a local client will be allowed to connect to the server.")
            return

        while request != "":
            # Receive data from the client
            request = await loop.sock_recv(client, xmppobject.sizebufferrecv)

            # Check if the received message is potentially incomplete
            if len(request) >= xmppobject.sizebufferrecv:
                logger.warning(
                    f"Message may be incomplete: size of received message equals max buffer size ({xmppobject.sizebufferrecv}). Verify the sizebufferrecv parameter."
                )

            # Handle AES decryption if encryption is enabled
            if xmppobject.encryptionAES and len(xmppobject.config.keyAES32) > 0:
                if not isBase64(request.strip()):
                    logger.warning("Input message is not encrypted.")
                else:
                    logger.warning("Input message is base64 encoded.")

                # Decrypt the request using AES
                cipher = AESCipher(xmppobject.config.keyAES32)
                request = cipher.decrypt(str(request.decode("utf8")))
                logger.warning(f"Decrypted request data: {request}")

            # Convert the received request into a Python object
            requestobj = _convert_string(request)

            # If conversion fails, exit the loop
            if requestobj is None:
                break

            # Handle string requests
            if isinstance(requestobj, str):
                testresult = requestobj[:4].lower()
                # Check for commands to end the connection
                if (
                    requestobj == ""
                    or requestobj == "quit_server_kiosk"
                    or testresult == "quit"
                    or testresult == "exit"
                    or testresult == "end"
                ):
                    logger.debug("Receiving a 'connection end' request")
                else:
                    logger.warning(f"Receiving data: {requestobj}")

                # Send a default response to the client and exit the loop
                await loop.sock_sendall(client, "no result".encode("utf-8"))
                break

            # Handle dictionary requests
            if isinstance(requestobj, dict):
                try:
                    # Delegate request handling to the xmppobject
                    codeerror, result = xmppobject.handle_client_connection(
                        json.dumps(requestobj)
                    )
                    logger.warning(f"Received data: __{codeerror}__ __{result}__")

                    # Handle different types of results and send them back to the client
                    if not result or result == "":
                        await loop.sock_sendall(client, "no result".encode("utf-8"))

                    if isinstance(result, (list, dict, set, tuple)):
                        try:
                            # Convert the result to JSON and send it
                            _result = json.dumps(
                                result, cls=DateTimebytesEncoderjson, indent=4
                            ).encode("utf-8")
                        except Exception as e:
                            # Handle serialization errors
                            _result = '{"type":"error", "from":"agent-machine", "message":e}'.encode(
                                "utf-8"
                            )
                        finally:
                            await loop.sock_sendall(client, _result)

                    elif isinstance(result, str):
                        if result != "":
                            try:
                                # Send string result to the client
                                await loop.sock_sendall(client, result.encode("utf-8"))
                            except (
                                BrokenPipeError,
                                ConnectionResetError,
                                ConnectionAbortedError,
                            ):
                                logger.warning("Client disconnected before sending the response.")
                        else:
                            try:
                                await loop.sock_sendall(client, "no result".encode("utf-8"))
                            except (
                                BrokenPipeError,
                                ConnectionResetError,
                                ConnectionAbortedError,
                            ):
                                logger.warning("Client disconnected before sending the response.")

                    elif isinstance(result, bytes):
                        # Send bytes result to the client
                        await loop.sock_sendall(client, result)

                    else:
                        try:
                            # Convert other types of results to string and send
                            strdata = str(result).encode("utf-8")
                            try:
                                await loop.sock_sendall(client, result)
                            except (
                                BrokenPipeError,
                                ConnectionResetError,
                                ConnectionAbortedError,
                            ):
                                logger.warning("Client disconnected before sending the response.")
                        except Exception as e:
                            try:
                                # Send error message if conversion fails
                                await loop.sock_sendall(client, str(e).encode("utf-8"))
                            except (
                                BrokenPipeError,
                                ConnectionResetError,
                                ConnectionAbortedError,
                            ):
                                logger.warning("Client disconnected before sending the response.")

                        logger.warning(f"Type of received data: {type(result)}")
                    break  # Exit the loop after processing the request

                except Exception as e:
                    try:
                        # Handle any exceptions that occur during request processing
                        await loop.sock_sendall(client, str(e).encode("utf-8"))
                    except (
                        BrokenPipeError,
                        ConnectionResetError,
                        ConnectionAbortedError,
                    ):
                        logger.warning("Client disconnected before sending the response.")
                    break

    except Exception:
        # Log any unexpected errors that occur in the main loop
        logger.error(
            "We hit a backtrace in the handle_client function \n %s"
            % traceback.format_exc()
        )
    finally:
        # Close the client connection
        client.close()


async def run_server(xmppobject):
    """
    Runs the TCP/IP server to handle incoming client connections.

    This function sets up a TCP server on a specified port, ensuring that the server is not
    already running on that port. The server listens for incoming connections and spawns
    a new task to handle each client using `handle_client`.

    Args:
        xmppobject (object): An object containing server configuration, including the port to listen on.

    Returns:
        None
    """

    # Check if the server is already running on the specified port
    if sys.platform.startswith("linux") or sys.platform.startswith("darwin"):
        # Command to check running server on Linux/MacOS
        linux_command = (
            f'netstat -lnt4p | grep python | grep ":{xmppobject.port_tcp_kiosk}"'
        )
        logger.warning(f"Linux command: {linux_command}")
        result = simplecommand(linux_command)

        # If there's a result, it means the server is already running
        if len(result["result"]) > 0:
            logger.debug(
                f"The TCP/IP kiosk server is already running locally on port {xmppobject.port_tcp_kiosk}"
            )
            return
    elif sys.platform.startswith("win"):
        # Command to check running server on Windows
        windows_command = f'netstat -aof -p TCP | findstr LISTENING | findstr ":{xmppobject.port_tcp_kiosk}"'
        result = simplecommand(windows_command)

        # If there's a result, it means the server is already running
        if len(result["result"]) > 0:
            logger.debug(
                f"The TCP/IP kiosk server is already running locally on port {xmppobject.port_tcp_kiosk}"
            )
            return
    else:
        # Unsupported OS
        logger.error(f"Operating system {sys.platform} is not supported")
        return

    # Create a TCP socket for the server
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)  # Reuse the address

    try:
        # Bind the server to localhost on the specified port
        server.bind(("localhost", xmppobject.port_tcp_kiosk))
        server.listen(8)  # Listen for incoming connections, with a backlog of 8
    except Exception as e:
        # Log any errors during binding or listening
        logger.error(f"The run_server function failed with the error: {str(e)}")
        logger.error("Traceback:\n%s" % traceback.format_exc())
        return

    # Set the socket to non-blocking mode for use with asyncio
    server.setblocking(False)

    # Get the current event loop
    loop = asyncio.get_event_loop()

    # Server loop: accept and handle incoming connections
    while True:
        # Accept a client connection
        client, client_address = await loop.sock_accept(server)

        # Create a new task to handle the client connection
        loop.create_task(handle_client(client, xmppobject))
