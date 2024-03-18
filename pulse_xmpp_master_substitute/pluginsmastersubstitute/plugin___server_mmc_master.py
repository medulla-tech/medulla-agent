#!/usr/bin/python3
# -*- coding: utf-8; -*-
# SPDX-FileCopyrightText: 2016-2023 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-3.0-or-later

"""
 plugin register machine dans presence table xmpp.
 file pluginsmastersubstitute/plugin___server_mmc_master.py
 Ce serveur est implementer par plugin
 Il permet les conexion ipv6/ipv4
 son fichier de configuration s'auto genere au premier lancement si il n'existe pas.
 file /etc/pulse-xmpp-agent-substitute/__server_mmc_master.ini
 ce serveur sera l'interface entre les instances de mmcs et les different acteur xmppmaster.(Extensible Messaging and Presence Protocol)
"""

import ssl
import socket
import select
import os
import sys
import traceback
import json
import logging
from lib.utils import (
    name_random,
    getRandomName,
    call_plugin,
    call_plugin_separate,
    simplecommand,
    convert,
    MotDePasse,
)
from lib.iq_custom import iq_custom_xep
import datetime
import time

# this import will be used later
import types
import netaddr
import configparser
import re

# 3rd party modules
import gzip
import threading
import ipaddress
import inspect

import asyncio

if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

from slixmpp import ClientXMPP
import xml.etree.ElementTree as ET

logger = logging.getLogger()

plugin = {"VERSION": "1.0", "NAME": "__server_mmc_master", "TYPE": "code"}  # fmt: skip
name_queue = ["/mysend", "/myrep"]


class DateTimebytesEncoderjson(json.JSONEncoder):
    """
    Used to handle datetime in json files.
    """

    def default(self, obj):
        if isinstance(obj, datetime):
            encoded_object = obj.isoformat()
        elif isinstance(obj, bytes):
            encoded_object = obj.decode("utf-8")
        else:
            encoded_object = json.JSONEncoder.default(self, obj)
        return encoded_object


def action(xmppobject, action):
    try:
        logger.debug("=====================================================")
        logger.debug("call plugin code %s " % (plugin))
        logger.debug("=====================================================")
        compteurcallplugin = getattr(xmppobject, "num_call%s" % action)

        if compteurcallplugin == 0:
            try:
                logger.debug("=====================================================")
                logger.debug("================ INITIALIZATION =====================")
                logger.debug("=====================================================")
                ## cette variale permet
                xmppobject.running_mmc = True
                connexions_simultane = 10
                read_conf__server_mmc_master(xmppobject)
                xmppobject.sockets_mmc = []
                # Timeout en secondes
                timeout = 2
                try:
                    # Création du socket TCP/IP avec IPv4
                    server_socket_ipv4 = socket.socket(
                        socket.AF_INET, socket.SOCK_STREAM
                    )
                    # Activation de l'option pour réutiliser l'adresse
                    server_socket_ipv4.setsockopt(
                        socket.SOL_SOCKET, socket.SO_REUSEADDR, 1
                    )
                    # ecoute sur toutes les interfae ipv4
                    server_socket_ipv4.bind(
                        (
                            xmppobject.server_mmc_master_server_host_ipv4,
                            xmppobject.server_mmc_master_server_port_ipv4,
                        )
                    )
                    # connexions simultane 10
                    server_socket_ipv4.listen(connexions_simultane)

                    xmppobject.sockets_mmc.append(server_socket_ipv4)
                    logger.debug(
                        f"Serveur démarré sur {xmppobject.server_mmc_master_server_host_ipv4}:"
                        "{xmppobject.server_mmc_master_server_port_ipv4}"
                    )
                except Exception as e:
                    logger.error(
                        "create socket ipv4\nWe obtained the backtrace %s"
                        % traceback.format_exc()
                    )
                    logger.error(
                        "le serveur master n est pas "
                        "fonctionel en ipv4 sur "
                        "interface %s et le port %s"
                        % (
                            xmppobject.server_mmc_master_server_host_ipv4,
                            xmppobject.server_mmc_master_server_port_ipv4,
                        )
                    )
                try:
                    # Création du socket TCP/IP avec IPv6
                    server_socket_ipv6 = socket.socket(
                        socket.AF_INET6, socket.SOCK_STREAM
                    )
                    # Activation de l'option pour réutiliser l'adresse
                    server_socket_ipv6.setsockopt(
                        socket.SOL_SOCKET, socket.SO_REUSEADDR, 1
                    )
                    # ecoute sur toutes les interfae ipv6
                    server_socket_ipv6.bind(
                        (
                            xmppobject.server_mmc_master_server_host_ipv6,
                            xmppobject.server_mmc_master_server_port_ipv6,
                        )
                    )
                    # connexions simultane 10
                    server_socket_ipv6.listen(connexions_simultane)

                    xmppobject.sockets_mmc.append(server_socket_ipv6)
                except Exception as e:
                    logger.error(
                        "create socket ipv6\nWe obtained the backtrace %s"
                        % traceback.format_exc()
                    )
                    logger.error(
                        "le serveur master n est pas "
                        "fonctionel en ipv6 sur "
                        "interface %s et le port %s"
                        % (
                            xmppobject.server_mmc_master_server_host_ipv6,
                            xmppobject.server_mmc_master_server_port_ipv6,
                        )
                    )

                ### Liste des sockets à surveiller
                xmppobject.sockets_mmc = [server_socket_ipv4, server_socket_ipv6]

                # Boucle principale
                while xmppobject.running_mmc:
                    if xmppobject.shutdown:  # information CTRL + C
                        break
                    # Utilisation de select pour surveiller la liste des sockets en attente de connexion
                    readable, _, _ = select.select(
                        xmppobject.sockets_mmc, [], [], timeout
                    )

                    # Parcourir les sockets prêts à être lus
                    for sock in readable:
                        if sock == server_socket_ipv4:
                            # Nouvelle connexion IPv4
                            connection, address = server_socket_ipv4.accept()
                            # Démarrer un thread pour traiter la connexion IPv4 en SSL
                            connection_threadip4 = threading.Thread(
                                target=xmppobject.process_connection_ssl,
                                args=(connection,),
                            )

                            connection_threadip4.start()
                        elif sock == server_socket_ipv6:
                            # Nouvelle connexion IPv6
                            connection, address = server_socket_ipv6.accept()
                            # Démarrer un thread pour traiter la connexion IPv6 en SSL
                            connection_threadip6 = threading.Thread(
                                target=xmppobject.process_connection_ssl,
                                args=(connection,),
                            )
                            connection_threadip6.start()

            finally:
                # Fermeture du socket lorsque la boucle se termine
                # xmppobject.stop_server()
                server_socket_ipv6.close()
                server_socket_ipv4.close()
    except Exception as e:
        pass


## Fonction pour traiter la connexion en SSL dans un thread séparé
def process_connection_ssl(self, connection):
    """
    Cette fonction permet de traiter les connexions ipv4/ipv6 au serveur
    si 1 tocken est definie celui ci est placer en tete de trame.
    """
    try:
        # il faut 1 boucle d'execution async dans ce thread
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        logger.debug("JFKJFK REV MESSAGE")

        if (
            self.server_mmc_master_active_filter
            and self.server_mmc_master_allowed_list_ips
        ):
            # Obtenir l'adresse distante (raddr)
            raddr = list(connection.getpeername())
            remote_adesse = raddr[0]
            remote_port = raddr[1]
            logger.debug("remote_adesse %s" % remote_adesse)
            logger.debug(
                "self.server_mmc_master_allowed_list_ips %s"
                % self.server_mmc_master_allowed_list_ips
            )
            addrtest = ipaddress.ip_address(remote_adesse)
            for cidr in self.server_mmc_master_allowed_list_ips:
                if addrtest in ipaddress.ip_network(cidr):
                    logger.debug(
                        "clint address %s(%s) est permit par le CIDR %s"
                        % (remote_adesse, remote_port, cidr)
                    )
                    break
            else:
                logger.warning(
                    "nous acceptons pas le client venant de  %s(%s)"
                    % (remote_adesse, remote_port)
                )
                logger.warning(
                    "The allowed_ips setting does not have a CIDR value that includes the ip of the client"
                )
                return
        try:
            # Création du contexte SSL
            ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            ssl_context.load_cert_chain(
                certfile=self.server_mmc_master_certfile,
                keyfile=self.server_mmc_master_keyfile,
            )
            # Wrapping du socket en SSL
            ssl_connection = ssl_context.wrap_socket(connection, server_side=True)
            # Traitement de la connexion SSL
            try:
                data = convert.decompress_data_to_bytes(ssl_connection.recv(2097152))
            except Exception as e:
                logger.error("erreur traitement message recu")
                raise
            if self.server_mmc_master_allowed_token:
                tockentrame = data[: len(self.server_mmc_master_allowed_token)]
                logger.debug(tockentrame)
                logger.debug(self.server_mmc_master_allowed_token)
                if tockentrame == convert.convert_to_bytes(
                    self.server_mmc_master_allowed_token
                ):
                    logger.debug("tocken correct")
                    data = data[len(self.server_mmc_master_allowed_token) :]
                else:
                    logger.error(
                        "Ce message n'est pas traite acces interdit verifie tocken"
                    )
                    return
            datatest = convert.is_base64(data)
            # decode si data est en base64
            data = datatest if datatest else data
            if data == b"Start/restart MMC":
                logger.info("%s" % convert.convert_bytes_datetime_to_string(data))
                return

            try:
                data = convert.convert_json_to_dict(data)
                logger.error("data est 1 json")
            except json.decoder.JSONDecodeError as e:
                # type n est pas 1 json.
                logger.error("data pas 1 json ")
                try:
                    data = convert.yaml_string_to_dict(data)
                    logger.error("data est 1 yam")
                except:
                    logger.error("data pas 1 yam ")
                    try:
                        data = convert.xml_to_dict(data)
                        logger.error("data est 1 xml")
                    except:
                        logger.error("data pas 1 xml")

            logger.debug("process_connection_ssl  ******* data %s" % type(data))
            if isinstance(data, (str, bytes)):
                logger.debug("master n'a pas recu 1 message")
                # call fonction de traitement des message de type sting
                self.mast_serv_recv_string(message_string=data)
            elif isinstance(data, (dict)):
                logger.debug("traitement Message")
                # call fonction de traitement des message de type dict
                self.mast_serv_recv_dict(ssl_connect=ssl_connection, message_dict=data)
                logger.debug("traitement Message")
            else:
                logger.warning("msg de type %s non traite" % type(data))
        except ssl.SSLError as e:
            logger.debug("======== process_connection_ssl fin  ========")
            logger.debug("process_connection_ssl fin SSL : %s" % e)
        except Exception as e:
            logger.debug("error the backtrace %s" % traceback.format_exc())
        finally:
            logger.debug("======== process_connection_ssl finally  ========")
            # Fermeture de la connexion SSL
            ssl_connection.close()
            logger.debug("======== process_connection_ssl finally  ========")
    finally:
        # Close the event loop
        logger.debug(
            "======== close boucle asyncprocess_connection_ssl finally  ========"
        )
        loop.close()


def mast_serv_recv_string(self, *args, **kwargs):
    logger.debug("reception message de type chaine")
    logger.debug("nombre args %s" % len(args))
    logger.debug("nombre kwargs %s" % len(kwargs))


def mast_serv_recv_dict(self, ssl_connect=None, message_dict=None, tocken=""):
    loop = asyncio.get_event_loop()
    # Do something with the event loop
    logger.debug("reception message de type dict sur serveur mmc")
    try:
        typemsg = message_dict["metadatas"]["type"]
        to = message_dict["metadatas"]["to"]
        timeout = int(message_dict["metadatas"]["timeout"])
        self.fin = False
    except Exception as e:
        logger.error("meta parametre missing")
        return
    # on supprime les metas parametres
    del message_dict["metadatas"]
    logger.debug("typemsg %s" % typemsg)
    logger.debug("to %s" % to)
    logger.debug("timeout %s" % timeout)

    if typemsg == "plugin":
        if message_dict["action"] == "list_mmc_module":
            logger.debug("INITIALISATION LIST MODULE MMC %s" % message_dict["data"])
            # la list des module est initialiser directement sans appel de plugin
            self.list_mmc = message_dict["data"]
            # peut etre à faire 1 plugin pour diffuser cette information a tout les ars ou substituts
            # par exemple 1 substitut koisk devrait etre au courant si moduke actif.
            if "xmppmaster" not in self.list_mmc:
                logger.error("Le module xmppmaster n'est pas actif.")
            message_dict["data"] = {"result": "information list module actif passe"}
            message_dict["action"] = "result_" + message_dict["action"]
            self.retour_result(ssl_connect, message_dict)
            return
        # call plugin interne
        dataerreur = {
            "action": "result" + message_dict["action"],
            "data": {"msg": "error plugin : " + message_dict["action"]},
            "sessionid": message_dict["sessionid"],
            "ret": 255,
            "base64": False,
        }
        module = "%s/plugin_%s.py" % (self.modulepath, message_dict["action"])
        msg = {
            "from": "master@pulse/MASTER",
            "to": "master@pulse/MASTER",
            "type": "chat",
        }
        call_plugin(
            module,
            self,
            message_dict["action"],
            message_dict["sessionid"],
            message_dict["data"],
            msg,
            dataerreur,
        )
        return

    elif typemsg == "msg":
        # send message jid
        self.send_message(mbody=json.dumps(message_dict), mto=to, mtype="chat")
    elif typemsg == "iq":
        logger.debug("#############################################################")
        logger.debug("####################### traitement IQ #######################")
        logger.debug("#############################################################")
        iqc = iq_custom_xep(self, to, message_dict, timeout=30, sessionid=None)
        result = iqc.iq_send()
        self.retour_result(ssl_connect, result)

    else:
        logger.error("meta parametre missing")


def retour_result(self, socket_reponse, reponse):
    # on s assure que le dict soit serialisable
    reponse = convert.convert_bytes_datetime_to_string(reponse)
    if isinstance(reponse, (dict)):
        reponse = convert.convert_dict_to_json(reponse)
    try:
        if self.server_mmc_master_allowed_token:
            reponse = self.server_mmc_master_allowed_token + str(reponse)
        a = convert.compress_data_to_bytes(reponse)
        socket_reponse.sendall(a)
    except Exception as e:
        logger.error("ompossible de renvoyer 1 reponse")


def read_conf__server_mmc_master(xmppobject):
    # creation fonction stop_server
    xmppobject.stop_server_mmc = types.MethodType(stop_server_mmc, xmppobject)
    xmppobject.mast_serv_recv_string = types.MethodType(
        mast_serv_recv_string, xmppobject
    )
    xmppobject.mast_serv_recv_dict = types.MethodType(mast_serv_recv_dict, xmppobject)
    xmppobject.retour_result = types.MethodType(retour_result, xmppobject)

    logger.debug("creation fonction process_connection_ssl")
    xmppobject.process_connection_ssl = types.MethodType(
        process_connection_ssl, xmppobject
    )

    logger.debug("Initializing plugin :% s " % plugin["NAME"])
    conffile_name = plugin["NAME"] + ".ini"
    try:
        conffile_path = os.path.join(xmppobject.config.pathdirconffile, conffile_name)
        logger.info("file config : %s" % conffile_path)
        xmppobject.master_conf = Configuration(xmppobject, conffile_path)
    except Exception as e:
        logger.error("We obtained the backtrace %s" % traceback.format_exc())

    logger.debug(
        "===============FICHIER DE CONF EST %s ====================" % conffile_path
    )


# Fonction pour arrêter le serveur
def stop_server_mmc(self):
    for sockserv in self.sockets_mmc:
        sockserv.close()
    self.sockets_mmc = []
    self.running_mmc = False


# Fonction de compression gzip
def compress_data(data):
    return gzip.compress(data)


# Fonction de décompression gzip
def decompress_data(data):
    return gzip.decompress(data)


class Configuration:
    def __init__(self, xmppobject, config_file):
        port_default_serveur = 57040
        taille_mac_message = 2097152  # bytes
        self.xmppobject = xmppobject
        xmppobject.server_mmc_master_certfile = "/var/lib/pulse2/masterkey/cert.pem"
        xmppobject.server_mmc_master_keyfile = "/var/lib/pulse2/masterkey/key.pem"
        xmppobject.server_mmc_master_server_host_ipv6 = "::"
        xmppobject.server_mmc_master_server_host_ipv4 = "0.0.0.0"
        xmppobject.server_mmc_master_server_port_ipv4 = port_default_serveur
        xmppobject.server_mmc_master_server_port_ipv6 = port_default_serveur + 1
        xmppobject.server_mmc_master_active_filter = True
        xmppobject.server_mmc_master_allowed_ips = "127.0.0.1/32, ::1/128"
        xmppobject.server_mmc_master_allowed_list_ips = [
            x.strip()
            for x in xmppobject.server_mmc_master_allowed_ips.split(",")
            if x.strip() != ""
        ]
        xmppobject.server_mmc_master_allowed_token = MotDePasse(32, 60).mot_de_passe
        xmppobject.server_mmc_master_size_allowed_token = len(
            xmppobject.server_mmc_master_allowed_token
        )
        xmppobject.server_mmc_master_max_message_size = taille_mac_message
        xmppobject.server_mmc_master_compress = True

        if os.path.isfile(config_file):
            self.config = configparser.ConfigParser()
            self.config.read(config_file)
            if os.path.exists(config_file + ".local"):
                self.config.read(config_file + ".local")
            # SSL parameters
            xmppobject.server_mmc_master_certfile = self.config.get(
                "ssl", "certfile", fallback="/var/lib/pulse2/masterkey/cert.pem"
            )
            xmppobject.server_mmc_master_keyfile = self.config.get(
                "ssl", "keyfile", fallback="/var/lib/pulse2/masterkey/key.pem"
            )
            # Server parameters
            xmppobject.server_mmc_master_server_host_ipv6 = self.config.get(
                "server", "server_host_ipv6", fallback="::"
            )
            xmppobject.server_mmc_master_server_host_ipv4 = self.config.get(
                "server", "server_host_ipv4", fallback="0,0,0,0"
            )
            xmppobject.server_mmc_master_server_port_ipv4 = self.config.getint(
                "server", "server_port_ipv4", fallback=port_default_serveur
            )
            xmppobject.server_mmc_master_server_port_ipv6 = self.config.getint(
                "server", "server_port_ipv6", fallback=port_default_serveur + 1
            )
            # Filtered addresses parameters
            xmppobject.server_mmc_master_active_filter = self.config.getboolean(
                "filter", "filter_enabled", fallback=True
            )
            xmppobject.server_mmc_master_allowed_ips = self.config.get(
                "filter", "allowed_ips", fallback="127.0.0.1/32,::1/128"
            )
            xmppobject.server_mmc_master_allowed_list_ips = [
                x.strip()
                for x in xmppobject.server_mmc_master_allowed_ips.split(",")
                if x.strip() != ""
            ]
            xmppobject.server_mmc_master_allowed_token = self.config.get(
                "filter", "allowed_token", fallback=""
            )
            xmppobject.server_mmc_master_size_allowed_token = len(
                xmppobject.server_mmc_master_allowed_token
            )
            # Message parameters
            xmppobject.server_mmc_master_max_message_size = self.config.getint(
                "message", "max_message_size", fallback=taille_mac_message
            )
            xmppobject.server_mmc_master_compress = self.config.getboolean(
                "message", "compress_message", fallback=True
            )
        else:
            # creation du fichier de configuration
            self.writte_conf(xmppobject, config_file)
        self.creation_or_validite_key_certificat(
            xmppobject, 1000, os.path.dirname(xmppobject.server_mmc_master_certfile)
        )
        logger.info(
            "Parameter default %s" % json.dumps(self.get_parameters(), indent=4)
        )

    def writte_conf(self, xmppobject, config_file):
        logger.warning(
            "génération d'un file de configuration %s par default" % config_file
        )
        # creation du fichier de configuration
        with open(config_file, "w") as f:
            f.write("# file conf generation automatique" + (os.linesep) * 2)
            f.write("[ssl]" + os.linesep)
            f.write("keyfile=%s" % xmppobject.server_mmc_master_keyfile + os.linesep)
            f.write(
                "certfile=%s" % xmppobject.server_mmc_master_certfile + (os.linesep) * 2
            )
            f.write("[server]" + os.linesep)
            f.write(
                "server_host_ipv6=%s" % xmppobject.server_mmc_master_server_host_ipv6
                + os.linesep
            )
            f.write(
                "server_host_ipv4=%s" % xmppobject.server_mmc_master_server_host_ipv4
                + os.linesep
            )
            f.write(
                "server_port_ipv4=%s" % xmppobject.server_mmc_master_server_port_ipv4
                + (os.linesep) * 1
            )
            f.write(
                "server_port_ipv6=%s" % xmppobject.server_mmc_master_server_port_ipv6
                + (os.linesep) * 2
            )
            f.write("[filter]" + os.linesep)
            f.write(
                "filter_enabled=%s" % xmppobject.server_mmc_master_active_filter
                + os.linesep
            )
            f.write(
                "# filter_enabled = True  on filtre les ip des clients. le parametre est allowed_ips"
                + os.linesep
            )
            f.write(
                "allowed_ips=%s" % xmppobject.server_mmc_master_allowed_ips + os.linesep
            )
            f.write(
                "# allowed_ips = list des CIDR permettant de controler que ip de la machine client est permise."
                + os.linesep
            )
            f.write(
                "# allowed_ips = "
                "  permet la connexion a tout les clients." + os.linesep
            )
            f.write(
                "# allowed_ips = 127.0.0.1/32, ::1/128, localhost permet la connexion a tout les clients local."
                + os.linesep
            )
            f.write(
                "# allowed_ips = '2001:db8::/96' permet par exemple '2001:0db8:0000:0000:0000:0000:0000:0001"
                + os.linesep
            )
            f.write(
                "allowed_token=%s" % xmppobject.server_mmc_master_allowed_token
                + os.linesep
            )
            f.write("[message]" + os.linesep)
            f.write(
                "max_message_size=%s" % xmppobject.server_mmc_master_max_message_size
                + os.linesep
            )
            f.write(
                "compress_message=%s" % xmppobject.server_mmc_master_compress
                + (os.linesep) * 2
            )

    def get_parameters(self):
        parameters = {
            "server_mmc_master_certfile": (
                self.xmppobject.server_mmc_master_certfile
                if hasattr(self.xmppobject, "server_mmc_master_certfile")
                else None
            ),
            "server_mmc_master_keyfile": (
                self.xmppobject.server_mmc_master_keyfile
                if hasattr(self.xmppobject, "server_mmc_master_keyfile")
                else None
            ),
            "server_mmc_master_server_host_ipv6": self.xmppobject.server_mmc_master_server_host_ipv6,
            "server_mmc_master_server_host_ipv4": self.xmppobject.server_mmc_master_server_host_ipv4,
            "server_mmc_master_server_port_ipv4": self.xmppobject.server_mmc_master_server_port_ipv4,
            "server_mmc_master_server_port_ipv6": self.xmppobject.server_mmc_master_server_port_ipv6,
            "server_mmc_master_active_filter": self.xmppobject.server_mmc_master_active_filter,
            "server_mmc_master_allowed_ips": (
                self.xmppobject.server_mmc_master_allowed_ips
                if hasattr(self.xmppobject, "server_mmc_master_allowed_ips")
                else ""
            ),
            "server_mmc_master_allowed_token": (
                self.xmppobject.server_mmc_master_allowed_token
                if hasattr(self.xmppobject, "server_mmc_master_allowed_token")
                else ""
            ),
            "server_mmc_master_max_message_size": self.xmppobject.server_mmc_master_max_message_size,
            "server_mmc_master_compress": self.xmppobject.server_mmc_master_compress,
        }
        return parameters

    def creation_or_validite_key_certificat(
        self, xmppobject, path_file_cert_pam="/var/lib/pulse2/masterkey", valid_days=365
    ):
        script = """#!/bin/bash
        create_certificate() {
            valid_days=$1
            directory=$2
            organization=$3
            country=$4
            common_name=$5

            # Vérifier si le répertoire existe
            if [ ! -d "$directory" ]; then
                echo "Création du répertoire $directory"
                mkdir -p "$directory"
                chmod 700 "$directory"
            fi

            # Générer la clé privée
            key_file="$directory/key.pem"
            openssl genpkey -algorithm RSA -out "$key_file"
            chmod 600 "$key_file"

            # Générer le certificat auto-signé
            cert_file="$directory/cert.pem"
            openssl req -new -key "$key_file" -x509 -days "$valid_days" -out "$cert_file" \
                -subj "/CN=$common_name/O=$organization/C=$country"
            chmod 600 "$cert_file"
            expiration_date=$(openssl x509 -enddate -noout -in "$cert_file" | awk -F "=" '{print $2}')
            echo "Clé et certificat générés avec succès dans le répertoire $directory"
            echo "Validite $valid_days Jours"
            echo "expiration $expiration_date"
            echo "SUCCESS $valid_days "
        }

        check_certificate() {
            valid_days=$1
            directory=$2
            organization=$3
            country=$4
            common_name=$5

            cert_file="$directory/cert.pem"
            key_threshold_days=15

        # Vérifier si le fichier du certificat existe
        if [ -f "$cert_file" ]; then
            # Vérifier la validité du certificat
            expiration_date=$(openssl x509 -enddate -noout -in "$cert_file" | awk -F "=" '{print $2}')
            expiration_timestamp=$(date -d "$expiration_date" +%%s)
            current_timestamp=$(date +%%s)

            if [ "$current_timestamp" -lt "$expiration_timestamp" ]; then
                remaining_seconds=$((expiration_timestamp - current_timestamp))
                remaining_days=$((remaining_seconds / (60 * 60 * 24)))
                echo "Le certificat $cert_file est valide pendant encore $remaining_days jour(s)."
                echo "SUCCESS $remaining_days"
                if [ "$remaining_days" -lt "$key_threshold_days" ]; then
                    echo "Attention : La clé est valide pendant moins de $key_threshold_days jour(s)."
                    echo "WARNING $remaining_days"
                fi
            else
                echo "Le certificat a expiré."
                echo "ERROR -1"
            fi
        else
            echo "Le certificat $cert_file n'existe pas. Création en cours for $valid_days Jours de validite..."
            create_certificate "$valid_days" "$directory" "$organization" "$country" "$common_name"
        fi
        }
        # Paramètres de création du certificat
        valid_days=%s
        directory="%s"
        organization="siveo.net"
        country="FR"
        common_name="serveur_master_xmpp"
        #fonction pour vérifier le certificat
        check_certificate "$valid_days" "$directory" "$organization" "$country" "$common_name"
""" % (
            path_file_cert_pam,
            valid_days,
        )
        with open("/tmp/script_key.sh", "w") as f:
            f.write(script + os.linesep)

        res = simplecommand("/bin/bash /tmp/script_key.sh")
        if res["code"] == 0:
            # correct download
            for t in res["result"]:
                logger.info("%s" % (t.strip()))
            os.remove("/tmp/script_key.sh")
            return True
        return False


def read_conf__server_mmc_master(xmppobject):
    logger.debug("creation fonction stop_server")
    xmppobject.stop_server_mmc = types.MethodType(stop_server_mmc, xmppobject)
    xmppobject.mast_serv_recv_string = types.MethodType(
        mast_serv_recv_string, xmppobject
    )
    xmppobject.mast_serv_recv_dict = types.MethodType(mast_serv_recv_dict, xmppobject)
    xmppobject.retour_result = types.MethodType(retour_result, xmppobject)

    logger.debug("creation fonction process_connection_ssl")
    xmppobject.process_connection_ssl = types.MethodType(
        process_connection_ssl, xmppobject
    )

    logger.debug("Initializing plugin :% s " % plugin["NAME"])
    conffile_name = plugin["NAME"] + ".ini"
    try:
        conffile_path = os.path.join(xmppobject.config.pathdirconffile, conffile_name)
        logger.info("file config : %s" % conffile_path)
        xmppobject.master_conf = Configuration(xmppobject, conffile_path)
    except Exception as e:
        logger.error("We obtained the backtrace %s" % traceback.format_exc())

    logger.debug(
        "===============FICHIER DE CONF EST %s ====================" % conffile_path
    )
