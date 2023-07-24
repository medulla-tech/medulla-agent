#!/usr/bin/python3
# -*- coding: utf-8; -*-
# SPDX-FileCopyrightText: 2016-2023 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-3.0-or-later

import os
import sys
import json
from lib.utils import (
    name_random,
    getRandomName,
    call_plugin,
    call_plugin_separate,
    simplecommand,
    convert,
    MotDePasse,
    DateTimebytesEncoderjson,
)
import asyncio
import datetime
import time

# this import will be used later
import types
import netaddr
import configparser
import re

# 3rd party modules
import gzip
import ipaddress
import inspect

from slixmpp import ClientXMPP
import xml.etree.ElementTree as ET

import logging
import traceback

DEBUGPULSE = 25
logger = logging.getLogger()


class iq_custom_xep:
    def __init__(self, xmppobject, to, dict_str, timeout=30, sessionid=None):
        # verification ressource dans JID
        self.iq = None
        self.fin = False
        self.result_iq = {}
        try:
            self.data = None
            self.timeout = int(30)
            self.sessionid = (
                sessionid
                if sessionid
                else getRandomName(8, pref="__" + xmppobject.boundjid.user + "__")
            )
            logger.debug("sessionid %s" % self.sessionid)
            self.xmppobject = (
                xmppobject if xmppobject.__class__.__name__ == "MUCBot" else None
            )
            res = to.strip().split("/")
            if not (len(res) == 2 and res[1] != ""):
                logger.error("Pas de ressource dans jid")
                self.to = None
            else:
                self.to = to
            try:
                if isinstance(dict_str, (dict, list)):
                    self.data = convert.encode_to_string_base64(
                        json.dumps(dict_str, cls=DateTimebytesEncoderjson)
                    )
                elif isinstance(dict_str, (bytes, str)):
                    if convert.check_base64_encoding(dict_str):
                        self.data = convert.convert_bytes_datetime_to_string(dict_str)
                    elif isinstance(dict__str, (bytes)):
                        self.data = convert.encode_to_string_base64(dict_str)
            except Exception as e:
                logger.error("%s" % (traceback.format_exc()))
                self.data = None

            if (
                self.data
                and self.timeout
                and self.sessionid
                and self.xmppobject
                and self.to
            ):
                try:
                    # creation de iq
                    self.iq = self.xmppobject.make_iq_get(
                        queryxmlns="custom_xep", ito=self.to
                    )
                    itemXML = ET.Element("{%s}data" % self.data)
                    for child in self.iq.xml:
                        if child.tag.endswith("query"):
                            child.append(itemXML)
                    self.iq["id"] = self.sessionid
                except Exception as e:
                    logger.error("%s" % (traceback.format_exc()))
            else:
                if not self.data:
                    logger.error("message nmal initialise")
                if not self.timeout:
                    logger.error("timeout nmal initialise")
                if not self.sessionid:
                    logger.error("sessionid nmal initialise")
                if not self.xmppobject:
                    logger.error("xmppobject nmal initialise")
                if not self.to:
                    logger.error("to nmal initialise")

        except Exception as e:
            logger.error("%s" % (traceback.format_exc()))

    def iq_send(self):
        logger.debug("#############################################################")
        logger.debug("####################### iq_send #######################")
        logger.debug("#############################################################")
        logger.debug(
            "#############################################################%s " % self.iq
        )

        if not self.iq:
            logger.debug("######################BYBYBY########################")
            return '{"error" : "initialisation erreur"}'
        timeoutloop = float(self.timeout + 5)
        logger.debug("#############################################################")
        logger.debug("####################### send #######################")
        logger.debug("#############################################################")

        logger.debug(" iq class %s  " % self.iq.__class__.__name__)

        self.iq.send(
            callback=self.on_response,
            timeout=int(self.timeout),
            timeout_callback=self.on_timeout,
        )
        logger.debug("#############################################################")
        logger.debug("####################### send #######################")
        logger.debug("#############################################################")
        while True:
            if not timeoutloop:
                er = "IQ type get id [%s] to [%s] in Timeout" % (
                    self.iq["id"],
                    self.iq["to"],
                )
                self.result_iq = {"error": er}
                return self.result_iq
            timeoutloop = timeoutloop - 0.5
            if self.fin:
                logger.debug(
                    "#############################################################"
                )
                logger.debug(
                    "####################### termine on fin #######################"
                )
                logger.debug(
                    "#############################################################"
                )
                break
            time.sleep(0.5)
        # la reponse
        self.reponse_iq = self.iq
        return self.result_iq

    def on_response(self, reponse_iq):
        logger.debug("#############################################################")
        logger.debug(
            "on_response iq id %s from %s" % (reponse_iq["iq"], reponse_iq["from"])
        )
        logger.debug("#############################################################")
        self.result_iq = {"error": "on_response"}
        try:
            self.reponse_iq = reponse_iq
            if reponse_iq["type"] == "error":
                texterror = ""
                actionerror = ""
                logger.error("on_response1 %s" % reponse_iq["type"])
                for child in reponse_iq.xml:
                    logger.error("---------\nchild %s" % child)
                    if child.tag.endswith("error"):
                        logger.error("result iq avec erreur")
                        for z in child:
                            logger.error("########\nz %s" % z.tag)
                            if z.tag.endswith("text"):
                                if z.text:
                                    texterror = "IQ Messsage is %s" % z.text
                                    logger.error(texterror)
                            elif z.tag.endswith("service-unavailable"):
                                actionerror = (
                                    "service-unavailable, Verify presense agent %s (user and resourse]"
                                    % reponse_iq["from"]
                                )
                                logger.error(actionerror)
                            elif z.tag.endswith("remote-server-not-found"):
                                actionerror = (
                                    "remote-server-not-found, Verify domaine jid agent %s"
                                    % reponse_iq["from"]
                                )
                                logger.error(actionerror)
                            elif z.tag.endswith("undefined-condition"):
                                actionerror = (
                                    "condition d'erreur pas définie dans le protocole XMPP iq xml iq \n verify jornal ejabberd for analyse %s"
                                    % reponse_iq.xml
                                )
                                logger.error(actionerror)

                self.result_iq = {
                    "error": "IQ error id [%s] to [%s] (%s) : %s"
                    % (reponse_iq["id"], reponse_iq["to"], texterror, actionerror)
                }
                self.fin = True
                return
            elif reponse_iq["type"] == "result":
                # traitement du result
                logger.debug("traitement de iq get custom_xep")
                for child in reponse_iq.xml:
                    if child.tag.endswith("query"):
                        # select data element query
                        for z in child:
                            # recuperation (bytes data) encode en base64
                            data = z.tag[1:-5]
                            try:
                                self.result_iq = convert.decode_base64_to_string_(data)
                                return self.result_iq
                            except Exception as e:
                                logger.error("on_response custom_xep : %s" % str(e))
                                logger.error("\n%s" % (traceback.format_exc()))
                                logger.error("xml reponse : %s " % str(e))
                                return {"err": "erreur decodage iq"}
            else:
                self.result_iq = {"error": "type iq [%s] " % reponse_iq["type"]}
                self.fin = True
        except Exception as e:
            self.result_iq = {"error": "type iq [%s] " % str(e)}
            self.fin = True
        finally:
            self.fin = True

    def on_timeout(self, reponse_iq):
        self.reponse_iq = reponse_iq
        er = "IQ type get id [%s] to [%s] in Timeout" % (
            reponse_iq["id"],
            reponse_iq["to"],
        )
        logger.error(er)
        self.result_iq = {"error": er}
        self.fin = True
