#!/usr/bin/python3
# -*- coding: utf-8; -*-
# SPDX-FileCopyrightText: 2016-2023 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-3.0-or-later

import sys
import traceback
import json
import logging
from lib.utils import name_random
import asyncio

if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

import datetime

import posix_ipc

logger = logging.getLogger()

plugin = {"VERSION": "1.0", "NAME": "__server_file", "TYPE": "code"}  # fmt: skip
name_queue = ["/mysend", "/myrep"]


def action(xmppobject, action):
    try:
        logger.debug("=====================================================")
        logger.debug("call plugin code %s " % (plugin))
        logger.debug("=====================================================")
        compteurcallplugin = getattr(xmppobject, "num_call%s" % action)

        if compteurcallplugin == 0:
            logger.debug("=====================================================")
            logger.debug("================ INITIALIZATION =====================")
            logger.debug("=====================================================")
            # Create the message queue.
            try:
                xmppobject.mq = posix_ipc.MessageQueue("/mysend", posix_ipc.O_CREX)
            except posix_ipc.ExistentialError:
                xmppobject.mq = posix_ipc.MessageQueue("/mysend")
            except OSError as e:
                logger.error("ERROR CREATE QUEUE POSIX %s" % e)
                logger.error(
                    "eg : admin (/etc/security/limits.conf and  /etc/sysctl.conf"
                )
            except Exception as e:
                logger.error("exception %s" % e)
                logger.error("\n%s" % (traceback.format_exc()))
            # try:
            # xmppobject.mq = posix_ipc.MessageQueue("/myrep", posix_ipc.O_CREX)
            # except posix_ipc.ExistentialError:
            # xmppobject.mq = posix_ipc.MessageQueue("/myrep")

        logger.debug("================ RUNNING SERVER MMC ================")
        while 1:
            logger.debug("================ SERVEUR FILE MESSAGE1 ================")
            # lit file d'attente json en bytes.
            # action suivant demande
            # send message
            try:
                msg, prioritymsg = xmppobject.mq.receive()
                decode_msg(xmppobject, msg, prioritymsg)
            except posix_ipc.BusyError:
                logger.debug("msg file empty")

    except Exception as e:
        logger.error("Plugin loadarscheck, we encountered the error %s" % str(e))
        logger.error("We obtained the backtrace %s" % traceback.format_exc())


def decode_msg(xmppobject, msg, prioritymsg):
    msg = msg.decode("utf-8")
    if prioritymsg == 9:
        # notify string
        logger.error("Notify  Priority msg :%s\nmsg :%s" % (prioritymsg, msg))
    elif prioritymsg == 4:
        # info mmc string
        logger.debug("information mmc Priority msg :%s\nmsg :%s" % (prioritymsg, msg))
        information_mmc(xmppobject, msg)
    elif prioritymsg == 5:
        # send message xmpp
        obj = json.loads(msg)
        logger.error("recv : type :%s\n%s" % (msg, prioritymsg))
        send_message_file(xmppobject, obj)


def information_mmc(xmppobject, *args, **kwargs):
    if args:
        for value in args:
            if isinstance(value, (bytes)):
                value = value.decode("utf-8")
        if args[0]:
            obj = json.loads(args[0])
            if "action" in obj:
                if obj["action"] == "list_mmc_module":
                    xmppobject.list_mmc = obj["data"]
                    logger.error(
                        "list des modules MMC sont : %s" % (xmppobject.list_mmc)
                    )


def send_iq_message(xmppobject, msg):
    obj = json.loads(msg)
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    # creation queu resultat
    try:
        mqresult = posix_ipc.MessageQueue(obj["name_iq_queue"], posix_ipc.O_CREX)
    except posix_ipc.ExistentialError:
        mqresult = posix_ipc.MessageQueue(obj["name_iq_queue"])

    mtimeout = obj["mtimeout"]
    destinataire = obj["mto"]
    del obj["mto"]
    del obj["mtimeout"]
    result = xmppobject.iqsendpulse1(destinataire, obj, mtimeout)


def send_message_file(xmppobject, *args, **kwargs):
    if args:
        for value in args:
            if isinstance(value, (bytes)):
                value = value.decode("utf-8")
    if kwargs:
        if "to" in kwargs:
            to = kwargs["to"]

        if "action" not in kwargs:
            return False
        else:
            action = (
                kwargs["action"].decode("utf-8")
                if isinstance(kwargs["action"], bytes)
                else kwargs["action"]
            )

        if "sessionid" in kwargs:
            sessionid = (
                kwargs["sessionid"].decode("utf-8")
                if isinstance(kwargs["sessionid"], bytes)
                else kwargs["sessionid"]
            )
        else:
            sessionid = name_random(6, "server_file")

        if "base64" in kwargs:
            if isinstance(kwargs["base64"], bool):
                Base64 = kwargs["base64"]
            elif isinstance(kwargs["base64"], int):
                if kwargs["base64"] > 0:
                    Base64 = True
                else:
                    Base64 = False
            else:
                Base64 = (
                    kwargs["base64"].decode("utf-8")
                    if isinstance(kwargs["base64"], bytes)
                    else kwargs["base64"]
                )
                if kwargs["base64"].strip().lower()[0] in ["t", "y", "o", "1"]:
                    Base64 = True
                else:
                    Base64 = False
        else:
            Base64 = False

        if "ret" in kwargs:
            if isinstance(kwargs["ret"], int):
                ret = kwargs["ret"]
            else:
                ret = (
                    int(kwargs["ret"].decode("utf-8"))
                    if isinstance(kwargs["ret"], bytes)
                    else int(kwargs["ret"])
                )
        else:
            ret = 0

        if "data" in kwargs:
            if isinstance(kwargs["data"], (list, dict, tuple, float, int, datetime)):
                data = json.dumps(kwargs["data"], cls=DateTimebytesEncoderjson)
            elif isinstance(kwargs["data"], (bytes)):
                data = kwargs["data"].decode("utf-8")
            elif isinstance(kwargs["data"], (str)):
                data = kwargs["data"]
            else:
                data = ""
        else:
            data = ""
        msg = {
            "action": action,
            "sessionid": sessionid,
            "ret": ret,
            "base64": Base64,
            "data": data,
        }
        msgsend = json.dumps(msg, cls=DateTimebytesEncoderjson)
    elif args:
        if len(args) == 2:
            # arg[0] jid to
            to = args[0]
            # arg[1] string body message or dict struct message
            if isinstance(args[1], (dict)):
                msg = json.dumps(args[1], cls=DateTimebytesEncoderjson)
        else:
            return False
    xmppobject.send_message(mto=to, mbody=msg, mtype="chat")
    return True


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
