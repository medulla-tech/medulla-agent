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
# file /pluginsmastersubstitute/plugin___server_file.py
#
import base64
import traceback
import os
import json
import logging
from lib.plugins.xmpp import XmppMasterDatabase
from lib.plugins.glpi import Glpi
from lib.plugins.kiosk import KioskDatabase
from lib.manageRSAsigned import MsgsignedRSA
from slixmpp import jid
from lib.utils import getRandomName, name_random
import re
from distutils.version import LooseVersion
import configparser
import netaddr
# this import will be used later
import types
import time
import sys
import hashlib

# 3rd party modules
import posix_ipc

logger = logging.getLogger()

plugin = {"VERSION": "1.0", "NAME": "__server_file", "TYPE": "code"}
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
        while 1:
            logger.debug("================ SERVEUR FILE MESSAGE =====================")
            # lit file d'attente json en bytes.
            # action suivant demande
            # send message
            try:
                msg, prioritymsg = xmppobject.mq.receive()
                logger.error("JFKJFK MSG RECU %s %s" % (msg, prioritymsg))
                decode_msg(xmppobject, msg, prioritymsg)
            except posix_ipc.BusyError:
                logger.debug("msg file empty")

    except Exception as e:
        logger.error("Plugin loadarscheck, we encountered the error %s" % str(e))
        logger.error("We obtained the backtrace %s" % traceback.format_exc())

    #['base', 'support', 'backuppc', 'glpi', 'xmppmaster', 'admin', 'dashboard', 'dyngroup', 'msc', 'pkgs', 'services', 'guacamole', 'imaging', 'pulse2']

def decode_msg(xmppobject, msg,prioritymsg):
    msg=msg.decode('utf-8')
    if prioritymsg == 9:
        # notify string
        logger.error("Notify  Priority msg :%s\nmsg :%s" % (prioritymsg, msg))
    elif prioritymsg == 4:
        # info mmc string
        logger.debug("information mmc Priority msg :%s\nmsg :%s" % (prioritymsg, msg))
        information_mmc(xmppobject, msg)
    elif prioritymsg == 5:
        # send message xmpp
        obj=json.loads(msg)
        logger.error("recv : type :%s\n%s" % (msg, prioritymsg))
        send_message_file(xmppobject, obj)


def information_mmc(xmppobject, *args, **kwargs):
    if args:
        for value in args:
            if isinsance(value, (bytes)):
                value = value.decode('utf-8')
        if args[0]:
            obj=json.loads(args[0])
            if 'action' in obj:
                if obj['action'] == "list_mmc_module":
                    xmppobject.list_mmc = obj['data']
                    logger.error("list des modules MMC sont : %s" % (xmppobject.list_mmc))

                    #xmppobject.list_mmc



def send_message_file(xmppobject, *args, **kwargs):
    if args:
        for value in args:
            if isinsance(value, (bytes)):
                value = value.decode('utf-8')
    if kwargs:
        if "to" in kwargs:
            to =  kwargs["to"]

        if "action" not in kwargs:
            return False
        else:
            action = kwargs["action"].decode('utf-8') if isinstance(kwargs["action"],bytes) else kwargs["action"]

        if "sessionid" in kwargs:
            sessionid = kwargs["sessionid"].decode('utf-8') if isinstance(kwargs["sessionid"],bytes) else kwargs["sessionid"]
        else:
            sessionid = name_random(6, "server_file")

        if "base64" in kwargs:
            if isinstance(kwargs["base64"], bool):
                Base64 = kwargs["base64"]
            elif isinstance(kwargs["base64"], int):
                if kwargs["base64"] > 0:
                    Base64  = True
                else:
                    Base64  = False
            else :
                Base64 = kwargs["base64"].decode('utf-8') if isinstance(kwargs["base64"], bytes) else kwargs["base64"]
                if kwargs["base64"].strip().lower()[0] in ["t","y","o","1"]:
                    Base64  = True
                else :
                    Base64  = False
        else:
            Base64 = False

        if "ret" in kwargs:
            if isinstance(kwargs["ret"], int):
                ret = kwargs["ret"]
            else:
                ret = int(kwargs["ret"].decode('utf-8')) if isinstance(kwargs["ret"], bytes) else int(kwargs["ret"])
        else:
            ret=0

        if "data" in kwargs:
            if isinsance(kwargs["data"], ( list, dict, tuple, float, int, datetime)):
                data = json.dumps(kwargs["data"], cls=DateTimebytesEncoderjson)
            elif isinsance(kwargs["data"], (bytes)):
               data = kwargs["data"].decode('utf-8')
            elif isinsance(kwargs["data"], (str)):
               data = kwargs["data"]
            else:
               data=""
        else:
            data=""
        msg = {
            "action": action,
            "sessionid": sessionid,
            "ret": ret,
            "base64": Base64,
            "data":data }
        msgsend=json.dumps( msg, cls=DateTimebytesEncoderjson )
    elif args:
        if len(args) == 2 :
            # arg[0] jid to
            to = arg[0]
            # arg[1] string body message or dict struct message
            if isinsance(arg[1], (dict)):
                msg = json.dumps( arg[1], cls=DateTimebytesEncoderjson )
        else:
            return False
    xmppobject.send_message(
        mto=to,
        mbody=msg,
        mtype="chat"
        )
    return True

class DateTimebytesEncoderjson(json.JSONEncoder):
    """
    Used to hanld datetime in json files.
    """
    def default(self, obj):
        if isinstance(obj, datetime):
            encoded_object = obj.isoformat()
        elif isinstance(obj, bytes):
            encoded_object = obj.decode('utf-8')
        else:
            encoded_object = json.JSONEncoder.default(self, obj)
        return encoded_object
