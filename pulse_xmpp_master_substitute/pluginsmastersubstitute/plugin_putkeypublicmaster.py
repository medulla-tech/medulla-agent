# -*- coding: utf-8 -*-
#
# (c) 2016 siveo, http://www.siveo.net
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
# file  pulse_xmpp_master_substitute/pluginsmastersubstitute/plugin_start.py
# recuper les key de master.
# this plugin calling from starting function agent

import json
import os
import logging
from lib.utils import getRandomName


logger = logging.getLogger()

DEBUGPULSEPLUGIN = 25

plugin = {"VERSION": "1.0", "NAME": "start", "TYPE": "substitute"}


def action(objectxmpp, action, sessionid, data, msg, dataerreur):
    logger.debug("=====================================================")
    logger.debug("call %s from %s" % (plugin, msg["from"]))
    logger.debug("=====================================================")
    Setdirectorytempinfo()  # create directory pour install key public master.
    # in starting agent ask public key of master.
    ask_key_master_public(objectxmpp)


def ask_key_master_public(self, objectxmpp):
    """
    ask public key on master
    """
    datasend = {
        "action": "ask_key_public_master",
        "data": {},
        "ret": 0,
        "sessionid": getRandomName(5, "ask_key_public_master"),
    }
    self.send_message(mto=self.agentmaster, mbody=json.dumps(datasend), mtype="chat")


def Setdirectorytempinfo():
    """
    create directory
    """
    dirtempinfo = os.path.join(
        os.path.dirname(os.path.realpath(__file__)), "..", "INFOSTMP"
    )
    if not os.path.exists(dirtempinfo):
        os.makedirs(dirtempinfo, mode=0o700)
    return dirtempinfo
