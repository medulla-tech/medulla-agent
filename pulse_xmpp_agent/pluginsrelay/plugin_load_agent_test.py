# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2016-2023 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-3.0-or-later

# file : /pluginsmastersubstitute/plugin_assessor_agent.py

import base64
import json
import os
import logging
import time
from lib.utils import ipfromdns, AESCipher, subnetnetwork, call_plugin
from lib.localisation import Point
from lib.plugins.xmpp import XmppMasterDatabase
from lib.manageADorganization import manage_fqdn_window_activedirectory

from random import randint
import operator
import traceback
import configparser
import netaddr
from math import cos, sin, atan2, sqrt

try:
    from lib.stat import statcallplugin

    statfuncton = True
except BaseException:
    statfuncton = False

logger = logging.getLogger()
DEBUGPULSEPLUGIN = 25
plugin = { "VERSION": "1.2", "NAME": "assessor_agent", "TYPE": "substitute", "FEATURE": "assessor", }  # fmt: skip


params = {"duration": 300}
# The parameter named duration is the time after which a configuration request is considered as expired.
# The connection agent re-sends a configuration request after 300 seconds, thus making the previous one
# obsolete as it will not be processed


def action(objectxmpp, action, sessionid, data, msg, ret, dataobj):
    logger.debug("=====================================================")
    logger.debug("call %s from %s" % (plugin, msg["from"]))
    logger.debug("=====================================================")
    msgq = {"to": str(msg["to"]), "from": str(msg["from"])}
