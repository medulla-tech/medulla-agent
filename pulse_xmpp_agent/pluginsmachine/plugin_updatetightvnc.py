# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2020-2023 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-2.0-or-later

import sys
from lib import utils
from distutils.version import StrictVersion
import pycurl
import logging
import platform
import tempfile
import os

TIGHTVNC = '2.8.81'

logger = logging.getLogger()

plugin = {"VERSION": "1.2", "NAME": "updatetightvnc", "TYPE": "machine"}


def action(xmppobject, action, sessionid, data, message, dataerreur):
    logger.debug("###################################################")
    logger.debug("call %s from %s" % (plugin, message['from']))
    logger.debug("###################################################")
    try:
        print("No Plugin TightVNC")
    except Exception:
        pass
