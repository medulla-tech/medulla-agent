# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2016-2023 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-2.0-or-later

import sys
import os
from distutils.version import StrictVersion
import logging
import shutil
from lib import utils
import hashlib

logger = logging.getLogger()

plugin = {"VERSION": "1.1", "NAME": "updatedoublerun", "TYPE": "machine"}


def action(xmppobject, action, sessionid, data, message, dataerreur):
    logger.debug("###################################################")
    logger.debug("call %s from %s" % (plugin, message['from']))
    logger.debug("###################################################")

    try:
        print("No plugin Doublerun")
    except Exception:
        pass
