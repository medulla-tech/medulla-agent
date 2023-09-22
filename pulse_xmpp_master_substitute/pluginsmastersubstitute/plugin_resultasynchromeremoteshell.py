#!/usr/bin/python3
# -*- coding: utf-8; -*-
# SPDX-FileCopyrightText: 2016-2023 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-3.0-or-later

import logging
import traceback
import sys
import os
import json
from lib.utils import file_put_content

logger = logging.getLogger()

plugin = {"VERSION": "1.0", "NAME": "resultasynchromeremoteshell", "TYPE": "mastersub"}


def action(xmppobject, action, sessionid, data, message, ret, dataobj):
    logger.debug("=====================================================")
    logger.debug(plugin)
    logger.debug("=====================================================")
    try:
        pathresult = os.path.join("/", "tmp", sessionid)
        print(pathresult)
        file_put_content(pathresult, json.dumps(data, indent=4), mode="w")
        print(json.dumps(data, indent=4))
    except Exception as e:
        logger.error("Error loading plugin: %s" % str(e))
        traceback.print_exc(file=sys.stdout)
        pass
