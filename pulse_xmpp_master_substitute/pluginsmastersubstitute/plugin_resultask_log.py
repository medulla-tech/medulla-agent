# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2016-2024 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-3.0-or-later


import datetime
import time
import json
import traceback
import sys
import logging
import os
import re
import types



plugin = {"VERSION": "1.5", "NAME": "resultask_log", "TYPE": "substitute"}  # fmt: skip
PREFIX_COMMAND = "commandkiosk"


def action(xmppobject, action, sessionid, data, message, ret, dataobj):
    logger.debug("#################################################")
    logger.debug(plugin)
    logger.debug(json.dumps(data, indent=4))
    logger.debug("#################################################")

