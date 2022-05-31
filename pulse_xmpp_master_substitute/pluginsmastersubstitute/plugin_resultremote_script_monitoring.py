#!/usr/bin/python
# -*- coding: utf-8; -*-
#
# (c) 2016-2022 siveo, http://www.siveo.net
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
# file : pluginsmastersubstitute/plugin_resultremote_script_monitoring.py

import sys
import json
import logging
import traceback
import zlib
import os
import base64
from datetime import date, datetime, timedelta

logger = logging.getLogger()
plugin = { "VERSION": "1.0", "NAME": "resultremote_script_monitoring", "TYPE": "substitute", }  # fmt: skip


class DateTimeEncoder(json.JSONEncoder):
    """
    Used to handle datetime in json files.
    """

    def default(self, obj):
        if isinstance(obj, datetime):
            encoded_object = obj.isoformat()
        else:
            encoded_object = json.JSONEncoder.default(self, obj)
        return encoded_object


def action(xmppobject, action, sessionid, data, message, ret, dataobj):
    logger.debug("#################################################")
    logger.debug("call plugin %s from %s" % (plugin, message["from"]))
    logger.debug("#################################################")
    logger.debug("data plugin %s" % (json.dumps(data, indent=4)))
    result_script = zlib.decompress(base64.b64decode(data["result_script"]))

    if "file_result" in data and data["file_result"]:
        logger.debug("result_script in file %s" % (data["file_result"]))
        with open(data["file_result"], "ab") as out:
            out.write(
                "\n-------- result remote script %s --------\n"
                "out script : %s \n"
                % (datetime.now().strftime("%a_%d%b%Y_%Hh%M"), result_script)
            )
    else:
        logger.debug("result_script %s" % result_script)
