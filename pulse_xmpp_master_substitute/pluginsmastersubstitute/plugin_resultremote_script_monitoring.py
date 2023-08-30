#!/usr/bin/python
# -*- coding: utf-8; -*-
# SPDX-FileCopyrightText: 2016-2023 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-3.0-or-later

import json
import logging
import zlib
import base64
from datetime import datetime

logger = logging.getLogger()
plugin = {"VERSION": "1.0", "NAME": "resultremote_script_monitoring", "TYPE": "substitute"}  # fmt: skip


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
