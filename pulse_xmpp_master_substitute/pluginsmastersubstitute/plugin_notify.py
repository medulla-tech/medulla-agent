# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2016-2023 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-3.0-or-later

import json
import logging

logger = logging.getLogger()

plugin = {"VERSION": "1.0", "NAME": "notify", "TYPE": "mastersub"}


def action(xmppobject, action, sessionid, data, message, ret, dataobj):
    logger.debug("#################################################")
    logger.debug(json.dumps(data, indent=4))
    logger.debug("#################################################")

    if "msg" in data:
        if "type" in data and data["type"] == "error":
            logger.error("%s" % data["msg"])
