#!/usr/bin/python3
# -*- coding: utf-8; -*-
# SPDX-FileCopyrightText: 2016-2023 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-3.0-or-later

import logging

logger =  logging.getLogger()

plugin = {"VERSION": "1.0", "NAME": "resultdisable_rescue", "TYPE": "mastersub"}


def action(xmppobject, action, sessionid, data, message, ret, dataobj):
    logger.debug(plugin)
    try:
        logger.debug("Disabling rescue agent on %s" % message["from"])
        pass
    except Exception as e:
        logger.error("Error in plugin disable rescue%s" % str(e))
        pass
