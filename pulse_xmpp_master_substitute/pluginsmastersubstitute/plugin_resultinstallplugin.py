#!/usr/bin/python3
# -*- coding: utf-8; -*-
# SPDX-FileCopyrightText: 2016-2023 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-3.0-or-later

import logging

logger = logging.getLogger()
plugin = {"VERSION": "1.0", "NAME": "resultinstallplugin", "TYPE": "mastersub"}


def action(xmppobject, action, sessionid, data, message, ret, dataobj):
    logger.debug(plugin)
    try:
        logger.debug(
            "plugin resultinstallplugin from %s  ret [%s]" % (message["from"], ret)
        )
        pass
    except Exception as e:
        logger.debug("Error in plugin resultinstallplugin %s" % str(e))
        pass
