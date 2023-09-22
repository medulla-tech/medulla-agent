#!/usr/bin/python3
# -*- coding: utf-8; -*-
# SPDX-FileCopyrightText: 2016-2023 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-3.0-or-later

import logging

logger = logging.getLogger()

plugin = {"VERSION": "1.0", "NAME": "resultforce_setup_agent", "TYPE": "mastersub"}


def action(xmppobject, action, sessionid, data, message, ret, dataobj):
    logger.debug("________________________________________________")
    logger.debug(plugin)
    logger.debug("________________________________________________")
