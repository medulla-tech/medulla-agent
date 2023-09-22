#!/usr/bin/python3
# -*- coding: utf-8; -*-
# SPDX-FileCopyrightText: 2016-2023 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-3.0-or-later

import logging

logger = logging.getLogger()

plugin = {"VERSION": "1.1", "NAME": "resultenddeploy", "TYPE": "substitute"}  # fmt: skip


def action(xmppobject, action, sessionid, data, message, ret, dataobj):
    logger.debug(plugin)
    pass
