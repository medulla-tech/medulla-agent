#!/usr/bin/python3
# -*- coding: utf-8; -*-
# SPDX-FileCopyrightText: 2016-2023 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-3.0-or-later

import logging

plugin = {"VERSION": "1.1", "NAME": "resultwakeonlan", "TYPE": "substitute"}  # fmt: skip


def action(xmppobject, action, sessionid, data, message, ret, dataobj):
    logging.getLogger().debug(plugin)
    try:
        logging.getLogger().debug("%s", data)
        pass
    except Exception as e:
        logging.getLogger().error("Error in plugin %s : %s" % (action, str(e)))
        pass
