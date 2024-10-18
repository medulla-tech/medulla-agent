#!/usr/bin/env python
# -*- coding: utf-8; -*-
# SPDX-FileCopyrightText: 2016-2023 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-3.0-or-later

import base64
import json
import os
import lib.utils
import pprint
import logging
from lib.plugins.pkgs import PkgsDatabase

logger = logging.getLogger()

plugin = {"VERSION": "1.1", "NAME": "notifysyncthing", "TYPE": "substitute"}  # fmt: skip


def action(objectxmpp, action, sessionid, data, msg, res, dataerreur):
    logger.debug("=====================================================")
    logger.debug(plugin)
    logger.debug("=====================================================")
    print(json.dumps(data, indent=4))
    if "suppdir" in data or "adddir" in data:
        logger.debug(
            "removing package %s %s %s"
            % (data["packageid"], "create", str(msg["from"]))
        )
        PkgsDatabase().pkgs_unregister_synchro_package(
            data["packageid"], None, str(msg["from"])
        )
    elif "notifydir" in data:
        logger.debug(
            "removing package %s %s %s" % (data["packageid"], "chang", str(msg["from"]))
        )
        PkgsDatabase().pkgs_unregister_synchro_package(
            data["packageid"], "chang", str(msg["from"])
        )
    else:
        logger.error(
            f"No matching conditions for package {data['packageid']} from {msg['from']}"
        )
        logger.error(f"The Json file is \n {json.dumps(data, indent=4)}")
