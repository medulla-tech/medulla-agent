#!/usr/bin/env python
# -*- coding: utf-8; -*-
# SPDX-FileCopyrightText: 2016-2023 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-2.0-or-later

import base64
import json
import os
import lib.utils
import pprint
import logging
from lib.plugins.pkgs import PkgsDatabase

logger = logging.getLogger()

plugin = {"VERSION": "1.0", "NAME": "notifysyncthing", "TYPE": "substitute"}


def action(objectxmpp, action, sessionid, data, msg, dataerreur):
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
    elif "MotifyFile" in data:
        logger.debug(
            "removing package %s %s %s" % (data["packageid"], "chang", str(msg["from"]))
        )
        PkgsDatabase().pkgs_unregister_synchro_package(
            data["packageid"], "chang", str(msg["from"])
        )
