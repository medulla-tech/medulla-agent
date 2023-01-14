#!/usr/bin/env python
# -*- coding: utf-8; -*-
#
# (c) 2016-2023 siveo, http://www.siveo.net
#
# This file is part of medulla, http://www.siveo.net
#
# medulla is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# medulla is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with medulla; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
# MA 02110-1301, USA.
#
# file /pluginsmastersubstitute/plugin_notifysyncthing.py

import base64
import json
import os
import lib.utils
import pprint
import logging
from lib.plugins.pkgs import PkgsDatabase

logger = logging.getLogger()

plugin = { "VERSION" : "1.0", "NAME" : "notifysyncthing", "TYPE" : "substitute" }

def action( objectxmpp, action, sessionid, data, msg, dataerreur):
    logger.debug("=====================================================")
    logger.debug(plugin)
    logger.debug("=====================================================")
    print json.dumps(data, indent = 4)
    if 'suppdir' in data or 'adddir' in data:
        logger.debug("removing package %s %s %s"%( data['packageid'], 'create', str(msg['from'])))
        PkgsDatabase().pkgs_unregister_synchro_package( data['packageid'],
                                                      None,
                                                      str(msg['from']))
    elif 'MotifyFile' in data:
        logger.debug("removing package %s %s %s"%( data['packageid'], 'chang', str(msg['from'])))
        PkgsDatabase().pkgs_unregister_synchro_package( data['packageid'],
                                                      'chang',
                                                      str(msg['from']))

