# -*- coding: utf-8 -*-
<<<<<<< HEAD
#
# (c) 2016 siveo, http://www.siveo.net
#
# This file is part of Pulse 2, http://www.siveo.net
#
# Pulse 2 is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# Pulse 2 is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Pulse 2; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
# MA 02110-1301, USA.
# file : pulse_xmpp_agent/pluginsmachine/plugin_pong.py
=======
# SPDX-FileCopyrightText: 2022-2023 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-2.0-or-later
>>>>>>> integration

import logging
import json

plugin = {"VERSION": "1.1", "NAME": "ping",  "TYPE": "all"}

logger = logging.getLogger()

def action( objectxmpp, action, sessionid, data, message, dataerreur):
    logging.getLogger().debug("###################################################")
    logging.getLogger().debug("call %s from %s session id %s" % (plugin, message['from'], sessionid))
    logging.getLogger().debug("###################################################")
    datasend = {  "action" : "pong",
                    "data" : { "agenttype" : objectxmpp.config.agenttype },
                    'sessionid': sessionid,
                    'ret': 0,
                    'base64': False
        }
    objectxmpp.send_message(mto=message['from'],
                                    mbody=json.dumps(datasend, indent=4),
                                    mtype='chat')
