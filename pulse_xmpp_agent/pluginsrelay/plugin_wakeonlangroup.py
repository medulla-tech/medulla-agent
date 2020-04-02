# -*- coding: utf-8 -*-
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

# file: pulse_xmpp_agent/pluginsmachine/plugin_wakeonlangroup.py

from  lib.utils import pluginprocess
from wakeonlan import wol
import json
import logging
import traceback

logger = logging.getLogger()

plugin={"VERSION": "1.0", "NAME" :"wakeonlangroup","TYPE":"relayserver"}

def action( objectxmpp, action, sessionid, data, message, dataerreur):
    logger.debug("###################################################")
    logger.debug("call %s from %s"%(plugin, message['from']))
    logger.debug("###################################################")
    if hasattr(objectxmpp.config, 'wol_port'):
        wol_port = int(objectxmpp.config.wol_port)
    else:
        wol_port = 9
    try:
        wol.send_magic_packet(*data['macaddress'], port=wol_port)
    except:
        logger.error("\n%s"%(traceback.format_exc()))
