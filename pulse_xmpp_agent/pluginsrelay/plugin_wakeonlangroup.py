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

from wakeonlan import wol
import logging
import traceback
from netifaces import interfaces, ifaddresses, AF_INET

logger = logging.getLogger()

plugin={"VERSION": "2.2", "NAME" :"wakeonlangroup","TYPE":"relayserver"}

def action( objectxmpp, action, sessionid, data, message, dataerreur):
    logger.debug("###################################################")
    logger.debug("call %s from %s"%(plugin, message['from']))
    logger.debug("###################################################")
    compteurcallplugin = getattr(objectxmpp, "num_call%s"%action)
    logger.debug("compteurcallplugin = %s" % compteurcallplugin )
    if compteurcallplugin == 0:
        objectxmpp.brodcastwol=[]
        if hasattr(objectxmpp.config, 'wol_port'):
            wol_port = int(objectxmpp.config.wol_port)
        else:   
            wol_port = 9
        for ifaceName in interfaces():
            addrs = ifaddresses(ifaceName)
            k=addrs[AF_INET]
            for t in k:
                if 'broadcast' not in t:
                    break
                if 'netmask' not in t:
                    break
                if 'addr' not in t:
                    break
                objectxmpp.brodcastwol.append(t['broadcast'])
                logger.debug("objectxmpp %s "%objectxmpp.brodcastwol)
    try:
        dellist=[]
        for z in objectxmpp.brodcastwol:
            try:
                wol.send_magic_packet(*data['macaddress'],
                                        ip_address=z,
                                        port=wol_port)
            except Exception as e:
                if "Connection refused" in str(e):
                    logger.debug('WOL impossible on broadcast %s' % z)
                    dellist.append(z)
        for t in dellist:
            objectxmpp.brodcastwol.remove(t)
    except:
        logger.error("\n%s"%(traceback.format_exc()))
