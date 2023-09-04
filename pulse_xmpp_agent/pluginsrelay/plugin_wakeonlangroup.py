# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2016-2023 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-3.0-or-later

# file: pulse_xmpp_agent/pluginsrelay/plugin_wakeonlangroup.py

import wakeonlan3 as wol
import logging
import traceback
from netifaces import interfaces, ifaddresses, AF_INET

logger = logging.getLogger()
plugin = {"VERSION": "2.3", "NAME": "wakeonlangroup", "TYPE": "relayserver"}  # fmt: skip


def action(objectxmpp, action, sessionid, data, message, dataerreur):
    logger.debug("###################################################")
    logger.debug("call %s from %s" % (plugin, message["from"]))
    logger.debug("###################################################")
    compteurcallplugin = getattr(objectxmpp, "num_call%s" % action)
    logger.debug("compteurcallplugin = %s" % compteurcallplugin)
    if compteurcallplugin == 0:
        objectxmpp.brodcastwol = []
        if hasattr(objectxmpp.config, "wol_port"):
            wol_port = int(objectxmpp.config.wol_port)
        else:
            wol_port = 9
        for ifaceName in interfaces():
            addrs = ifaddresses(ifaceName)
            k = addrs[AF_INET]
            for t in k:
                if "broadcast" not in t:
                    break
                if "netmask" not in t:
                    break
                if "addr" not in t:
                    break
                objectxmpp.brodcastwol.append(t["broadcast"])
                logger.debug("objectxmpp %s " % objectxmpp.brodcastwol)
    try:
        dellist = []
        for z in objectxmpp.brodcastwol:
            try:
                wol.send_magic_packet(*data["macaddress"], ip_address=z, port=wol_port)
            except Exception as e:
                if "Connection refused" in str(e):
                    logger.debug("WOL impossible on broadcast %s" % z)
                    dellist.append(z)
        for t in dellist:
            objectxmpp.brodcastwol.remove(t)
    except:
        logger.error("\n%s" % (traceback.format_exc()))
