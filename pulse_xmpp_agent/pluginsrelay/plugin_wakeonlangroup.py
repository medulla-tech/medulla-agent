# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2016-2023 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-2.0-or-later


from wakeonlan import wol
import logging
import traceback

logger = logging.getLogger()

plugin={"VERSION": "2.0", "NAME" :"wakeonlangroup","TYPE":"relayserver"}

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
