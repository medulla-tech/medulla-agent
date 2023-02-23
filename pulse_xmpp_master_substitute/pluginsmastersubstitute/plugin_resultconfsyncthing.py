#!/usr/bin/env python
# -*- coding: utf-8; -*-
# SPDX-FileCopyrightText: 2016-2023 Siveo <support@siveo.net> 
# SPDX-License-Identifier: GPL-2.0-or-later 

import logging
import traceback

logger = logging.getLogger()

plugin = {"VERSION": "1.1", "NAME": "resultconfsyncthing", "TYPE": "substitute"}

def action(xmppobject, action, sessionid, data, msg, ret, dataobj):
    logger.debug("=====================================================")
    logger.debug("call from %s %s"%(str(msg['from']), plugin))
    logger.debug("=====================================================")
    try:
        if 'syncthingconf' in data:
            logger.info("configuration Syncthing from %s: %s"%(str(msg['from']),
                                                               data['syncthingconf']))
        elif 'errorsyncthingconf'  in data:
            logger.error("Remote Error on syncthing agent (setup) %s"%str(msg['from'].resource) )
            logger.error(data['errorsyncthingconf'])
    except Exception as e:
        print traceback.format_exc()
        pass
