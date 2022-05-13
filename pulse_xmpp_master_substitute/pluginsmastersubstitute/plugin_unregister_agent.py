#!/usr/bin/env python
# -*- coding: utf-8; -*-
#
# (c) 2016-2017 siveo, http://www.siveo.net
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
#

import logging
import traceback
import json

from lib.plugins.xmpp import XmppMasterDatabase

logger = logging.getLogger()


plugin = {"VERSION": "1.0", "NAME": "unregister_agent", "TYPE" : "substitute", "FEATURE": "subscribe"}


"""
This plugin is called by the client When the machine agent detect a change of domain in his JID.

When a client connects to a new ARS, this has for consequence a change of ejabberd domain/server.
The old ejabberd account needs to be removed from the roster.
"""

def action(xmppobject, action, sessionid, data, msg, ret, dataobj):
    logger.debug("-----------------------------------------------------------------------------------------")
    logger.debug(plugin)
    logger.debug("-----------------------------------------------------------------------------------------")

    if "user" in data and "domain" in data and "resource" in data and \
        data['user'].strip() != "" and  data['domain'].strip() != "" and  data['resource'].strip() != "":
        try:
            relayserver = XmppMasterDatabase().getRelayServerfromjiddomain(data['domain'])
            msg = {"action": "unregister_agent",
                   "sessionid": sessionid,
                   "data": data,
                   "base64": False,
                   "ret": 0
                  }
            if relayserver:
                xmppobject.send_message(mto=relayserver['jid'],
                                        mbody=json.dumps(msg),
                                        mtype='chat')
            else:
                logger.error("No relay server found for the domain: %s" % data['domain'])

        except Exception, e:
            logger.error("An error occured when trying to unregister old JID. We got the error: %s" % str(e))
            logger.error("We hit the backtrace: \n%s" % traceback.format_exc())
    else:
        logger.error("The JID is incorrect")
