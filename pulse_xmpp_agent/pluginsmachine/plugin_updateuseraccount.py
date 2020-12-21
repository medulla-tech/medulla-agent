# -*- coding: utf-8 -*-
#
# (c) 2020 siveo, http://www.siveo.net
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

import logging
import json
from lib import utils
from sleekxmpp.exceptions import IqError

logger = logging.getLogger()

plugin = {"VERSION": "1.5", "NAME": "updateuseraccount", "TYPE": "machine"}


def action(xmppobject, action, sessionid, data, message, dataerreur):
    logger.debug("###################################################")
    logger.debug("call %s from %s" % (plugin, message['from']))
    logger.debug("###################################################")
    msg = []

    # Make sure user account and profile exists
    username = 'pulseuser'
    result, msglog = utils.pulseuser_useraccount_mustexist(username)
    if result is False:
        logger.error(msglog)
    msg.append(msglog)
    result, msglog = utils.pulseuser_profile_mustexist(username)
    if result is False:
        logger.error(msglog)
    msg.append(msglog)

    # Get necessary keys from relay server
    jidars = xmppobject.config.agentcommand
    timeout = 15
    try:
        iqresult = xmppobject.iqsendpulse(jidars,
                                          {"action": "information",
                                           "data": {"listinformation": ["get_ars_key_id_rsa",
                                                                        "keypub"],
                                                    "param": {}
                                                    }
                                           },
                                          timeout)
        res = json.loads(iqresult)
        result = res['result']['informationresult']
        relayserver_pubkey = result['keypub']
        relayserver_reversessh_idrsa = result['get_ars_key_id_rsa']
        logger.debug("relayserver_pubkey: %s" % relayserver_pubkey)
        logger.debug("relayserver_reversessh_idrsa: %s" % relayserver_reversessh_idrsa)
    except KeyError:
        logger.error("Error getting relayserver pubkey and reversessh idrsa via iq from %s" % jidars)
        return

    # Add the keys to pulseuser account
    result, msglog = utils.create_idrsa_on_client(username, relayserver_reversessh_idrsa)
    if result is False:
        logger.error(msglog)
    msg.append(msglog)
    result, msglog = utils.add_key_to_authorizedkeys_on_client(username, relayserver_pubkey)
    if result is False:
        logger.error(msglog)
    msg.append(msglog)

    # Write message to logger
    for line in msg:
        logger.debug(line)
