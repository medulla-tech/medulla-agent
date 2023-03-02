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
import traceback

logger = logging.getLogger()

plugin = {"VERSION": "1.7", "NAME": "updateuseraccount", "TYPE": "machine"}


def get_ars_key(xmppobject, remotejidars, timeout=15):
    try:
        iqresult = xmppobject.iqsendpulse(remotejidars,
                                          {"action": "information",
                                           "data": {"listinformation": ["get_ars_key_id_rsa",
                                                                        "keypub"],
                                                    "param": {}
                                                    }
                                           },
                                          timeout)
        res = json.loads(iqresult)
        return res
    except KeyError:
        logger.error("Error getting relayserver pubkey and reversessh idrsa via iq from %s" % remotejidars)
        return None

def action(xmppobject, action, sessionid, data, message, dataerreur):
    logger.debug("###################################################")
    logger.debug("call %s from %s" % (plugin, message['from']))
    logger.debug("###################################################")
    msg = []
    try:
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
        jidarsmain = 'rspulse@pulse/mainrelay'
        res = get_ars_key(xmppobject, jidars)
        if res is None: return
        try:
            result = res['result']['informationresult']
        except KeyError :
            logger.error("IQ Error: Please verify that the ARS %s is online." % jidars)
            logger.error("IQ Error: Please verify that the ARS Jid is correct in the ejabberd connected_users command")

            logger.error("The Key of the ARS %s is not installed on the machine %s" % (jidars, xmppobject.boundjid.bare))
            return

        relayserver_pubkey = result['keypub']
        relayserver_reversessh_idrsa = result['get_ars_key_id_rsa']
        logger.debug("The public Key of the relayserver is %s" % relayserver_pubkey)
        logger.debug("The idrsa key of the reversessh use on relayserver is %s" % relayserver_reversessh_idrsa)

        if jidarsmain == jidars:
            mainserver_pubkey = relayserver_pubkey
        else:
            #ars on recherche key pub ars principal
            res = get_ars_key(xmppobject, jidarsmain)
            if res is None: return
            try:
                result = res['result']['informationresult']
            except KeyError :
                logger.error("IQ Error: Please verify that the ARS %s is online." % jidars)
                logger.error("IQ Error: Please verify that the ARS Jid is correct in the ejabberd connected_users command")
            
                logger.error("The Key of the ARS %s is not installed on the machine %s" % (jidars, xmppobject.boundjid.bare))
                return

            mainserver_pubkey = result['keypub']
            logger.debug("The public Key of the relayserver is %s" % relayserver_pubkey)
            # Add the keys to pulseuser account
            result, msglog = utils.create_idrsa_on_client(username, relayserver_reversessh_idrsa)

        if result is False:
            logger.error(msglog)
        msg.append(msglog)
        result, msglog = utils.add_key_to_authorizedkeys_on_client(username, relayserver_pubkey)
        if result is False:
            logger.error(msglog)
        msg.append(msglog)
        result, msglog = utils.add_key_to_authorizedkeys_on_client(username, mainserver_pubkey)
        if result is False:
            logger.error(msglog)
        msg.append(msglog)

        # Write message to logger
        for line in msg:
            logger.debug(line)
    except Exception:
        logger.error("\n%s" % (traceback.format_exc()))
