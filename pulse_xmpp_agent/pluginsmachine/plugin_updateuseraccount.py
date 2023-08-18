# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2020-2023 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-3.0-or-later

import logging
import json
from lib import utils
import traceback

logger = logging.getLogger()
plugin = {"VERSION": "1.7", "NAME": "updateuseraccount", "TYPE": "machine"}  # fmt: skip


def get_ars_key(xmppobject, remotejidars, timeout=15):
    try:
        iqresult = xmppobject.iqsendpulse(
            remotejidars,
            {
                "action": "information",
                "data": {
                    "listinformation": ["get_ars_key_id_rsa", "keypub"],
                    "param": {},
                },
            },
            timeout,
        )
        if isinstance(iqresult, str):
            res = json.loads(iqresult.encode("utf-8"))
        elif isinstance(iqresult, dict):
            return iqresult
        res = json.loads(iqresult)
        return res
    except KeyError:
        logger.error(
            "Error getting relayserver pubkey and reversessh idrsa via iq from %s"
            % remotejidars
        )
        return None


def action(xmppobject, action, sessionid, data, message, dataerreur):
    logger.debug("###################################################")
    logger.debug("call %s from %s" % (plugin, message["from"]))
    logger.debug("###################################################")
    msg = []
    try:
        # Make sure user account and profile exists
        username = "pulseuser"
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
        jidarsmain = "rspulse@pulse/mainrelay"
        res = get_ars_key(xmppobject, jidars)
        if res is None:
            return
        try:
            result = res["result"]["informationresult"]
        except KeyError:
            logger.error("IQ Error: Please verify that the ARS %s is online." % jidars)
            logger.error(
                "IQ Error: Please verify that the ARS Jid is correct in the ejabberd connected_users command"
            )

            logger.error(
                "The Key of the ARS %s is not installed on the machine %s"
                % (jidars, xmppobject.boundjid.bare)
            )
            return

        relayserver_pubkey = result["keypub"]
        relayserver_reversessh_idrsa = result["get_ars_key_id_rsa"]
        logger.debug("The public Key of the relayserver is %s" % relayserver_pubkey)
        logger.debug(
            "The idrsa key of the reversessh use on relayserver is %s"
            % relayserver_reversessh_idrsa
        )

        if jidarsmain == jidars:
            mainserver_pubkey = relayserver_pubkey
        else:
            # ars on recherche key pub ars principal
            res = get_ars_key(xmppobject, jidarsmain)
            if res is None:
                return
            try:
                result = res["result"]["informationresult"]
            except KeyError:
                logger.error(
                    "IQ Error: Please verify that the ARS %s is online." % jidars
                )
                logger.error(
                    "IQ Error: Please verify that the ARS Jid is correct in the ejabberd connected_users command"
                )

                logger.error(
                    "The Key of the ARS %s is not installed on the machine %s"
                    % (jidars, xmppobject.boundjid.bare)
                )
                return

            mainserver_pubkey = result["keypub"]
            logger.debug("The public Key of the relayserver is %s" % relayserver_pubkey)
            # Add the keys to pulseuser account
            result, msglog = utils.create_idrsa_on_client(
                username, relayserver_reversessh_idrsa
            )

        if result is False:
            logger.error(msglog)
        msg.append(msglog)
        result, msglog = utils.add_key_to_authorizedkeys_on_client(
            username, relayserver_pubkey
        )
        if result is False:
            logger.error(msglog)
        msg.append(msglog)
        result, msglog = utils.add_key_to_authorizedkeys_on_client(
            username, mainserver_pubkey
        )
        if result is False:
            logger.error(msglog)
        msg.append(msglog)

        # Write message to logger
        for line in msg:
            logger.debug(line)
    except Exception:
        logger.error("\n%s" % (traceback.format_exc()))
