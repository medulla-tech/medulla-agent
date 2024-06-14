# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2020-2023 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-3.0-or-later

import logging
import json
from lib import utils
import traceback
import getpass
from lib.utils import set_logging_level
import sys
import asyncio

if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
# without this iqsendpulse can't work.

logger = logging.getLogger()
plugin = {"VERSION": "1.11", "NAME": "updateuseraccount", "TYPE": "machine"}  # fmt: skip
JIDARSNAME = 'rspulse@pulse/mainrelay'


def installkey_ars_ssh_key(xmppobject, sessionid, to):
    """
    Envoie une requete pour installer une cle SSH des ars via un message XMPP.

    Args:
        xmppobject: Un objet XMPP connecte qui sera utilise pour envoyer le message.
            Cet objet doit deja etre connecte et authentifie avec le serveur XMPP.
        sessionid (str): L'ID de session unique pour la transaction en cours.
            Utilise pour identifier de maniere unique cette requete dans le cadre d'une session.
        to (str): L'adresse JID du destinataire du message XMPP.
            Le message sera envoye a cette adresse.
    Raises:
        ValueError: Si l'objet xmppobject n'est pas connecte.
        Exception: Si l'envoi du message echoue pour une raison quelconque.

    """
    installkey = {
        "action": "installkey",
        "data": {"jidAM": xmppobject.boundjid.bare},
        "sessionid": sessionid,
        "ret": 0,
        "base64": False,
    }
    xmppobject.send_message(
        mto=to,
        mbody=json.dumps(installkey),
        mtype="chat",
    )


@set_logging_level
def action(xmppobject, action, sessionid, data, message, dataerreur):
    """
    Effectue des actions pour creer le profil utilisateur de l'agent Medulla
    et installer les cles SSH des ARS le concernant.

    Cette fonction verifie d'abord que le compte utilisateur et le profil existent.
    Ensuite, elle appelle le plugin install_key sur les ars.
    Ce plugin gere aussi les profils.
    il install les key necessaires depuis le serveur relais et installe
    les cles SSH des ARS associees.

    Args:
        xmppobject: Un objet XMPP connecte qui sera utilise pour envoyer des messages.
            Cet objet doit deja etre connecte et authentifie avec le serveur XMPP.
        action (str): Le nom de l'action a executer.
        sessionid (str): L'ID de session unique pour la transaction en cours.
            Utilise pour identifier de maniere unique cette requete dans le cadre d'une session.
        data (dict): Les donnees associees a l'action.
        message (dict): Le message XMPP recu qui a declenche cette action.
        dataerreur (dict): Les donnees d'erreur associees a l'action, si disponible.
    Raises:
        Exception: Si une erreur se produit lors de la verification des comptes utilisateurs,
                   de l'obtention des cles, ou de l'installation des cles SSH.
    """
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
        jidarsmain = JIDARSNAME
        installkey_ars_ssh_key(xmppobject, sessionid, jidars)
        if jidars != jidarsmain:
            installkey_ars_ssh_key(xmppobject, sessionid, jidarsmain)
    except Exception:
        logger.error("\n%s" % (traceback.format_exc()))
