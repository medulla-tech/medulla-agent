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
plugin = {"VERSION": "1.9", "NAME": "updateuseraccount", "TYPE": "machine"}  # fmt: skip
USERNAME = "pulseuser" # le profil du compte agent medulla
JIDARSNAME = "rspulse@pulse/mainrelay" #jid relay server principal

def installkey_ars_ssh_key(xmppobject, sessionid, to):
    """
    Envoie une requête pour installer une clé SSH des ars via un message XMPP.

    Args:
        xmppobject: Un objet XMPP connecté qui sera utilisé pour envoyer le message.
            Cet objet doit déjà être connecté et authentifié avec le serveur XMPP.
        sessionid (str): L'ID de session unique pour la transaction en cours.
            Utilisé pour identifier de manière unique cette requête dans le cadre d'une session.
        to (str): L'adresse JID du destinataire du message XMPP.
            Le message sera envoyé à cette adresse.
    Raises:
        ValueError: Si l'objet xmppobject n'est pas connecté.
        Exception: Si l'envoi du message échoue pour une raison quelconque.

    """
    installkey= { "action": "installkey",
                  "data": {"jidAM" : xmppobject.boundjid.bare},
                  "sessionid": sessionid,
                  "ret": 0,
                  "base64": False,
                }
    xmppobject.send_message( mto=to,
                             mbody=json.dumps(installkey),
                             mtype="chat",)


@set_logging_level
def action(xmppobject, action, sessionid, data, message, dataerreur):
    """
    Effectue des actions pour créer le profil utilisateur de l'agent Medulla
    et installer les clés SSH des ARS le concernant.

    Cette fonction vérifie d'abord que le compte utilisateur et le profil existent.
    Ensuite, elle appelle le plugin install_key sur les ars.
    Ce plugin gere aussi les profils.
    il install les key nécessaires depuis le serveur relais et installe
    les clés SSH des ARS associées.

    Args:
        xmppobject: Un objet XMPP connecté qui sera utilisé pour envoyer des messages.
            Cet objet doit déjà être connecté et authentifié avec le serveur XMPP.
        action (str): Le nom de l'action à exécuter.
        sessionid (str): L'ID de session unique pour la transaction en cours.
            Utilisé pour identifier de manière unique cette requête dans le cadre d'une session.
        data (dict): Les données associées à l'action.
        message (dict): Le message XMPP reçu qui a déclenché cette action.
        dataerreur (dict): Les données d'erreur associées à l'action, si disponible.
    Raises:
        Exception: Si une erreur se produit lors de la vérification des comptes utilisateurs,
                   de l'obtention des clés, ou de l'installation des clés SSH.
    """
    logger.debug("###################################################")
    logger.debug("call %s from %s" % (plugin, message["from"]))
    logger.debug("###################################################")
    try:
        # Make sure user account and profile exists
        username = USERNAME
        result, msglog = utils.pulseuser_useraccount_mustexist(username)
        if result is False:
            logger.error(msglog)
        result, msglog = utils.pulseuser_profile_mustexist(username)
        if result is False:
            logger.error(msglog)
        # Get necessary keys from relay server
        jidars = xmppobject.config.agentcommand
        jidarsmain = JIDARSNAME
        res = get_ars_key(xmppobject, jidars)
        installkey_ars_ssh_key(xmppobject, sessionid, jidars)
        if jidars != jidarsmain:
            installkey_ars_ssh_key(xmppobject, sessionid, jidarsmain)
    except Exception:
        logger.error("\n%s" % (traceback.format_exc()))

