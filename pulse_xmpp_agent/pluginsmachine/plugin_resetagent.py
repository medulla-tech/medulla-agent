# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2016-2023 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-3.0-or-later

"""
plugin_resetagent - Reinitialisation forcee de la base agent.

Recu depuis le master substitut, ce plugin declenche une reinstallation
complete et inconditionnelle de tous les fichiers de base de l'agent :
  1. Supprime img_agent pour forcer un retelecharger integral.
  2. Supprime BOOL_DISABLE_IMG pour debloquer la mise a jour si present.
  3. Envoie une demande de descripteur frais au master substitut.
     Le mecanisme updateagent standard prend le relais : tous les fichiers
     sont considers manquants et retransferes sans verification d'empreinte.
  4. Une fois img_agent complet, reinstall_agent() repart et l'agent
     redemarrer avec sa base propre.

Le plugin ne touche pas directement aux fichiers de l'agent en cours
d'execution : il ne fait que vider img_agent et relancer le cycle.
Cela rend le reset safe meme sur un agent partiellement corrompu.
"""

import os
import shutil
import json
import logging
import traceback
from lib import utils

plugin = {"VERSION": "1.0", "NAME": "resetagent", "TYPE": "machine"}  # fmt: skip

logger = logging.getLogger()


@utils.set_logging_level
def action(objectxmpp, action, sessionid, data, message, dataerreur):
    """
    Declenche la reinitialisation forcee de la base agent.

    Payload attendu (optionnel) :
    {
        "reason": "description de la raison du reset"
    }
    """
    logger.info("[RESETAGENT] ========================================")
    logger.info("[RESETAGENT] Reinitialisation forcee demandee par %s" % message["from"])

    reason = data.get("reason", "non specifiee") if isinstance(data, dict) else "non specifiee"
    logger.info("[RESETAGENT] Raison : %s" % reason)

    try:
        # Etape 1 : supprimer BOOL_DISABLE_IMG si present (leve le verrou)
        bool_disable = os.path.join(objectxmpp.pathagent, "BOOL_DISABLE_IMG")
        if os.path.exists(bool_disable):
            os.remove(bool_disable)
            logger.info("[RESETAGENT] BOOL_DISABLE_IMG supprime (verrou leve)")

        # Etape 2 : vider img_agent pour forcer le retelecharger de tous les fichiers
        if os.path.isdir(objectxmpp.img_agent):
            shutil.rmtree(objectxmpp.img_agent)
            logger.info("[RESETAGENT] img_agent supprime : %s" % objectxmpp.img_agent)
        # Recreer la structure vide attendue par Update_Remote_Agent
        for subdir in [objectxmpp.img_agent,
                       os.path.join(objectxmpp.img_agent, "lib"),
                       os.path.join(objectxmpp.img_agent, "script")]:
            os.makedirs(subdir, exist_ok=True)
        logger.info("[RESETAGENT] Structure img_agent reinitialisee (vide)")

        # Etape 3 : supprimer BOOL_UPDATE_AGENT residuel si present
        bool_update = os.path.join(objectxmpp.pathagent, "BOOL_UPDATE_AGENT")
        if os.path.exists(bool_update):
            os.remove(bool_update)

        # Etape 4 : reinitialiser descriptor_master pour forcer une demande fraiche
        objectxmpp.descriptor_master = None

        # Etape 5 : demander un descripteur frais au master substitut
        # Le relayupdateagent transmettra le descripteur et le mecanisme
        # updateagent standard prendra le relais avec img_agent vide :
        # TOUS les fichiers seront consideres manquants et retransferes.
        try:
            agent_installor = objectxmpp.sub_registration
        except AttributeError:
            agent_installor = "master@pulse/MASTER"

        msg_request = {
            "action": "updateagent",
            "sessionid": sessionid,
            "data": {
                "subaction": "ars_update",
                "jidagent": str(objectxmpp.boundjid.bare),
                "ars_update": str(objectxmpp.boundjid.full),
                "descriptoragent": {},
            },
            "ret": 0,
            "base64": False,
        }
        objectxmpp.send_message(
            mto=agent_installor,
            mbody=json.dumps(msg_request),
            mtype="chat",
        )
        logger.info("[RESETAGENT] Demande de descripteur frais envoyee a %s" % agent_installor)
        logger.info("[RESETAGENT] Tous les fichiers seront retransferes inconditionnellement")
        logger.info("[RESETAGENT] ========================================")

    except Exception as e:
        logger.error("[RESETAGENT] Erreur lors du reset : %s" % str(e))
        logger.error(traceback.format_exc())
