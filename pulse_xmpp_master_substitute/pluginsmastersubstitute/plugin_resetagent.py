# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2016-2023 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-3.0-or-later

"""plugin_resetagent (substitut) - reset direct vs reset automatique.

Ce plugin expose deux roles volontairement dissocies:
1) Reset direct par message XMPP (mode manuel), sans dependance a la table.
2) Reset automatique base sur la table reset_machine (mode file d'attente).

Payload supporte:
- Appel direct historique: {"jid": "machine@...", "reason": "..."}
- Appel direct explicite: {"mode": "direct", "jid": "machine@...", "reason": "..."}
- Ajout en file explicite: {"mode": "queue_add", "jid": "machine@...", "reason": "..."}
- Traitement file explicite: {"mode": "queue_process"}
- Appel sans payload: mode automatique (queue_process)

Le message XMPP vers l'agent garde le format standard:
{"action", "base64", "sessionid", "data"}
"""

import json
import logging
import traceback
from lib.plugins.xmpp import XmppMasterDatabase
from lib.utils import getRandomName

logger = logging.getLogger()
DEBUGPULSEPLUGIN = 25
plugin = {"VERSION": "1.2", "NAME": "resetagent", "TYPE": "substitute"}  # fmt: skip


def _send_reset(xmppobject, jid, reason=""):
    """Envoie l'ordre de reset a la machine ciblee."""
    msg = {
        "action": "resetagent",
        "sessionid": getRandomName(5, "resetagent"),
        "data": {"reason": reason},
        "ret": 0,
        "base64": False,
    }
    xmppobject.send_message(mto=jid, mbody=json.dumps(msg), mtype="chat")
    logger.info(
        "[RESETAGENT-SUB] Reset direct envoye a %s (raison: %s)"
        % (jid, reason or "non specifiee")
    )


def _parse_payload(data):
    """Normalise les differentes formes de payload."""
    mode = ""
    jid_target = ""
    reason = ""

    if isinstance(data, list) and len(data) >= 1:
        jid_target = str(data[0]).strip()
        reason = str(data[2][0]) if len(data) >= 3 and isinstance(data[2], list) else ""
    elif isinstance(data, dict):
        mode = str(data.get("mode", "")).strip().lower()
        jid_target = str(data.get("jid", "")).strip()
        reason = str(data.get("reason", "")).strip()

    return mode, jid_target, reason


def _queue_add(jid_target, reason):
    """Ajoute une machine en file base de donnees."""
    XmppMasterDatabase().reset_machine_add(jid_target, reason)
    logger.info("[RESETAGENT-SUB] %s ajoutee a reset_machine" % jid_target)


def _queue_process(xmppobject):
    """Traite toute la file reset_machine."""
    try:
        queue = XmppMasterDatabase().reset_machine_get_all()
    except Exception:
        logger.error("[RESETAGENT-SUB] Impossible de lire la table reset_machine")
        logger.error(traceback.format_exc())
        return

    if not queue:
        logger.debug("[RESETAGENT-SUB] Table reset_machine vide")
        return

    logger.info("[RESETAGENT-SUB] %d machine(s) en attente de reset" % len(queue))

    for entry in queue:
        jid = entry.get("jid", "").strip()
        reason = entry.get("reason", "")
        nb_att = entry.get("nb_attempt", 0)

        if not jid:
            continue

        try:
            present = XmppMasterDatabase().getPresencejid(jid)
        except Exception:
            present = False

        if present:
            try:
                _send_reset(xmppobject, jid, reason)
                XmppMasterDatabase().reset_machine_delete(jid)
                logger.info("[RESETAGENT-SUB] %s reinitialise et retire de la table" % jid)
            except Exception:
                logger.error("[RESETAGENT-SUB] Echec reset pour %s" % jid)
                logger.error(traceback.format_exc())
                XmppMasterDatabase().reset_machine_increment_attempt(jid)
        else:
            logger.debug(
                "[RESETAGENT-SUB] %s hors ligne (tentative %d), conserve en table"
                % (jid, nb_att)
            )
            XmppMasterDatabase().reset_machine_increment_attempt(jid)


def action(xmppobject, action, sessionid, data, message, ret=None, dataobj=None):
    """Traite une demande de reinitialisation d'agent."""
    logger.debug("[RESETAGENT-SUB] Appel depuis %s" % message["from"])

    mode, jid_target, reason = _parse_payload(data)

    # Compatibilite historique: si un jid est fourni sans mode, le comportement
    # reste direct + fallback queue si la machine est hors ligne.
    if not mode and jid_target:
        mode = "direct_or_queue"

    # Mode explicite: reset XMPP direct, sans base reset_machine.
    if mode == "direct":
        if not jid_target:
            logger.error("[RESETAGENT-SUB] Mode direct sans jid, abandon")
            return
        _send_reset(xmppobject, jid_target, reason)
        return

    # Mode explicite: ajout en file reset_machine, sans envoi direct.
    if mode == "queue_add":
        if not jid_target:
            logger.error("[RESETAGENT-SUB] Mode queue_add sans jid, abandon")
            return
        try:
            _queue_add(jid_target, reason)
        except Exception:
            logger.error("[RESETAGENT-SUB] Impossible d'ajouter en table")
            logger.error(traceback.format_exc())
        return

    # Mode historique: si online envoi direct, sinon enqueue.
    if mode == "direct_or_queue":
        try:
            present = XmppMasterDatabase().getPresencejid(jid_target)
        except Exception:
            # DB indisponible: on preserve le mode manuel et on tente l'envoi direct.
            present = True

        if present:
            _send_reset(xmppobject, jid_target, reason)
        else:
            logger.warning(
                "[RESETAGENT-SUB] %s hors ligne, ajout en table reset_machine" % jid_target
            )
            try:
                _queue_add(jid_target, reason)
            except Exception:
                logger.error("[RESETAGENT-SUB] Impossible d'ajouter en table")
                logger.error(traceback.format_exc())
        return

    # Mode explicite queue_process et mode par defaut sans payload.
    _queue_process(xmppobject)
