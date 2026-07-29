# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2016-2023 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-3.0-or-later

"""
plugin_resetagent (substitut) - Gestionnaire de reinitialisation des agents.

Ce plugin cote master substitut gere la file d'attente des machines qui
necessitent une reinitialisation forcee de leur base agent.

Deux modes de declenchement :
  1. Appel direct (QA, API) avec payload {"jid": "machine@...", "reason": "..."}
  2. File d'attente JSON dans le repertoire de configuration du plugin
     (resetagent_queue.json) : le substitut l'interroge periodiquement et
     envoie l'ordre de reset aux machines en ligne.

Format du fichier de file d'attente :
  [
    {"jid": "pc-win11pro-3.7v7@pulse", "reason": "boucle update infinie"},
    {"jid": "pc-linux-5.lan@pulse",    "reason": "agent corrompu"}
  ]

Une fois l'ordre envoye a une machine en ligne, elle est retiree de la file.
Les machines hors ligne restent dans la file jusqu'a leur prochaine connexion.
"""

import json
import logging
import os
import traceback
from lib.plugins.xmpp import XmppMasterDatabase
from lib.utils import getRandomName

logger = logging.getLogger()
DEBUGPULSEPLUGIN = 25
plugin = {"VERSION": "1.0", "NAME": "resetagent", "TYPE": "substitute"}  # fmt: skip


def _queue_path(xmppobject):
    """Chemin du fichier de file d'attente."""
    return os.path.join(
        xmppobject.config.pathdirconffile, "resetagent_queue.json"
    )


def _load_queue(xmppobject):
    """Charge la file d'attente depuis le fichier JSON."""
    path = _queue_path(xmppobject)
    if not os.path.isfile(path):
        return []
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, list) else []
    except Exception as e:
        logger.error("[RESETAGENT-SUB] Impossible de lire la file : %s" % e)
        return []


def _save_queue(xmppobject, queue):
    """Sauvegarde la file d'attente dans le fichier JSON."""
    path = _queue_path(xmppobject)
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(queue, f, indent=2)
    except Exception as e:
        logger.error("[RESETAGENT-SUB] Impossible de sauvegarder la file : %s" % e)


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
    logger.info("[RESETAGENT-SUB] Ordre de reset envoye a %s (raison: %s)" % (jid, reason or "non specifiee"))


def action(xmppobject, action, sessionid, data, message, ret=None, dataobj=None):
    """
    Traite une demande de reinitialisation d'agent.

    Accepte :
    - Appel direct : {"jid": "machine@...", "reason": "..."}
    - Appel liste QA : ["machine@...", {}, ["raison"]]
    - Sans payload : traite uniquement la file d'attente JSON
    """
    logger.debug("[RESETAGENT-SUB] Appel depuis %s" % message["from"])

    jid_target = ""
    reason = ""

    # --- Parsing du payload ---
    if isinstance(data, list) and len(data) >= 1:
        jid_target = str(data[0]).strip()
        reason = str(data[2][0]) if len(data) >= 3 and isinstance(data[2], list) else ""
    elif isinstance(data, dict):
        jid_target = str(data.get("jid", "")).strip()
        reason = str(data.get("reason", "")).strip()

    # --- Appel direct avec JID ---
    if jid_target:
        try:
            present = XmppMasterDatabase().getPresencejid(jid_target)
        except Exception:
            present = True  # si la DB n'est pas accessible, on tente quand meme

        if present:
            _send_reset(xmppobject, jid_target, reason)
        else:
            logger.warning(
                "[RESETAGENT-SUB] Machine %s hors ligne, ajout en file d'attente" % jid_target
            )
            queue = _load_queue(xmppobject)
            # Eviter les doublons
            if not any(e.get("jid") == jid_target for e in queue):
                queue.append({"jid": jid_target, "reason": reason})
                _save_queue(xmppobject, queue)
        return

    # --- Traitement de la file d'attente ---
    queue = _load_queue(xmppobject)
    if not queue:
        logger.debug("[RESETAGENT-SUB] File d'attente vide")
        return

    logger.info("[RESETAGENT-SUB] Traitement de la file : %d machine(s)" % len(queue))
    remaining = []
    for entry in queue:
        jid = entry.get("jid", "").strip()
        r   = entry.get("reason", "")
        if not jid:
            continue
        try:
            present = XmppMasterDatabase().getPresencejid(jid)
        except Exception:
            present = False

        if present:
            try:
                _send_reset(xmppobject, jid, r)
            except Exception:
                logger.error("[RESETAGENT-SUB] Echec envoi reset a %s" % jid)
                logger.error(traceback.format_exc())
                remaining.append(entry)
        else:
            logger.debug("[RESETAGENT-SUB] %s hors ligne, conserve en file" % jid)
            remaining.append(entry)

    _save_queue(xmppobject, remaining)
    logger.info(
        "[RESETAGENT-SUB] File traitee : %d envoyes, %d en attente"
        % (len(queue) - len(remaining), len(remaining))
    )
