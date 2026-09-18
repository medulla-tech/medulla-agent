# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2016-2023 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-3.0-or-later

"""plugin_regenerateagent - Gestion de la file de regeneration agent.

Le substitute ne transmet aux ARS que les machines XMPP presentes. Les demandes
sont regroupees par ARS et envoyees par lots de taille configurable.
"""

import json
import logging
import traceback

from lib.plugins.xmpp import XmppMasterDatabase
from lib.utils import getRandomName

logger = logging.getLogger()
plugin = {"VERSION": "1.0", "NAME": "regenerateagent", "TYPE": "substitute"}  # fmt: skip


def _get_relay_jid(jid):
    """Retourne le JID de l'ARS affecte a la machine."""
    relay = XmppMasterDatabase().groupdeployfromjid(jid)
    return str(relay[0]).strip() if relay != -1 and relay else ""


def _send_regenerate(xmppobject, jidrelay, entries):
    """Envoie a un ARS une liste de machines a regenerer."""
    msg = {
        "action": "regenerateagent",
        "sessionid": getRandomName(5, "regenerateagent"),
        "data": {"jidmachines": [entry["jid"] for entry in entries]},
        "ret": 0,
        "base64": False,
    }
    xmppobject.send_message(mto=jidrelay, mbody=json.dumps(msg), mtype="chat")
    logger.info(
        "[REGENERATEAGENT-SUB] Lot de %d regeneration(s) envoye a l'ARS %s"
        % (len(entries), jidrelay)
    )


def _parse_payload(data):
    """Normalise le payload direct, file d'attente ou historique."""
    mode = ""
    jid_target = ""
    reason = ""

    if isinstance(data, list) and data:
        jid_target = str(data[0]).strip()
        reason = str(data[2][0]) if len(data) >= 3 and isinstance(data[2], list) else ""
    elif isinstance(data, dict):
        if isinstance(data.get("data"), list) and data["data"]:
            payload_list = data["data"]
            jid_target = str(payload_list[0]).strip()
            reason = str(payload_list[2][0]) if len(payload_list) >= 3 and isinstance(payload_list[2], list) else ""
        else:
            mode = str(data.get("mode", "")).strip().lower()
            jid_target = str(data.get("jid", "")).strip()
            reason = str(data.get("reason", "")).strip()

    return mode, jid_target, reason


def _queue_add(jid_target, reason):
    """Ajoute une demande dans la file de regeneration."""
    XmppMasterDatabase().regenerate_agent_add(jid_target, reason)
    logger.info("[REGENERATEAGENT-SUB] %s ajoutee a regenerate_agent" % jid_target)


def _queue_process(xmppobject):
    """Envoie les machines presentes par lots limites au meme ARS."""
    try:
        queue = XmppMasterDatabase().regenerate_agent_get_all()
    except Exception:
        logger.error("[REGENERATEAGENT-SUB] Impossible de lire regenerate_agent")
        logger.error(traceback.format_exc())
        return

    entries_by_relay = {}
    for entry in queue:
        jid = entry.get("jid", "").strip()
        jidrelay = entry.get("jidrelay", "").strip()
        if not jid or not jidrelay:
            continue
        try:
            if XmppMasterDatabase().getPresencejid(jid):
                entries_by_relay.setdefault(jidrelay, []).append(entry)
            else:
                XmppMasterDatabase().regenerate_agent_increment_attempt(jid)
        except Exception:
            logger.error("[REGENERATEAGENT-SUB] Echec pour %s" % jid)
            logger.error(traceback.format_exc())
            XmppMasterDatabase().regenerate_agent_increment_attempt(jid)

    batch_size = getattr(xmppobject, "regenerate_queue_batch_size", 5)
    for jidrelay, entries in entries_by_relay.items():
        for start in range(0, len(entries), batch_size):
            batch = entries[start:start + batch_size]
            try:
                _send_regenerate(xmppobject, jidrelay, batch)
                for entry in batch:
                    XmppMasterDatabase().regenerate_agent_delete(entry["jid"])
            except Exception:
                logger.error("[REGENERATEAGENT-SUB] Echec envoi lot vers %s" % jidrelay)
                logger.error(traceback.format_exc())
                for entry in batch:
                    XmppMasterDatabase().regenerate_agent_increment_attempt(entry["jid"])


def action(xmppobject, action, sessionid, data, message, ret=None, dataobj=None):
    """Traite une demande directe ou differee de regeneration agent."""
    mode, jid_target, reason = _parse_payload(data)
    if not mode and jid_target:
        mode = "direct_or_queue"

    if mode == "direct":
        if jid_target:
            jidrelay = _get_relay_jid(jid_target)
            if jidrelay:
                _send_regenerate(xmppobject, jidrelay, [{"jid": jid_target}])
            else:
                logger.error("[REGENERATEAGENT-SUB] Aucun ARS affecte a %s" % jid_target)
        return

    if mode == "queue_add":
        if jid_target:
            _queue_add(jid_target, reason)
        return

    if mode == "direct_or_queue":
        try:
            jidrelay = _get_relay_jid(jid_target)
            present = bool(jidrelay) and XmppMasterDatabase().getPresencejid(jid_target)
        except Exception:
            jidrelay = ""
            present = False
        if present:
            _send_regenerate(xmppobject, jidrelay, [{"jid": jid_target}])
        else:
            _queue_add(jid_target, reason)
        return

    _queue_process(xmppobject)
