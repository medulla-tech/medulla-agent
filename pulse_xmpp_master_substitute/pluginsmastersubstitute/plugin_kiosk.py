# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2016-2023 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-3.0-or-later

import logging

from lib.plugins.kiosk import KioskDatabase, send_packages
from lib.plugins.xmpp import XmppMasterDatabase

logger = logging.getLogger()
plugin = {"VERSION": "1.1", "NAME": "kiosk", "TYPE": "mastersub"}


def action(xmppobject, action, sessionid, data, message, dataobj):
    logger.debug("=====================================================")
    logger.debug(plugin)
    logger.debug("=====================================================")
    subaction = data.get("subaction")
    if subaction == "profiles_changed":
        profiles_changed(xmppobject, data)
    else:
        logger.warning("kiosk - subaction %s not recognized" % subaction)


def profiles_changed(xmppobject, data):
    """
    Send their packages again to the kiosks concerned by a change of profiles.

    data["entity_ids"]: GLPI entities of the changed profiles; their machines
    and those of the entities below them are updated. Empty or absent: every
    machine with a kiosk.
    """
    entity_ids = data.get("entity_ids") or []
    try:
        entity_ids = [int(entity_id) for entity_id in entity_ids]
    except (TypeError, ValueError):
        logger.error("kiosk - profiles_changed: invalid entity_ids %s" % entity_ids)
        return
    jids = KioskDatabase().get_kiosk_machines(entity_ids)
    sent = 0
    for jid in jids:
        machine = XmppMasterDatabase().getMachinefromjid(jid)
        if send_packages(xmppobject, machine, "profiles_updated"):
            sent += 1
    logger.info(
        "kiosk - profiles_changed: %s of %s kiosks updated" % (sent, len(jids))
    )
