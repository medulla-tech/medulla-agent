# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2026 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-3.0-or-later
# file : pulse_xmpp_master_substitute/pluginsmastersubstitute/plugin_updates.py

"""
Windows updates: reception of the machine reports
(sent by the machine plugin updates_windows), of the tracking
changes, of the approval changes and of the upgrades launched
on an entity (sent by the MMC).
"""

import logging
import threading
import traceback

from lib.plugins.updates import UpdatesDatabase
from lib.plugins.updates.packages import start_build
from lib.plugins.updates.replication import start_refresh
from lib.plugins.xmpp import XmppMasterDatabase

logger = logging.getLogger()

plugin = {"VERSION": "1.0", "NAME": "updates", "TYPE": "substitute"}  # fmt: skip


def action(xmppobject, action, sessionid, data, msg, ret, dataobj):
    jid = str(msg["from"].bare)
    if isinstance(data, dict) and "tracking_changed" in data:
        tracking_changed(xmppobject, jid, data["tracking_changed"])
        return
    if isinstance(data, dict) and "approvals_changed" in data:
        approvals_changed(xmppobject, jid, data["approvals_changed"])
        return
    if isinstance(data, dict) and "upgrades_launched" in data:
        upgrades_launched(xmppobject, jid, data["upgrades_launched"])
        return
    if not isinstance(data, dict) or "format" not in data:
        logger.error("Invalid Windows updates report from %s" % jid)
        return
    database = UpdatesDatabase()
    if not database.is_activated:
        logger.error("Plugin updates: add updates to activate_plugin")
        return
    try:
        glpi_uuid = XmppMasterDatabase().get_inventory_uuid_from_bare_jid(jid)
        with database.store() as store:
            store.save_machine_report(jid, data, glpi_uuid)
        logger.debug(
            "Windows updates report of %s stored (search %s)"
            % (jid, (data.get("search") or {}).get("status"))
        )
    except Exception:
        logger.error(
            "Windows updates report of %s not stored\n%s"
            % (jid, traceback.format_exc())
        )
        return
    try:
        database.recompute_machine(jid)
    except Exception:
        logger.error(
            "Updates of %s not recomputed\n%s" % (jid, traceback.format_exc())
        )
        return
    # A report may bring an update already approved by a rule: its package is built now
    start_build(database)
    # A report may end a step of a launched upgrade: the next one starts now
    threading.Thread(target=database.run_upgrades, name="updates_upgrades", daemon=True).start()


def master_change(xmppobject, jid, entity_id, change):
    """Updates database for a change sent by the MMC master, None if refused."""
    if jid != str(xmppobject.agentmaster.bare):
        logger.error("Updates %s change refused from %s" % (change, jid))
        return None
    if isinstance(entity_id, bool) or not isinstance(entity_id, int):
        logger.error("Invalid updates %s change: %r" % (change, entity_id))
        return None
    database = UpdatesDatabase()
    if not database.is_activated:
        logger.error("Plugin updates: add updates to activate_plugin")
        return None
    return database


def tracking_changed(xmppobject, jid, entity_id):
    database = master_change(xmppobject, jid, entity_id, "tracking")
    if database is None:
        return
    # without loadupdates there is no mirror: machines are only recomputed
    start_refresh(getattr(xmppobject, "updates_mirror", None), database, entity_id)


def approvals_changed(xmppobject, jid, entity_id):
    database = master_change(xmppobject, jid, entity_id, "approvals")
    if database is None:
        return
    start_build(database)


def upgrades_launched(xmppobject, jid, entity_id):
    database = master_change(xmppobject, jid, entity_id, "upgrades")
    if database is None:
        return
    # Without waiting for the next scheduled pass
    threading.Thread(target=database.run_upgrades, name="updates_upgrades", daemon=True).start()
