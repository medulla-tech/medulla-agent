# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2026 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-3.0-or-later
# file : pulse_xmpp_master_substitute/pluginsmastersubstitute/plugin_loadupdates.py

"""
Windows updates: periodic replication of the medulla-wsus mirror
into the updates database, then build of the packages of the
approved updates, and their automatic deployment.
"""

import configparser
import logging
import os

from lib.plugins.updates import UpdatesDatabase
from lib.plugins.updates import deployments
from lib.plugins.updates.packages import set_proxy, start_build
from lib.plugins.updates.replication import NOT_CONFIGURED, MirrorClient, start_refresh

logger = logging.getLogger()

# seconds between two automatic deployment runs
AUTO_DEPLOY_INTERVAL = 600

plugin = {"VERSION": "1.0", "NAME": "loadupdates", "TYPE": "substitute", "LOAD": "START"}  # fmt: skip


def action(objectxmpp, action, sessionid, data, msg, dataerreur):
    if getattr(objectxmpp, "num_call%s" % action) == 0:
        start(objectxmpp)


def start(objectxmpp):
    config = read_config(objectxmpp)
    database = UpdatesDatabase()
    if not database.is_activated:
        logger.error("Plugin loadupdates: add updates to activate_plugin")
        return
    if not (config["url"] and config["server_id"] and config["key"]):
        logger.error("Plugin loadupdates: url, server_id and key are required in loadupdates.ini")
        with database.store() as store:
            store.save_error(NOT_CONFIGURED)
        return
    set_proxy(config["proxy"])
    client = MirrorClient(config["url"], config["server_id"], config["key"], config["proxy"])
    # used by the plugin updates when the tracking of an entity changes
    objectxmpp.updates_mirror = client
    objectxmpp.schedule(
        "updates_replication",
        config["interval"],
        refresh,
        (client, database),
        repeat=True,
    )
    objectxmpp.schedule(
        "updates_auto_deploy",
        AUTO_DEPLOY_INTERVAL,
        deployments.start,
        (database, config["auto_deploy_limit"]),
        repeat=True,
    )
    objectxmpp.schedule(
        "updates_upgrades",
        AUTO_DEPLOY_INTERVAL,
        database.run_upgrades,
        (),
        repeat=True,
    )
    # the stored results follow the computation code after an upgrade
    refresh(client, database, recompute=True)


def refresh(client, database, recompute=False):
    start_refresh(
        client,
        database,
        then=lambda: start_build(database, retry_failed=True),
        recompute=recompute,
    )


def read_config(objectxmpp):
    path = os.path.join(objectxmpp.config.pathdirconffile, plugin["NAME"] + ".ini")
    config = configparser.ConfigParser(interpolation=None)
    config.read([path, path + ".local"])
    return {
        "url": config.get("parameters", "url", fallback=""),
        "server_id": config.get("parameters", "server_id", fallback=""),
        "key": config.get("parameters", "key", fallback=""),
        "interval": config.getint("parameters", "interval", fallback=3600),
        "proxy": config.get("parameters", "proxy", fallback=""),
        "auto_deploy_limit": config.getint(
            "parameters", "auto_deploy_limit", fallback=deployments.DEFAULT_LIMIT
        ),
    }

