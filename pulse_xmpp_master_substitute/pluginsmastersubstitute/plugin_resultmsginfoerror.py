#!/usr/bin/python3
# -*- coding: utf-8; -*-
# SPDX-FileCopyrightText: 2016-2023 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-3.0-or-later

import logging
import os
import time

logger = logging.getLogger()

DEBUGPULSEPLUGIN = 25
plugin = {"VERSION": "2.1", "NAME": "resultmsginfoerror", "TYPE": "substitute"}  # fmt: skip


def action(xmppobject, action, sessionid, data, message, ret, dataobj):
    """Traite les retours installplugin pour piloter cooldown et restart différé."""
    logging.getLogger().debug(plugin)
    if "msg" in data:
        if ret >= 50 and ret <= 80:
            logging.getLogger().warning(
                "msg [%s] : %s" % (message["from"], data["msg"])
            )
        elif ret == 0:
            logging.getLogger().info("msg [%s] : %s" % (message["from"], data["msg"]))
        else:
            logging.getLogger().error("msg [%s] : %s" % (message["from"], data["msg"]))

    if data.get("install_action") != "installplugin":
        return

    # We correlate the agent answer with the pending deployment queue using the
    # exact plugin file name and target version sent by the substitute.
    jid_from = str(message["from"])
    pluginname = data.get("pluginname", "")
    plugin_version = str(data.get("plugin_version", "") or "")
    plugin_short_name = os.path.splitext(os.path.basename(pluginname))[0]
    if plugin_short_name.startswith("plugin_"):
        plugin_short_name = plugin_short_name[7:]

    if not hasattr(xmppobject, "pending_plugin_installs"):
        xmppobject.pending_plugin_installs = {}
    if not hasattr(xmppobject, "pending_plugin_install_success"):
        xmppobject.pending_plugin_install_success = {}
    if not hasattr(xmppobject, "plugin_install_failures"):
        xmppobject.plugin_install_failures = {}
    if not hasattr(xmppobject, "install_plugin_failure_cooldown"):
        xmppobject.install_plugin_failure_cooldown = 1800

    pending = xmppobject.pending_plugin_installs.setdefault(jid_from, set())
    successes = xmppobject.pending_plugin_install_success.setdefault(jid_from, set())
    # The matching pending entry is cleared regardless of success or failure.
    pending.discard((plugin_short_name, plugin_version))

    failure_key = (jid_from, plugin_short_name, plugin_version)
    if ret == 0:
        # A successful validation clears any previous cooldown for the same target version.
        successes.add((plugin_short_name, plugin_version))
        if failure_key in xmppobject.plugin_install_failures:
            del xmppobject.plugin_install_failures[failure_key]
        logger.info(
            "Plugin install success agent=%s plugin=%s version=%s pending_left=%s",
            jid_from,
            plugin_short_name,
            plugin_version,
            sorted(list(pending)),
        )
    else:
        xmppobject.plugin_install_failures[failure_key] = (
            time.time() + xmppobject.install_plugin_failure_cooldown
        )
        logger.warning(
            "Plugin install failure agent=%s plugin=%s version=%s ret=%s cooldown=%ss msg=%s pending_left=%s",
            jid_from,
            plugin_short_name,
            plugin_version,
            ret,
            xmppobject.install_plugin_failure_cooldown,
            data.get("msg", ""),
            sorted(list(pending)),
        )

    if not pending and successes:
        # Restart only after the current install batch has no pending answer left.
        logger.info(
            "Restarting agent=%s after validated plugin batch success=%s",
            jid_from,
            sorted(list(successes)),
        )
        xmppobject.event("restartmachineasynchrone", jid_from)
        xmppobject.pending_plugin_install_success[jid_from] = set()
