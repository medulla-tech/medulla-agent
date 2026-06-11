# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2016-2023 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-3.0-or-later

import json
import logging
import traceback

logger = logging.getLogger()
DEBUGPULSEPLUGIN = 25
plugin = {"VERSION": "1.0", "NAME": "reinstallplugin", "TYPE": "substitute"}  # fmt: skip


def _normalize_plugin_name(plugin_name):
    name = str(plugin_name or "").strip()
    if name.endswith(".py"):
        name = name[:-3]
    if name.startswith("plugin_"):
        name = name[len("plugin_") :]
    return name


def _to_bool(value, default=True):
    if isinstance(value, bool):
        return value
    if value is None:
        return default
    value_str = str(value).strip().lower()
    if value_str in ("1", "true", "yes", "on"):
        return True
    if value_str in ("0", "false", "no", "off"):
        return False
    return default


def _safe_dump_payload(payload):
    try:
        return json.dumps(payload, indent=4, sort_keys=True, default=str)
    except Exception:
        return repr(payload)


def action(xmppobject, action, sessionid, data, msg, ret=None, dataobj=None):
    """
    Force plugin reinstallation on one machine.

    Expected payload:
    {
        "jid": "machine@example.net/resource",
        "plugin": "inventory" | "plugin_inventory" | "plugin_inventory.py",
        "restart": true  # optional, default true
    }
    """
    logger.debug("reinstallplugin: action() entered")
    logger.debug("=====================================================")
    logger.debug("call %s from %s" % (plugin, msg["from"]))
    logger.debug(
        "reinstallplugin: sessionid=%s ret=%s data_type=%s"
        % (sessionid, ret, type(data).__name__)
    )
    logger.debug("reinstallplugin: raw payload=%s" % _safe_dump_payload(data))
    logger.debug("=====================================================")

    jid_machine = ""
    plugin_name = ""
    do_restart = True

    # QA path from MMC sends list payload: [jid, infomachine, [plugin, restart]]
    if isinstance(data, list) and len(data) >= 3:
        logger.debug("reinstallplugin: parsing QA list payload")
        jid_machine = str(data[0]).strip()
        params = data[2] if isinstance(data[2], list) else []
        plugin_name = _normalize_plugin_name(params[0] if len(params) > 0 else "")
        do_restart = _to_bool(params[1] if len(params) > 1 else True, default=True)
    elif (
        isinstance(data, dict)
        and isinstance(data.get("data"), list)
        and len(data.get("data")) >= 3
    ):
        logger.debug("reinstallplugin: parsing wrapped QA dict payload")
        payload = data.get("data")
        jid_machine = str(payload[0]).strip()
        params = payload[2] if isinstance(payload[2], list) else []
        plugin_name = _normalize_plugin_name(params[0] if len(params) > 0 else "")
        do_restart = _to_bool(params[1] if len(params) > 1 else True, default=True)
    elif isinstance(data, dict):
        logger.debug("reinstallplugin: parsing direct dict payload")
        jid_machine = str(data.get("jid", "")).strip()
        plugin_name = _normalize_plugin_name(data.get("plugin", ""))
        do_restart = _to_bool(data.get("restart", True), default=True)
    else:
        logger.debug("reinstallplugin: unsupported payload format")

    logger.debug(
        "reinstallplugin: parsed jid=%s plugin=%s restart=%s"
        % (jid_machine, plugin_name, do_restart)
    )

    if not jid_machine or not plugin_name:
        logger.error("reinstallplugin: missing required fields 'jid' and/or 'plugin'")
        return

    try:
        # deployPlugin is dynamically attached by plugin_loadpluginlistversion
        logger.debug(
            "reinstallplugin: has deployPlugin=%s"
            % hasattr(xmppobject, "deployPlugin")
        )
        if not hasattr(xmppobject, "deployPlugin"):
            logger.error(
                "reinstallplugin: deployPlugin() is unavailable. "
                "Ensure plugin_loadpluginlistversion is loaded."
            )
            return

        logger.info(
            "reinstallplugin: force deploy plugin_%s.py to %s"
            % (plugin_name, jid_machine)
        )
        xmppobject.deployPlugin(jid_machine, plugin_name)
        logger.debug(
            "reinstallplugin: deployPlugin called for plugin_%s.py to %s"
            % (plugin_name, jid_machine)
        )

        if do_restart:
            xmppobject.event("restartmachineasynchrone", jid_machine)
            logger.debug(
                "reinstallplugin: restartmachineasynchrone event sent to %s"
                % jid_machine
            )
        else:
            logger.debug("reinstallplugin: restart skipped by payload")

    except Exception:
        logger.error("reinstallplugin failed")
        logger.error("\n%s" % traceback.format_exc())
