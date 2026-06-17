# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2016-2023 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-3.0-or-later
# Reference file: pluginsmachine/plugin_updateagent.py
# Extension rapide:
# 1) Ajouter une fonction _handle_<nom>_section(updater, payload, result).
# 2) Declarer cette section dans SECTION_HANDLERS (ex: "reboot": _handle_reboot_section).
# 3) Reutiliser _new_result/_as_list pour garder un format de retour stable.

"""Plugin execute Linux update actions from deployment descriptor payload.

This plugin is called by grafcetdeploy when a step contains:
@@@DEPLOY_ACTION_UPDATE_LINUX_COMMAND@@@

Expected payload (dynamic descriptor parameters):
{
    "section": "update",
    "linux_actions": ["security", "kernel", "other"]
}

Additional payload for message feature:
{
    "section": "message",
    "message": "texte libre"
}
"""

import json
import logging
import sys

from lib import utils

logger = logging.getLogger()
DEBUGPULSEPLUGIN = 25
plugin = {"VERSION": "1.0", "VERSIONAGENT": "1.0", "NAME": "update_linux_command", "TYPE": "machine", "waittingmax": 120, "waittingmin": 5}  # fmt: skip

SUPPORTED_LINUX_ACTIONS = {"security", "kernel", "other"}
SUCCESS_STYLE = "color:#ffffff;background:#198754;padding:2px 6px;border-radius:3px;"
ERROR_STYLE = "color:#ffffff;background:#b02a37;padding:2px 6px;border-radius:3px;"

def _as_payload(value):
    """Return a dict payload from supported raw input formats.

    Supported inputs:
    - dict: returned as-is
    - JSON string containing an object
    - any other value: converted to empty dict
    """
    if isinstance(value, dict):
        return value
    if isinstance(value, str) and value.strip():
        try:
            parsed = json.loads(value)
            if isinstance(parsed, dict):
                return parsed
        except Exception:
            return {}
    return {}


def _extract_payload(data):
    """Extract deployment parameters from known wrapper keys.

    Priority order (highest first):
    - marker_payload: extracted from @@@DEPLOY_ACTION_UPDATE_LINUX_COMMAND@@@
    - payload: merged result (advanced > MSC command_parameters)
    - command_parameters: MSC-provided defaults
    - dynamic_param_deploy: same as command_parameters
    - raw data dict (if it contains section/linux_actions/etc.)
    """
    if not isinstance(data, dict):
        return {}

    # Try marker_payload first (highest priority - explicitly set in descriptor)
    for key in ("marker_payload", "payload", "command_parameters", "dynamic_param_deploy"):
        payload = _as_payload(data.get(key))
        if payload:
            return payload

    # Fallback: treat data itself as payload if it has recognized keys
    return _as_payload(data)


def _as_list(value):
    """Convert a scalar/list value to a normalized list of strings."""
    if value is None:
        return []
    if isinstance(value, list):
        return [str(x).strip().lower() for x in value if str(x).strip()]
    return [str(value).strip().lower()] if str(value).strip() else []


def _new_result(section, requested_actions, unknown_actions):
    """Build the shared result envelope returned by section handlers."""
    return {
        "section": section,
        "requested_actions": requested_actions,
        "applied": [],
        "unknown_actions": unknown_actions,
    }


def _handle_update_section(updater, payload, result):
    """Handle section=update with linux_actions and optional policy override."""
    policy = payload.get("linux_policy") or payload.get("policy")
    if policy:
        updater.update(policy=str(policy))
        result["applied"].append({"policy": str(policy)})
        return result

    valid_actions = [x for x in result["requested_actions"] if x in SUPPORTED_LINUX_ACTIONS]
    if valid_actions:
        result["applied"].append(updater.update_from_human_actions(valid_actions))
        return result

    result["message"] = "No supported linux_actions found for update section"
    return result


def _handle_maintenance_section(updater, payload, result):
    """Handle section=maintenance."""
    result["maintenance"] = updater.maintenance()
    return result


def _handle_fetch_section(updater, payload, result):
    """Handle section=fetch/inventory/scan."""
    updater.fetch_updates()
    result["inventory"] = updater.to_json(return_dict=True)
    return result


def _handle_message_section(updater, payload, result):
    """Handle section=message for generic extensible message payload."""
    msg = payload.get("message")
    if msg is None:
        msg = payload.get("msg")
    if msg is None:
        msg = payload.get("text")

    result["message"] = "" if msg is None else str(msg)
    result["applied"].append({"message": result["message"]})
    logger.info("update_linux_command message section: %s", result["message"])
    return result


# Extensibility point:
# To add a new feature, create a _handle_<name>_section function and map section aliases here.
SECTION_HANDLERS = {
    "update": _handle_update_section,
    "maintenance": _handle_maintenance_section,
    "fetch": _handle_fetch_section,
    "inventory": _handle_fetch_section,
    "scan": _handle_fetch_section,
    "message": _handle_message_section,
}


def _send_deploy_xmpplog(objectxmpp, sessionid, message_text, priority=0):
    """Send deployment-correlated log entry when xmpplog is available."""
    try:
        objectxmpp.xmpplog(
            message_text,
            type="deploy",
            sessionname=sessionid,
            priority=priority,
            action="xmpplog",
            who=objectxmpp.boundjid.bare,
            how="",
            why="",
            module="Deployment | Execution | Update Linux",
            date=None,
            fromuser="",
            touser="",
        )
    except Exception:
        # Keep plugin execution resilient even if xmpplog backend fails.
        logger.debug("xmpplog unavailable for update_linux_command", exc_info=True)




def _dispatch_payload(updater, payload):
    """Dispatch plugin behavior from JSON payload content using handler registry."""
    section = str(payload.get("section", "update")).strip().lower()
    requested_actions = _as_list(payload.get("linux_actions"))
    unknown_actions = [x for x in requested_actions if x not in SUPPORTED_LINUX_ACTIONS]
    result = _new_result(section, requested_actions, unknown_actions)

    handler = SECTION_HANDLERS.get(section)
    if handler is None:
        result["message"] = "Unsupported section or empty payload"
        return result

    return handler(updater, payload, result)


def _extract_distribution_from_result(result):
    """Extract distribution name from update result payload when available."""
    for entry in result.get("applied", []):
        if not isinstance(entry, dict):
            continue
        dist = entry.get("distribution")
        if dist:
            return str(dist)
    return "linux"


def _format_ok_message(label, distribution):
    return (
        "<span class='log_ok' style='"
        + SUCCESS_STYLE
        + "'>"
        + label
        + " update completed successfully</span> (distribution="
        + distribution
        + ")."
    )


def _format_error_message(label, reason):
    return (
        "<span class='log_err' style='"
        + ERROR_STYLE
        + "'>"
        + label
        + " update failed</span>: "
        + reason
    )


def _action_label(action_name):
    mapping = {
        "security": "Security",
        "kernel": "Kernel",
        "other": "Other packages",
    }
    return mapping.get(action_name, str(action_name).capitalize())


def _collect_update_action_statuses(result):
    """Return per-action status map for requested update actions.

    Output format:
    {
      "security": {"ok": True/False, "reason": "..."},
      ...
    }
    """
    statuses = {}

    if str(result.get("section", "")).lower() != "update":
        return statuses

    requested_actions = _as_list(result.get("requested_actions"))
    if not requested_actions:
        return statuses

    unknown_actions = set(_as_list(result.get("unknown_actions") or []))
    applied_actions = set()
    failed_reasons = {}

    for entry in result.get("applied", []):
        if not isinstance(entry, dict):
            continue

        for item in entry.get("applied", []) if isinstance(entry.get("applied"), list) else []:
            if isinstance(item, dict):
                action_name = str(item.get("action", "")).strip().lower()
                if action_name:
                    applied_actions.add(action_name)

        for item in entry.get("failed", []) if isinstance(entry.get("failed"), list) else []:
            if isinstance(item, dict):
                action_name = str(item.get("action", "")).strip().lower()
                if action_name:
                    failed_reasons[action_name] = str(item.get("error", "unknown error"))

    generic_reason = str(result.get("message", "")).strip() or "result not confirmed"

    for action_name in requested_actions:
        if action_name in unknown_actions:
            statuses[action_name] = {"ok": False, "reason": "unsupported action"}
        elif action_name in failed_reasons:
            statuses[action_name] = {"ok": False, "reason": failed_reasons[action_name]}
        elif action_name in applied_actions:
            statuses[action_name] = {"ok": True, "reason": ""}
        else:
            statuses[action_name] = {"ok": False, "reason": generic_reason}

    return statuses

@utils.set_logging_level
def action(objectxmpp, action, sessionid, data, message, dataerreur):
    """Run Linux updates based on descriptor parameters.

    The plugin intentionally logs result details and lets the deployment
    workflow continue. Errors are logged for troubleshooting.
    """
    logger.debug("###################################################")
    logger.debug("call %s from %s", plugin, message["from"])
    logger.debug("###################################################")
    logger.info("ma data %s", json.dumps(data, indent=4))
    payload = _extract_payload(data)
    logger.info("update_linux_command payload: %s", json.dumps(payload, indent=4))
    priority = 0
    try:
        priority = int(data.get("deploy_step", 0)) if isinstance(data, dict) else 0
    except Exception:
        priority = 0

    _send_deploy_xmpplog(
        objectxmpp,
        sessionid,
        "update_linux_command execute payload=" + json.dumps(payload, sort_keys=True),
        priority=priority,
    )

    if not sys.platform.startswith("linux"):
        logger.info("update_linux_command ignored on non-linux platform: %s", sys.platform)
        _send_deploy_xmpplog(
            objectxmpp,
            sessionid,
            "update_linux_command skipped: unsupported platform " + sys.platform,
            priority=priority,
        )
        return

    try:
        try:
            from lib.update_linux import UpdateLinux
        except Exception:
            from update_linux import UpdateLinux

        # Use the shared Linux updater abstraction (debian/ubuntu/rhel/etc.).
        updater = UpdateLinux(dry_run=False, intranet_security=False)
        result = _dispatch_payload(updater, payload)
        logger.info(
            "update_linux_command result: %s",
            json.dumps(result, indent=4, sort_keys=True),
        )

        _send_deploy_xmpplog(
            objectxmpp,
            sessionid,
            "update_linux_command result=" + json.dumps(result, sort_keys=True),
            priority=priority,
        )

        distribution = _extract_distribution_from_result(result)
        statuses = _collect_update_action_statuses(result)
        for action_name in _as_list(result.get("requested_actions")):
            status = statuses.get(action_name)
            if status is None:
                continue

            label = _action_label(action_name)
            if status.get("ok"):
                user_message = _format_ok_message(label, distribution)
            else:
                user_message = _format_error_message(label, str(status.get("reason", "unknown error")))

            _send_deploy_xmpplog(
                objectxmpp,
                sessionid,
                user_message,
                priority=priority,
            )
    except Exception as exc:
        logger.warning("Update Linux partiel: %s", str(exc))
        _send_deploy_xmpplog(
            objectxmpp,
            sessionid,
            f"update_linux_command error={str(exc)}",
            priority=priority,
        )
        _send_deploy_xmpplog(
            objectxmpp,
            sessionid,
            "<span class='log_err' style='"
            + ERROR_STYLE
            + "'>Linux update command failed</span>: "
            + str(exc),
            priority=priority,
        )
