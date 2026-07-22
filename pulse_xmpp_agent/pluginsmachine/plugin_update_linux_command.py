# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2016-2023 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-3.0-or-later
# file : pulse_xmpp_agent/pluginsmachine/plugin_update_linux_command.py
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

Additional payload for Debian major-upgrade audit feature:
{
    "section": "upgrade_audit",
    "upgrade_spec": {
        "target_version": "13",
        "target_codename": "trixie",
        "repo_profile": "debian13-main",
        "change_ticket": "CHG-2026-0001",
        "allow_third_party_repositories": false
    }
}

Aliases accepted for major-upgrade audit:
- preupgrade_audit
- preupgrade
"""

import json
import logging
import sys
import importlib
import importlib.util
import subprocess
import glob
import datetime
import re
from pathlib import Path

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

    The grafcet engine wraps the parameters in several keys depending on
    how the descriptor was written. This function resolves the first
    non-empty dict found, in priority order:

    1. marker_payload  -> set by @@@UPDATE_LINUX@@@ / @@@DEPLOY_ACTION_UPDATE_LINUX_COMMAND@@@
    2. payload         -> merged view (advanced.paramdeploy > msc.commands.parameters)
    3. command_parameters -> raw value from msc.commands.parameters
    4. dynamic_param_deploy -> same source as command_parameters (alias)
    5. raw data dict   -> fallback: data itself when no wrapper key is found

    The resolved dict must contain at minimum a 'section' key to be useful.
    If no wrapper key yields a non-empty dict, an empty dict is returned and
    _dispatch_payload will use the default section (update).
    """
    if not isinstance(data, dict):
        return {}

    # Walk priority keys; return the first non-empty dict found.
    for key in ("marker_payload", "payload", "command_parameters", "dynamic_param_deploy"):
        payload = _as_payload(data.get(key))
        if payload:
            return payload

    # Fallback: treat data itself as payload if it has recognized keys
    return _as_payload(data)


def _payload_source(data):
    """Return the source key used to resolve the payload for logging."""
    if not isinstance(data, dict):
        return "none"

    for key in ("marker_payload", "payload", "command_parameters", "dynamic_param_deploy"):
        payload = _as_payload(data.get(key))
        if payload:
            return key

    fallback = _as_payload(data)
    if fallback:
        return "raw_data"
    return "none"


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


def _load_debian_major_upgrade_audit_class():
    """Load DebianMajorUpgradeAudit with robust fallbacks across agent layouts."""
    # 1) Common runtime layout where "lib" is directly importable.
    try:
        module = importlib.import_module("lib.linux_major_upgrade")
        return getattr(module, "DebianMajorUpgradeAudit")
    except Exception:
        pass

    # 2) Legacy/simple layout where module is directly importable by name.
    try:
        module = importlib.import_module("linux_major_upgrade")
        return getattr(module, "DebianMajorUpgradeAudit")
    except Exception:
        pass

    # 3) File-based fallback: sibling lib directory near this plugin file.
    plugin_dir = Path(__file__).resolve().parent
    candidates = [
        plugin_dir.parent / "lib" / "linux_major_upgrade.py",
        Path("/opt/medulla/lib/python3.11/site-packages/pulse_xmpp_agent/lib/linux_major_upgrade.py"),
        Path("/usr/local/lib/python3.11/dist-packages/pulse_xmpp_agent/lib/linux_major_upgrade.py"),
        Path("/usr/lib/python3/dist-packages/pulse_xmpp_agent/lib/linux_major_upgrade.py"),
    ]

    for candidate in candidates:
        if not candidate.exists():
            continue
        spec = importlib.util.spec_from_file_location("linux_major_upgrade", str(candidate))
        if spec is None or spec.loader is None:
            continue
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return getattr(module, "DebianMajorUpgradeAudit")

    raise ModuleNotFoundError("DebianMajorUpgradeAudit loader: linux_major_upgrade.py not found in known paths")


def _handle_upgrade_audit_section(updater, payload, result):
    """Handle section=upgrade_audit/preupgrade for Debian major-upgrade audit.

    This section collects host data automatically and validates missing
    external data required to perform a major OS upgrade safely.
    """
    try:
        DebianMajorUpgradeAudit = _load_debian_major_upgrade_audit_class()

        audit = DebianMajorUpgradeAudit(payload=payload).build()
        result["upgrade_audit"] = audit
        result["message"] = (
            "Major upgrade audit ready"
            if audit.get("upgrade_possible")
            else "Major upgrade audit blocked"
        )
        result["applied"].append(
            {
                "action": "upgrade_audit",
                "upgrade_possible": bool(audit.get("upgrade_possible")),
                "missing_external_data": list(audit.get("missing_external_data") or []),
                "blocking_reasons": list(audit.get("blocking_reasons") or []),
            }
        )
        return result
    except Exception as exc:
        result["message"] = "upgrade_audit failed"
        result["applied"].append({"action": "upgrade_audit", "error": str(exc)})
        return result


def _run_release_upgrade_command(command, callback=None):
    """Run a shell command for release-upgrade workflow and return output."""
    if callback:
        callback(f"[CMD] {command}")
    output = subprocess.check_output(
        command,
        shell=True,
        text=True,
        stderr=subprocess.STDOUT,
    ).strip()
    if callback and output:
        preview = (output[:700] + "...") if len(output) > 700 else output
        callback(f"[OUT] {preview}")
    return output


def _rewrite_apt_sources_for_target(current_codename, target_codename, current_version=None, target_version=None, callback=None):
    """Rewrite APT source files for Debian release upgrade.

    Covers both codename-based entries (bookworm->trixie) and versioned
    repository paths (debian/12->debian/13). Returns a summary dict with
    changed files and backups.
    """
    files = ["/etc/apt/sources.list"]
    files.extend(sorted(glob.glob("/etc/apt/sources.list.d/*.list")))
    files.extend(sorted(glob.glob("/etc/apt/sources.list.d/*.sources")))

    changed_files = []
    backup_files = []
    ts = datetime.datetime.utcnow().strftime("%Y%m%d-%H%M%S")

    replacements = [
        (re.compile(rf"\b{re.escape(current_codename)}-security\b"), f"{target_codename}-security"),
        (re.compile(rf"\b{re.escape(current_codename)}-updates\b"), f"{target_codename}-updates"),
        (re.compile(rf"\b{re.escape(current_codename)}-backports\b"), f"{target_codename}-backports"),
        (re.compile(rf"\b{re.escape(current_codename)}\b"), target_codename),
    ]

    # Handle repo URLs like .../debian/12/... in .list and .sources files.
    if current_version and target_version:
        replacements.append(
            (
                re.compile(rf"(/debian/){re.escape(str(current_version))}(?=/)"),
                rf"\g<1>{target_version}",
            )
        )
        replacements.append(
            (
                re.compile(rf"(/debian-security/){re.escape(str(current_version))}(?=/)"),
                rf"\g<1>{target_version}",
            )
        )

    for path in files:
        p = Path(path)
        if not p.exists():
            continue
        try:
            original = p.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue

        updated = original
        hit_count = 0
        for pattern, replacement in replacements:
            updated, hits = pattern.subn(replacement, updated)
            hit_count += hits

        if updated != original:
            backup = f"{path}.bak-upgrade-{ts}"
            Path(backup).write_text(original, encoding="utf-8")
            p.write_text(updated, encoding="utf-8")
            changed_files.append(path)
            backup_files.append(backup)
            if callback:
                callback(f"[INFO] sources updated: {path} (backup: {backup}, replacements: {hit_count})")

    return {"changed_files": changed_files, "backup_files": backup_files}


def _probe_apt_source_url(url, timeout=8):
    """Probe a single APT repo URL with an HTTP HEAD request.

    Returns (ok: bool, status_code_or_error: str).
    """
    import urllib.request
    import urllib.error
    try:
        req = urllib.request.Request(url, method="HEAD")
        req.add_header("User-Agent", "Debian APT-HTTP/1.3 (medulla-upgrade-probe)")
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return True, str(resp.status)
    except urllib.error.HTTPError as e:
        return False, str(e.code)
    except Exception as e:
        return False, str(e)


def _extract_urls_from_sources_line(line):
    """Extract the repo base URL from a deb/URIs source line."""
    stripped = line.strip()
    if stripped.startswith("#") or not stripped:
        return None
    if stripped.startswith("deb ") or stripped.startswith("deb-src "):
        parts = stripped.split()
        for part in parts[1:]:
            if part.startswith("http://") or part.startswith("https://"):
                return part.rstrip("/") + "/"
            # skip option blocks like [trusted=yes]
            if part.startswith("["):
                continue
        return None
    if stripped.startswith("URIs:"):
        val = stripped.split(":", 1)[1].strip()
        url = val.split()[0] if val else ""
        return url.rstrip("/") + "/" if url.startswith("http") else None
    return None


def _comment_out_unavailable_apt_sources(callback=None, timeout=8):
    """Probe each APT repo URL, comment out unavailable ones with a message.

    Returns a dict with commented_files, commented_lines, probe_results.
    """
    files = ["/etc/apt/sources.list"]
    files.extend(sorted(glob.glob("/etc/apt/sources.list.d/*.list")))
    files.extend(sorted(glob.glob("/etc/apt/sources.list.d/*.sources")))

    ts = datetime.datetime.utcnow().strftime("%Y%m%d-%H%M%S")
    commented_files = []
    commented_lines = []
    probe_results = []
    seen_urls = {}

    for path in files:
        p = Path(path)
        if not p.exists():
            continue
        try:
            original_lines = p.read_text(encoding="utf-8", errors="ignore").splitlines(keepends=True)
        except Exception:
            continue

        new_lines = []
        file_changed = False

        for line in original_lines:
            stripped = line.rstrip("\n").rstrip("\r")
            url = _extract_urls_from_sources_line(stripped)

            if url is None or stripped.lstrip().startswith("#"):
                new_lines.append(line)
                continue

            if url in seen_urls:
                ok = seen_urls[url][0]
                status = seen_urls[url][1]
            else:
                ok, status = _probe_apt_source_url(url, timeout=timeout)
                seen_urls[url] = (ok, status)
                probe_results.append({"url": url, "ok": ok, "status": status})
                if callback:
                    indicator = "OK" if ok else "UNAVAILABLE"
                    callback(f"[PROBE] {indicator} (http {status}): {url}")

            if not ok:
                comment_line = f"# [medulla-upgrade-{ts}] commented out: HTTP {status} on {url}\n"
                new_lines.append(comment_line)
                new_lines.append("# " + line if not line.startswith("#") else line)
                file_changed = True
                commented_lines.append({"file": path, "url": url, "status": status, "line": stripped})
                if callback:
                    callback(f"[WARN] source commented out in {path}: {stripped[:120]} (HTTP {status})")
            else:
                new_lines.append(line)

        if file_changed:
            backup = f"{path}.bak-probe-{ts}"
            p.with_name(Path(path).name).write_text("".join(original_lines), encoding="utf-8")
            Path(backup).write_text("".join(original_lines), encoding="utf-8")
            p.write_text("".join(new_lines), encoding="utf-8")
            commented_files.append(path)
            if callback:
                callback(f"[INFO] {path} updated: unavailable sources commented out (backup: {backup})")

    return {
        "commented_files": commented_files,
        "commented_lines": commented_lines,
        "probe_results": probe_results,
    }



def _execute_debian_release_upgrade(updater, payload, audit, result):
    """Execute Debian release-upgrade steps after audit validation.

    This function updates APT sources from current codename to target codename,
    refreshes indexes, then runs upgrade/full-upgrade.
    """
    callback = None
    try:
        callback = getattr(getattr(updater, "system", None), "_log_callback", None)
    except Exception:
        callback = None

    current = audit.get("current_system") or {}
    provided = audit.get("provided_external_data") or {}
    distro = str(current.get("distribution", "")).lower()
    current_codename = str(current.get("codename", "")).strip().lower()
    current_version = str(current.get("version", "")).strip()
    target_codename = str(provided.get("target_codename", "")).strip().lower()
    target_version = str(provided.get("target_version", "")).strip()

    if distro != "debian":
        raise RuntimeError(f"release upgrade execution currently supported only for Debian (got: {distro})")
    if not current_codename or not target_codename:
        raise RuntimeError("missing current_codename or target_codename in audit result")
    if current_codename == target_codename:
        if callback:
            callback(f"[INFO] source codename already target ({target_codename}), skipping source rewrite")
        source_change = {"changed_files": [], "backup_files": []}
    else:
        source_change = _rewrite_apt_sources_for_target(
            current_codename,
            target_codename,
            current_version=current_version,
            target_version=target_version,
            callback=callback,
        )

    execution_warnings = []
    # Vérifier chaque source APT et commenter celles qui sont indisponibles
    # avant de lancer apt-get update pour éviter des erreurs 404 bloquantes.
    probe_result = _comment_out_unavailable_apt_sources(callback=callback, timeout=8)
    if probe_result["commented_lines"]:
        commented_info = {
            "code": "APT_SOURCES_COMMENTED_OUT",
            "message": f"{len(probe_result['commented_lines'])} source(s) indisponible(s) commentée(s) avant apt-get update.",
            "commented_lines": probe_result["commented_lines"],
        }
        execution_warnings.append(commented_info)
        if callback:
            callback(f"[INFO] {commented_info['message']}")

    update_cmd = "DEBIAN_FRONTEND=noninteractive apt-get -qq update"
    try:
        _run_release_upgrade_command(update_cmd, callback=callback)
    except subprocess.CalledProcessError as exc:
        if getattr(exc, "returncode", None) == 100:
            raw_output = str(getattr(exc, "output", "") or "").strip()
            tail = "\n".join(raw_output.splitlines()[-12:]) if raw_output else ""
            warning_message = (
                "apt-get update returned rc=100 (partial index refresh). "
                "Continuing with available indexes."
            )
            execution_warnings.append(
                {
                    "code": "APT_UPDATE_PARTIAL_FAILURE",
                    "message": warning_message,
                    "command": update_cmd,
                    "returncode": 100,
                    "output_tail": tail,
                }
            )
            if callback:
                callback(f"[WARN] {warning_message}")
                if tail:
                    preview = (tail[:700] + "...") if len(tail) > 700 else tail
                    callback(f"[WARN_OUT] {preview}")
        else:
            raise

    _run_release_upgrade_command("DEBIAN_FRONTEND=noninteractive apt-get -y upgrade", callback=callback)
    _run_release_upgrade_command("DEBIAN_FRONTEND=noninteractive apt-get -y full-upgrade", callback=callback)

    execute_result = {
        "action": "upgrade_execute",
        "status": "completed",
        "current_codename": current_codename,
        "target_codename": target_codename,
        "target_version": target_version,
        "repo_profile": provided.get("repo_profile", ""),
        "change_ticket": provided.get("change_ticket", ""),
        "sources_changed": source_change.get("changed_files", []),
        "sources_backups": source_change.get("backup_files", []),
        "warnings": execution_warnings,
    }
    result["applied"].append(execute_result)
    result["message"] = (
        f"Release upgrade execution completed: {current_codename} -> {target_codename} "
        f"(target_version={target_version})"
    )
    return result


def _normalize_upgrade_payload(payload):
    """Normalize upgrade payload: map upgradeparameter -> upgrade_spec if needed."""
    if isinstance(payload.get("upgrade_spec"), dict):
        return payload
    if isinstance(payload.get("upgradeparameter"), dict):
        normalized = dict(payload)
        normalized["upgrade_spec"] = payload["upgradeparameter"]
        return normalized
    return payload


def _handle_upgrade_section(updater, payload, result):
    """Handle section=upgrade for major OS upgrade (Debian 12->13, etc.).

    Accepts upgradeparameter (field name used by grafcet descriptors) or
    upgrade_spec (canonical internal key) and delegates to upgrade_audit.
    """
    result["section"] = "upgrade"
    normalized = _normalize_upgrade_payload(payload)
    result = _handle_upgrade_audit_section(updater, normalized, result)

    audit = result.get("upgrade_audit") or {}
    if not audit:
        result["message"] = "upgrade failed: audit payload missing"
        result["applied"].append({"action": "upgrade_execute", "status": "skipped", "reason": "audit_missing"})
        return result

    if not audit.get("upgrade_possible", False):
        result["message"] = "upgrade blocked: audit did not pass"
        result["applied"].append(
            {
                "action": "upgrade_execute",
                "status": "skipped",
                "reason": "audit_blocked",
                "blocking_reasons": list(audit.get("blocking_reasons") or []),
            }
        )
        return result

    try:
        return _execute_debian_release_upgrade(updater, normalized, audit, result)
    except Exception as exc:
        result["message"] = f"upgrade execution failed: {str(exc)}"
        result["applied"].append({"action": "upgrade_execute", "status": "failed", "error": str(exc)})
        return result


# ---------------------------------------------------------------------------
# Handler registry: section value in payload -> handler function
#
# The 'section' key inside the resolved payload dict selects which handler
# is called. If the key is absent, 'update' is used as default.
#
# section = "update"
#   Classic Linux update: expects linux_actions list ([security, kernel, other])
#   or an explicit policy string.
#   Example payload:
#     {"section": "update", "linux_actions": ["security", "kernel"]}
#
# section = "upgrade"
#   Debian major upgrade (12 -> 13, etc.): expects upgradeparameter or
#   upgrade_spec dict with target_version, target_codename, repo_profile,
#   change_ticket. Calls DebianMajorUpgradeAudit to validate and prepare.
#   Example payload:
#     {"section": "upgrade", "upgradeparameter": {
#         "target_version": "13", "target_codename": "trixie",
#         "repo_profile": "debian13-main", "change_ticket": "CHG-001"}}
#
# section = "upgrade_audit" / "preupgrade_audit" / "preupgrade"
#   Same as upgrade but with canonical key upgrade_spec.
#
# section = "maintenance"
#   Triggers system maintenance (clean, autoremove, etc.).
#
# section = "fetch" / "inventory" / "scan"
#   Refreshes the local update inventory without installing anything.
#
# section = "message"
#   Sends a free-text message through the deployment log.
#   Example payload:
#     {"section": "message", "message": "Preparation terminee"}
#
# Extensibility point:
#   To add a new feature:
#   1. Create _handle_<name>_section(updater, payload, result)
#   2. Add the section alias(es) in SECTION_HANDLERS below.
# ---------------------------------------------------------------------------
SECTION_HANDLERS = {
    "update":          _handle_update_section,       # classic: linux_actions=[security|kernel|other]
    "upgrade":         _handle_upgrade_section,      # major upgrade: upgradeparameter ou upgrade_spec
    "upgrade_audit":   _handle_upgrade_audit_section,# idem upgrade avec cle upgrade_spec
    "preupgrade_audit":_handle_upgrade_audit_section,# alias preupgrade
    "preupgrade":      _handle_upgrade_audit_section,# alias preupgrade
    "maintenance":     _handle_maintenance_section,  # nettoyage systeme
    "fetch":           _handle_fetch_section,        # inventaire sans installation
    "inventory":       _handle_fetch_section,        # alias fetch
    "scan":            _handle_fetch_section,        # alias fetch
    "message":         _handle_message_section,      # message libre dans le log
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
    """Dispatch plugin behavior from JSON payload content using handler registry.

    Selection logic:
      1. Read payload["section"] (default: "update" if absent).
      2. Look up the section in SECTION_HANDLERS.
      3. Call the matching handler(updater, payload, result).
      4. If section is unknown, return an error result without raising.
    """
    # Step 1: resolve section from payload (default to classic update)
    section = str(payload.get("section", "update")).strip().lower()

    # Backward-compatible routing:
    # some descriptors still send section=update with upgradeparameter payload.
    # In that case, route to upgrade handler when no classic update intent is present.
    has_upgrade_payload = isinstance(payload.get("upgradeparameter"), dict) or isinstance(
        payload.get("upgrade_spec"), dict
    )
    has_classic_update_intent = bool(_as_list(payload.get("linux_actions"))) or bool(
        payload.get("linux_policy") or payload.get("policy")
    )
    if section == "update" and has_upgrade_payload and not has_classic_update_intent:
        logger.info(
            "update_linux_command compat routing: section=update + upgrade payload -> section=upgrade"
        )
        section = "upgrade"

    logger.info("update_linux_command dispatch: section=%s", section)

    requested_actions = _as_list(payload.get("linux_actions"))
    unknown_actions = [x for x in requested_actions if x not in SUPPORTED_LINUX_ACTIONS]
    result = _new_result(section, requested_actions, unknown_actions)

    # Step 2: find handler in registry
    handler = SECTION_HANDLERS.get(section)
    if handler is None:
        # Unknown section: log and return gracefully
        logger.warning("update_linux_command: unknown section '%s' — no handler found", section)
        result["message"] = "Unsupported section or empty payload"
        return result

    # Step 3: execute handler
    logger.info("update_linux_command handler selected: %s -> %s", section, handler.__name__)
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

def _make_xmpplog_callback(objectxmpp, sessionid, priority):
    """Return a log function sent via xmpplog for each system command/output.

    The returned callback is passed to UpdateLinux so every apt command and
    its output is forwarded to the deployment session log in real time.
    """
    def callback(message: str):
        logger.info("[UPDATE_ACTION] %s", message)
        _send_deploy_xmpplog(objectxmpp, sessionid, message, priority=priority)
    return callback


@utils.set_logging_level
def action(objectxmpp, action, sessionid, data, message, dataerreur):
    """Run Linux updates based on descriptor parameters.

    The plugin intentionally logs result details and lets the deployment
    workflow continue. Errors are logged for troubleshooting.
    """
    logger.debug("###################################################")
    logger.debug("call %s from %s", plugin, message["from"])
    logger.debug("###################################################")
    logger.info(
        "update_linux_command called: sessionid=%s from=%s to=%s",
        sessionid,
        message.get("from", ""),
        message.get("to", ""),
    )
    logger.info("[DEV] ma data %s", json.dumps(data, indent=4))
    logger.info("update_linux_command payload source: %s", _payload_source(data))
    payload = _extract_payload(data)
    logger.info("[DEV] update_linux_command payload: %s", json.dumps(payload, indent=4))
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
        # log_callback forwards every apt command and output to xmpplog in real time.
        xmpp_log = _make_xmpplog_callback(objectxmpp, sessionid, priority)
        updater = UpdateLinux(dry_run=False, intranet_security=False, log_callback=xmpp_log)
        result = _dispatch_payload(updater, payload)
        logger.info(
            "[DEV] update_linux_command result: %s",
            json.dumps(result, indent=4, sort_keys=True),
        )

        _send_deploy_xmpplog(
            objectxmpp,
            sessionid,
            "update_linux_command result=" + json.dumps(result, sort_keys=True),
            priority=priority,
        )

        # Send a detailed xmpplog line per applied/failed entry for upgrade/audit sections
        section = str(result.get("section", "")).lower()
        if section in ("upgrade", "upgrade_audit", "preupgrade_audit", "preupgrade"):
            audit = result.get("upgrade_audit", {})
            if audit:
                upgrade_possible = audit.get("upgrade_possible", False)
                blocking = audit.get("blocking_reasons") or []
                missing = audit.get("missing_external_data") or []
                provided = audit.get("provided_external_data") or {}
                current = audit.get("current_system") or {}

                _send_deploy_xmpplog(objectxmpp, sessionid,
                    f"upgrade_audit: distribution={current.get('distro_id','?')} "
                    f"version={current.get('current_version','?')} "
                    f"codename={current.get('current_codename','?')}",
                    priority=priority)

                _send_deploy_xmpplog(objectxmpp, sessionid,
                    f"upgrade_audit: target={provided.get('target_version','?')} "
                    f"codename={provided.get('target_codename','?')} "
                    f"profile={provided.get('repo_profile','?')} "
                    f"ticket={provided.get('change_ticket','?')}",
                    priority=priority)

                resources = audit.get("resources") or {}
                disks = resources.get("disk_free_gb") or {}
                mem = resources.get("memory") or {}
                _send_deploy_xmpplog(objectxmpp, sessionid,
                    f"upgrade_audit: disk_root={disks.get('/','?')}GB "
                    f"disk_var={disks.get('/var','?')}GB "
                    f"disk_boot={disks.get('/boot','?')}GB "
                    f"ram_total_mb={mem.get('ram_total_mb','?')}",
                    priority=priority)

                pkg_state = resources.get("package_state") or {}
                _send_deploy_xmpplog(objectxmpp, sessionid,
                    f"upgrade_audit: apt_check={pkg_state.get('apt_check_ok','?')} "
                    f"apt_update={pkg_state.get('apt_update_ok','?')} "
                    f"broken={pkg_state.get('broken_packages','?')} "
                    f"held={pkg_state.get('held_packages',[])}",
                    priority=priority)

                third_party = audit.get("third_party_repositories") or []
                if third_party:
                    _send_deploy_xmpplog(objectxmpp, sessionid,
                        f"upgrade_audit: third_party_repos={[r.get('source','?') for r in third_party]}",
                        priority=priority)

                if blocking:
                    _send_deploy_xmpplog(objectxmpp, sessionid,
                        "<span style='" + ERROR_STYLE + "'>upgrade_audit BLOCKED</span>: "
                        + ", ".join(blocking),
                        priority=priority)
                else:
                    _send_deploy_xmpplog(objectxmpp, sessionid,
                        "<span style='" + SUCCESS_STYLE + "'>upgrade_audit OK</span>: upgrade_possible=True",
                        priority=priority)

                if missing:
                    _send_deploy_xmpplog(objectxmpp, sessionid,
                        f"upgrade_audit: missing_external_data={missing}",
                        priority=priority)

            # Intelligent execution message for release-upgrade
            execute_entry = None
            for entry in result.get("applied", []):
                if isinstance(entry, dict) and entry.get("action") == "upgrade_execute":
                    execute_entry = entry
                    break
            if execute_entry:
                status = str(execute_entry.get("status", "")).lower()
                src = execute_entry.get("current_codename", "?")
                dst = execute_entry.get("target_codename", "?")
                ticket = execute_entry.get("change_ticket", "")
                if status == "completed":
                    _send_deploy_xmpplog(
                        objectxmpp,
                        sessionid,
                        "<span style='" + SUCCESS_STYLE + "'>Release upgrade started and completed</span>: "
                        f"{src} -> {dst} ticket={ticket}",
                        priority=priority,
                    )
                    changed = execute_entry.get("sources_changed") or []
                    if changed:
                        _send_deploy_xmpplog(
                            objectxmpp,
                            sessionid,
                            f"upgrade_execute: apt sources updated={changed}",
                            priority=priority,
                        )
                elif status == "skipped":
                    _send_deploy_xmpplog(
                        objectxmpp,
                        sessionid,
                        "<span style='" + ERROR_STYLE + "'>Release upgrade not started</span>: "
                        + str(execute_entry.get("reason", "unknown")),
                        priority=priority,
                    )
                elif status == "failed":
                    _send_deploy_xmpplog(
                        objectxmpp,
                        sessionid,
                        "<span style='" + ERROR_STYLE + "'>Release upgrade failed</span>: "
                        + str(execute_entry.get("error", "unknown error")),
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
