# -*- coding: utf-8; -*-
# SPDX-FileCopyrightText: 2026 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-3.0-or-later
# file : pulse_xmpp_master_substitute/lib/plugins/updates/reports.py

"""
Mapping of a machine updates report (Windows or Linux) to the updates tables rows.
"""

import json

from lib.plugins.updates.replication import to_datetime

# machine_reports columns refreshed by the last search only
SEARCH_COLUMNS = (
    "search_status",
    "search_error",
    "search_server",
    "search_duration",
    "searched_at",
)

TITLE_LENGTH = 500

# Architecture names of the Windows reports
ARCHITECTURES = {"x86_64": "x64", "amd64": "x64", "aarch64": "arm64"}


def to_int(value):
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def to_bool(value):
    return None if value is None else bool(value)


def to_date(value):
    return to_datetime(value).date() if value else None


def report_row(jid, report, glpi_uuid=None):
    """machine_reports row (received_at is set by the database)."""
    system = report.get("system") or {}
    esu = report.get("esu") or {}
    search = report.get("search") or {}
    policy = report.get("policy") or {}
    windows11 = report.get("windows11") or {}
    blockers = windows11.get("blockers")
    linux = is_linux(report)
    return {
        "jid": jid,
        "glpi_uuid": glpi_uuid or None,
        "hostname": system.get("hostname") or jid.split("@")[0],
        "format": to_int(report.get("format")),
        "os": "linux" if linux else "windows",
        "distribution": system.get("distribution") if linux else None,
        "family": report.get("family") if linux else None,
        "kernel": system.get("kernel") if linux else None,
        "product": system.get("name") if linux else system.get("product"),
        "edition": system.get("edition"),
        "release": system.get("version") if linux else system.get("release"),
        "build": to_int(system.get("build")),
        "ubr": to_int(system.get("ubr")),
        "architecture": ARCHITECTURES.get(system.get("architecture"), system.get("architecture")),
        "language": system.get("language"),
        "system_type": system.get("type"),
        "esu_licensed": to_bool(esu.get("licensed")),
        "search_status": search.get("status"),
        "search_error": search.get("error"),
        "search_server": search.get("server"),
        "search_duration": to_int(search.get("duration")),
        "searched_at": to_datetime(search.get("searched_at")),
        "wsus_server": policy.get("wsus_server"),
        "automatic_updates": policy.get("automatic_updates"),
        "service_state": policy.get("service"),
        "windows11_eligible": to_bool(windows11.get("eligible")),
        "windows11_blockers": ",".join(blockers) if blockers else None,
        "windows11_source": windows11.get("source"),
        "reboot_pending": to_bool(report.get("reboot_pending")),
        "report": json.dumps(report),
    }


def installed_rows(jid, report):
    """Rows to store, or None when the machine could not list them."""
    if report.get("installed") is None:
        return None
    rows = {}
    for item in report["installed"]:
        kb = to_int(item.get("kb"))
        if kb is not None and kb not in rows:
            rows[kb] = {"jid": jid, "kb": kb, "installed_on": to_date(item.get("date"))}
    return list(rows.values())


def missing_rows(jid, report):
    """Rows to store, or None when the previous list must be kept."""
    search = report.get("search") or {}
    if search.get("status") != "ok":
        return None
    rows = {}
    for item in search.get("missing") or []:
        update_id = item.get("id")
        if update_id and update_id not in rows:
            rows[update_id] = {
                "jid": jid,
                "windows_update_id": update_id,
                "kb": to_int(item.get("kb")),
                "title": (item.get("title") or "")[:TITLE_LENGTH] or None,
            }
    return list(rows.values())


def is_linux(report):
    return report.get("os") == "linux"


def linux_update_rows(jid, report):
    """machine_updates rows of the packages the machine would upgrade, or None
    when the previous list must be kept. Not in the catalog: no update_id."""
    if (report.get("search") or {}).get("status") != "ok":
        return None
    rows = {}
    for item in report.get("packages") or []:
        name = item.get("name")
        key = (name, item.get("arch"))
        if not name or key in rows:
            continue
        rows[key] = {
            "jid": jid,
            "update_id": None,
            "kb": None,
            "title": ("%s %s" % (name, item.get("available") or "")).strip()[:TITLE_LENGTH],
            "origin": "machine",
            "package": name,
            "installed_version": item.get("installed"),
            "available_version": item.get("available"),
            "classification": item.get("classification"),
            "severity": item.get("severity"),
        }
    return list(rows.values())


def updated_columns(report):
    """Columns overwritten when the machine already has a report.

    A throttled (skipped) search keeps the result of the last real search."""
    columns = [column for column in report_row("", report) if column != "jid"]
    if (report.get("search") or {}).get("status") == "skipped":
        columns = [column for column in columns if column not in SEARCH_COLUMNS]
    return columns
