# SPDX-FileCopyrightText: 2004-2007 Linbox / Free&ALter Soft, http://linbox.com
# SPDX-FileCopyrightText: 2007 Mandriva, http://www.mandriva.com
# SPDX-FileCopyrightText: 2016-2023 Siveo, http://www.siveo.net
# SPDX-FileCopyrightText: 2024-2025 Medulla, http://www.medulla-tech.io
# SPDX-License-Identifier: GPL-3.0-or-later
# file : pulse_xmpp_master_substitute/lib/glpi_xml_sync/machine_inject.py
"""Injection/synchronisation du domaine machine (core)."""

from __future__ import annotations

from typing import Any

from .db import now_sql
from .models import MachineRecord, SyncConfig


def sync_machine(cursor: Any, record: MachineRecord, config: SyncConfig) -> tuple[str, int]:
    """Cree ou met a jour la machine GLPI et retourne (action, computers_id).

    Mode standalone: pas de dependance a glpi_plugin_ocsinventoryng_ocslinks.
    Recherche d'existant par serial puis name.

    Args:
        cursor: Curseur SQL actif.
        record: Donnees machine normalisees.
        config: Configuration metier inject/sync.

    Returns:
        Tuple (action, computers_id) avec action inserted, updated,
        skipped_existing ou sync_created.
    """
    row = None
    if record.serial:
        cursor.execute(
            """
            SELECT id
            FROM glpi_computers
            WHERE serial = %s
            ORDER BY id ASC
            LIMIT 1
            """,
            (record.serial,),
        )
        row = cursor.fetchone()

    if row is None and record.name:
        cursor.execute(
            """
            SELECT id
            FROM glpi_computers
            WHERE name = %s
            ORDER BY id ASC
            LIMIT 1
            """,
            (record.name,),
        )
        row = cursor.fetchone()

    current_time = now_sql()

    if row:
        computers_id = row[0]
        # En mode inject, on n'ecrase jamais une machine deja presente.
        if config.mode == "inject":
            return "skipped_existing", int(computers_id)

        cursor.execute(
            """
            UPDATE glpi_computers
            SET name = %s,
                serial = %s,
                date_mod = %s,
                is_dynamic = 1
            WHERE id = %s
            """,
            (record.name, record.serial, current_time, computers_id),
        )
        return "updated", int(computers_id)

    action = "sync_created" if config.mode == "sync" else "inserted"

    cursor.execute(
        """
        INSERT INTO glpi_computers
            (entities_id, name, serial, is_recursive, is_dynamic, date_mod, date_creation)
        VALUES
            (%s, %s, %s, %s, 1, %s, %s)
        """,
        (
            config.default_entity,
            record.name,
            record.serial,
            config.default_recursive,
            current_time,
            current_time,
        ),
    )
    computers_id = int(cursor.lastrowid)
    return action, computers_id
