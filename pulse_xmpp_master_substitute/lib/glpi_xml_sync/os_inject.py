# SPDX-FileCopyrightText: 2004-2007 Linbox / Free&ALter Soft, http://linbox.com
# SPDX-FileCopyrightText: 2007 Mandriva, http://www.mandriva.com
# SPDX-FileCopyrightText: 2016-2023 Siveo, http://www.siveo.net
# SPDX-FileCopyrightText: 2024-2025 Medulla, http://www.medulla-tech.io
# SPDX-License-Identifier: GPL-3.0-or-later
# file : pulse_xmpp_master_substitute/lib/glpi_xml_sync/os_inject.py
"""Injection/synchronisation OS vers tables GLPI natives."""

from __future__ import annotations

from typing import Any

from .models import MachineRecord


def _table_columns(cursor: Any, table_name: str) -> set[str]:
    """Retourne les colonnes disponibles d'une table GLPI.

    Args:
        cursor: Curseur SQL actif.
        table_name: Nom de la table cible.

    Returns:
        Ensemble des colonnes detectees.
    """
    cursor.execute(
        """
        SELECT COLUMN_NAME
        FROM INFORMATION_SCHEMA.COLUMNS
        WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = %s
        """,
        (table_name,),
    )
    return {row[0] for row in cursor.fetchall()}


def _get_or_create_by_name(cursor: Any, table: str, name: str) -> int:
    """Cree ou retrouve un enregistrement par son nom dans la table donnee.

    Args:
        cursor: Curseur SQL actif.
        table: Table GLPI cible.
        name: Valeur du champ name a rechercher/creer.

    Returns:
        Identifiant de l'enregistrement existant ou cree.
    """
    cursor.execute(f"SELECT id FROM {table} WHERE name = %s LIMIT 1", (name,))
    row = cursor.fetchone()
    if row:
        return int(row[0])

    cols = _table_columns(cursor, table)
    values: dict[str, Any] = {"name": name}
    if "comment" in cols:
        values["comment"] = ""

    filtered = {k: v for k, v in values.items() if k in cols}
    names = list(filtered.keys())
    placeholders = ", ".join(["%s"] * len(names))
    cursor.execute(
        f"INSERT INTO {table} ({', '.join(names)}) VALUES ({placeholders})",
        tuple(filtered[n] for n in names),
    )
    return int(cursor.lastrowid)


def _get_or_create_version(cursor: Any, os_id: int, version_name: str) -> int:
    """Cree ou retrouve une version d'OS en s'adaptant au schema GLPI reel.

    Args:
        cursor: Curseur SQL actif.
        os_id: Identifiant du systeme d'exploitation parent.
        version_name: Libelle de version a rechercher/creer.

    Returns:
        Identifiant de la version d'OS.
    """
    cols = _table_columns(cursor, "glpi_operatingsystemversions")

    if "operatingsystems_id" in cols:
        cursor.execute(
            """
            SELECT id FROM glpi_operatingsystemversions
            WHERE operatingsystems_id = %s AND name = %s
            LIMIT 1
            """,
            (os_id, version_name),
        )
    else:
        cursor.execute(
            """
            SELECT id FROM glpi_operatingsystemversions
            WHERE name = %s
            LIMIT 1
            """,
            (version_name,),
        )

    row = cursor.fetchone()
    if row:
        return int(row[0])

    values: dict[str, Any] = {"name": version_name}
    if "operatingsystems_id" in cols:
        values["operatingsystems_id"] = os_id

    filtered = {k: v for k, v in values.items() if k in cols}
    names = list(filtered.keys())
    placeholders = ", ".join(["%s"] * len(names))
    cursor.execute(
        f"INSERT INTO glpi_operatingsystemversions ({', '.join(names)}) VALUES ({placeholders})",
        tuple(filtered[n] for n in names),
    )
    return int(cursor.lastrowid)


def sync_operating_system(cursor: Any, computers_id: int, record: MachineRecord) -> str:
    """Synchronise l'OS dans les tables GLPI natives.

    Args:
        cursor: Curseur SQL actif.
        computers_id: Identifiant GLPI du poste.
        record: Donnees machine normalisees.

    Returns:
        os_synced si un OS est traite, sinon os_empty.
    """
    if not record.operating_systems:
        return "os_empty"

    os_data = record.operating_systems[0]
    os_name = (os_data.name or os_data.full_name or "").strip()
    os_version = (os_data.version or "").strip()
    os_arch = (os_data.architecture or "").strip()

    if not os_name:
        return "os_empty"

    os_id = _get_or_create_by_name(cursor, "glpi_operatingsystems", os_name)
    version_id: int | None = None
    arch_id: int | None = None

    if os_version:
        version_id = _get_or_create_version(cursor, os_id, os_version)

    if os_arch:
        arch_id = _get_or_create_by_name(cursor, "glpi_operatingsystemarchitectures", os_arch)

    cols_items = _table_columns(cursor, "glpi_items_operatingsystems")
    cursor.execute(
        """
        SELECT id
        FROM glpi_items_operatingsystems
        WHERE itemtype = 'Computer' AND items_id = %s
        LIMIT 1
        """,
        (computers_id,),
    )
    item_row = cursor.fetchone()

    values: dict[str, Any] = {
        "itemtype": "Computer",
        "items_id": computers_id,
        "operatingsystems_id": os_id,
        "operatingsystemversions_id": version_id,
        "operatingsystemarchitectures_id": arch_id,
        "is_dynamic": 1,
    }
    filtered = {k: v for k, v in values.items() if k in cols_items and v is not None}

    if item_row:
        item_id = int(item_row[0])
        updates = [f"{k} = %s" for k in filtered.keys() if k not in {"itemtype", "items_id"}]
        params = [filtered[k] for k in filtered.keys() if k not in {"itemtype", "items_id"}]
        if updates:
            params.append(item_id)
            cursor.execute(
                f"UPDATE glpi_items_operatingsystems SET {', '.join(updates)} WHERE id = %s",
                tuple(params),
            )
    else:
        names = list(filtered.keys())
        placeholders = ", ".join(["%s"] * len(names))
        cursor.execute(
            f"INSERT INTO glpi_items_operatingsystems ({', '.join(names)}) VALUES ({placeholders})",
            tuple(filtered[n] for n in names),
        )

    return "os_synced"
