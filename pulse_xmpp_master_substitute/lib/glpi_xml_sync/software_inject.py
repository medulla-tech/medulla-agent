# SPDX-FileCopyrightText: 2004-2007 Linbox / Free&ALter Soft, http://linbox.com
# SPDX-FileCopyrightText: 2007 Mandriva, http://www.mandriva.com
# SPDX-FileCopyrightText: 2016-2023 Siveo, http://www.siveo.net
# SPDX-FileCopyrightText: 2024-2025 Medulla, http://www.medulla-tech.io
# SPDX-License-Identifier: GPL-3.0-or-later
# file : pulse_xmpp_master_substitute/lib/glpi_xml_sync/software_inject.py
"""Injection/synchronisation du domaine software."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from .db import now_sql
from .models import MachineRecord, SyncConfig


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


def _dynamic_insert(cursor: Any, table: str, values: dict[str, Any], columns: set[str]) -> int:
    """Insert une ligne en filtrant les champs inexistants dans la table cible.

    Args:
        cursor: Curseur SQL actif.
        table: Table cible.
        values: Valeurs candidates a inserer.
        columns: Colonnes disponibles dans la table cible.

    Returns:
        Identifiant de la ligne creee.
    """
    filtered = {k: v for k, v in values.items() if k in columns}
    if not filtered:
        raise RuntimeError(f"Aucune colonne valide pour l'insert dans {table}")

    names = list(filtered.keys())
    placeholders = ", ".join(["%s"] * len(names))
    sql = f"INSERT INTO {table} ({', '.join(names)}) VALUES ({placeholders})"
    cursor.execute(sql, tuple(filtered[name] for name in names))
    return int(cursor.lastrowid)


def _to_sql_date(raw: str) -> str | None:
    """Convertit une date XML en format SQL YYYY-MM-DD si possible.

    Args:
        raw: Valeur date brute issue de l'inventaire.

    Returns:
        Date au format SQL, ou None si la conversion est impossible.
    """
    value = (raw or "").strip()
    if not value:
        return None

    formats = [
        "%Y-%m-%d",
        "%Y-%m-%d %H:%M:%S",
        "%Y/%m/%d",
        "%d/%m/%Y",
        "%Y%m%d",
    ]
    for fmt in formats:
        try:
            dt = datetime.strptime(value, fmt)
            return dt.strftime("%Y-%m-%d")
        except ValueError:
            continue
    return None


def sync_software(cursor: Any, computers_id: int, record: MachineRecord, config: SyncConfig) -> str:
    """Synchronise les logiciels d'une machine dans GLPI.

    Args:
        cursor: Curseur SQL actif.
        computers_id: Identifiant GLPI du poste.
        record: Donnees machine normalisees.
        config: Configuration metier de synchronisation.

    Returns:
        software_synced si au moins un logiciel est traite, sinon software_empty.
    """
    if not record.softwares:
        return "software_empty"

    now = now_sql()

    cols_softwares = _table_columns(cursor, "glpi_softwares")
    cols_versions = _table_columns(cursor, "glpi_softwareversions")
    cols_links = _table_columns(cursor, "glpi_items_softwareversions")

    cursor.execute(
        """
        SELECT entities_id, is_recursive
        FROM glpi_computers
        WHERE id = %s
        LIMIT 1
        """,
        (computers_id,),
    )
    computer_row = cursor.fetchone()
    entities_id = int(computer_row[0]) if computer_row else config.default_entity
    is_recursive = int(computer_row[1]) if computer_row else config.default_recursive

    cursor.execute(
        """
        SELECT isv.id, s.name, sv.name
        FROM glpi_items_softwareversions isv
        INNER JOIN glpi_softwareversions sv ON sv.id = isv.softwareversions_id
        INNER JOIN glpi_softwares s ON s.id = sv.softwares_id
        WHERE isv.itemtype = 'Computer'
          AND isv.items_id = %s
        """,
        (computers_id,),
    )
    existing_links = {
        f"{(row[1] or '').strip().lower()}||{(row[2] or '').strip().lower()}": int(row[0])
        for row in cursor.fetchall()
    }

    touched = 0
    for sw in record.softwares:
        soft_name = (sw.name or "").strip()
        if not soft_name:
            continue

        soft_version = (sw.version or "").strip()
        soft_comments = (sw.comments or "").strip()

        cursor.execute(
            """
            SELECT id
            FROM glpi_softwares
            WHERE name = %s
              AND entities_id IN (0, %s)
            ORDER BY entities_id DESC
            LIMIT 1
            """,
            (soft_name, entities_id),
        )
        software_row = cursor.fetchone()
        if software_row:
            softwares_id = int(software_row[0])
        else:
            softwares_id = _dynamic_insert(
                cursor,
                "glpi_softwares",
                {
                    "name": soft_name,
                    "entities_id": entities_id,
                    "is_recursive": is_recursive,
                    "comment": soft_comments,
                    "date_mod": now,
                    "date_creation": now,
                },
                cols_softwares,
            )

        cursor.execute(
            """
            SELECT id
            FROM glpi_softwareversions
            WHERE softwares_id = %s AND name = %s
            LIMIT 1
            """,
            (softwares_id, soft_version),
        )
        version_row = cursor.fetchone()
        if version_row:
            softwareversions_id = int(version_row[0])
            if soft_comments and "comment" in cols_versions:
                cursor.execute(
                    "UPDATE glpi_softwareversions SET comment = %s WHERE id = %s",
                    (soft_comments, softwareversions_id),
                )
        else:
            softwareversions_id = _dynamic_insert(
                cursor,
                "glpi_softwareversions",
                {
                    "softwares_id": softwares_id,
                    "name": soft_version,
                    "comment": soft_comments,
                    "is_dynamic": 1,
                    "date_mod": now,
                    "date_creation": now,
                },
                cols_versions,
            )

        link_key = f"{soft_name.lower()}||{soft_version.lower()}"
        install_date = _to_sql_date(sw.install_date)
        if link_key in existing_links:
            link_id = existing_links[link_key]
            update_clauses: list[str] = []
            update_values: list[Any] = []
            if "is_dynamic" in cols_links:
                update_clauses.append("is_dynamic = %s")
                update_values.append(1)
            if install_date and "date_install" in cols_links:
                update_clauses.append("date_install = %s")
                update_values.append(install_date)
            if update_clauses:
                update_values.append(link_id)
                cursor.execute(
                    f"UPDATE glpi_items_softwareversions SET {', '.join(update_clauses)} WHERE id = %s",
                    tuple(update_values),
                )
        else:
            # Unique key conflicts can happen if the same software/version is already linked
            # with a different dynamic flag or if this inventory contains duplicates.
            cursor.execute(
                """
                SELECT id
                FROM glpi_items_softwareversions
                WHERE itemtype = 'Computer'
                  AND items_id = %s
                  AND softwareversions_id = %s
                LIMIT 1
                """,
                (computers_id, softwareversions_id),
            )
            existing_link_row = cursor.fetchone()
            if existing_link_row:
                link_id = int(existing_link_row[0])
                update_clauses: list[str] = []
                update_values: list[Any] = []
                if "is_dynamic" in cols_links:
                    update_clauses.append("is_dynamic = %s")
                    update_values.append(1)
                if install_date and "date_install" in cols_links:
                    update_clauses.append("date_install = %s")
                    update_values.append(install_date)
                if update_clauses:
                    update_values.append(link_id)
                    cursor.execute(
                        f"UPDATE glpi_items_softwareversions SET {', '.join(update_clauses)} WHERE id = %s",
                        tuple(update_values),
                    )
                existing_links[link_key] = link_id
            else:
                link_id = _dynamic_insert(
                    cursor,
                    "glpi_items_softwareversions",
                    {
                        "itemtype": "Computer",
                        "items_id": computers_id,
                        "softwareversions_id": softwareversions_id,
                        "is_dynamic": 1,
                        "date_install": install_date,
                    },
                    cols_links,
                )
                existing_links[link_key] = link_id

        touched += 1

    return "software_synced" if touched else "software_empty"
