# SPDX-FileCopyrightText: 2004-2007 Linbox / Free&ALter Soft, http://linbox.com
# SPDX-FileCopyrightText: 2007 Mandriva, http://www.mandriva.com
# SPDX-FileCopyrightText: 2016-2023 Siveo, http://www.siveo.net
# SPDX-FileCopyrightText: 2024-2025 Medulla, http://www.medulla-tech.io
# SPDX-License-Identifier: GPL-3.0-or-later
# file : pulse_xmpp_master_substitute/lib/glpi_xml_sync/peripheral_inject.py
"""Injection native GLPI des imprimantes et peripheriques issus des sections XML brutes."""

from __future__ import annotations

import logging
from typing import Any

from .db import now_sql
from .models import MachineRecord, SyncConfig


logger = logging.getLogger(__name__)


def _get_peripheral_link_backend(cursor: Any) -> dict[str, Any] | None:
    """Detecte la table de liaison peripherique <-> ordinateur selon la version GLPI.

    GLPI 11 utilise `glpi_assets_assets_peripheralassets`.
    GLPI 10.x utilise `glpi_computers_items` pour ce type de liaison.
    """
    if _table_exists(cursor, "glpi_assets_assets_peripheralassets"):
        return {
            "kind": "assets_peripheralassets",
            "table": "glpi_assets_assets_peripheralassets",
            "columns": _table_columns(cursor, "glpi_assets_assets_peripheralassets"),
        }

    if _table_exists(cursor, "glpi_computers_items"):
        return {
            "kind": "computers_items",
            "table": "glpi_computers_items",
            "columns": _table_columns(cursor, "glpi_computers_items"),
        }

    logger.warning(
        "No supported peripheral link table found (expected glpi_assets_assets_peripheralassets or glpi_computers_items)"
    )
    return None


def _table_columns(cursor: Any, table_name: str) -> set[str]:
    """Retourne les colonnes disponibles d'une table GLPI.

    Args:
        cursor: Curseur SQL actif.
        table_name: Nom de la table cible dans le schema courant.

    Returns:
        Ensemble des noms de colonnes detectees.
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


def _table_exists(cursor: Any, table_name: str) -> bool:
    """Verifie si une table existe dans le schema courant.

    Args:
        cursor: Curseur SQL actif.
        table_name: Nom de table a verifier.

    Returns:
        True si la table existe, sinon False.
    """
    cursor.execute(
        """
        SELECT 1
        FROM INFORMATION_SCHEMA.TABLES
        WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = %s
        LIMIT 1
        """,
        (table_name,),
    )
    return cursor.fetchone() is not None


def _dynamic_insert(cursor: Any, table: str, values: dict[str, Any], columns: set[str]) -> int:
    """Insere une ligne en filtrant sur les colonnes disponibles.

    Args:
        cursor: Curseur SQL actif.
        table: Nom de la table cible.
        values: Dictionnaire de valeurs candidates a inserer.
        columns: Colonnes autorisees dans la table cible.

    Returns:
        Identifiant de la ligne creee.
    """
    filtered = {key: value for key, value in values.items() if key in columns and value is not None}
    names = list(filtered.keys())
    placeholders = ", ".join(["%s"] * len(names))
    cursor.execute(
        f"INSERT INTO {table} ({', '.join(names)}) VALUES ({placeholders})",
        tuple(filtered[name] for name in names),
    )
    return int(cursor.lastrowid)


def _update_by_id(cursor: Any, table: str, row_id: int, values: dict[str, Any], columns: set[str]) -> None:
    """Met a jour une ligne par son identifiant en filtrant les colonnes disponibles.

    Args:
        cursor: Curseur SQL actif.
        table: Nom de la table cible.
        row_id: Identifiant de la ligne a mettre a jour.
        values: Dictionnaire de valeurs candidates a ecrire.
        columns: Colonnes autorisees dans la table cible.
    """
    filtered = {key: value for key, value in values.items() if key in columns and value is not None}
    if not filtered:
        return
    assignments = ", ".join(f"{key} = %s" for key in filtered)
    params = [filtered[key] for key in filtered]
    params.append(row_id)
    cursor.execute(f"UPDATE {table} SET {assignments} WHERE id = %s", tuple(params))


def _find_linked_item(
    cursor: Any,
    table: str,
    itemtype_peripheral: str,
    computers_id: int,
    name: str,
    link_backend: dict[str, Any],
) -> int | None:
    """Recherche un peripherique deja lie a un ordinateur via la table d'assets.

    Args:
        cursor: Curseur SQL actif.
        table: Table cible (`glpi_printers` ou `glpi_peripherals`).
        itemtype_peripheral: Type GLPI du peripherique (`Printer` ou `Peripheral`).
        computers_id: Identifiant GLPI du poste.
        name: Nom logique du peripherique recherche.

    Returns:
        Identifiant trouve, ou None si aucun lien n'existe.
    """
    # La recherche passe par la table de liaison pour eviter de confondre
    # des peripheriques homonymes affectes a d'autres machines.
    if link_backend["kind"] == "assets_peripheralassets":
        cursor.execute(
            f"""
            SELECT target.id
            FROM {table} AS target
            INNER JOIN glpi_assets_assets_peripheralassets AS link
                ON link.items_id_peripheral = target.id
            WHERE target.name = %s
              AND link.itemtype_peripheral = %s
              AND link.items_id_asset = %s
              AND link.itemtype_asset = 'Computer'
            ORDER BY target.id ASC
            LIMIT 1
            """,
            (name, itemtype_peripheral, computers_id),
        )
    else:
        cursor.execute(
            f"""
            SELECT target.id
            FROM {table} AS target
            INNER JOIN glpi_computers_items AS link
                ON link.items_id = target.id
            WHERE target.name = %s
              AND link.itemtype = %s
              AND link.computers_id = %s
            ORDER BY target.id ASC
            LIMIT 1
            """,
            (name, itemtype_peripheral, computers_id),
        )
    row = cursor.fetchone()
    return int(row[0]) if row else None


def _ensure_link(
    cursor: Any,
    computers_id: int,
    itemtype_peripheral: str,
    peripheral_id: int,
    link_backend: dict[str, Any],
) -> None:
    """Cree ou met a jour le lien entre un peripherique et un ordinateur GLPI.

    Args:
        cursor: Curseur SQL actif.
        computers_id: Identifiant GLPI du poste.
        itemtype_peripheral: Type GLPI du peripherique.
        peripheral_id: Identifiant du peripherique.
        cols_links: Colonnes disponibles dans la table de liaison.
    """
    cols_links = link_backend["columns"]

    if link_backend["kind"] == "assets_peripheralassets":
        cursor.execute(
            """
            SELECT id
            FROM glpi_assets_assets_peripheralassets
            WHERE items_id_asset = %s
              AND itemtype_asset = 'Computer'
              AND itemtype_peripheral = %s
              AND items_id_peripheral = %s
            LIMIT 1
            """,
            (computers_id, itemtype_peripheral, peripheral_id),
        )
    else:
        cursor.execute(
            """
            SELECT id
            FROM glpi_computers_items
            WHERE computers_id = %s
              AND itemtype = %s
              AND items_id = %s
            LIMIT 1
            """,
            (computers_id, itemtype_peripheral, peripheral_id),
        )
    row = cursor.fetchone()
    now = now_sql()
    if row:
        if link_backend["kind"] == "assets_peripheralassets":
            _update_by_id(
                cursor,
                "glpi_assets_assets_peripheralassets",
                int(row[0]),
                {
                    "is_dynamic": 1,
                    "is_deleted": 0,
                    "date_mod": now,
                },
                cols_links,
            )
        else:
            _update_by_id(
                cursor,
                "glpi_computers_items",
                int(row[0]),
                {
                    "is_dynamic": 1,
                    "is_deleted": 0,
                    "date_mod": now,
                },
                cols_links,
            )
        return

    if link_backend["kind"] == "assets_peripheralassets":
        _dynamic_insert(
            cursor,
            "glpi_assets_assets_peripheralassets",
            {
                "items_id_asset": computers_id,
                "itemtype_asset": "Computer",
                "itemtype_peripheral": itemtype_peripheral,
                "items_id_peripheral": peripheral_id,
                "is_dynamic": 1,
                "is_deleted": 0,
                "date_creation": now,
                "date_mod": now,
            },
            cols_links,
        )
    else:
        _dynamic_insert(
            cursor,
            "glpi_computers_items",
            {
                "computers_id": computers_id,
                "itemtype": itemtype_peripheral,
                "items_id": peripheral_id,
                "is_dynamic": 1,
                "is_deleted": 0,
                "date_creation": now,
                "date_mod": now,
            },
            cols_links,
        )


def _sync_printers(cursor: Any, computers_id: int, entries: list[dict[str, str]], config: SyncConfig) -> int:
    """Synchronise les imprimantes remontees par l'inventaire.

    Args:
        cursor: Curseur SQL actif.
        computers_id: Identifiant GLPI du poste.
        entries: Lignes brutes de la section PRINTERS.
        config: Configuration metier (entite par defaut, etc.).

    Returns:
        Nombre d'imprimantes traitees.
    """
    if not entries or not _table_exists(cursor, "glpi_printers"):
        return 0

    link_backend = _get_peripheral_link_backend(cursor)
    if link_backend is None:
        return 0

    cols_printers = _table_columns(cursor, "glpi_printers")
    touched = 0
    now = now_sql()

    for entry in entries:
        # L'inventaire peut varier selon l'agent: on compose un nom a partir
        # des champs les plus fiables disponibles.
        name = (entry.get("NAME") or entry.get("DESCRIPTION") or entry.get("DRIVER") or "").strip()
        if not name:
            continue

        printer_id = _find_linked_item(
            cursor,
            "glpi_printers",
            "Printer",
            computers_id,
            name,
            link_backend,
        )
        values = {
            "name": name,
            "comment": "\n".join([part for part in [entry.get("PORT", "").strip(), entry.get("DRIVER", "").strip()] if part]),
            "entities_id": config.default_entity,
            "is_dynamic": 1,
            "is_deleted": 0,
            "is_global": 0,
            "date_mod": now,
            "date_creation": now,
        }

        if printer_id is None:
            printer_id = _dynamic_insert(cursor, "glpi_printers", values, cols_printers)
        else:
            _update_by_id(cursor, "glpi_printers", printer_id, values, cols_printers)

        _ensure_link(cursor, computers_id, "Printer", printer_id, link_backend)
        touched += 1

    return touched


def _sync_peripherals(
    cursor: Any,
    computers_id: int,
    entries: list[dict[str, str]],
    config: SyncConfig,
) -> int:
    """Synchronise les peripheriques USB/HID remontees par l'inventaire.

    Args:
        cursor: Curseur SQL actif.
        computers_id: Identifiant GLPI du poste.
        entries: Lignes brutes d'une section de peripheriques (USBDEVICES/INPUTS).
        config: Configuration metier (entite par defaut, etc.).

    Returns:
        Nombre de peripheriques traites.
    """
    if not entries or not _table_exists(cursor, "glpi_peripherals"):
        return 0

    link_backend = _get_peripheral_link_backend(cursor)
    if link_backend is None:
        return 0

    cols_peripherals = _table_columns(cursor, "glpi_peripherals")
    touched = 0
    now = now_sql()

    for entry in entries:
        # Meme strategie de fallback que pour les imprimantes pour maximiser
        # la recuperation des inventaires heterogenes.
        name = (
            entry.get("CAPTION")
            or entry.get("DESCRIPTION")
            or entry.get("NAME")
            or entry.get("TYPE")
            or ""
        ).strip()
        if not name:
            continue

        peripheral_id = _find_linked_item(
            cursor,
            "glpi_peripherals",
            "Peripheral",
            computers_id,
            name,
            link_backend,
        )
        comment_parts = [
            entry.get("TYPE", "").strip(),
            entry.get("INTERFACE", "").strip(),
            entry.get("VENDORID", "").strip(),
            entry.get("PRODUCTID", "").strip(),
        ]
        values = {
            "name": name,
            "brand": (entry.get("MANUFACTURER") or "").strip(),
            "comment": " | ".join([part for part in comment_parts if part]),
            "entities_id": config.default_entity,
            "is_dynamic": 1,
            "is_deleted": 0,
            "is_global": 0,
            "date_mod": now,
            "date_creation": now,
        }

        if peripheral_id is None:
            peripheral_id = _dynamic_insert(cursor, "glpi_peripherals", values, cols_peripherals)
        else:
            _update_by_id(cursor, "glpi_peripherals", peripheral_id, values, cols_peripherals)

        _ensure_link(cursor, computers_id, "Peripheral", peripheral_id, link_backend)
        touched += 1

    return touched


def sync_peripherals(cursor: Any, computers_id: int, record: MachineRecord, config: SyncConfig) -> str:
    """Synchronise imprimantes et peripheriques GLPI depuis les sections brutes du XML.

    Args:
        cursor: Curseur SQL actif.
        computers_id: Identifiant GLPI du poste.
        record: Enregistrement machine normalise contenant les sections brutes.
        config: Configuration metier de synchronisation.

    Returns:
        `peripheral_synced` si au moins un element est traite, sinon `peripheral_empty`.
    """
    raw = record.raw_sections
    if not raw:
        return "peripheral_empty"

    touched = 0
    touched += _sync_printers(cursor, computers_id, raw.get("PRINTERS", []), config)
    touched += _sync_peripherals(cursor, computers_id, raw.get("USBDEVICES", []), config)
    touched += _sync_peripherals(cursor, computers_id, raw.get("INPUTS", []), config)

    return "peripheral_synced" if touched else "peripheral_empty"
