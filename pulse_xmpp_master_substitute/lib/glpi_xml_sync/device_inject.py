# SPDX-FileCopyrightText: 2004-2007 Linbox / Free&ALter Soft, http://linbox.com
# SPDX-FileCopyrightText: 2007 Mandriva, http://www.mandriva.com
# SPDX-FileCopyrightText: 2016-2023 Siveo, http://www.siveo.net
# SPDX-FileCopyrightText: 2024-2025 Medulla, http://www.medulla-tech.io
# SPDX-License-Identifier: GPL-3.0-or-later
# file : pulse_xmpp_master_substitute/lib/glpi_xml_sync/device_inject.py
"""Injection/synchronisation du domaine devices.

Ce module est le point d'extension pour CPU, RAM, cartes reseau,
stockage, etc.
"""

from __future__ import annotations

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
    """Insert une ligne en filtrant les champs inexistants.

    Args:
        cursor: Curseur SQL actif.
        table: Table cible.
        values: Valeurs candidates a inserer.
        columns: Colonnes disponibles dans la table cible.

    Returns:
        Identifiant de la ligne creee.
    """
    filtered = {k: v for k, v in values.items() if k in columns and v is not None}
    if not filtered:
        raise RuntimeError(f"Aucune colonne valide pour l'insert dans {table}")

    names = list(filtered.keys())
    placeholders = ", ".join(["%s"] * len(names))
    sql = f"INSERT INTO {table} ({', '.join(names)}) VALUES ({placeholders})"
    cursor.execute(sql, tuple(filtered[name] for name in names))
    return int(cursor.lastrowid)


def _sync_network_interface(
    cursor: Any,
    computers_id: int,
    machine_name: str,
    iface: Any,
    cols_ports: set[str],
    cols_names: set[str],
    cols_ips: set[str],
) -> None:
    """Synchronise une interface réseau vers les tables GLPI standard.

    Args:
        cursor: Curseur SQL actif.
        computers_id: Identifiant GLPI du poste.
        machine_name: Nom de la machine (fallback de nom d'interface).
        iface: Interface normalisee issue du parsing inventaire.
        cols_ports: Colonnes disponibles pour glpi_networkports.
        cols_names: Colonnes disponibles pour glpi_networknames.
        cols_ips: Colonnes disponibles pour glpi_ipaddresses.
    """
    now = now_sql()
    mac = (iface.mac or "").strip().upper()
    port_name = (iface.name or "").strip() or mac or "ocs-network-port"

    # Priorite a la MAC pour assurer une reconciliation stable entre inventaires.
    if mac:
        cursor.execute(
            """
            SELECT id
            FROM glpi_networkports
            WHERE itemtype = 'Computer' AND items_id = %s AND mac = %s
            ORDER BY is_dynamic DESC, id ASC
            LIMIT 1
            """,
            (computers_id, mac),
        )
    else:
        cursor.execute(
            """
            SELECT id
            FROM glpi_networkports
            WHERE itemtype = 'Computer' AND items_id = %s AND name = %s
            ORDER BY is_dynamic DESC, id ASC
            LIMIT 1
            """,
            (computers_id, port_name),
        )

    row = cursor.fetchone()
    if row:
        networkports_id = int(row[0])
        updates: list[str] = []
        params: list[Any] = []
        if "name" in cols_ports:
            updates.append("name = %s")
            params.append(port_name)
        if mac and "mac" in cols_ports:
            updates.append("mac = %s")
            params.append(mac)
        if "is_dynamic" in cols_ports:
            updates.append("is_dynamic = %s")
            params.append(1)
        if "date_mod" in cols_ports:
            updates.append("date_mod = %s")
            params.append(now)
        if updates:
            params.append(networkports_id)
            cursor.execute(
                f"UPDATE glpi_networkports SET {', '.join(updates)} WHERE id = %s",
                tuple(params),
            )
    else:
        # Creation tolerante: seuls les champs existants dans ce schema GLPI sont utilises.
        networkports_id = _dynamic_insert(
            cursor,
            "glpi_networkports",
            {
                "name": port_name,
                "mac": mac,
                "items_id": computers_id,
                "itemtype": "Computer",
                "is_dynamic": 1,
                "is_deleted": 0,
                "date_mod": now,
                "date_creation": now,
            },
            cols_ports,
        )

    cursor.execute(
        """
        SELECT id
        FROM glpi_networknames
        WHERE itemtype = 'NetworkPort' AND items_id = %s
        ORDER BY is_dynamic DESC, id ASC
        LIMIT 1
        """,
        (networkports_id,),
    )
    networkname_row = cursor.fetchone()
    if networkname_row:
        networknames_id = int(networkname_row[0])
        updates: list[str] = []
        params: list[Any] = []
        if "name" in cols_names:
            updates.append("name = %s")
            params.append(machine_name or port_name)
        if "is_dynamic" in cols_names:
            updates.append("is_dynamic = %s")
            params.append(1)
        if updates:
            params.append(networknames_id)
            cursor.execute(
                f"UPDATE glpi_networknames SET {', '.join(updates)} WHERE id = %s",
                tuple(params),
            )
    else:
        networknames_id = _dynamic_insert(
            cursor,
            "glpi_networknames",
            {
                "itemtype": "NetworkPort",
                "items_id": networkports_id,
                "is_dynamic": 1,
                "is_deleted": 0,
                "name": machine_name or port_name,
            },
            cols_names,
        )

    for ip in iface.ips:
        ip_value = (ip or "").strip()
        if not ip_value:
            continue

        cursor.execute(
            """
            SELECT id
            FROM glpi_ipaddresses
            WHERE itemtype = 'NetworkName' AND items_id = %s AND name = %s
            LIMIT 1
            """,
            (networknames_id, ip_value),
        )
        ip_row = cursor.fetchone()
        if ip_row:
            ip_id = int(ip_row[0])
            if "is_dynamic" in cols_ips:
                cursor.execute(
                    "UPDATE glpi_ipaddresses SET is_dynamic = %s WHERE id = %s",
                    (1, ip_id),
                )
            continue

        _dynamic_insert(
            cursor,
            "glpi_ipaddresses",
            {
                "name": ip_value,
                "itemtype": "NetworkName",
                "items_id": networknames_id,
                "is_dynamic": 1,
                "is_deleted": 0,
            },
            cols_ips,
        )


def sync_devices(cursor: Any, computers_id: int, record: MachineRecord, config: SyncConfig) -> str:
    """Synchronise les devices d'une machine (focus interfaces reseau).

    Args:
        cursor: Curseur SQL actif.
        computers_id: Identifiant GLPI du poste.
        record: Donnees machine normalisees.
        config: Configuration metier de synchronisation.

    Returns:
        device_synced si au moins une interface est traitee, sinon device_empty.
    """
    _ = config
    if not record.network_interfaces:
        return "device_empty"

    # Mise en cache des colonnes pour eviter une introspection SQL par interface.
    cols_ports = _table_columns(cursor, "glpi_networkports")
    cols_names = _table_columns(cursor, "glpi_networknames")
    cols_ips = _table_columns(cursor, "glpi_ipaddresses")

    touched = 0
    for iface in record.network_interfaces:
        _sync_network_interface(
            cursor,
            computers_id,
            record.name,
            iface,
            cols_ports,
            cols_names,
            cols_ips,
        )
        touched += 1

    return "device_synced" if touched else "device_empty"
