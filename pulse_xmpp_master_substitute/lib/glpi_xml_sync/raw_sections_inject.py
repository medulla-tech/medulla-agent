# SPDX-FileCopyrightText: 2004-2007 Linbox / Free&ALter Soft, http://linbox.com
# SPDX-FileCopyrightText: 2007 Mandriva, http://www.mandriva.com
# SPDX-FileCopyrightText: 2016-2023 Siveo, http://www.siveo.net
# SPDX-FileCopyrightText: 2024-2025 Medulla, http://www.medulla-tech.io
# SPDX-License-Identifier: GPL-3.0-or-later
# file : pulse_xmpp_master_substitute/lib/glpi_xml_sync/raw_sections_inject.py
"""Injection des sections XML brutes dans des tables plugin GLPI standalone."""

from __future__ import annotations

import hashlib
import json
from typing import Any

from .db import now_sql
from .models import MachineRecord


def _create_table(cursor: Any) -> None:
    """Cree la table plugin recevant les sections XML brutes.

    Args:
        cursor: Curseur SQL actif.
    """
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS glpi_plugin_xmlsync_sections (
          id INT AUTO_INCREMENT PRIMARY KEY,
          computers_id INT NOT NULL,
          section_name VARCHAR(80) NOT NULL,
          section_key VARCHAR(255) NOT NULL,
          raw_json LONGTEXT,
          updated_at DATETIME NOT NULL,
          UNIQUE KEY uniq_section (computers_id, section_name, section_key)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
        """
    )


def sync_raw_sections(cursor: Any, computers_id: int, record: MachineRecord) -> str:
    """Synchronise les sections brutes non mappees dans une table GLPI dediee.

    Args:
        cursor: Curseur SQL actif.
        computers_id: Identifiant GLPI du poste.
        record: Donnees machine normalisees, incluant raw_sections.

    Returns:
        raw_sections_synced si des sections sont traitees, sinon raw_sections_empty.
    """
    if not record.raw_sections:
        return "raw_sections_empty"

    _create_table(cursor)
    now = now_sql()
    touched = 0

    for section_name, entries in record.raw_sections.items():
        for idx, entry in enumerate(entries):
            raw_json = json.dumps(entry, ensure_ascii=True, sort_keys=True)
            fingerprint = hashlib.sha1(raw_json.encode("utf-8")).hexdigest()[:16]
            preferred_key = (
                entry.get("NAME")
                or entry.get("DESCRIPTION")
                or entry.get("SERIAL")
                or entry.get("SERIALNUMBER")
                or entry.get("ID")
                or f"{section_name}-{idx + 1}"
            )
            section_key = f"{(preferred_key or f'{section_name}-{idx + 1}')[:200]}-{fingerprint}"[:255]

            cursor.execute(
                """
                INSERT INTO glpi_plugin_xmlsync_sections
                    (computers_id, section_name, section_key, raw_json, updated_at)
                VALUES (%s,%s,%s,%s,%s)
                ON DUPLICATE KEY UPDATE
                    raw_json=VALUES(raw_json),
                    updated_at=VALUES(updated_at)
                """,
                (computers_id, section_name, section_key, raw_json, now),
            )
            touched += 1

    return "raw_sections_synced" if touched else "raw_sections_empty"
