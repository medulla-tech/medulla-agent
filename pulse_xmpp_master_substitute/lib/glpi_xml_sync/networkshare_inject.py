# SPDX-FileCopyrightText: 2004-2007 Linbox / Free&ALter Soft, http://linbox.com
# SPDX-FileCopyrightText: 2007 Mandriva, http://www.mandriva.com
# SPDX-FileCopyrightText: 2016-2023 Siveo, http://www.siveo.net
# SPDX-FileCopyrightText: 2024-2025 Medulla, http://www.medulla-tech.io
# SPDX-License-Identifier: GPL-3.0-or-later
# file : pulse_xmpp_master_substitute/lib/glpi_xml_sync/networkshare_inject.py
"""Injection/synchronisation du domaine network shares."""

from __future__ import annotations

from typing import Any

from .models import MachineRecord, SyncConfig


def sync_networkshares(cursor: Any, computers_id: int, record: MachineRecord, config: SyncConfig) -> str:
    """Synchronise les partages reseau d'une machine (placeholder).

    Args:
        cursor: Curseur SQL actif.
        computers_id: Identifiant GLPI du poste.
        record: Donnees machine normalisees.
        config: Configuration metier de synchronisation.

    Returns:
        networkshare_pending tant que l'implementation metier n'est pas finalisee.
    """
    _ = (cursor, computers_id, record, config)
    return "networkshare_pending"
