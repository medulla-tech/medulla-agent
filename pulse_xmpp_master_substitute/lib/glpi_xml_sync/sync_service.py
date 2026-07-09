# SPDX-FileCopyrightText: 2004-2007 Linbox / Free&ALter Soft, http://linbox.com
# SPDX-FileCopyrightText: 2007 Mandriva, http://www.mandriva.com
# SPDX-FileCopyrightText: 2016-2023 Siveo, http://www.siveo.net
# SPDX-FileCopyrightText: 2024-2025 Medulla, http://www.medulla-tech.io
# SPDX-License-Identifier: GPL-3.0-or-later
# file : pulse_xmpp_master_substitute/lib/glpi_xml_sync/sync_service.py
"""Service d'injection/synchronisation vers GLPI."""

from __future__ import annotations

from typing import Any

from .device_inject import sync_devices
from .hardware_inject import sync_hardware_sections
from .machine_inject import sync_machine
from .models import MachineRecord, SyncConfig
from .networkshare_inject import sync_networkshares
from .os_inject import sync_operating_system
from .peripheral_inject import sync_peripherals
from .raw_sections_inject import sync_raw_sections
from .runningprocess_inject import sync_runningprocesses
from .service_inject import sync_services
from .software_inject import sync_software
from .user_inject import sync_users


def process_record(cursor: Any, record: MachineRecord, config: SyncConfig) -> str:
    """Injecte/synchronise une machine et declenche les domaines annexes.

    Args:
        cursor: Curseur SQL actif.
        record: Donnees machine normalisees.
        config: Configuration metier de synchronisation.

    Returns:
        Action principale issue de sync_machine.
    """
    action, computers_id = sync_machine(cursor, record, config)

    # Hooks domaines metier. Les modules existent et sont maintenant separables.
    # Le detail SQL de chaque domaine sera complete iterativement.
    sync_operating_system(cursor, computers_id, record)
    sync_devices(cursor, computers_id, record, config)
    sync_peripherals(cursor, computers_id, record, config)
    sync_hardware_sections(cursor, computers_id, record)
    sync_raw_sections(cursor, computers_id, record)
    sync_software(cursor, computers_id, record, config)
    sync_networkshares(cursor, computers_id, record, config)
    sync_runningprocesses(cursor, computers_id, record, config)
    sync_services(cursor, computers_id, record, config)
    sync_users(cursor, computers_id, record, config)

    return action
