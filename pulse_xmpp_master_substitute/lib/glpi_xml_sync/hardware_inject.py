# SPDX-FileCopyrightText: 2004-2007 Linbox / Free&ALter Soft, http://linbox.com
# SPDX-FileCopyrightText: 2007 Mandriva, http://www.mandriva.com
# SPDX-FileCopyrightText: 2016-2023 Siveo, http://www.siveo.net
# SPDX-FileCopyrightText: 2024-2025 Medulla, http://www.medulla-tech.io
# SPDX-License-Identifier: GPL-3.0-or-later
# file : pulse_xmpp_master_substitute/lib/glpi_xml_sync/hardware_inject.py
"""Injection/synchronisation standalone des sections hardware detaillees."""

from __future__ import annotations

import json
from typing import Any

from .db import now_sql
from .models import MachineRecord


def _create_tables(cursor: Any) -> None:
    """Cree les tables standalone si absentes.

    Args:
        cursor: Curseur SQL actif.
    """
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS glpi_plugin_xmlsync_bios (
          id INT AUTO_INCREMENT PRIMARY KEY,
          computers_id INT NOT NULL,
          ssn VARCHAR(190) DEFAULT '',
          bmanufacturer VARCHAR(255) DEFAULT '',
          bversion VARCHAR(255) DEFAULT '',
          smodel VARCHAR(255) DEFAULT '',
          mmodel VARCHAR(255) DEFAULT '',
          raw_json LONGTEXT,
          updated_at DATETIME NOT NULL,
          UNIQUE KEY uniq_bios_computer (computers_id)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
        """
    )

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS glpi_plugin_xmlsync_cpus (
          id INT AUTO_INCREMENT PRIMARY KEY,
          computers_id INT NOT NULL,
          cpu_key VARCHAR(255) NOT NULL,
          name VARCHAR(255) DEFAULT '',
          manufacturer VARCHAR(255) DEFAULT '',
          familyname VARCHAR(255) DEFAULT '',
          core_count INT DEFAULT 0,
          thread_count INT DEFAULT 0,
          raw_json LONGTEXT,
          updated_at DATETIME NOT NULL,
          UNIQUE KEY uniq_cpu (computers_id, cpu_key)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
        """
    )

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS glpi_plugin_xmlsync_storages (
          id INT AUTO_INCREMENT PRIMARY KEY,
          computers_id INT NOT NULL,
          storage_key VARCHAR(255) NOT NULL,
          name VARCHAR(255) DEFAULT '',
          model VARCHAR(255) DEFAULT '',
          manufacturer VARCHAR(255) DEFAULT '',
          serialnumber VARCHAR(255) DEFAULT '',
          diskgb INT DEFAULT 0,
          storage_type VARCHAR(100) DEFAULT '',
          raw_json LONGTEXT,
          updated_at DATETIME NOT NULL,
          UNIQUE KEY uniq_storage (computers_id, storage_key)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
        """
    )

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS glpi_plugin_xmlsync_sounds (
          id INT AUTO_INCREMENT PRIMARY KEY,
          computers_id INT NOT NULL,
          sound_key VARCHAR(255) NOT NULL,
          name VARCHAR(255) DEFAULT '',
          manufacturer VARCHAR(255) DEFAULT '',
          description VARCHAR(255) DEFAULT '',
          raw_json LONGTEXT,
          updated_at DATETIME NOT NULL,
          UNIQUE KEY uniq_sound (computers_id, sound_key)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
        """
    )

    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS glpi_plugin_xmlsync_batteries (
          id INT AUTO_INCREMENT PRIMARY KEY,
          computers_id INT NOT NULL,
          battery_key VARCHAR(255) NOT NULL,
          name VARCHAR(255) DEFAULT '',
          manufacturer VARCHAR(255) DEFAULT '',
          serial VARCHAR(255) DEFAULT '',
          chemistry VARCHAR(100) DEFAULT '',
          capacity INT DEFAULT 0,
          real_capacity INT DEFAULT 0,
          voltage INT DEFAULT 0,
          raw_json LONGTEXT,
          updated_at DATETIME NOT NULL,
          UNIQUE KEY uniq_battery (computers_id, battery_key)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
        """
    )


def _upsert(cursor: Any, sql: str, params: tuple[Any, ...]) -> None:
    """Execute un upsert SQL parametre pour les donnees hardware.

    Args:
        cursor: Curseur SQL actif.
        sql: Requete SQL d'insert/update.
        params: Parametres SQL associes.
    """
    cursor.execute(sql, params)


def sync_hardware_sections(cursor: Any, computers_id: int, record: MachineRecord) -> str:
    """Synchronise BIOS/CPU/STORAGES/SOUNDS/BATTERIES dans des tables standalone.

    Args:
        cursor: Curseur SQL actif.
        computers_id: Identifiant GLPI du poste.
        record: Donnees machine normalisees.

    Returns:
        hardware_synced si au moins une section est traitee, sinon hardware_empty.
    """
    _create_tables(cursor)
    now = now_sql()

    for bios in record.bios:
        raw_json = json.dumps(bios.raw, ensure_ascii=True)
        _upsert(
            cursor,
            """
            INSERT INTO glpi_plugin_xmlsync_bios
                (computers_id, ssn, bmanufacturer, bversion, smodel, mmodel, raw_json, updated_at)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s)
            ON DUPLICATE KEY UPDATE
                ssn=VALUES(ssn),
                bmanufacturer=VALUES(bmanufacturer),
                bversion=VALUES(bversion),
                smodel=VALUES(smodel),
                mmodel=VALUES(mmodel),
                raw_json=VALUES(raw_json),
                updated_at=VALUES(updated_at)
            """,
            (
                computers_id,
                bios.ssn,
                bios.bmanufacturer,
                bios.bversion,
                bios.smodel,
                bios.mmodel,
                raw_json,
                now,
            ),
        )

    for idx, cpu in enumerate(record.cpus):
        raw_json = json.dumps(cpu.raw, ensure_ascii=True)
        cpu_key = (cpu.name or "cpu") + f"#{idx + 1}"
        _upsert(
            cursor,
            """
            INSERT INTO glpi_plugin_xmlsync_cpus
                (computers_id, cpu_key, name, manufacturer, familyname, core_count, thread_count, raw_json, updated_at)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)
            ON DUPLICATE KEY UPDATE
                name=VALUES(name),
                manufacturer=VALUES(manufacturer),
                familyname=VALUES(familyname),
                core_count=VALUES(core_count),
                thread_count=VALUES(thread_count),
                raw_json=VALUES(raw_json),
                updated_at=VALUES(updated_at)
            """,
            (
                computers_id,
                cpu_key[:255],
                cpu.name,
                cpu.manufacturer,
                cpu.familyname,
                cpu.core,
                cpu.thread,
                raw_json,
                now,
            ),
        )

    for idx, storage in enumerate(record.storages):
        raw_json = json.dumps(storage.raw, ensure_ascii=True)
        storage_key = (storage.serialnumber or storage.name or "storage") + f"#{idx + 1}"
        _upsert(
            cursor,
            """
            INSERT INTO glpi_plugin_xmlsync_storages
                (computers_id, storage_key, name, model, manufacturer, serialnumber, diskgb, storage_type, raw_json, updated_at)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
            ON DUPLICATE KEY UPDATE
                name=VALUES(name),
                model=VALUES(model),
                manufacturer=VALUES(manufacturer),
                serialnumber=VALUES(serialnumber),
                diskgb=VALUES(diskgb),
                storage_type=VALUES(storage_type),
                raw_json=VALUES(raw_json),
                updated_at=VALUES(updated_at)
            """,
            (
                computers_id,
                storage_key[:255],
                storage.name,
                storage.model,
                storage.manufacturer,
                storage.serialnumber,
                storage.diskgb,
                storage.storage_type,
                raw_json,
                now,
            ),
        )

    for idx, sound in enumerate(record.sounds):
        raw_json = json.dumps(sound.raw, ensure_ascii=True)
        sound_key = (sound.name or sound.description or "sound") + f"#{idx + 1}"
        _upsert(
            cursor,
            """
            INSERT INTO glpi_plugin_xmlsync_sounds
                (computers_id, sound_key, name, manufacturer, description, raw_json, updated_at)
            VALUES (%s,%s,%s,%s,%s,%s,%s)
            ON DUPLICATE KEY UPDATE
                name=VALUES(name),
                manufacturer=VALUES(manufacturer),
                description=VALUES(description),
                raw_json=VALUES(raw_json),
                updated_at=VALUES(updated_at)
            """,
            (
                computers_id,
                sound_key[:255],
                sound.name,
                sound.manufacturer,
                sound.description,
                raw_json,
                now,
            ),
        )

    for idx, battery in enumerate(record.batteries):
        raw_json = json.dumps(battery.raw, ensure_ascii=True)
        battery_key = (battery.serial or battery.name or "battery") + f"#{idx + 1}"
        _upsert(
            cursor,
            """
            INSERT INTO glpi_plugin_xmlsync_batteries
                (computers_id, battery_key, name, manufacturer, serial, chemistry, capacity, real_capacity, voltage, raw_json, updated_at)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
            ON DUPLICATE KEY UPDATE
                name=VALUES(name),
                manufacturer=VALUES(manufacturer),
                serial=VALUES(serial),
                chemistry=VALUES(chemistry),
                capacity=VALUES(capacity),
                real_capacity=VALUES(real_capacity),
                voltage=VALUES(voltage),
                raw_json=VALUES(raw_json),
                updated_at=VALUES(updated_at)
            """,
            (
                computers_id,
                battery_key[:255],
                battery.name,
                battery.manufacturer,
                battery.serial,
                battery.chemistry,
                battery.capacity,
                battery.real_capacity,
                battery.voltage,
                raw_json,
                now,
            ),
        )

    if record.bios or record.cpus or record.storages or record.sounds or record.batteries:
        return "hardware_synced"
    return "hardware_empty"
