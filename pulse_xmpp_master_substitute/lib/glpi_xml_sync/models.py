# SPDX-FileCopyrightText: 2004-2007 Linbox / Free&ALter Soft, http://linbox.com
# SPDX-FileCopyrightText: 2007 Mandriva, http://www.mandriva.com
# SPDX-FileCopyrightText: 2016-2023 Siveo, http://www.siveo.net
# SPDX-FileCopyrightText: 2024-2025 Medulla, http://www.medulla-tech.io
# SPDX-License-Identifier: GPL-3.0-or-later
# file : pulse_xmpp_master_substitute/lib/glpi_xml_sync/models.py
"""Modeles de donnees utilises par le synchroniseur XML GLPI."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class SoftwareRecord:
    """Donnees normalisees d'un logiciel issu du XML."""

    name: str
    version: str = ""
    publisher: str = ""
    comments: str = ""
    install_date: str = ""


@dataclass
class NetworkInterfaceRecord:
    """Donnees normalisees d'une interface reseau issue du XML."""

    name: str = ""
    mac: str = ""
    iface_type: str = ""
    speed: str = ""
    ip_mask: str = ""
    ip_gateway: str = ""
    ip_subnet: str = ""
    ips: list[str] = field(default_factory=list)


@dataclass
class BiosRecord:
    """Donnees BIOS normalisees."""

    ssn: str = ""
    bmanufacturer: str = ""
    bversion: str = ""
    smodel: str = ""
    mmodel: str = ""
    raw: dict[str, str] = field(default_factory=dict)


@dataclass
class CpuRecord:
    """Donnees CPU normalisees."""

    name: str = ""
    manufacturer: str = ""
    familyname: str = ""
    core: int = 0
    thread: int = 0
    raw: dict[str, str] = field(default_factory=dict)


@dataclass
class StorageRecord:
    """Donnees de stockage normalisees."""

    name: str = ""
    model: str = ""
    manufacturer: str = ""
    serialnumber: str = ""
    diskgb: int = 0
    storage_type: str = ""
    raw: dict[str, str] = field(default_factory=dict)


@dataclass
class SoundRecord:
    """Donnees audio normalisees."""

    name: str = ""
    manufacturer: str = ""
    description: str = ""
    raw: dict[str, str] = field(default_factory=dict)


@dataclass
class BatteryRecord:
    """Donnees batterie normalisees."""

    name: str = ""
    manufacturer: str = ""
    serial: str = ""
    chemistry: str = ""
    capacity: int = 0
    real_capacity: int = 0
    voltage: int = 0
    raw: dict[str, str] = field(default_factory=dict)


@dataclass
class OperatingSystemRecord:
    """Donnees systeme d'exploitation normalisees."""

    name: str = ""
    version: str = ""
    architecture: str = ""
    kernel_name: str = ""
    kernel_version: str = ""
    full_name: str = ""
    raw: dict[str, str] = field(default_factory=dict)


@dataclass
class MachineRecord:
    """Donnees normalisees extraites du XML pour une machine."""

    ocsid: str
    name: str
    deviceid: str
    versionclient: str
    versionprovider: str
    serial: str
    tag: str
    softwares: list[SoftwareRecord] = field(default_factory=list)
    network_interfaces: list[NetworkInterfaceRecord] = field(default_factory=list)
    bios: list[BiosRecord] = field(default_factory=list)
    cpus: list[CpuRecord] = field(default_factory=list)
    storages: list[StorageRecord] = field(default_factory=list)
    sounds: list[SoundRecord] = field(default_factory=list)
    batteries: list[BatteryRecord] = field(default_factory=list)
    operating_systems: list[OperatingSystemRecord] = field(default_factory=list)
    raw_sections: dict[str, list[dict[str, str]]] = field(default_factory=dict)


@dataclass
class DbConfig:
    """Configuration de connexion a la base GLPI."""

    host: str
    port: int
    name: str
    user: str
    password: str


@dataclass
class SyncConfig:
    """Configuration metier de traitement inject/sync."""

    mode: str
    default_entity: int
    default_recursive: int
