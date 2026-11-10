# SPDX-FileCopyrightText: 2004-2007 Linbox / Free&ALter Soft, http://linbox.com
# SPDX-FileCopyrightText: 2007 Mandriva, http://www.mandriva.com
# SPDX-FileCopyrightText: 2016-2023 Siveo, http://www.siveo.net
# SPDX-FileCopyrightText: 2024-2025 Medulla, http://www.medulla-tech.io
# SPDX-License-Identifier: GPL-3.0-or-later
# file : pulse_xmpp_master_substitute/lib/glpi_xml_sync/config_loader.py
"""Chargement et conversion de la configuration INI pour le CLI XML sync."""

from __future__ import annotations

import configparser
from pathlib import Path
from typing import Any


SECTION_NAME = "glpi_xml_sync"


def load_ini_config(ini_path: Path) -> dict[str, Any]:
    """Charge un fichier INI et retourne un dictionnaire normalise.

    Args:
        ini_path: Chemin du fichier INI a lire.

    Returns:
        Dictionnaire de configuration normalise pour glpi_xml_sync.
    """
    if not ini_path.exists() or not ini_path.is_file():
        raise FileNotFoundError(f"Fichier INI introuvable: {ini_path}")

    parser = configparser.ConfigParser()
    parser.read(ini_path, encoding="utf-8")

    if SECTION_NAME not in parser:
        raise ValueError(f"Section INI manquante: [{SECTION_NAME}]")

    section = parser[SECTION_NAME]

    def get_str(key: str) -> str | None:
        value = section.get(key)
        if value is None:
            return None
        value = value.strip()
        return value if value else None

    def get_int(key: str) -> int | None:
        value = get_str(key)
        if value is None:
            return None
        return int(value)

    def get_bool(key: str) -> bool | None:
        value = get_str(key)
        if value is None:
            return None
        lowered = value.lower()
        if lowered in {"1", "true", "yes", "on"}:
            return True
        if lowered in {"0", "false", "no", "off"}:
            return False
        raise ValueError(f"Valeur booleenne invalide pour '{key}': {value}")

    return {
        "mode": get_str("mode"),
        "xml_path": get_str("xml_path"),
        "db_host": get_str("db_host"),
        "db_port": get_int("db_port"),
        "db_name": get_str("db_name"),
        "db_user": get_str("db_user"),
        "db_pass": get_str("db_pass"),
        "default_entity": get_int("default_entity"),
        "default_recursive": get_int("default_recursive"),
        "allow_missing_ocsid": get_bool("allow_missing_ocsid"),
        "dry_run": get_bool("dry_run"),
    }
