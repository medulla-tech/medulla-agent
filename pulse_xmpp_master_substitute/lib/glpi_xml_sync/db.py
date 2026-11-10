# SPDX-FileCopyrightText: 2004-2007 Linbox / Free&ALter Soft, http://linbox.com
# SPDX-FileCopyrightText: 2007 Mandriva, http://www.mandriva.com
# SPDX-FileCopyrightText: 2016-2023 Siveo, http://www.siveo.net
# SPDX-FileCopyrightText: 2024-2025 Medulla, http://www.medulla-tech.io
# SPDX-License-Identifier: GPL-3.0-or-later
# file : pulse_xmpp_master_substitute/lib/glpi_xml_sync/db.py
"""Connexion base GLPI et utilitaires SQL."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from .models import DbConfig


def connect_db(config: DbConfig) -> Any:
    """Etablit la connexion DB avec mysql-connector-python ou PyMySQL.

    Args:
        config: Parametres d'acces a la base GLPI.

    Returns:
        Connexion DB-API compatible curseur/commit/rollback.
    """
    try:
        import mysql.connector  # type: ignore

        return mysql.connector.connect(
            host=config.host,
            port=config.port,
            user=config.user,
            password=config.password,
            database=config.name,
        )
    except ModuleNotFoundError:
        pass

    try:
        import pymysql  # type: ignore

        return pymysql.connect(
            host=config.host,
            port=config.port,
            user=config.user,
            password=config.password,
            database=config.name,
            autocommit=False,
            charset="utf8mb4",
        )
    except ModuleNotFoundError as exc:
        raise RuntimeError(
            "Driver MySQL introuvable. Installez 'mysql-connector-python' ou 'pymysql'."
        ) from exc


def now_sql() -> str:
    """Date/heure SQL au format GLPI.

    Args:
        Aucun.

    Returns:
        Horodatage UTC formate en YYYY-MM-DD HH:MM:SS.
    """
    return datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
