# -*- coding: utf-8; -*-
# SPDX-FileCopyrightText: 2026 Medulla <support@medulla-tech.io>
# SPDX-License-Identifier: GPL-3.0-or-later
"""Access to the Dyngroup database and its machine cache."""

import logging

from sqlalchemy import create_engine, text

from lib.configuration import confParameter


class DyngroupDatabase:
    """Database access for dynamic-group machine cache operations."""

    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self):
        if getattr(self, "_initialized", False):
            return
        self._initialized = True
        self.is_activated = False
        self.logger = logging.getLogger()
        self.config = confParameter()
        self.engine_dyngroup_base = None

    def activate(self):
        if self.is_activated:
            return True

        config = self.config
        self.logger.info(
            "Dyngroup parameters connections: user=%s host=%s port=%s schema=%s",
            config.dyngroup_dbuser,
            config.dyngroup_dbhost,
            config.dyngroup_dbport,
            config.dyngroup_dbname,
        )
        try:
            self.engine_dyngroup_base = create_engine(
                "mysql://%s:%s@%s:%s/%s?charset=%s"
                % (
                    config.dyngroup_dbuser,
                    config.dyngroup_dbpasswd,
                    config.dyngroup_dbhost,
                    config.dyngroup_dbport,
                    config.dyngroup_dbname,
                    config.charset,
                ),
                pool_recycle=config.dyngroup_dbpoolrecycle,
                pool_size=config.dyngroup_dbpoolsize,
                pool_timeout=config.dyngroup_dbpooltimeout,
            )
            with self.engine_dyngroup_base.connect():
                pass
            self.is_activated = True
            self.logger.info("Dyngroup database connected")
            return True
        except Exception:
            self.logger.exception("We failed to connect to the Dyngroup database")
            self.is_activated = False
            return False

    def getAllMachinesUuid(self):
        """Return the UUID-to-name cache stored by Dyngroup."""
        with self.engine_dyngroup_base.connect() as connection:
            rows = connection.execute(text("SELECT uuid, name FROM Machines")).fetchall()
        return {row[0]: row[1] for row in rows}

    def updateNewNames(self, machines):
        """Update cached machine names, keyed by their GLPI UUID."""
        updates = [
            {"uuid": uuid, "name": name}
            for uuid, name in machines.items()
            if uuid and name
        ]
        if not updates:
            return 0

        with self.engine_dyngroup_base.begin() as connection:
            result = connection.execute(
                text("UPDATE Machines SET name = :name WHERE uuid = :uuid"), updates
            )
        return result.rowcount
