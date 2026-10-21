# -*- coding: utf-8; -*-
# SPDX-FileCopyrightText: 2026 Medulla <support@medulla-tech.io>
# SPDX-License-Identifier: GPL-3.0-or-later
"""Access to the Dyngroup database and its machine cache."""

import logging

from sqlalchemy import Column, Integer, MetaData, String, Table, create_engine, text

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
            self.ensureIdentityQueue()
            self.ensureInventoryConvergenceQueue()
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

    def ensureIdentityQueue(self):
        """Create the substitute-owned retry queue without altering Dyngroup tables."""
        metadata = MetaData()
        queue = Table(
            "substitute_pending_machine_identity",
            metadata,
            Column("xmpp_machine_id", Integer, primary_key=True),
            Column("old_uuid", String(64), primary_key=True),
            Column("new_uuid", String(64), nullable=False),
            mysql_engine="InnoDB",
        )
        queue.create(self.engine_dyngroup_base, checkfirst=True)

    def rememberMachineIdentity(self, machine_id, old_uuid, new_uuid):
        """Persist the old identity before XMPP changes; retain all unresolved UUIDs."""
        if not machine_id or not new_uuid:
            raise ValueError("Dyngroup identity queue requires a machine ID and UUID")
        with self.engine_dyngroup_base.begin() as connection:
            query = (
                "SELECT old_uuid FROM substitute_pending_machine_identity "
                "WHERE xmpp_machine_id = :machine_id ORDER BY old_uuid"
            )
            if connection.dialect.name in {"mysql", "mariadb"}:
                query += " FOR UPDATE"
            parameters = {"machine_id": machine_id, "new_uuid": new_uuid}
            pending = connection.execute(text(query), parameters).fetchall()
            connection.execute(
                text(
                    "UPDATE substitute_pending_machine_identity SET new_uuid = :new_uuid "
                    "WHERE xmpp_machine_id = :machine_id"
                ),
                parameters,
            )
            if old_uuid and old_uuid != new_uuid and old_uuid not in {
                row[0] for row in pending
            }:
                connection.execute(
                    text(
                        "INSERT INTO substitute_pending_machine_identity "
                        "(xmpp_machine_id, old_uuid, new_uuid) "
                        "VALUES (:machine_id, :old_uuid, :new_uuid)"
                    ),
                    dict(parameters, old_uuid=old_uuid),
                )

    def ensureInventoryConvergenceQueue(self):
        """Share durable inventory notifications with the MMC convergence worker."""
        queue = Table(
            "substitute_inventory_convergence",
            MetaData(),
            Column("id", Integer, primary_key=True, autoincrement=True),
            Column("machine_uuid", String(64), nullable=False, unique=True),
            Column("revision", Integer, nullable=False, server_default="1"),
            mysql_engine="InnoDB",
        )
        queue.create(self.engine_dyngroup_base, checkfirst=True)

    def requestInventoryConvergence(self, machine_uuid):
        if not machine_uuid or not machine_uuid.startswith("UUID"):
            raise ValueError("Inventory convergence requires a GLPI UUID")
        with self.engine_dyngroup_base.begin() as connection:
            if connection.dialect.name in {"mysql", "mariadb"}:
                update = "ON DUPLICATE KEY UPDATE revision = revision + 1"
            elif connection.dialect.name == "sqlite":
                update = (
                    "ON CONFLICT(machine_uuid) DO UPDATE SET revision = revision + 1"
                )
            else:
                raise RuntimeError("Unsupported inventory convergence queue database")
            connection.execute(
                text(
                    "INSERT INTO substitute_inventory_convergence (machine_uuid) "
                    "VALUES (:machine_uuid) " + update
                ),
                {"machine_uuid": machine_uuid},
            )

    def reconcilePendingMachineIdentity(self, machine_id, new_uuid, hostname):
        """Replay and clear pending links atomically with membership reconciliation."""
        with self.engine_dyngroup_base.begin() as connection:
            query = (
                "SELECT old_uuid, new_uuid FROM substitute_pending_machine_identity "
                "WHERE xmpp_machine_id = :machine_id ORDER BY old_uuid"
            )
            if connection.dialect.name in {"mysql", "mariadb"}:
                query += " FOR UPDATE"
            pending = connection.execute(
                text(query), {"machine_id": machine_id}
            ).fetchall()
            if any(row[1] != new_uuid for row in pending):
                raise ValueError("Dyngroup pending identity target changed; retry inventory")
            result = {"status": "missing", "merged": 0}
            for old_uuid in [row[0] for row in pending] or [new_uuid]:
                current = self._reconcileMachineIdentity(
                    connection, old_uuid, new_uuid, hostname
                )
                if current["status"] == "updated":
                    result["status"] = "updated"
                result["merged"] += current["merged"]
            connection.execute(
                text(
                    "DELETE FROM substitute_pending_machine_identity "
                    "WHERE xmpp_machine_id = :machine_id"
                ),
                {"machine_id": machine_id},
            )
            return result

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

    def reconcileMachineIdentity(self, old_uuid, new_uuid, hostname):
        """Preserve group links across a GLPI UUID change in one transaction.

        Keep the old Dyngroup ID where possible. Conflicting imaging profiles
        raise ValueError before any write; callers must report the conflict.
        No machine or group membership is created when neither UUID exists.
        """
        with self.engine_dyngroup_base.begin() as connection:
            return self._reconcileMachineIdentity(
                connection, old_uuid, new_uuid, hostname
            )

    def _reconcileMachineIdentity(self, connection, old_uuid, new_uuid, hostname):
        if not new_uuid or not hostname:
            raise ValueError("Dyngroup identity requires a new UUID and hostname")
        query = (
            "SELECT id, uuid FROM Machines "
            "WHERE uuid IN (:old_uuid, :new_uuid) ORDER BY id"
        )
        if connection.dialect.name in {"mysql", "mariadb"}:
            query += " FOR UPDATE"
        machines = connection.execute(
            text(query), {"old_uuid": old_uuid, "new_uuid": new_uuid}
        ).fetchall()
        if not machines:
            return {"status": "missing", "merged": 0}
        target_id = next(
            (row[0] for row in machines if row[1] == old_uuid), machines[0][0]
        )
        profiles = []
        memberships = []
        for machine_id, _ in machines:
            profiles.extend(
                connection.execute(
                    text(
                        "SELECT FK_groups, FK_machines FROM ProfilesResults "
                        "WHERE FK_machines = :id"
                    ),
                    {"id": machine_id},
                ).fetchall()
            )
            memberships.extend(
                connection.execute(
                    text(
                        "SELECT id, FK_groups FROM Results "
                        "WHERE FK_machines = :id ORDER BY id"
                    ),
                    {"id": machine_id},
                ).fetchall()
            )
        profile_ids = {row[0] for row in profiles}
        if len(profile_ids) > 1:
            raise ValueError(
                "Dyngroup profile conflict: old_uuid=%s new_uuid=%s profiles=%s"
                % (old_uuid, new_uuid, sorted(profile_ids))
            )

        seen_groups = set()
        for result_id, group_id in memberships:
            if group_id in seen_groups:
                connection.execute(
                    text("DELETE FROM Results WHERE id = :id"), {"id": result_id}
                )
            else:
                connection.execute(
                    text("UPDATE Results SET FK_machines = :target WHERE id = :id"),
                    {"target": target_id, "id": result_id},
                )
                seen_groups.add(group_id)

        # A machine can have only one profile, unlike ordinary group links.
        if profiles:
            keeper_id = profiles[0][1]
            for _, machine_id in profiles[1:]:
                connection.execute(
                    text("DELETE FROM ProfilesResults WHERE FK_machines = :id"),
                    {"id": machine_id},
                )
            connection.execute(
                text(
                    "UPDATE ProfilesResults SET FK_machines = :target "
                    "WHERE FK_machines = :id"
                ),
                {"target": target_id, "id": keeper_id},
            )
        for machine_id, _ in machines:
            if machine_id != target_id:
                connection.execute(
                    text("DELETE FROM Machines WHERE id = :id"), {"id": machine_id}
                )
        connection.execute(
            text("UPDATE Machines SET uuid = :uuid, name = :name WHERE id = :id"),
            {"uuid": new_uuid, "name": hostname, "id": target_id},
        )
        return {"status": "updated", "merged": len(machines) - 1}
