# -*- coding: utf-8; -*-
# SPDX-FileCopyrightText: 2026 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-3.0-or-later
# file : pulse_xmpp_master_substitute/lib/plugins/updates/__init__.py

"""
updates database handler
"""

from contextlib import contextmanager
from datetime import datetime, timedelta
import json
import logging
import threading
import traceback

from sqlalchemy import bindparam, create_engine, text

from lib.configuration import confParameter
from lib.plugins.updates import compute, upgrades
from lib.plugins.updates.deployments import (
    DEPLOY_FINAL_SQL,
    DEPLOY_RUNNING_SQL,
    TRANSFER_FAILED,
    in_window,
    pending_command_sql,
)
from lib.plugins.updates.replication import file_rows, to_datetime
from lib.plugins.updates.reports import (
    installed_rows,
    is_linux,
    linux_update_rows,
    missing_rows,
    report_row,
    updated_columns,
)
from lib.plugins.xmpp import XmppMasterDatabase

logger = logging.getLogger()


class Singleton(object):
    def __new__(type, *args):
        if "_the_instance" not in type.__dict__:
            type._the_instance = object.__new__(type)
        return type._the_instance


UPGRADES_LOCK = threading.Lock()
# The server's presence delay: a machine silent for less may still be in its step
LOST_STEP_DELAY = timedelta(minutes=10)


class UpdatesDatabase(Singleton):
    """
    Singleton giving access to the updates database.
    """

    is_activated = False

    def activate(self):
        if self.is_activated:
            return True
        config = confParameter()
        logger.info(
            "updates parameters connections is user = %s, host = %s, port = %s, schema = %s"
            % (
                config.updates_dbuser,
                config.updates_dbhost,
                config.updates_dbport,
                config.updates_dbname,
            )
        )
        try:
            self.engine = create_engine(
                "mysql://%s:%s@%s:%s/%s?charset=%s"
                % (
                    config.updates_dbuser,
                    config.updates_dbpasswd,
                    config.updates_dbhost,
                    config.updates_dbport,
                    config.updates_dbname,
                    config.charset,
                ),
                pool_recycle=config.updates_dbpoolrecycle,
                pool_size=config.updates_dbpoolsize,
                pool_timeout=config.updates_dbpooltimeout,
            )
            self.engine.connect().close()
            self.is_activated = True
            return True
        except Exception as error:
            logger.error("We failed to connect to the updates database: %s" % error)
            return False

    @contextmanager
    def store(self):
        """Yield an UpdatesStore working in one transaction."""
        with self.engine.begin() as connection:
            yield UpdatesStore(connection)

    def recompute_machine(self, jid):
        """Recompute the updates missing on one machine."""
        with self.store() as store:
            glpi_uuid = store.machine_glpi_uuid(jid)
            store.recompute_machine(jid, machine_entity(jid, glpi_uuid))

    def recompute_machines(self, entity_ids=None):
        """Recompute every stored machine, or those of the given GLPI entities."""
        with self.store() as store:
            machines = store.machines()
        for jid, glpi_uuid in machines:
            try:
                machine_entity_id = machine_entity(jid, glpi_uuid)
                if entity_ids is not None and machine_entity_id not in entity_ids:
                    continue
                with self.store() as store:
                    store.recompute_machine(jid, machine_entity_id)
            except Exception as error:
                logger.error("Updates of %s not recomputed: %s" % (jid, error))

    def recompute_all(self):
        self.recompute_machines()

    def purge_orphan_reports(self):
        """Drop the reports of machines no longer known to xmppmaster
        (deleted, or registered again under another JID)."""
        with self.store() as store:
            purged = store.purge_orphan_reports()
        if purged:
            logger.info("Updates: %d report(s) of unknown machines removed" % purged)
        return purged

    def run_upgrades(self):
        """Steps of the upgrades launched by the admin (scheduled with the automatic deployments)."""
        from lib.plugins.updates.deployments import DURATION, create_deployment
        from lib.plugins.updates.packages import start_build

        def create(candidate):
            now = datetime.now().replace(microsecond=0)
            create_deployment(candidate, now, now + DURATION)

        # The scheduled pass and the one of a launch must not both deploy a step
        if not UPGRADES_LOCK.acquire(blocking=False):
            return
        try:
            with self.store() as store:
                upgrades.run_launched(store, create, lambda: start_build(self))
        except Exception:
            logger.error("Upgrades not run\n%s" % traceback.format_exc())
        finally:
            UPGRADES_LOCK.release()

    def recompute_entity(self, entity_id):
        """Recompute the machines of the entity and of its descendants."""
        with self.store() as store:
            entity_ids = store.descendants(entity_id)
        self.recompute_machines(entity_ids)


def reported_dotnet(raw):
    """.NET versions of the stored report, None when it does not give them."""
    try:
        dotnet = (json.loads(raw).get("system") or {}).get("dotnet")
    except (TypeError, ValueError, AttributeError):
        return None
    return dotnet if isinstance(dotnet, list) else None


def machine_entity(jid, glpi_uuid):
    """GLPI entity of the machine, None when GLPI does not know it."""
    database = XmppMasterDatabase()
    glpi_uuid = glpi_uuid or database.get_inventory_uuid_from_bare_jid(jid)
    if not glpi_uuid:
        return None
    return database.get_glpi_machine_entity(glpi_uuid)


class UpdatesStore(object):
    """
    SQL access to the updates tables, inside the caller's transaction.
    """

    def __init__(self, connection):
        self.connection = connection
        # {family or value of packages.LINUX_UPGRADES: package identifier}, built at first need
        self.linux_packages = None

    def execute(self, sql, params=None):
        return self.connection.execute(text(sql), params or {})

    def execute_in(self, sql, params, *names):
        """Execute with the given parameters expanded as IN lists."""
        statement = text(sql).bindparams(
            *[bindparam(name, expanding=True) for name in names]
        )
        return self.connection.execute(statement, params)

    def execute_many(self, sql, rows):
        if rows:
            self.connection.execute(text(sql), rows)

    def state(self):
        row = self.execute(
            "SELECT mirror_generation, mirror_version FROM replication WHERE id = 1"
        ).fetchone()
        return row[0], row[1]

    def mark_attempt(self):
        self.execute("UPDATE replication SET last_attempt_at = NOW() WHERE id = 1")

    def save_success(self, generation, version):
        self.execute(
            "UPDATE replication SET mirror_generation = :generation,"
            " mirror_version = :version, last_success_at = NOW(), last_error = NULL"
            " WHERE id = 1",
            {"generation": generation, "version": version},
        )

    def save_error(self, error):
        self.execute(
            "UPDATE replication SET last_error = :error WHERE id = 1", {"error": error}
        )

    def media_version(self):
        return self.execute(
            "SELECT media_version FROM replication WHERE id = 1"
        ).scalar()

    def save_media(self, media, version):
        self.execute("DELETE FROM media_files")
        self.execute_many(
            "INSERT INTO media_files (file_name, edition, base_build, architecture,"
            " language_code, size, sha256, url) VALUES (:file_name, :edition,"
            " :base_build, :architecture, :language_code, :size, :sha256, :url)",
            media,
        )
        self.execute(
            "UPDATE replication SET media_version = :version WHERE id = 1",
            {"version": version},
        )

    def linux_releases_version(self):
        return self.execute(
            "SELECT linux_releases_version FROM replication WHERE id = 1"
        ).scalar()

    def save_linux_releases(self, releases, version):
        self.execute("DELETE FROM linux_releases")
        self.execute_many(
            "INSERT INTO linux_releases (distribution, release_name, codename, released)"
            " VALUES (:distribution, :release, :codename, :released)",
            releases,
        )
        self.execute(
            "UPDATE replication SET linux_releases_version = :version WHERE id = 1",
            {"version": version},
        )

    def kept_references(self):
        """Approvals and package links, with the Microsoft identity of their update."""
        identity = ("mucatalog_id", "wsus_id", "kb", "title")
        kept = {}
        for table, alias, columns in (
            ("approvals", "a", ("entity_id", "status", "decided_by", "decided_at")),
            ("update_packages", "p", ("package_uuid",)),
        ):
            rows = self.execute(
                "SELECT %s, %s FROM %s %s JOIN updates u ON u.id = %s.update_id"
                % (
                    ", ".join("%s.%s" % (alias, column) for column in columns),
                    ", ".join("u.%s" % column for column in identity),
                    table,
                    alias,
                    alias,
                )
            )
            kept[table] = [dict(zip(columns + identity, row)) for row in rows]
        return kept

    def clear_updates(self):
        """Empty the copied updates; files and CVEs are kept (keyed by hash and name)."""
        for table in ("approvals", "update_packages", "supersedences"):
            self.execute("DELETE FROM %s" % table)
        # The Linux packages are not copied from the mirror
        self.execute("DELETE FROM machine_updates WHERE package IS NULL")
        self.execute("DELETE FROM updates")

    def update_identities(self):
        columns = ("id", "mucatalog_id", "wsus_id", "kb", "title")
        rows = self.execute("SELECT %s FROM updates" % ", ".join(columns))
        return [dict(zip(columns, row)) for row in rows]

    def restore_references(self, table, rows):
        if table == "approvals":
            self.execute_many(
                "INSERT INTO approvals (entity_id, update_id, status, decided_by, decided_at)"
                " VALUES (:entity_id, :update_id, :status, :decided_by, :decided_at)"
                " ON DUPLICATE KEY UPDATE status = VALUES(status)",
                rows,
            )
        else:
            self.execute_many(
                "INSERT IGNORE INTO update_packages (update_id, package_uuid)"
                " VALUES (:update_id, :package_uuid)",
                rows,
            )

    def reset_copied(self):
        self.execute("UPDATE products SET copied = 0")

    def tracked_products(self, copied):
        """Products tracked by at least one entity."""
        rows = self.execute(
            "SELECT DISTINCT p.mirror_id FROM products p"
            " JOIN entity_products e ON e.product_id = p.id WHERE p.copied = :copied",
            {"copied": int(copied)},
        )
        return [row[0] for row in rows]

    def copied_products(self):
        return self.tracked_products(True)

    def pending_products(self):
        return self.tracked_products(False)

    def mark_copied(self, mirror_ids):
        self.execute_many(
            "UPDATE products SET copied = 1 WHERE mirror_id = :mirror_id",
            [{"mirror_id": mirror_id} for mirror_id in mirror_ids],
        )

    def product_ids(self):
        return dict(self.execute("SELECT mirror_id, id FROM products").fetchall())

    def release_ids(self):
        rows = self.execute("SELECT os_product_name, build, id FROM releases")
        return {(row[0], row[1]): row[2] for row in rows}

    def save_products(self, products):
        self.execute_many(
            "INSERT INTO products (mirror_id, name, family, display_group, display_name,"
            " position, supported, copied, created_at)"
            " VALUES (:id, :name, :family, :display_group, :display_name,"
            " :position, :supported, 0, NOW())"
            " ON DUPLICATE KEY UPDATE name = VALUES(name), family = VALUES(family),"
            " display_group = VALUES(display_group), display_name = VALUES(display_name),"
            " position = VALUES(position), supported = VALUES(supported)",
            [
                {
                    "id": item["id"],
                    "name": item["name"],
                    "family": item.get("family"),
                    "display_group": item.get("display_group"),
                    "display_name": item.get("display_name"),
                    "position": item.get("position") or 0,
                    "supported": int(item.get("supported", 1)),
                }
                for item in products
            ],
        )

    def save_releases(self, releases):
        if not releases:
            return
        product_ids = self.product_ids()
        self.execute_many(
            "INSERT INTO releases (product_id, os_product_name, build, name, architecture)"
            " VALUES (:product_id, :os_product_name, :build, :name, :architecture)"
            " ON DUPLICATE KEY UPDATE product_id = VALUES(product_id),"
            " name = VALUES(name), architecture = VALUES(architecture)",
            [
                {
                    "product_id": product_ids.get(item.get("product_id")),
                    "os_product_name": item["os_product_name"],
                    "build": item["build"],
                    "name": item.get("name"),
                    "architecture": item.get("architecture"),
                }
                for item in releases
            ],
        )

    def save_updates(self, updates):
        if not updates:
            return
        product_ids = self.product_ids()
        release_ids = self.release_ids()
        rows = []
        for update in updates:
            release = update.get("release")
            release_id = None
            if release:
                release_id = release_ids.get((release["os_product_name"], release["build"]))
            rows.append(
                {
                    "id": update["id"],
                    "mucatalog_id": update.get("mucatalog_id"),
                    "wsus_id": update.get("wsus_id"),
                    "kb": update.get("kb"),
                    "title": update.get("title"),
                    "description": update.get("description"),
                    "classification": update.get("classification"),
                    "severity": update.get("severity"),
                    "release_id": release_id,
                    "target_version": update.get("target_version"),
                    "dotnet_versions": ",".join(map(str, update.get("dotnet") or [])) or None,
                    "published_at": to_datetime(update.get("published_at")),
                    "superseded": bool(update.get("superseded")),
                    "removed": bool(update.get("removed")),
                }
            )
        self.execute_many(
            "INSERT INTO updates (id, mucatalog_id, wsus_id, kb, title, description,"
            " classification, severity, release_id, target_version, dotnet_versions,"
            " published_at, superseded, removed, updated_at)"
            " VALUES (:id, :mucatalog_id, :wsus_id, :kb, :title, :description,"
            " :classification, :severity, :release_id, :target_version, :dotnet_versions,"
            " :published_at, :superseded, :removed, NOW())"
            " ON DUPLICATE KEY UPDATE mucatalog_id = VALUES(mucatalog_id),"
            " wsus_id = VALUES(wsus_id), kb = VALUES(kb), title = VALUES(title),"
            " description = VALUES(description), classification = VALUES(classification),"
            " severity = VALUES(severity), release_id = VALUES(release_id),"
            " target_version = VALUES(target_version),"
            " dotnet_versions = VALUES(dotnet_versions), published_at = VALUES(published_at),"
            " superseded = VALUES(superseded), removed = VALUES(removed), updated_at = NOW()",
            rows,
        )

        ids = [{"update_id": update["id"]} for update in updates]
        self.execute_many("DELETE FROM update_products WHERE update_id = :update_id", ids)
        self.execute_many("DELETE FROM update_files WHERE update_id = :update_id", ids)
        self.execute_many("DELETE FROM supersedences WHERE update_id = :update_id", ids)

        update_products = []
        update_files = {}
        supersedences = []
        for update in updates:
            for mirror_id in update.get("products") or []:
                if mirror_id in product_ids:
                    update_products.append(
                        {"update_id": update["id"], "product_id": product_ids[mirror_id]}
                    )
            for superseded_id in update.get("supersedes") or []:
                supersedences.append(
                    {"update_id": update["id"], "superseded_id": superseded_id}
                )
            for file, language in file_rows(update):
                key = (update["id"], self.save_file(file))
                # A file shared by several language variants has no language
                update_files[key] = language if update_files.get(key, language) == language else None

        self.execute_many(
            "INSERT INTO update_products (update_id, product_id)"
            " VALUES (:update_id, :product_id)",
            update_products,
        )
        self.execute_many(
            "INSERT INTO update_files (update_id, file_id, language)"
            " VALUES (:update_id, :file_id, :language)",
            [
                {"update_id": update_id, "file_id": file_id, "language": language}
                for (update_id, file_id), language in update_files.items()
            ],
        )
        self.execute_many(
            "INSERT INTO supersedences (update_id, superseded_id)"
            " VALUES (:update_id, :superseded_id)",
            supersedences,
        )

    def save_file(self, file):
        """Upsert a file by sha1 and return its id."""
        self.execute(
            "INSERT INTO files (sha1, sha256, name, size, url, kind)"
            " VALUES (:sha1, :sha256, :name, :size, :url, :kind)"
            " ON DUPLICATE KEY UPDATE sha256 = VALUES(sha256), name = VALUES(name),"
            " size = VALUES(size), url = VALUES(url), kind = VALUES(kind)",
            {
                "sha1": file["sha1"],
                "sha256": file.get("sha256"),
                "name": file.get("name"),
                "size": file.get("size"),
                "url": file.get("url"),
                "kind": file.get("kind"),
            },
        )
        return self.execute(
            "SELECT id FROM files WHERE sha1 = :sha1", {"sha1": file["sha1"]}
        ).scalar()

    def save_cves(self, cves):
        for cve in cves:
            self.execute(
                "INSERT INTO cves (cve, title, severity, cvss_score, exploited,"
                " publicly_disclosed, published_at)"
                " VALUES (:cve, :title, :severity, :cvss_score, :exploited,"
                " :publicly_disclosed, :published_at)"
                " ON DUPLICATE KEY UPDATE title = VALUES(title), severity = VALUES(severity),"
                " cvss_score = VALUES(cvss_score), exploited = VALUES(exploited),"
                " publicly_disclosed = VALUES(publicly_disclosed),"
                " published_at = VALUES(published_at)",
                {
                    "cve": cve["cve"],
                    "title": cve.get("title"),
                    "severity": cve.get("severity"),
                    "cvss_score": cve.get("cvss_score"),
                    "exploited": bool(cve.get("exploited")),
                    "publicly_disclosed": bool(cve.get("publicly_disclosed")),
                    "published_at": to_datetime(cve.get("published_at")),
                },
            )
            cve_id = self.execute(
                "SELECT id FROM cves WHERE cve = :cve", {"cve": cve["cve"]}
            ).scalar()
            self.execute("DELETE FROM kb_cves WHERE cve_id = :cve_id", {"cve_id": cve_id})
            self.execute_many(
                "INSERT INTO kb_cves (kb, cve_id) VALUES (:kb, :cve_id)",
                [{"kb": kb, "cve_id": cve_id} for kb in set(cve.get("kbs") or [])],
            )

    def save_machine_report(self, jid, report, glpi_uuid=None):
        """Store the updates report of a machine. Linux: the packages it would
        upgrade are its missing updates, nothing to compute."""
        row = report_row(jid, report, glpi_uuid)
        columns = list(row)
        # Upsert, never REPLACE: the cascade would drop the missing updates.
        # A report sent while the machine registers has no GLPI uuid yet: keep the known one
        self.execute(
            "INSERT INTO machine_reports (%s, received_at) VALUES (%s, NOW())"
            " ON DUPLICATE KEY UPDATE %s, received_at = NOW(),"
            " glpi_uuid = COALESCE(VALUES(glpi_uuid), glpi_uuid)"
            % (
                ", ".join("`%s`" % column for column in columns),
                ", ".join(":%s" % column for column in columns),
                ", ".join(
                    "`%s` = VALUES(`%s`)" % (column, column)
                    for column in updated_columns(report)
                    if column != "glpi_uuid"
                ),
            ),
            row,
        )
        if row["glpi_uuid"]:
            # Same GLPI machine under another jid: renamed or reinstalled
            self.execute(
                "DELETE FROM machine_reports WHERE glpi_uuid = :glpi_uuid AND jid <> :jid",
                {"glpi_uuid": row["glpi_uuid"], "jid": jid},
            )
        installed = installed_rows(jid, report)
        if installed is not None:
            self.execute(
                "DELETE FROM machine_installed_kbs WHERE jid = :jid", {"jid": jid}
            )
            self.execute_many(
                "INSERT INTO machine_installed_kbs (jid, kb, installed_on)"
                " VALUES (:jid, :kb, :installed_on)",
                installed,
            )
        if is_linux(report):
            packages = linux_update_rows(jid, report)
            if packages is not None:
                self.save_machine_updates(jid, packages)
            return
        missing = missing_rows(jid, report)
        if missing is not None:
            self.execute(
                "DELETE FROM machine_missing_updates WHERE jid = :jid", {"jid": jid}
            )
            self.execute_many(
                "INSERT INTO machine_missing_updates (jid, windows_update_id, kb, title)"
                " VALUES (:jid, :windows_update_id, :kb, :title)",
                missing,
            )

    def machines(self):
        return self.execute("SELECT jid, glpi_uuid FROM machine_reports").fetchall()

    def purge_orphan_reports(self):
        """Child rows go with the report (ON DELETE CASCADE).
        Nothing is removed when xmppmaster lists no machine at all."""
        if not self.execute("SELECT EXISTS (SELECT 1 FROM xmppmaster.machines)").scalar():
            return 0
        return self.execute(
            "DELETE FROM machine_reports WHERE jid NOT IN"
            " (SELECT SUBSTRING_INDEX(jid, '/', 1) FROM xmppmaster.machines)"
        ).rowcount

    def machine_glpi_uuid(self, jid):
        return self.execute(
            "SELECT glpi_uuid FROM machine_reports WHERE jid = :jid", {"jid": jid}
        ).scalar()

    def machine_report(self, jid):
        columns = (
            "build",
            "ubr",
            "architecture",
            "release",
            "system_type",
            "esu_licensed",
            "search_status",
            "search_server",
            "searched_at",
            "edition",
            "language",
            "windows11_eligible",
            "windows11_blockers",
            "report",
            "os",
            "reboot_pending",
        )
        row = self.execute(
            "SELECT %s FROM machine_reports WHERE jid = :jid"
            % ", ".join("`%s`" % column for column in columns),
            {"jid": jid},
        ).fetchone()
        if not row:
            return None
        report = dict(zip(columns, row))
        raw = report.pop("report")
        report["dotnet"] = reported_dotnet(raw)
        if report.get("os") == "linux":
            report["raw_report"] = raw
        if report["windows11_eligible"] is not None:
            report["windows11_eligible"] = bool(report["windows11_eligible"])
        return report

    def descendants(self, entity_id):
        """The entity and every entity below it."""
        rows = self.execute(
            "SELECT entity_id FROM entity_ancestors WHERE ancestor_id = :entity_id",
            {"entity_id": entity_id},
        )
        return {row[0] for row in rows} | {entity_id}

    def tracking_source(self, entity_id):
        """Entity whose tracked products apply to entity_id, None if none."""
        return self.execute(
            "SELECT source_id FROM effective_products WHERE entity_id = :entity_id",
            {"entity_id": entity_id},
        ).scalar()

    def entity_products(self, entity_id):
        rows = self.execute(
            "SELECT product_id FROM entity_products WHERE entity_id = :entity_id",
            {"entity_id": entity_id},
        )
        return {row[0] for row in rows}

    def entity_releases(self, entity_id):
        rows = self.execute(
            "SELECT product_id, release_name FROM entity_releases"
            " WHERE entity_id = :entity_id",
            {"entity_id": entity_id},
        )
        return {(row[0], row[1]) for row in rows}

    def linux_releases_source(self, entity_id):
        """Entity whose tracked Linux versions apply to entity_id: nearest ancestor
        with its own, possibly empty; None if none."""
        return self.execute(
            "SELECT eo.entity_id FROM entity_ancestors ea"
            " JOIN entity_overrides eo ON eo.entity_id = ea.ancestor_id"
            " AND eo.setting = 'linux_releases'"
            " WHERE ea.entity_id = :entity_id ORDER BY ea.depth LIMIT 1",
            {"entity_id": entity_id},
        ).scalar()

    def tracked_linux_releases(self, entity_id, distribution):
        rows = self.execute(
            "SELECT release_name FROM entity_linux_releases"
            " WHERE entity_id = :entity_id AND distribution = :distribution",
            {"entity_id": entity_id, "distribution": distribution},
        )
        return {row[0] for row in rows}

    def machine_releases(self, build, architecture, system_type):
        rows = self.execute(
            "SELECT os_product_name, product_id, name FROM releases"
            " WHERE build = :build AND architecture = :architecture",
            {"build": build, "architecture": architecture},
        )
        return compute.own_releases([tuple(row) for row in rows], system_type)

    def installed_kbs(self, jid):
        rows = self.execute(
            "SELECT kb FROM machine_installed_kbs WHERE jid = :jid", {"jid": jid}
        )
        return {row[0] for row in rows}

    def windows_missing(self, jid):
        rows = self.execute(
            "SELECT m.kb, m.title, m.windows_update_id, i.installed_on"
            " FROM machine_missing_updates m"
            " LEFT JOIN machine_installed_kbs i ON i.jid = m.jid AND i.kb = m.kb"
            " WHERE m.jid = :jid",
            {"jid": jid},
        )
        return [{"kb": row[0], "title": row[1], "windows_update_id": row[2], "installed_on": row[3]}
                for row in rows]

    def machine_catalog(self, build, architecture, kbs):
        """Current updates and system cumulatives of the machine release, and every update of kbs."""
        rows = self.execute_in(
            "SELECT u.id, u.kb, u.title, r.build, r.architecture, u.published_at,"
            " u.superseded, u.removed, u.classification, r.product_id, r.name,"
            " u.target_version, u.dotnet_versions, u.wsus_id"
            " FROM updates u LEFT JOIN releases r ON r.id = u.release_id"
            " WHERE (r.build = :build AND r.architecture = :architecture"
            " AND (u.superseded = 0 OR u.title LIKE '%Cumulative Update for Windows%'"
            " OR u.title LIKE '%Cumulative Update Preview for Windows%') AND u.removed = 0"
            " AND (u.classification IS NULL OR u.classification <> :upgrades))"
            " OR u.kb IN :kbs",
            # An empty IN list is not valid SQL
            {
                "build": build,
                "architecture": architecture,
                "upgrades": compute.UPGRADES,
                "kbs": list(kbs) or [None],
            },
            "kbs",
        ).fetchall()
        catalog = {
            row[0]: {
                "id": row[0],
                "kb": row[1],
                "title": row[2],
                "build": row[3],
                "architecture": row[4],
                "published_at": row[5],
                "superseded": bool(row[6]),
                "removed": bool(row[7]),
                "classification": row[8],
                "release": (row[9], row[10]) if row[10] is not None else None,
                "target_version": row[11],
                "dotnet": row[12].split(",") if row[12] else None,
                "wsus_id": row[13],
                "products": set(),
            }
            for row in rows
        }
        if catalog:
            links = self.execute_in(
                "SELECT update_id, product_id FROM update_products"
                " WHERE update_id IN :ids",
                {"ids": list(catalog)},
                "ids",
            )
            for update_id, product_id in links:
                catalog[update_id]["products"].add(product_id)
        return list(catalog.values())

    def supersedes(self, update_ids):
        """Supersedence chains above update_ids: {superseded: [(update, kb)]}."""
        if not update_ids:
            return {}
        rows = self.execute_in(
            "WITH RECURSIVE chain (id) AS ("
            " SELECT update_id FROM supersedences WHERE superseded_id IN :ids"
            " UNION SELECT s.update_id FROM supersedences s"
            " JOIN chain c ON s.superseded_id = c.id)"
            " SELECT s.superseded_id, s.update_id, u.kb FROM supersedences s"
            " LEFT JOIN updates u ON u.id = s.update_id"
            " WHERE s.superseded_id IN :ids OR s.superseded_id IN (SELECT id FROM chain)",
            {"ids": list(update_ids)},
            "ids",
        )
        supersedes = {}
        for superseded_id, update_id, kb in rows:
            supersedes.setdefault(superseded_id, []).append((update_id, kb))
        return supersedes

    def tracked_release_rows(self, entity_id, system_type):
        """Releases checked for the entity, with their build and architecture, of the
        machine system type when known: a name is shared by a client and a server."""
        rows = self.execute(
            "SELECT r.name, r.build, r.architecture, r.os_product_name FROM releases r"
            " JOIN entity_releases e ON e.product_id = r.product_id"
            " AND e.release_name = r.name WHERE e.entity_id = :entity_id",
            {"entity_id": entity_id},
        )
        return [dict(zip(("name", "build", "architecture"), row)) for row in rows
                if not system_type or compute.of_system(row[3], system_type)]

    def shared_builds(self):
        """(build, build) of releases sharing a system cumulative KB: same base."""
        rows = self.execute(
            "SELECT DISTINCT ra.build, rb.build FROM updates ua"
            " JOIN releases ra ON ra.id = ua.release_id"
            " JOIN updates ub ON ub.kb = ua.kb AND ub.id <> ua.id"
            " JOIN releases rb ON rb.id = ub.release_id"
            " WHERE ra.build < rb.build"
            " AND ua.title LIKE '%Cumulative Update for Windows%'"
            " AND ub.title LIKE '%Cumulative Update for Windows%'"
            " AND ua.title NOT LIKE '%Dynamic%' AND ub.title NOT LIKE '%Dynamic%'"
        )
        return [tuple(row) for row in rows]

    def upgrade_media(self, architecture):
        rows = self.execute(
            "SELECT file_name, edition, base_build, architecture, language_code"
            " FROM media_files WHERE architecture = :architecture",
            {"architecture": architecture},
        )
        columns = ("file_name", "edition", "base_build", "architecture", "language_code")
        return [dict(zip(columns, row)) for row in rows]

    def save_machine_upgrade(self, jid, row):
        """Computed columns only: the launch by the admin is kept."""
        self.execute(
            "INSERT INTO machine_upgrades (jid, state, target_release, target_build,"
            " steps, reason, media_file, computed_at) VALUES (:jid, :state,"
            " :target_release, :target_build, :steps, :reason, :media_file, NOW())"
            " ON DUPLICATE KEY UPDATE state = VALUES(state),"
            " target_release = VALUES(target_release), target_build = VALUES(target_build),"
            " steps = VALUES(steps), reason = VALUES(reason),"
            " media_file = VALUES(media_file), computed_at = NOW()",
            dict(row, jid=jid, steps=",".join(row["steps"]) or None),
        )

    def recompute_upgrade(self, jid, report, source_id, rows, facts=None):
        """Upgrade target and steps of the machine; a failure is our defect, never hidden.
        Linux: rows are its pending packages. Windows: facts of machine_facts."""
        try:
            if report.get("os") == "linux":
                raw_report = json.loads(report["raw_report"])
                distribution = (raw_report.get("system") or {}).get("distribution")
                row = upgrades.linux_upgrade(
                    raw_report,
                    len(rows),
                    self.tracked_linux_releases(source_id, distribution) if source_id is not None else set(),
                    self.release_failed(jid),
                    self.launched_target(jid),
                )
            else:
                row = upgrades.machine_upgrade(
                    report,
                    self.tracked_release_rows(source_id, report["system_type"]) if source_id is not None else [],
                    self.shared_builds(),
                    self.upgrade_media(report["architecture"]),
                    bool(compute.missing_cumulatives(report, *facts)),
                )
        except Exception as error:
            logger.error("Upgrade of %s not computed: %s" % (jid, error))
            row = upgrades.result(upgrades.UNDETERMINED, reason=str(error)[:255])
        if row["state"] == upgrades.UNDETERMINED:
            logger.error("Upgrade of %s undetermined: %s" % (jid, row["reason"]))
        self.save_machine_upgrade(jid, row)

    def launched_upgrades(self):
        """Launched upgrades; in_window: a step may start now (upgrade window of the entity)."""
        columns = ("jid", "glpi_uuid", "hostname", "architecture", "build", "received_at",
                   "reboot_pending", "state", "steps", "reason", "target_release", "target_build",
                   "launched_at", "media_file", "edition", "os", "family", "pending_packages",
                   "window_start", "window_end", "entity_id", "distribution")
        rows = self.execute(
            "SELECT m.jid, mr.glpi_uuid, mr.hostname, mr.architecture, mr.build, mr.received_at,"
            " mr.reboot_pending, m.state, m.steps, m.reason, m.target_release, m.target_build,"
            " m.launched_at, m.media_file, mr.edition, mr.os, mr.family,"
            " (SELECT COUNT(DISTINCT mu.package) FROM machine_updates mu WHERE mu.jid = m.jid),"
            " es.upgrade_window_start, es.upgrade_window_end, lgm.entities_id, mr.distribution"
            " FROM machine_upgrades m JOIN machine_reports mr ON mr.jid = m.jid"
            " LEFT JOIN xmppmaster.local_glpi_machines lgm"
            " ON mr.glpi_uuid REGEXP '^UUID[0-9]+$'"
            " AND lgm.id = CAST(SUBSTRING(mr.glpi_uuid, 5) AS UNSIGNED)"
            " LEFT JOIN effective_settings es ON es.entity_id = lgm.entities_id"
            " WHERE m.launched_at IS NOT NULL"
        )
        now = datetime.now().time()
        upgrades_rows = []
        for row in rows:
            upgrade = dict(zip(columns, row))
            upgrade["steps"] = upgrade["steps"].split(",") if upgrade["steps"] else []
            upgrade["in_window"] = in_window(now, upgrade.pop("window_start"),
                                             upgrade.pop("window_end"))
            upgrades_rows.append(upgrade)
        return upgrades_rows

    def step_update(self, upgrade, step):
        """Update whose package runs the step: the system cumulative the machine
        misses, or the upgrade entry of the target (its enablement package)."""
        if step == upgrades.CUMULATIVE:
            return self.missing_cumulative(upgrade["jid"])
        return self.execute(
            upgrades.enablement_update_sql(":build", ":architecture"),
            {"build": upgrade["target_build"], "architecture": upgrade["architecture"]},
        ).scalar()

    def missing_cumulative(self, jid):
        """Most recent system cumulative the machine misses, tracked or not."""
        report = self.machine_report(jid)
        if report is None:
            return None
        facts = self.machine_facts(jid, report)
        return compute.latest_cumulative_id(compute.missing_cumulatives(report, *facts), facts[3])

    def launched_cumulatives(self):
        """Cumulatives of the launched upgrades, to build."""
        rows = self.execute(
            "SELECT jid FROM machine_upgrades"
            " WHERE launched_at IS NOT NULL AND FIND_IN_SET('cumulative', steps)"
        ).fetchall()
        return {self.missing_cumulative(row[0]) for row in rows} - {None}

    def step_package(self, update_id):
        row = self.execute(
            "SELECT p.uuid, p.state, u.kb FROM update_packages up"
            " JOIN packages p ON p.uuid = up.package_uuid JOIN updates u ON u.id = up.update_id"
            " WHERE up.update_id = :update_id",
            {"update_id": update_id},
        ).fetchone()
        return dict(zip(("uuid", "state", "kb"), row)) if row else None

    def media_package(self, file_name, edition):
        """Package of the media (ESD and edition) of the scan and media steps."""
        row = self.execute(
            "SELECT p.uuid, p.state FROM media_packages mp JOIN packages p ON p.uuid = mp.package_uuid"
            " WHERE mp.file_name = :file_name AND mp.edition = :edition",
            {"file_name": file_name, "edition": edition},
        ).fetchone()
        return {"uuid": row[0], "state": row[1], "kb": None} if row else None

    def linux_upgrade_package(self, distribution):
        """Package of the release upgrade of the distribution, None when not built."""
        from lib.plugins.updates import packages
        from lib.plugins.updates.deployments import linux_packages

        if self.linux_packages is None:
            self.linux_packages = linux_packages(UpdatesDatabase())
        package_id = self.linux_packages.get(packages.LINUX_UPGRADES.get(distribution))
        return {"uuid": package_id, "state": "ready", "kb": None} if package_id else None

    def linux_pending_packages(self, jid):
        rows = self.execute(
            "SELECT DISTINCT package FROM machine_updates"
            " WHERE jid = :jid AND package IS NOT NULL ORDER BY package",
            {"jid": jid},
        )
        return [row[0] for row in rows]

    def last_deployment(self, glpi_uuid, package_uuid, since):
        """Last deployment of the package on the machine since the launch, None if none.

        Read in its logs, not in deploy.state, which is rewritten after the end
        (ABORT ON TIMEOUT, PENDING REBOOT): ended = « DEPLOYMENT TERMINATE », a
        success or an error line, or the command end date passed, a transfer failure
        being restarted by xmppmaster until that date; success =
        « Execution successful » without « Package execution error »,
        postponed = POSTPONED_COMMENT logged by the package (restart pending, Windows busy),
        interrupted = ended by the server without a result from the machine (machine
        lost from sight a moment: the package may still run)."""
        params = {"uuid": glpi_uuid, "package": package_uuid, "since": since}
        pending = self.execute(
            pending_command_sql(":uuid") +
            " AND c.package_id COLLATE utf8mb4_unicode_ci = :package"
            " AND c.creation_date >= :since LIMIT 1",
            params,
        ).first()
        deployments = (
            " FROM xmppmaster.deploy d JOIN msc.commands c ON c.id = d.command"
            " WHERE d.inventoryuuid = :uuid"
            " AND c.package_id COLLATE utf8mb4_unicode_ci = :package"
            " AND d.start >= :since"
        )
        attempts = self.execute("SELECT COUNT(*)" + deployments, params).scalar() or 0
        row = self.execute(
            "SELECT d.state, d.sessionid, d.endcmd" + deployments + " ORDER BY d.id DESC LIMIT 1",
            params,
        ).fetchone()
        if row is None:
            if pending:
                return {"running": True, "success": False, "postponed": False, "interrupted": False,
                        "state": "pending", "ended_at": None, "attempts": attempts}
            return None
        state, session, endcmd = row
        logs = self.execute(
            "SELECT MAX(date),"
            " SUM(text LIKE 'DEPLOYMENT TERMINATE%'),"
            " SUM(text LIKE '%Execution successful%'),"
            " SUM(text LIKE '%Package execution error%'),"
            " SUM(text LIKE :postponed)"
            " FROM xmppmaster.logs WHERE sessionname = :session",
            {"session": session, "postponed": "%%%s%%" % upgrades.POSTPONED_COMMENT},
        ).fetchone()
        ended_at, terminated, successful, errors, postponed = logs
        # A successful deployment may log no TERMINATE line
        answered = bool(terminated or successful or errors)
        expired = endcmd is not None and endcmd < datetime.now()
        # xmppmaster restarts it while its window is open
        restarting = (state or "").endswith(TRANSFER_FAILED) and not expired
        ended = not restarting and (answered or expired)
        return {
            "running": bool(pending) or not ended,
            "success": ended and bool(successful) and not errors,
            "postponed": ended and bool(postponed),
            "interrupted": ended and not answered,
            "state": state,
            "session": session,
            "ended_at": ended_at or endcmd,
            "attempts": attempts,
        }

    def last_return_code(self, session):
        """Code the failed step of the deployment ended with, None if unknown."""
        return upgrades.result_return_code(self.execute(
            "SELECT result FROM xmppmaster.deploy WHERE sessionid = :session LIMIT 1",
            {"session": session},
        ).scalar())

    def machine_busy(self, glpi_uuid):
        """A deployment of any package still runs on the machine."""
        return self.execute(
            "SELECT 1 FROM xmppmaster.deploy d WHERE d.inventoryuuid = :uuid AND "
            + DEPLOY_RUNNING_SQL + " LIMIT 1",
            {"uuid": glpi_uuid},
        ).first() is not None

    # Deployments of a launched upgrade not ended yet
    OPEN_STEPS_SQL = (
        " xmppmaster.deploy d JOIN msc.commands c ON c.id = d.command"
        " WHERE d.inventoryuuid = :uuid AND ("
        + " OR ".join("d.title LIKE '%s'" % title.replace("%s", "%")
                      for title in (upgrades.WINDOWS_TITLE, upgrades.LINUX_TITLE))
        + ")"
        " AND d.start >= :since AND NOT " + DEPLOY_FINAL_SQL + " AND d.endcmd > NOW()"
    )
    # The report shows the package of the step applied: its KB installed, or the
    # build of its upgrade entry or of its media reached. Linux: never, the server
    # ends the step at its end date
    STEP_APPLIED_SQL = (
        " AND (EXISTS (SELECT 1 FROM update_packages up JOIN updates u ON u.id = up.update_id"
        " LEFT JOIN releases r ON r.id = u.release_id"
        " WHERE c.package_id COLLATE utf8mb4_unicode_ci = up.package_uuid AND ("
        "(u.classification = 'Upgrades' AND r.build <= :build)"
        " OR (COALESCE(u.classification, '') <> 'Upgrades'"
        " AND u.kb IN (SELECT kb FROM machine_installed_kbs WHERE jid = :jid))))"
        " OR EXISTS (SELECT 1 FROM media_packages mp JOIN media_files f"
        " ON f.file_name = mp.file_name AND f.edition = mp.edition"
        " WHERE c.package_id COLLATE utf8mb4_unicode_ci = mp.package_uuid"
        " AND CAST(SUBSTRING_INDEX(f.base_build, '.', 1) AS UNSIGNED) <= :build))"
    )

    def open_steps(self, upgrade):
        """Deployments of the launched upgrade not ended yet."""
        return self.execute(
            "SELECT COUNT(*) FROM" + self.OPEN_STEPS_SQL,
            {"uuid": upgrade["glpi_uuid"], "since": upgrade["launched_at"]},
        ).scalar() or 0

    def end_lost_steps(self, upgrade, package_uuid=None):
        """Bring forward the end date of the deployments of the launched upgrade, other
        than the package of its current step, still open while a report received since,
        and older than the server's 10 minutes of presence, shows them applied: the server
        then closes them in ABORT ON TIMEOUT, its state for an expired deployment."""
        received = upgrade["received_at"]
        if received is None or received > datetime.now() - LOST_STEP_DELAY:
            return 0
        lost = self.execute(
            "SELECT d.id FROM" + self.OPEN_STEPS_SQL + self.STEP_APPLIED_SQL +
            " AND d.start < :received"
            " AND (:package IS NULL OR c.package_id COLLATE utf8mb4_unicode_ci <> :package)",
            {"uuid": upgrade["glpi_uuid"], "since": upgrade["launched_at"], "received": received,
             "package": package_uuid, "jid": upgrade["jid"], "build": upgrade["build"]},
        ).fetchall()
        self.execute_many(
            "UPDATE xmppmaster.deploy SET endcmd = NOW() WHERE id = :id",
            [{"id": row[0]} for row in lost],
        )
        if lost:
            logger.warning("Upgrade of %s: %d deployment(s) of a previous step ended, session lost"
                           % (upgrade["jid"], len(lost)))
        return len(lost)

    def release_failed(self, jid):
        error = self.execute(
            "SELECT run_error FROM machine_upgrades WHERE jid = :jid", {"jid": jid}
        ).scalar()
        return (error or "").startswith(upgrades.RELEASE + ":")

    def launched_target(self, jid):
        return self.execute(
            "SELECT target_release FROM machine_upgrades"
            " WHERE jid = :jid AND launched_at IS NOT NULL",
            {"jid": jid},
        ).scalar()

    def stop_upgrade(self, jid, error):
        self.execute(
            "UPDATE machine_upgrades SET launched_at = NULL, run_error = :error WHERE jid = :jid",
            {"jid": jid, "error": error[:255] if error else None},
        )

    def clear_run_error(self, jid):
        """A step runs again: only now the last failure is over (release_failed)."""
        self.execute("UPDATE machine_upgrades SET run_error = NULL WHERE jid = :jid", {"jid": jid})

    LINUX_UPDATE_COLUMNS = ("package", "installed_version", "available_version",
                            "classification", "severity")

    def save_machine_updates(self, jid, rows):
        self.execute("DELETE FROM machine_updates WHERE jid = :jid", {"jid": jid})
        defaults = dict(dict.fromkeys(self.LINUX_UPDATE_COLUMNS), offer=compute.MAIN)
        self.execute_many(
            "INSERT INTO machine_updates (jid, update_id, kb, title, origin, offer,"
            " %s, computed_at)"
            " VALUES (:jid, :update_id, :kb, :title, :origin, :offer, %s, NOW())"
            % (", ".join(self.LINUX_UPDATE_COLUMNS),
               ", ".join(":" + column for column in self.LINUX_UPDATE_COLUMNS)),
            [dict(defaults, **dict(row, jid=jid)) for row in rows],
        )

    def recompute_machine(self, jid, entity_id):
        """Replace the machine rows, inside the caller's transaction."""
        report = self.machine_report(jid)
        if report is None:
            return
        if report.get("os") == "linux":
            # Linux: the rows are the packages of the report, stored with it
            source_id = None if entity_id is None else self.linux_releases_source(entity_id)
            self.recompute_upgrade(jid, report, source_id, self.linux_pending_packages(jid))
            return
        if entity_id is None:
            logger.debug("Updates of %s: no GLPI entity" % jid)
            self.save_machine_updates(jid, [])
            self.save_machine_upgrade(jid, upgrades.result(upgrades.NO_REPORT, reason="no_entity"))
            return
        source_id = self.tracking_source(entity_id)
        if source_id is None:
            tracked, tracked_releases = set(), set()
        else:
            tracked = self.entity_products(source_id)
            tracked_releases = self.entity_releases(source_id)
        facts = self.machine_facts(jid, report)
        rows = compute.machine_updates(report, tracked, tracked_releases, *facts)
        self.save_machine_updates(jid, rows)
        logger.debug("Updates of %s: %d missing" % (jid, len(rows)))
        self.recompute_upgrade(jid, report, source_id, rows, facts)

    def machine_facts(self, jid, report):
        """(machine_releases, installed_kbs, windows_missing, catalog, supersedes) of compute."""
        machine_releases = self.machine_releases(
            report["build"], report["architecture"], report["system_type"]
        )
        installed = self.installed_kbs(jid)
        missing = self.windows_missing(jid) if compute.uses_windows_list(report) else []
        catalog = self.machine_catalog(
            report["build"],
            report["architecture"],
            # Installed cumulatives superseded since then still date the coverage
            {item["kb"] for item in missing if item["kb"] is not None} | installed,
        )
        supersedes = self.supersedes([update["id"] for update in catalog])
        return machine_releases, installed, missing, catalog, supersedes
