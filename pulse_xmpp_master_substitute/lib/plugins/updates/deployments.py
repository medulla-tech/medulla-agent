# -*- coding: utf-8; -*-
# SPDX-FileCopyrightText: 2026 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-3.0-or-later
# file : pulse_xmpp_master_substitute/lib/plugins/updates/deployments.py

"""
Automatic deployment of the approved Windows updates and Linux packages, inside
the window of each entity that enabled it (auto_deploy). The fileless KBs
(packages.fileless_kbs(), the Defender definitions) follow neither that setting nor
its window: kept up to date at any time once their product is tracked and a rule
covers them. Workstations only: a server is never updated automatically.
"""

from contextlib import contextmanager
from datetime import datetime, time, timedelta
import hashlib
import json
import logging
import traceback

logger = logging.getLogger()

CREATOR = "automatic"
TITLE = "Windows update"
DURATION = timedelta(days=1)
DEFAULT_LIMIT = 20

# xmppmaster.deploy states after which a deployment no longer runs; a transfer
# failure, ERROR or ABORT, is restarted by xmppmaster after 10 minutes while its
# window is open (mmc_restart_blocked_deployments_transfer_error)
TRANSFER_FAILED = "TRANSFER FAILED"
DEPLOY_FINAL_SQL = (
    "(d.state IN ('DEPLOYMENT SUCCESS', 'UNINSTALL SUCCESS')"
    " OR ((d.state LIKE 'ERROR%%' OR d.state LIKE 'ABORT%%')"
    " AND d.state NOT LIKE '%%%s'))" % TRANSFER_FAILED
)
DEPLOY_RUNNING_SQL = "NOT " + DEPLOY_FINAL_SQL + " AND (d.endcmd IS NULL OR d.endcmd >= NOW())"


def pending_command_sql(uuid):
    """Command of the machine uuid (SQL expression) not yet handed to the deployment loop."""
    return (
        "SELECT 1 FROM msc.commands c"
        " JOIN msc.commands_on_host coh ON coh.fk_commands = c.id"
        " JOIN msc.target t ON t.id = coh.fk_target"
        " JOIN msc.phase ph ON ph.fk_commands_on_host = coh.id"
        " WHERE t.target_uuid COLLATE utf8mb4_unicode_ci = " + uuid +
        " AND ph.name = 'execute' AND ph.state = 'ready' AND c.end_date >= NOW()"
    )


# The precheck of the package would postpone it and end in error; unknown: as today
NO_RESTART_PENDING_SQL = "COALESCE(mr.reboot_pending, 0) = 0"

# Machines of the reports known to GLPI and enabled, with their entity (lgm.entities_id)
MACHINES_SQL = (
    " FROM machine_reports mr"
    " JOIN xmppmaster.local_glpi_machines lgm"
    " ON mr.glpi_uuid REGEXP '^UUID[0-9]+$'"
    " AND lgm.id = CAST(SUBSTRING(mr.glpi_uuid, 5) AS UNSIGNED)"
    " AND lgm.is_deleted = 0 AND lgm.is_template = 0"
    " JOIN xmppmaster.machines xm"
    " ON SUBSTRING_INDEX(xm.jid, '/', 1) = mr.jid AND xm.enabled = 1"
)
# Another deployment still holds the machine
NOT_DEPLOYING_SQL = (
    " AND NOT EXISTS (SELECT 1 FROM xmppmaster.deploy d"
    " WHERE d.inventoryuuid = mr.glpi_uuid AND " + DEPLOY_RUNNING_SQL + ")"
)
# An upgrade launched by the admin runs its own steps
NO_LAUNCHED_UPGRADE_SQL = (
    " AND NOT EXISTS (SELECT 1 FROM machine_upgrades mg"
    " WHERE mg.jid = mr.jid AND mg.launched_at IS NOT NULL)"
)
# A command not yet handed to the deployment loop
NO_PENDING_COMMAND_SQL = " AND NOT EXISTS (" + pending_command_sql("mr.glpi_uuid") + ")"

# Entities of the automatic deployments of updates and Linux packages; not asked for
# the fileless KBs
ENTITIES_SQL = (
    "SELECT entity_id, window_start, window_end FROM effective_settings"
    " WHERE auto_deploy = 1"
)

CANDIDATES_SQL = (
    "SELECT mr.jid, mr.glpi_uuid, COALESCE(xm.hostname, mr.hostname),"
    " u.id, u.kb, up.package_uuid,"
    " EXISTS (SELECT 1 FROM kb_cves kc JOIN cves c ON c.id = kc.cve_id"
    " WHERE kc.kb = u.kb AND c.exploited = 1) AS exploited,"
    " (u.severity = 'Critical') AS critical"
    + MACHINES_SQL +
    " JOIN machine_updates mu ON mu.jid = mr.jid AND mu.offer = 'main'"
    " JOIN approved_updates au"
    " ON au.entity_id = lgm.entities_id AND au.update_id = mu.update_id"
    " JOIN updates u ON u.id = mu.update_id"
    " JOIN update_packages up ON up.update_id = u.id"
    " JOIN packages p ON p.uuid = up.package_uuid AND p.state = 'ready'"
    " WHERE lgm.entities_id IN :entities"
    " AND mr.system_type = 'client'"
    " AND " + NO_RESTART_PENDING_SQL
    + NOT_DEPLOYING_SQL
    + NO_LAUNCHED_UPGRADE_SQL +
    # One automatic try per package and machine: after a failure the admin redeploys
    " AND NOT EXISTS (SELECT 1 FROM xmppmaster.deploy d"
    " JOIN msc.commands c ON c.id = d.command"
    " WHERE d.inventoryuuid = mr.glpi_uuid"
    " AND c.package_id COLLATE utf8mb4_unicode_ci = up.package_uuid)"
    + NO_PENDING_COMMAND_SQL +
    " ORDER BY exploited DESC, critical DESC, u.published_at IS NULL,"
    " u.published_at, u.id, mr.jid"
)

# A launched upgrade runs its own steps; after a failed release step the sources may
# already be on the target: its packages only go through the upgrade procedure
LINUX_UPGRADE_HOLD_SQL = (
    "SELECT 1 FROM machine_upgrades mg WHERE mg.jid = mr.jid"
    " AND (mg.launched_at IS NOT NULL OR mg.run_error LIKE 'release:%')"
)

# Linux machines with packages approved by a Linux rule of their entity, one
# deployment per machine with all of them; one try per report: the report that
# follows a deployment says what is left (binds :entities, :packages, the
# identifiers of the Linux packages)
LINUX_CANDIDATES_SQL = (
    "SELECT mr.jid, mr.glpi_uuid, COALESCE(xm.hostname, mr.hostname), mr.family,"
    " GROUP_CONCAT(DISTINCT mu.package ORDER BY mu.package SEPARATOR ' '),"
    " GROUP_CONCAT(DISTINCT CONCAT(mu.package, '=', COALESCE(mu.available_version, ''))"
    " SEPARATOR ' ')"
    + MACHINES_SQL +
    " JOIN effective_rules er ON er.entity_id = lgm.entities_id AND er.os = 'linux'"
    " JOIN machine_updates mu ON mu.jid = mr.jid AND mu.package IS NOT NULL"
    " JOIN approval_rules ar ON ar.entity_id = er.source_id AND ar.os = 'linux'"
    " AND ar.classification = mu.classification"
    " AND (ar.severity IS NULL OR ar.severity = mu.severity)"
    " WHERE lgm.entities_id IN :entities"
    " AND mr.os = 'linux' AND mr.family IN :families"
    # Unknown type: not a desktop for sure, a server is never updated automatically
    " AND mr.system_type = 'client'"
    + NOT_DEPLOYING_SQL +
    " AND NOT EXISTS (" + LINUX_UPGRADE_HOLD_SQL + ")"
    " AND NOT EXISTS (SELECT 1 FROM xmppmaster.deploy d"
    " JOIN msc.commands c ON c.id = d.command"
    " WHERE d.inventoryuuid = mr.glpi_uuid"
    " AND c.package_id COLLATE utf8mb4_unicode_ci IN :packages"
    " AND d.start >= mr.received_at)"
    + NO_PENDING_COMMAND_SQL +
    " GROUP BY mr.jid, mr.glpi_uuid, xm.hostname, mr.hostname, mr.family"
    " ORDER BY mr.jid"
)
LINUX_TITLE = "Linux updates"

# Releases of the build of the machine, of its system type (compute.own_releases)
OWN_RELEASES_SQL = (
    "r.build = mr.build AND r.architecture = mr.architecture"
    " AND r.os_product_name LIKE CONCAT(mr.system_type, '.%')"
)

def report_value_sql(path):
    """Scalar of the raw report of the machine as text, NULL when absent. JSON_EXTRACT
    alone keeps the quotes of a string and gives a boolean as the text true."""
    return "JSON_UNQUOTE(JSON_EXTRACT(mr.report, '%s'))" % path


# Windows workstations whose last report made a search that lists a fileless KB
# (packages.fileless_kbs(): never a row of machine_updates), of a product their entity
# tracks, with a Windows rule of their entity covering a catalog entry of the KB, and
# Defender said active by the report. One try per report, as for Linux, hence per
# search. Any entity, at any time: neither auto_deploy nor its window. A pending restart
# does not stop it: its package has no precheck and never restarts (binds :kb, :package,
# the identifier of the package of the KB)
FILELESS_CANDIDATES_SQL = (
    "SELECT mr.jid, mr.glpi_uuid, COALESCE(xm.hostname, mr.hostname)"
    + MACHINES_SQL +
    " JOIN effective_products ep ON ep.entity_id = lgm.entities_id"
    " JOIN effective_rules er ON er.entity_id = lgm.entities_id AND er.os = 'windows'"
    " JOIN packages p ON p.uuid = :package AND p.state = 'ready'"
    " WHERE mr.os = 'windows' AND mr.system_type = 'client'"
    # The stored list is the one of this report: a report without a search (skipped)
    # keeps the list and the search_status of the last search
    " AND " + report_value_sql("$.search.status") + " = 'ok'"
    # Absent, null or false: the script of the package would fail at every report
    " AND " + report_value_sql("$.defender.enabled") + " = 'true'"
    " AND EXISTS (SELECT 1 FROM machine_missing_updates mm"
    " WHERE mm.jid = mr.jid AND mm.kb = :kb)"
    # A machine on a known version the entity does not track gets nothing
    # (compute.is_version_tracked)
    " AND (NOT EXISTS (SELECT 1 FROM releases r"
    " WHERE " + OWN_RELEASES_SQL + " AND r.name IS NOT NULL)"
    " OR EXISTS (SELECT 1 FROM releases r JOIN entity_releases erl"
    " ON erl.entity_id = ep.source_id AND erl.product_id = r.product_id"
    " AND erl.release_name = r.name WHERE " + OWN_RELEASES_SQL + "))"
    " AND EXISTS (SELECT 1 FROM updates u"
    " JOIN update_products upr ON upr.update_id = u.id"
    " JOIN entity_products enp"
    " ON enp.entity_id = ep.source_id AND enp.product_id = upr.product_id"
    " JOIN approval_rules ar ON ar.entity_id = er.source_id AND ar.os = 'windows'"
    " AND ar.classification = u.classification"
    " AND (ar.severity IS NULL OR ar.severity = u.severity)"
    " WHERE u.kb = :kb AND u.removed = 0)"
    + NOT_DEPLOYING_SQL
    + NO_LAUNCHED_UPGRADE_SQL +
    " AND NOT EXISTS (SELECT 1 FROM xmppmaster.deploy d"
    " JOIN msc.commands c ON c.id = d.command"
    " WHERE d.inventoryuuid = mr.glpi_uuid"
    " AND c.package_id COLLATE utf8mb4_unicode_ci = :package"
    " AND d.start >= mr.received_at)"
    + NO_PENDING_COMMAND_SQL +
    " ORDER BY mr.jid"
)
TARGETS_PARAMETER = "targets"


def to_time(value):
    """TIME column as datetime.time (the driver returns a timedelta)."""
    if value is None or isinstance(value, time):
        return value
    seconds = int(value.total_seconds()) % 86400
    return time(seconds // 3600, seconds // 60 % 60, seconds % 60)


def in_window(now, start, end):
    """now inside [start, end); the window may cross midnight.
    No window, or start = end: any time."""
    start, end = to_time(start), to_time(end)
    if start is None or end is None or start == end:
        return True
    if start < end:
        return start <= now < end
    return now >= start or now < end


def pick(candidates, limit):
    """At most limit pairs, one per machine, in the candidates order."""
    chosen = []
    machines = set()
    for candidate in candidates:
        if len(chosen) >= limit:
            break
        if candidate["jid"] in machines:
            continue
        machines.add(candidate["jid"])
        chosen.append(candidate)
    return chosen


def label(candidate):
    return candidate.get("title") or "KB%s" % candidate["kb"]


def title(candidate, now):
    """« -@upd@- » files the deployment as an update (session « update »)."""
    label = candidate.get("title") or "%s KB%s" % (TITLE, candidate["kb"])
    return "%s -@upd@- %s" % (label, now.strftime("%Y-%m-%d %H:%M:%S"))


class DeploymentStore(object):
    """SQL of the automatic deployments, inside the caller's transaction."""

    def __init__(self, store):
        self.store = store

    def relays(self, jid):
        return machine_relays(self.store.execute, jid)

    def open_entities(self, now):
        rows = self.store.execute(ENTITIES_SQL)
        return [row[0] for row in rows if in_window(now, row[1], row[2])]

    def candidates(self, entity_ids):
        if not entity_ids:
            return []
        rows = self.store.execute_in(
            CANDIDATES_SQL, {"entities": list(entity_ids)}, "entities"
        )
        columns = ("jid", "glpi_uuid", "hostname", "update_id", "kb", "package_uuid")
        return [dict(zip(columns, row)) for row in rows]

    def linux_candidates(self, entity_ids, packages):
        """packages: linux_packages(); its upgrade keys match no family."""
        if not entity_ids or not packages:
            return []
        rows = self.store.execute_in(
            LINUX_CANDIDATES_SQL,
            {"entities": list(entity_ids), "families": list(packages),
             "packages": list(packages.values())},
            "entities", "families", "packages",
        )
        candidates = [linux_candidate(row, packages) for row in rows.fetchall()]
        return [candidate for candidate in candidates if not self.linux_attempted(candidate)]

    def fileless_candidates(self, packages):
        """packages: fileless_packages(), {KB: identifier of its package}. Machines of
        any entity: open_entities() is not asked."""
        candidates = []
        for kb, package_uuid in sorted(packages.items()):
            rows = self.store.execute(
                FILELESS_CANDIDATES_SQL, {"kb": kb, "package": package_uuid}
            )
            candidates += [
                {"jid": row[0], "glpi_uuid": row[1], "hostname": row[2], "kb": kb,
                 "package_uuid": package_uuid}
                for row in rows
            ]
        return candidates

    def linux_attempted(self, candidate):
        """One automatic try per list of packages and versions: after a failure the
        admin deploys, or the list changes. Read in the parameters of the command."""
        return self.store.execute(
            "SELECT 1 FROM xmppmaster.deploy d JOIN msc.commands c ON c.id = d.command"
            " WHERE d.inventoryuuid = :uuid AND c.parameters LIKE :mark LIMIT 1",
            {"uuid": candidate["glpi_uuid"],
             "mark": '%%"%s":"%s"%%' % (TARGETS_PARAMETER, candidate["parameters"][TARGETS_PARAMETER])},
        ).first() is not None


def linux_candidate(row, packages):
    jid, glpi_uuid, hostname, family, names, targets = row
    return {
        "jid": jid,
        "glpi_uuid": glpi_uuid,
        "hostname": hostname,
        "kb": None,
        "package_uuid": packages[family],
        "title": LINUX_TITLE,
        "parameters": {
            "packages": (names or "").split(),
            TARGETS_PARAMETER: hashlib.sha1(" ".join(sorted((targets or "").split())).encode()).hexdigest(),
        },
    }


# Relays of the cluster of the machine: any of them may be given its deployment
MACHINE_RELAYS_SQL = (
    "SELECT DISTINCT r2.nameserver FROM xmppmaster.machines m"
    " JOIN xmppmaster.relayserver r ON r.jid = m.groupdeploy"
    " LEFT JOIN xmppmaster.has_cluster_ars h ON h.id_ars = r.id"
    " LEFT JOIN xmppmaster.has_cluster_ars h2 ON h2.id_cluster = h.id_cluster"
    " JOIN xmppmaster.relayserver r2 ON r2.id = COALESCE(h2.id_ars, r.id)"
    " WHERE SUBSTRING_INDEX(m.jid, '/', 1) = :jid"
)


def machine_relays(execute, jid):
    """Host names of the relays that may serve the machine."""
    return [row[0] for row in execute(MACHINE_RELAYS_SQL, {"jid": jid}) if row[0]]


def relays_pending(package_uuid, relays=None):
    """Why a deployment of the package waits for the relays of the machine, None when it
    may start."""
    from lib import package_sync
    from lib.plugins.updates.packages import PACKAGES_DIR

    try:
        return package_sync.pending("%s/%s" % (PACKAGES_DIR, package_uuid), relays)
    except package_sync.Unknown as error:
        # No answer: the deployment starts, a missing package is tried again as before
        logger.debug("Relays not asked for %s: %s" % (package_uuid, error))
        return None


def create_deployment(candidate, start_date, end_date):
    """Same records as the deployment of an update from the console."""
    from lib.plugins.msc import MscDatabase
    from lib.plugins.xmpp import XmppMasterDatabase

    command = MscDatabase().createcommanddirectxmpp(
        candidate["package_uuid"],
        "",
        json.dumps(dict(candidate.get("parameters") or {}, section="update"),
                   separators=(",", ":")),
        "fileslistpackage",
        "enable",
        "enable",
        start_date,
        end_date,
        "root",
        CREATOR,
        title(candidate, start_date),
        60,
        4,
        0,
        "",
        None,
        None,
        None,
        "none",
        "active",
        "1",
        cmd_type=0,
    )
    target = MscDatabase().xmpp_create_Target(
        candidate["glpi_uuid"], candidate["hostname"]
    )
    com_on_host = MscDatabase().xmpp_create_CommandsOnHost(
        command.id, target["id"], candidate["hostname"], command.end_date,
        command.start_date,
    )
    MscDatabase().xmpp_create_CommandsOnHostPhasedeploykiosk(com_on_host.id)
    XmppMasterDatabase().addlogincommand(
        CREATOR, command.id, "", "", "", "", "", 0, 0, 0, 0, {}
    )


def run(open_store, limit=DEFAULT_LIMIT, create=create_deployment, now=None, linux_packages=None,
        pending=None, fileless_packages=None):
    """Create the deployments of this run; return how many were created.
    linux_packages: {family: package identifier} of the Linux packages built.
    fileless_packages: {KB: package identifier} of the fileless packages built; their
    candidates come last, of any entity and outside the windows, within the same limit."""
    now = now or datetime.now().replace(microsecond=0)
    with open_store() as store:
        entity_ids = store.open_entities(now.time())
        candidates = store.candidates(entity_ids)
        candidates += store.linux_candidates(entity_ids, linux_packages or {})
        candidates += store.fileless_candidates(fileless_packages or {})
    chosen = pick(candidates, limit)
    with open_store() as store:
        relays = {candidate["jid"]: store.relays(candidate["jid"]) for candidate in chosen}
    pending = pending or relays_pending
    created = 0
    for candidate in chosen:
        waiting = pending(candidate["package_uuid"], relays[candidate["jid"]])
        if waiting:
            logger.info("Automatic deployment of %s on %s waits: %s"
                        % (label(candidate), candidate["hostname"], waiting))
            continue
        try:
            create(candidate, now, now + DURATION)
        except Exception:
            logger.error(
                "Automatic deployment of %s on %s failed\n%s"
                % (label(candidate), candidate["hostname"], traceback.format_exc())
            )
            continue
        created += 1
        logger.info(
            "Automatic deployment of %s on %s"
            % (label(candidate), candidate["hostname"])
        )
    logger.debug(
        "Automatic deployments: %d entities in window, %d candidates,"
        " %d created (limit %d)"
        % (len(entity_ids), len(candidates), created, limit)
    )
    return created


def database_store(database):
    @contextmanager
    def open_store():
        with database.store() as store:
            yield DeploymentStore(store)

    return open_store


def linux_packages(database):
    """{family: package identifier} of the Linux packages, and the release upgrade
    ones under the values of packages.LINUX_UPGRADES, written and registered when
    missing (cheap once they exist)."""
    from lib.plugins.updates import packages

    builder = packages.Builder(packages.database_store(database))
    built = {}
    for family in packages.LINUX_FAMILIES + tuple(packages.LINUX_UPGRADES.values()):
        try:
            built[family] = builder.linux_package(family)
        except Exception:
            logger.error("Linux package %s not built\n%s" % (family, traceback.format_exc()))
    return built


def fileless_packages(database):
    """{KB: package identifier} of the fileless KBs (packages.fileless_kbs()) a tracked
    product holds, written and registered when missing (cheap once they exist)."""
    from lib.plugins.updates import packages

    builder = packages.Builder(packages.database_store(database))
    built = {}
    for kb in sorted(packages.fileless_kbs()):
        try:
            package_id = builder.fileless_package(kb)
        except Exception:
            logger.error("Package of KB%s not built\n%s" % (kb, traceback.format_exc()))
            continue
        if package_id:
            built[kb] = package_id
    return built


def windows_update_package(database):
    """Identifier of the package of the installation by Windows Update, written and
    registered when missing (cheap once it exists); None when it could not be. Never
    deployed from here: by the admin only, from the machine page."""
    from lib.plugins.updates import packages

    try:
        return packages.Builder(packages.database_store(database)).windows_update_package()
    except Exception:
        logger.error("Windows Update package not built\n%s" % traceback.format_exc())
        return None


def start(database, limit=DEFAULT_LIMIT):
    windows_update_package(database)
    try:
        run(database_store(database), limit, linux_packages=linux_packages(database),
            fileless_packages=fileless_packages(database))
    except Exception:
        logger.error("Automatic deployments failed\n%s" % traceback.format_exc())
