# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2026 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-3.0-or-later
# file : pulse_xmpp_master_substitute/lib/plugins/updates/upgrades.py

"""
Version upgrade of a machine: target and path, from its report and the replicated catalog.

Inputs (loaded by UpdatesStore):
- report: machine_reports row (edition, build, architecture, language, system_type,
  windows11_eligible, windows11_blockers), None without report
- tracked: releases rows {name, build, architecture} checked by the admin for the machine entity
- shared_builds: (build, build) pairs of releases sharing a cumulative KB; connected
  builds are one base, reached from one another by an enablement package
- media: media_files rows {file_name, edition, base_build, architecture, language_code}
- missing_cumulative: True when the machine misses a system cumulative

The target is the most recent tracked release, by name, above the machine one, that has
a path. Same base: enablement package. Other base: complete media of that base (exact
edition, installation language), then the enablement package when the target is above
the media base. Medulla runs every step it can (cumulative first, compatibility scan);
the admin only sees a limit Medulla cannot remove (hardware, per Windows).

Debian, Ubuntu, AlmaLinux: the next major release the machine reports (linux_upgrade),
once checked for its entity, reached by its pending packages, then the release upgrade
package of the distribution.
"""

from datetime import datetime, timedelta
import json
import logging
import re
import traceback

logger = logging.getLogger()

UP_TO_DATE = "up_to_date"
READY = "ready"
NOT_ELIGIBLE = "not_eligible"
NOT_CONCERNED = "not_concerned"
# Transient: the machine is asked for a report
NO_REPORT = "no_report"
# Our defect, never the admin's: counted and reported
UNDETERMINED = "undetermined"

# Steps run by the upgrade, in order
CUMULATIVE = "cumulative"
SCAN = "scan"
MEDIA = "media"
ENABLEMENT = "enablement"
# Linux: one deployment, the pending packages then the next major release
RELEASE = "release"
LINUX_STEPS = (RELEASE,)

# Titles of the step deployments, also read back to find the open ones
WINDOWS_TITLE = "Windows upgrade to %s"
LINUX_TITLE = "Linux upgrade to %s %s"
# Distributions upgraded (ID of os-release), as named in the titles
LINUX_DISTRIBUTIONS = {"debian": "Debian", "ubuntu": "Ubuntu", "almalinux": "AlmaLinux"}
# Each step is one deployment: its name tells them apart in the history
WINDOWS_STEP_NAMES = {
    "cumulative": "cumulative update",
    "scan": "installation",
    "media": "installation",
    "enablement": "enablement",
}
TARGET_LENGTH = 20
# Logged at INFO by the package when its guard postpones it, read back by last_deployment
POSTPONED_COMMENT = "Installation postponed"
# ERROR_DISK_FULL, then its HRESULT 0x80070070 unsigned and signed
DISK_FULL_CODES = (112, 2147942512, -2147024784)
DISK_FULL = "disk_full"
# Linux release package: exit codes of a stop that left the machine as it was. Only
# "release:" in run_error tells an upgrade really begun, to resume
PRECHECK = "precheck"
STOPPED = "stopped"
PRECHECK_CODES = {113: DISK_FULL, 114: STOPPED}
# Linux release package: a restart is needed first, nothing of the upgrade begun. The
# package logs POSTPONED_COMMENT: the step runs again after the restart
RESTART_FIRST_CODE = 115
# Never "release:", which holds the machine for a resumption, nor "precheck:"
RESTART_FIRST_FAILURE = "upgrade: restart still pending"
CODENAME = re.compile(r"\(([a-z]+)\)$")

# Long-term servicing editions never move to the general channel
LTSC_EDITION = re.compile(r"^(IoT)?EnterpriseS[NK]?$")


def bases(shared_builds):
    """{build: base} where base is the lowest build connected to it."""
    parent = {}

    def find(build):
        parent.setdefault(build, build)
        while parent[build] != build:
            parent[build] = parent[parent[build]]
            build = parent[build]
        return build

    for first, second in shared_builds:
        a, b = find(first), find(second)
        if a != b:
            parent[max(a, b)] = min(a, b)
    return {build: find(build) for build in parent}


def base_of(build, base_by_build):
    return base_by_build.get(build, build)


def media_build(row):
    return int(row["base_build"].split(".")[0])


def enablement_update_sql(build, architecture):
    """Upgrade entry of a client release, the one holding its enablement package."""
    return (
        "SELECT u.id FROM updates u JOIN releases r ON r.id = u.release_id"
        " WHERE u.classification = 'Upgrades' AND r.build = " + build +
        " AND r.architecture = " + architecture +
        " AND r.os_product_name LIKE 'Client.%'"
        " ORDER BY u.published_at DESC LIMIT 1"
    )


def result(state, target=None, steps=(), reason=None, media_file=None):
    return {
        "state": state,
        "target_release": target["name"] if target else None,
        "target_build": target["build"] if target else None,
        "steps": list(steps),
        "reason": reason,
        "media_file": media_file,
    }


def machine_upgrade(report, tracked, shared_builds, media, missing_cumulative):
    """Upgrade row of one machine: {state, target_release, target_build, steps, reason, media_file}."""
    if not report or not report.get("build") or not report.get("architecture"):
        return result(NO_REPORT)
    edition = report.get("edition") or ""
    if report.get("system_type") == "server":
        return result(NOT_CONCERNED, reason="server")
    if LTSC_EDITION.match(edition):
        return result(NOT_CONCERNED, reason="ltsc")

    base_by_build = bases(shared_builds)
    machine_base = base_of(report["build"], base_by_build)
    candidates = sorted(
        (
            release
            for release in tracked
            if release["architecture"] == report["architecture"]
            and release["build"] > report["build"]
        ),
        key=lambda release: (release["name"] or "", release["build"]),
        reverse=True,
    )
    for target in candidates:
        target_base = base_of(target["build"], base_by_build)
        if target_base == machine_base:
            return result(READY, target, ([CUMULATIVE] if missing_cumulative else []) + [ENABLEMENT])

        base_media = [
            row
            for row in media
            if row["architecture"] == report["architecture"]
            and base_of(media_build(row), base_by_build) == target_base
            and media_build(row) <= target["build"]
        ]
        if not base_media:
            # No Microsoft media for this base (e.g. 26H1, new devices only)
            continue
        if report.get("windows11_eligible") is False:
            return result(NOT_ELIGIBLE, target, reason=report.get("windows11_blockers") or None)
        language = (report.get("language") or "").lower()
        matching = [
            row for row in base_media if row["edition"] == edition and row["language_code"] == language
        ]
        if not matching:
            # Every client edition and installation language has Microsoft media
            return result(UNDETERMINED, target, reason="no media: %s %s" % (edition, language or "?"))
        steps = [SCAN, MEDIA]
        if target["build"] > max(map(media_build, base_media)):
            steps.append(ENABLEMENT)
        # Unknown eligibility: the scan, first step, decides
        return result(READY, target, steps, media_file=max(matching, key=media_build)["file_name"])
    return result(UP_TO_DATE)


def linux_release_name(release):
    """« 26.04 (resolute) », « 10 » without a code name."""
    name = release["version"]
    if release.get("codename"):
        name = "%s (%s)" % (name, release["codename"])
    return name[:TARGET_LENGTH]


def linux_upgrade(report, pending_packages, tracked, release_failed=False, launched_target=None):
    """Upgrade row of a Linux machine from its raw report; LINUX_DISTRIBUTIONS only.

    report["upgrade"] (plugin updates_linux): {current, target, blockers}.
    tracked: versions checked for the entity and distribution of the machine.
    release_failed: the last release step failed; it may already announce the
    target release, the packages left still to upgrade.
    launched_target: target_release of the launched upgrade, None if none. Only that
    target goes on unchecked: the next release the machine reports once there does not."""
    upgrade = report.get("upgrade")
    if not upgrade:
        if (report.get("system") or {}).get("distribution") not in LINUX_DISTRIBUTIONS:
            return result(NOT_CONCERNED, reason="distribution")
        # Plugin older than the upgrade part of the report
        return result(NO_REPORT)
    target = upgrade.get("target")
    if target:
        # The launched target reached: the next release is not part of this launch
        if launched_target and launched_target.split(" ")[0] == (upgrade.get("current") or {}).get("version"):
            return result(UP_TO_DATE)
        version = target["version"]
        target = {"name": linux_release_name(target), "build": None}
        # Before the blockers: they would show the target
        if not (version in tracked or release_failed or target["name"] == launched_target):
            return result(UP_TO_DATE)
    # Before the target: without distro-info-data the next release is unknown
    if upgrade.get("blockers"):
        return result(NOT_ELIGIBLE, target, reason=", ".join(upgrade["blockers"]))
    if not target:
        current = upgrade.get("current") or {}
        if release_failed and pending_packages > 0 and current.get("codename"):
            return result(READY, {"name": linux_release_name(current), "build": None}, [RELEASE])
        return result(UP_TO_DATE)
    return result(READY, target, [RELEASE])


def release_codename(target_release):
    """trixie of « 13 (trixie) », None otherwise."""
    match = CODENAME.search(target_release or "")
    return match.group(1) if match else None


# What the runner does for a launched upgrade
DEPLOY = "deploy"
WAIT = "wait"
DONE = "done"
FAILED = "failed"
# The scan is the first part of the media package: both run one deployment
MEDIA_STEPS = (SCAN, MEDIA)
AUTOMATED_STEPS = (CUMULATIVE, SCAN, MEDIA, ENABLEMENT) + LINUX_STEPS
# A step postponed by the package guard (restart pending, Windows busy) is tried again
MAX_ATTEMPTS = 3
# A step over, its effect still not reported: a locked machine may wait for its user
# for days, not for ever (restart refused, setup rolled back, machine gone)
STEP_WAIT_LIMIT = timedelta(days=14)


def report_after(deployment, received_at):
    """The last report follows the end of the deployment."""
    ended_at = deployment["ended_at"]
    return received_at is not None and ended_at is not None and received_at > ended_at


def lost_release(deployment, received_at):
    # Never run again by itself; a report older than the end says nothing of the result
    if report_after(deployment, received_at):
        return FAILED, "%s: %s" % (RELEASE, deployment["state"])
    return WAIT, RELEASE


def step_action(upgrade, deployment, received_at):
    if upgrade["state"] == UP_TO_DATE:
        if deployment is None:
            return DONE, None
        if deployment["running"]:
            # The release changes mid-step: the step goes on
            return WAIT, RELEASE
        if deployment["interrupted"] and upgrade.get("pending_packages"):
            return lost_release(deployment, received_at)
        if (not deployment["success"] and not deployment["postponed"]
                and not deployment["interrupted"]):
            return FAILED, "%s: %s" % (RELEASE, deployment["state"])
        return DONE, None
    if upgrade["state"] != READY:
        return FAILED, "%s: %s" % (upgrade["state"], upgrade.get("reason") or "")
    step = upgrade["steps"][0] if upgrade["steps"] else None
    if deployment is None:
        return DEPLOY, step
    if deployment["running"]:
        return WAIT, step
    if deployment["interrupted"] and step in LINUX_STEPS:
        return lost_release(deployment, received_at)
    if deployment["interrupted"] and step in MEDIA_STEPS:
        # Never run again by itself: setup may have prepared the machine
        return WAIT, step
    if deployment["postponed"] or deployment["interrupted"]:
        if deployment["attempts"] >= MAX_ATTEMPTS:
            return FAILED, "%s: %s" % (step, deployment["state"])
        # Try again once the machine reports after its restart; a step done in
        # the meantime is no longer the first one of the report
        if not report_after(deployment, received_at) or upgrade.get("reboot_pending"):
            return WAIT, step
        return DEPLOY, step
    if not deployment["success"]:
        return FAILED, "%s: %s" % (step, deployment["state"])
    if (not report_after(deployment, received_at) or upgrade.get("reboot_pending")
            or step in MEDIA_STEPS):
        # The step takes effect at the restart: wait for the report that follows it.
        # An upgrade cancelled at the restart comes back with no flag: never « no effect »
        return WAIT, step
    return FAILED, "%s: no effect on the machine" % step


def wait_cause(upgrade, deployment, received_at):
    if not report_after(deployment, received_at):
        return "no report from the machine"
    return "restart still pending" if upgrade.get("reboot_pending") else "machine unchanged"


def run_action(upgrade, deployment, received_at, now=None):
    """(action, reason) for a launched upgrade.

    upgrade: machine_upgrades row (state, steps as a list, reboot_pending,
    pending_packages), recomputed from the last report. deployment: last deployment of
    the package of its first step since the launch, {"running", "success", "postponed",
    "interrupted": bool, "state", "session", "ended_at", "attempts": deployments of that
    package since the launch}, None when there is none (Linux up to date: the release step one,
    a failed upgrade may already announce the new release). received_at: date of the
    last report. now: past STEP_WAIT_LIMIT after the end of the step, waiting is over.
    The next step always comes from the machine as reported, never from a counter.
    """
    action, reason = step_action(upgrade, deployment, received_at)
    if (action == WAIT and now is not None and deployment is not None
            and not deployment["running"] and deployment["ended_at"] is not None
            and now - deployment["ended_at"] > STEP_WAIT_LIMIT):
        return FAILED, "%s: %s %d days after the step" % (
            reason, wait_cause(upgrade, deployment, received_at), STEP_WAIT_LIMIT.days)
    return action, reason


def step_code(step):
    code = step.get("codereturn") if isinstance(step, dict) else None
    if not isinstance(code, (int, str)) or isinstance(code, bool):
        return None
    try:
        return int(code)
    except ValueError:
        return None


def result_return_code(result):
    """Last non-zero code of the last run in xmppmaster.deploy.result, None if none:
    the report step that follows a failed step always ends with 0."""
    try:
        runs = json.loads(result)["descriptorslist"]
        sequence = runs[-1]
    except (TypeError, ValueError, KeyError, IndexError):
        return None
    if not isinstance(sequence, list):
        return None
    codes = [step_code(step) for step in sequence]
    return next((code for code in reversed(codes) if code), None)


def failure_reason(store, upgrade, deployment, step, reason):
    """Cause of a stopped upgrade: a failed step out of disk space says so, a Linux
    release package that stopped without changing anything is not a release failure.
    Its step may be gone from a machine already on the target."""
    if deployment is None or deployment["success"]:
        return reason
    if upgrade.get("os") == "linux" and deployment["postponed"]:
        return RESTART_FIRST_FAILURE
    try:
        code = store.last_return_code(deployment.get("session"))
    except Exception as error:
        logger.warning("Upgrade of %s: return code not read: %s" % (upgrade["jid"], error))
        return reason
    if upgrade.get("os") == "linux" and code == RESTART_FIRST_CODE:
        return RESTART_FIRST_FAILURE
    if upgrade.get("os") == "linux" and code in PRECHECK_CODES:
        return "%s: %s" % (PRECHECK, PRECHECK_CODES[code])
    return "%s: %s" % (step or RELEASE, DISK_FULL) if code in DISK_FULL_CODES else reason


def run_launched(store, create, request_build):
    """One pass over the upgrades launched by the admin; return the deployments created.

    store: UpdatesStore (caller's transaction); create(candidate): creates a deployment;
    request_build(): asks the package builder to run."""
    created = 0
    for upgrade in store.launched_upgrades():
        try:
            created += run_one(store, upgrade, create, request_build)
        except Exception:
            logger.error("Upgrade of %s not run\n%s" % (upgrade["jid"], traceback.format_exc()))
    return created


def run_one(store, upgrade, create, request_build):
    deployment = None
    step = upgrade["steps"][0] if upgrade["steps"] else None
    package = None
    if upgrade["state"] == READY and step in AUTOMATED_STEPS:
        if step in LINUX_STEPS:
            package = store.linux_upgrade_package(upgrade.get("distribution"))
        elif step in MEDIA_STEPS:
            package = store.media_package(upgrade["media_file"], upgrade["edition"])
        else:
            update_id = store.step_update(upgrade, step)
            if not update_id:
                if not store.open_steps(upgrade):
                    store.stop_upgrade(upgrade["jid"], "%s: no catalog update" % step)
                return 0
            package = store.step_package(update_id)
        if package is None or package["state"] == "building":
            if step not in LINUX_STEPS:
                request_build()
            return 0
        if package["state"] != "ready":
            store.stop_upgrade(upgrade["jid"], "%s: package %s" % (step, package["state"]))
            return 0
        deployment = store.last_deployment(upgrade["glpi_uuid"], package["uuid"], upgrade["launched_at"])
    elif upgrade["state"] == UP_TO_DATE and upgrade.get("os") == "linux":
        release = store.linux_upgrade_package(upgrade.get("distribution"))
        if release is not None:
            deployment = store.last_deployment(upgrade["glpi_uuid"], release["uuid"], upgrade["launched_at"])
    action, reason = run_action(upgrade, deployment, upgrade["received_at"], datetime.now())
    if action == DONE or (action == FAILED and upgrade["state"] not in (READY, UP_TO_DATE)):
        # A conclusion from the state alone waits for the open steps: a report may
        # change the state while they run. Those it shows applied lost their session
        if store.open_steps(upgrade):
            store.end_lost_steps(upgrade)
            return 0
    if action == DEPLOY and store.machine_busy(upgrade["glpi_uuid"]):
        if not upgrade.get("reboot_pending"):
            # A previous step the report shows applied may still hold the machine:
            # its agent session was lost, the server ends it as on any timeout
            store.end_lost_steps(upgrade, package["uuid"])
        # Another deployment holds the machine: next pass
        return 0
    if action == DEPLOY and not upgrade.get("in_window", True):
        # Outside the upgrade window of the entity: the step starts in it
        return 0
    if action == DONE:
        store.stop_upgrade(upgrade["jid"], None)
        logger.info("Upgrade of %s done: %s" % (upgrade["jid"], upgrade["target_release"]))
    elif action == FAILED:
        reason = failure_reason(store, upgrade, deployment, step, reason)
        store.stop_upgrade(upgrade["jid"], reason)
        logger.warning("Upgrade of %s stopped: %s" % (upgrade["jid"], reason))
        if upgrade.get("os") == "linux":
            # A failed release step is still to do: no need to wait for the next report
            store.recompute_machine(upgrade["jid"], upgrade.get("entity_id"))
    elif action == DEPLOY:
        candidate = {
            "jid": upgrade["jid"],
            "glpi_uuid": upgrade["glpi_uuid"],
            "hostname": upgrade["hostname"],
            "kb": package["kb"],
            "package_uuid": package["uuid"],
            "title": "%s (%s)" % (WINDOWS_TITLE % upgrade["target_release"],
                                  WINDOWS_STEP_NAMES.get(step, step)),
        }
        if step == RELEASE:
            codename = release_codename(upgrade["target_release"])
            candidate.update(title=LINUX_TITLE % (LINUX_DISTRIBUTIONS[upgrade["distribution"]],
                                                  upgrade["target_release"]),
                             parameters={"release": codename} if codename else {})
        create(candidate)
        store.clear_run_error(upgrade["jid"])
        logger.info("Upgrade of %s: %s step deployed" % (upgrade["jid"], step))
        return 1
    return 0
