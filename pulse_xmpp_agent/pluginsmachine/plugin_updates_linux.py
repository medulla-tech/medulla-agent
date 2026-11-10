# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2026 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-3.0-or-later
# file : pulse_xmpp_agent/pluginsmachine/plugin_updates_linux.py

"""
Linux updates report: asks the package manager of the machine what it
would upgrade (read only) and sends it to the updates substitute, in the
message of the Windows report. Debian, Ubuntu, AlmaLinux: also the next major
release and what blocks the upgrade to it.

Called by plugin_inventory, then every day by its own timer, every 30
minutes by scheduling_updates_linux when the machine changed, and by a
Linux update package at the end of its deployment
(@@@PLUGIN_CALL_updates_linux@@@ step of grafcetdeploy).
"""

import csv
from datetime import date, datetime, timezone
import glob
import gzip
import hashlib
import io
import json
import logging
import os
import platform
import re
import subprocess
import sys
import threading
import time
import traceback
import xml.etree.ElementTree as ElementTree

from lib import utils

logger = logging.getLogger()

plugin = {"VERSION": "1.1", "NAME": "updates_linux", "TYPE": "machine"}  # fmt: skip

REPORT_FORMAT = 1
REPORT_INTERVAL = 86400
# Refreshing the package lists is the network part of the search
REFRESH_TIMEOUT = 600
COMMAND_TIMEOUT = 300
LOCK_TIMEOUT = 1800
FINGERPRINT_FILE = "fingerprintupdateslinux"
LEGACY_FILES = (
    ("pathplugins", "plugin_update_linux_command.py"),
    ("pathplugins", "plugin_updatemedullainfo.py"),
    ("pathpluginsscheduled", "scheduling_win11compatcheck.py"),
    ("pathpluginsscheduled", "win11compatcheck.crontab"),
)
OS_RELEASE = ("/etc/os-release", "/usr/lib/os-release")
# Installed packages history sent in the report: recent transactions only
HISTORY_DAYS = 30
HISTORY_TRANSACTIONS = 100
HISTORY_PACKAGES = 200
APT_HISTORY = "/var/log/apt/history.log"
# rpm keeps no transaction: packages installed less than this apart are grouped
RPM_TRANSACTION_GAP = 300
# Running package tools (/proc/<pid>/comm, 15 characters at most): an upgrade or an
# installation under way, the report would disturb it and describe a moving state
PROC = "/proc"
APT_PROCESSES = ("apt", "apt-get", "aptitude", "dpkg", "unattended-upgr")
APT_WAIT = 30
# Debian releases and their dates (package distro-info-data)
DEBIAN_RELEASES = "/usr/share/distro-info/debian.csv"
APT_SOURCES = ("/etc/apt/sources.list", "/etc/apt/sources.list.d/*.list",
               "/etc/apt/sources.list.d/*.sources")
# Written by the upgrade package before it switches the sources
APT_BACKUP = "/var/backups/medulla-apt-%s"
# Debian 13 release notes, 5.1.5: /boot of 768 MB at least, about 300 MB free
BOOT_SIZE_MB = 768
BOOT_FREE_MB = 300
# Not a Debian value: below it the upgrade clearly cannot fit. Set low, the package
# compares a simulation of the upgrade to the free space and has the last word
DISK_FREE_MB = 1000
BLOCK_DEVICE_SIZE = "/sys/dev/block/%d:%d/size"
UBUNTU_RELEASES = "/usr/share/distro-info/ubuntu.csv"
RELEASE_CHECK_TIMEOUT = 120
# « New release '26.04.1 LTS' available. » of do-release-upgrade -c
UBUNTU_TARGET = re.compile(r"^New release '(\d+\.\d+)[^']*' available", re.MULTILINE)
# The paths documented by ELevate
ALMALINUX_PATHS = {"8": "9", "9": "10"}
# Written by the upgrade package once leapp waits for its restart, or refuses until
# one: the version it leaves and the boot it waits in
LEAPP_MARKER = "/var/lib/medulla/leapp-upgrade"
BOOT_ID = "/proc/sys/kernel/random/boot_id"
# Written by the upgrade package when SELinux, enforcing before, stays permissive: the reason
SELINUX_LEFT = "/var/lib/medulla/selinux-left-permissive"
SELINUX_ENFORCE = "/sys/fs/selinux/enforce"

# Package manager of each family, by the ID / ID_LIKE values of os-release
FAMILIES = (
    ("apt", ("debian", "ubuntu")),
    ("dnf", ("rhel", "fedora", "centos")),
    ("zypper", ("suse", "opensuse")),
)

# Vocabulary of the Windows catalog, shown as is by the interface
SECURITY = "Security Updates"
OTHER = "Updates"
SEVERITIES = ("Critical", "Important", "Moderate", "Low")

# Files changed by an installation or a pending restart (fingerprint)
STATE_FILES = {
    "apt": ("/var/lib/dpkg/status", "/var/run/reboot-required", "/etc/apt/sources.list",
            "/etc/apt/sources.list.d"),
    "dnf": ("/var/lib/rpm/rpmdb.sqlite", "/var/lib/rpm/Packages"),
    "zypper": ("/var/lib/rpm/rpmdb.sqlite", "/var/lib/rpm/Packages"),
}

ENVIRONMENT = dict(os.environ, LC_ALL="C", LANG="C", DEBIAN_FRONTEND="noninteractive")


def action(xmppobject, action, sessionid, data, message, dataerreur):
    if not sys.platform.startswith("linux"):
        return
    deployment = after_deployment(data)
    if not hasattr(xmppobject, "updates_linux_lock"):
        xmppobject.updates_linux_lock = threading.Lock()
        xmppobject.schedule(
            "updates_linux_report",
            REPORT_INTERVAL,
            start_report,
            (xmppobject,),
            repeat=True,
        )
    if deployment:
        # Never hold the deployment step or the XMPP event loop
        threading.Thread(
            target=send_report, args=(xmppobject, True), name="updates_linux", daemon=True
        ).start()
        return
    if isinstance(data, dict) and data.get("check") is True:
        # Scheduled check: a report only when the machine changed since the last one
        if state_changed():
            start_report(xmppobject)
        return
    start_report(xmppobject)


def start_report(xmppobject):
    """Timer callback: never block the event loop."""
    threading.Thread(
        target=send_report, args=(xmppobject, False), name="updates_linux", daemon=True
    ).start()


def send_report(xmppobject, wait):
    lock = xmppobject.updates_linux_lock
    if not (lock.acquire(timeout=LOCK_TIMEOUT) if wait else lock.acquire(False)):
        logger.debug("Linux updates report already running")
        return
    try:
        clean_legacy(xmppobject)
        family = family_of(read_os_release())
        if family == "apt" and not apt_idle(wait):
            logger.debug("Linux updates report: apt or dpkg running, not sent")
            return
        # Before the report: a change during the collection is seen by the next check
        fingerprint = state_fingerprint(family)
        logger.debug("Linux updates report: collecting")
        report = build_report()
        logger.debug("Linux updates report: %d packages, sending" % len(report["packages"]))
        xmppobject.send_message(
            mto=getattr(xmppobject, "sub_updates", "master_upd@pulse"),
            mbody=json.dumps(
                {
                    "action": "updates",
                    "sessionid": utils.getRandomName(6, "updates"),
                    "data": report,
                    "ret": 0,
                    "base64": False,
                }
            ),
            mtype="chat",
        )
        if fingerprint is not None:
            utils.file_put_contents(fingerprint_path(), fingerprint)
        logger.debug("Linux updates report: sent")
    except Exception:
        logger.error("Linux updates report failed\n%s" % traceback.format_exc())
    finally:
        lock.release()


def clean_legacy(xmppobject):
    """Remove the files of the previous engine, named; a failure never stops the report."""
    for folder, name in LEGACY_FILES:
        try:
            path = os.path.join(getattr(xmppobject.config, folder), name)
            if os.path.isfile(path):
                os.remove(path)
                logger.info("Legacy file removed: %s" % path)
        except Exception as error:
            logger.warning("Legacy file %s not removed: %s" % (name, error))


def apt_running():
    for path in glob.glob(os.path.join(PROC, "[0-9]*", "comm")):
        try:
            with open(path) as handle:
                if handle.read().strip() not in APT_PROCESSES:
                    continue
            # Same comm as unattended-upgrades, but this daemon runs permanently
            with open(os.path.join(os.path.dirname(path), "cmdline"), "rb") as handle:
                if b"unattended-upgrade-shutdown" not in handle.read():
                    return True
        except OSError:
            continue
    return False


def apt_idle(wait):
    """No package tool runs; wait: the report closing a deployment waits for them."""
    deadline = time.time() + LOCK_TIMEOUT
    while apt_running():
        if not wait or time.time() >= deadline:
            return False
        time.sleep(APT_WAIT)
    return True


def system_type():
    """client on a desktop, as the CHECK_SESSIONS step of the packages; None if unknown."""
    code, output, _ = run(["systemctl", "get-default"])
    if code != 0:
        return None
    return "client" if output.strip() == "graphical.target" else "server"


def build_report():
    release = read_os_release()
    family = family_of(release)
    report = {
        "format": REPORT_FORMAT,
        "os": "linux",
        "system": {
            "hostname": platform.node().split(".")[0],
            "type": system_type(),
            "distribution": release.get("ID"),
            "id_like": release.get("ID_LIKE"),
            "name": release.get("PRETTY_NAME") or release.get("NAME"),
            "version": release.get("VERSION_ID"),
            "codename": release.get("VERSION_CODENAME"),
            "architecture": platform.machine(),
            "kernel": platform.release(),
        },
        "family": family,
        "policy": {"automatic_updates": None, "tool": None},
        "reboot_pending": None,
        "packages": [],
        "installed": None,
        "upgrade": None,
    }
    started = time.time()
    if family is None:
        report["search"] = search_result("failed", "unsupported distribution", started)
        return report
    try:
        status, error, packages = SEARCHES[family]()
    except Exception as error:
        logger.error("Linux updates search failed\n%s" % traceback.format_exc())
        status, error, packages = "failed", str(error)[:1000], []
    report["search"] = search_result(status, error, started)
    report["packages"] = packages
    report["reboot_pending"] = REBOOT_CHECKS[family]()
    try:
        report["installed"] = HISTORIES[family](time.time() - HISTORY_DAYS * 86400)
    except Exception:
        logger.error("Linux updates history failed\n%s" % traceback.format_exc())
    report["policy"] = automatic_updates(family)
    try:
        report["upgrade"] = release_upgrade(release)
    except Exception:
        logger.error("Release upgrade check failed\n%s" % traceback.format_exc())
    return report


def search_result(status, error, started):
    return {
        "status": status,
        "error": error,
        "duration": int(time.time() - started),
        "searched_at": iso_utc(time.time()),
    }


def run(command, timeout=COMMAND_TIMEOUT):
    """(exit code, stdout, stderr); exit code None on timeout."""
    logger.debug("Linux updates report: running %s" % " ".join(command))
    try:
        process = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=ENVIRONMENT,
            timeout=timeout,
            universal_newlines=True,
        )
    except subprocess.TimeoutExpired:
        return None, "", "timeout"
    except OSError as error:
        return 127, "", str(error)
    return process.returncode, process.stdout, process.stderr


def read_os_release():
    for path in OS_RELEASE:
        try:
            with open(path) as handle:
                return parse_os_release(handle.read())
        except OSError:
            continue
    return {}


# apt


def search_apt():
    code, _, error = run(["apt-get", "update", "-q"], REFRESH_TIMEOUT)
    if code is None:
        return "timeout", "apt-get update", []
    if code != 0:
        return apt_failure(error), error.strip()[-1000:], []
    code, output, error = run(["apt-get", "-s", "-q", "dist-upgrade"])
    if code is None:
        return "timeout", "apt-get dist-upgrade", []
    if code != 0:
        return apt_failure(error), error.strip()[-1000:], []
    return "ok", None, parse_apt_simulation(output)


def apt_failure(error):
    return "locked" if "Could not get lock" in error or "Unable to lock" in error else "failed"


def reboot_apt():
    return os.path.exists("/var/run/reboot-required")


def history_apt(since):
    transactions = []
    for path in glob.glob(APT_HISTORY + "*"):
        try:
            if os.stat(path).st_mtime < since:
                continue
            opener = gzip.open if path.endswith(".gz") else open
            with opener(path, "rt", errors="replace") as handle:
                transactions += parse_apt_history(handle.read(), since)
        except OSError:
            continue
    return latest_transactions(transactions)


def release_upgrade(release):
    """{"current", "target", "blockers"}, None for a distribution not upgraded."""
    check = UPGRADE_CHECKS.get(release.get("ID"))
    return check(release) if check else None


def debian_upgrade(release):
    try:
        with open(DEBIAN_RELEASES) as handle:
            rows = parse_distro_info(handle.read())
    except OSError:
        rows = None
    upgrade = upgrade_target(rows, release, date.today().isoformat())
    if upgrade["target"]:
        codename = upgrade["current"]["codename"]
        # Started: what the package only refuses before switching no longer applies
        if not sources_switched(read_apt_sources(), codename, upgrade["target"]["codename"],
                                os.path.isdir(APT_BACKUP % codename)):
            upgrade["blockers"] = upgrade_blockers(codename)
    return upgrade


def upgrade_blockers(codename):
    """What the upgrade package refuses, as short codes."""
    blockers = []
    if backports_enabled(read_apt_sources(), codename):
        blockers.append("backports")
    return blockers + apt_blockers()


def apt_blockers():
    blockers = []
    if run(["apt-mark", "showhold"])[1].strip():
        blockers.append("held_packages")
    if run(["dpkg", "--audit"])[1].strip():
        blockers.append("dpkg_audit")
    return blockers + disk_blockers()


def ubuntu_upgrade(release):
    upgrade = {"current": {"version": release.get("VERSION_ID"), "codename": release.get("VERSION_CODENAME")},
               "target": None, "blockers": []}
    code, output, _ = run(["do-release-upgrade", "-c"], RELEASE_CHECK_TIMEOUT)
    if code == 127:
        upgrade["blockers"] = ["release_upgrader"]
        return upgrade
    version = ubuntu_target(output)
    if version:
        try:
            with open(UBUNTU_RELEASES) as handle:
                rows = parse_distro_info(handle.read())
        except OSError:
            rows = []
        upgrade["target"] = {"version": version, "codename": ubuntu_codename(rows, version)}
        upgrade["blockers"] = apt_blockers()
    return upgrade


def almalinux_upgrade(release):
    version = almalinux_major(release)
    target = ALMALINUX_PATHS.get(version)
    upgrade = {"current": {"version": version, "codename": None},
               "target": {"version": target, "codename": None} if target else None,
               "blockers": []}
    # Prepared: what the package only refuses before leapp no longer applies
    if target and not leapp_pending():
        upgrade["blockers"] = disk_blockers()
    selinux = selinux_left_permissive()
    if selinux:
        upgrade["selinux_left_permissive"] = selinux
    return upgrade


def selinux_left_permissive():
    """Why the upgrade left SELinux permissive, None once enforcing again."""
    try:
        with open(SELINUX_LEFT) as handle:
            reason = handle.read().strip()
        with open(SELINUX_ENFORCE) as handle:
            return reason if handle.read().strip() == "0" else None
    except OSError:
        return None


def leapp_pending():
    """leapp waits for its restart; after it the marker goes, the upgrade done or not."""
    try:
        with open(LEAPP_MARKER) as handle:
            marker = handle.read().split()
        with open(BOOT_ID) as handle:
            boot = handle.read().strip()
    except OSError:
        return False
    if len(marker) == 2 and marker[1] == boot and marker[0].split(".")[0] == almalinux_major(read_os_release()):
        return True
    try:
        os.remove(LEAPP_MARKER)
    except OSError as error:
        logger.warning("%s not removed: %s" % (LEAPP_MARKER, error))
    return False


def free_mb(path):
    """Free space as df counts it, None when unknown."""
    try:
        stat = os.statvfs(path)
    except OSError:
        return None
    return stat.f_bavail * stat.f_frsize // 1000000


def own_partition(path):
    try:
        return os.stat(path).st_dev != os.stat("/").st_dev
    except OSError:
        return False


def partition_mb(path):
    """Size of the block device, the file system shows less; None when unknown."""
    try:
        device = os.stat(path).st_dev
        with open(BLOCK_DEVICE_SIZE % (os.major(device), os.minor(device))) as handle:
            return int(handle.read()) * 512 // 1000000
    except (OSError, ValueError):
        return None


def disk_blockers():
    """Read only; what cannot be measured blocks nothing."""
    blockers = []
    free = free_mb("/boot")
    size = partition_mb("/boot") if own_partition("/boot") else None
    if (free is not None and free < BOOT_FREE_MB) or (size is not None and size < BOOT_SIZE_MB):
        blockers.append("disk_boot")
    free = free_mb("/")
    if free is not None and free < DISK_FREE_MB:
        blockers.append("disk_root")
    free = free_mb("/var")
    if own_partition("/var") and free is not None and free < DISK_FREE_MB:
        blockers.append("disk_var")
    return blockers


def read_apt_sources():
    texts = []
    for pattern in APT_SOURCES:
        for path in sorted(glob.glob(pattern)):
            try:
                with open(path, errors="replace") as handle:
                    texts.append(handle.read())
            except OSError:
                continue
    return "\n".join(texts)


# dnf


def search_dnf():
    # check-update exits 100 when updates are available
    code, output, error = run(["dnf", "-q", "check-update"], REFRESH_TIMEOUT)
    if code is None:
        return "timeout", "dnf check-update", []
    if code not in (0, 100):
        return dnf_failure(error), error.strip()[-1000:], []
    available = parse_dnf_check_update(output)
    if not available:
        return "ok", None, []
    _, installed_output, _ = run(
        ["rpm", "-q", "--qf", "%{NAME}.%{ARCH} %{EPOCH}:%{VERSION}-%{RELEASE}\\n"]
        + sorted({"%s.%s" % (name, arch) for name, arch in available})
    )
    _, advisories_output, _ = run(["dnf", "-q", "updateinfo", "list", "--updates"])
    return "ok", None, dnf_packages(
        available, parse_rpm_installed(installed_output), parse_dnf_updateinfo(advisories_output)
    )


def dnf_failure(error):
    return "locked" if "lock" in error.lower() else "failed"


def history_rpm(since):
    code, output, _ = run(["rpm", "-qa", "--qf", "%{INSTALLTIME} %{NAME} %{VERSION}-%{RELEASE}\\n"])
    return None if code != 0 else parse_rpm_history(output, since)


def reboot_dnf():
    if leapp_pending():
        return True
    # needs-restarting -r exits 1 when a restart is needed
    code, _, _ = run(["dnf", "-q", "needs-restarting", "-r"])
    return None if code not in (0, 1) else code == 1


# zypper


def search_zypper():
    code, output, error = run(
        ["zypper", "--non-interactive", "--xmlout", "list-updates"], REFRESH_TIMEOUT
    )
    if code is None:
        return "timeout", "zypper list-updates", []
    if code != 0:
        return ("locked" if code == 7 else "failed"), error.strip()[-1000:], []
    _, patches, _ = run(["zypper", "--non-interactive", "--xmlout", "list-patches"])
    return "ok", None, parse_zypper(output, patches)


def reboot_zypper():
    # needs-rebooting exits 102 when a restart is needed
    code, _, _ = run(["zypper", "needs-rebooting"])
    return None if code not in (0, 102) else code == 102


# Tool installing updates on its own, by family: its systemd timers
AUTOMATIC_TOOLS = {
    "apt": ("unattended-upgrades", ("apt-daily-upgrade.timer",)),
    "dnf": ("dnf-automatic", ("dnf-automatic.timer", "dnf-automatic-install.timer",
                              "dnf5-automatic.timer")),
}


def automatic_updates(family):
    """{"automatic_updates": "enabled" | "disabled" | None, "tool"}: whether the
    machine installs updates on its own, outside Medulla."""
    if family not in AUTOMATIC_TOOLS:
        return {"automatic_updates": None, "tool": None}
    tool, timers = AUTOMATIC_TOOLS[family]
    enabled = any(run(["systemctl", "is-enabled", "--quiet", timer])[0] == 0 for timer in timers)
    if enabled and family == "apt":
        # unattended-upgrades installed and its periodic run not set to 0
        installed = run(["dpkg-query", "-W", "-f=${Status}", tool])[1].endswith(" installed")
        _, periodic, _ = run(["apt-config", "dump", "APT::Periodic::Unattended-Upgrade"])
        enabled = installed and apt_periodic_enabled(periodic)
    return {"automatic_updates": "enabled" if enabled else "disabled", "tool": tool}


SEARCHES = {"apt": search_apt, "dnf": search_dnf, "zypper": search_zypper}
REBOOT_CHECKS = {"apt": reboot_apt, "dnf": reboot_dnf, "zypper": reboot_zypper}
HISTORIES = {"apt": history_apt, "dnf": history_rpm, "zypper": history_rpm}
UPGRADE_CHECKS = {"debian": debian_upgrade, "ubuntu": ubuntu_upgrade, "almalinux": almalinux_upgrade}


def fingerprint_path():
    return os.path.join(utils.Setdirectorytempinfo(), FINGERPRINT_FILE)


def state_changed():
    fingerprint = state_fingerprint(family_of(read_os_release()))
    if fingerprint is None:
        return False
    try:
        with open(fingerprint_path()) as handle:
            return handle.read().strip() != fingerprint
    except OSError:
        return True


def state_fingerprint(family):
    """MD5 of what makes a report change (installed packages, pending restart,
    running kernel, disk blockers where a release upgrade uses them), None for an
    unsupported family. Cheap: file dates and free space only."""
    if family is None:
        return None
    parts = [platform.release()]
    for path in STATE_FILES[family]:
        try:
            parts.append("%s %d" % (path, os.stat(path).st_mtime_ns))
        except OSError:
            parts.append(path)
    if family == "apt" or read_os_release().get("ID") == "almalinux":
        parts += disk_blockers()
    if family == "dnf":
        # A restart without a new kernel changes nothing else here; apt: its flag file
        try:
            with open(BOOT_ID) as handle:
                parts.append(handle.read().strip())
        except OSError:
            pass
    return hashlib.md5("\n".join(parts).encode("utf-8")).hexdigest()


# Pure functions below (unit tested on any OS)


def after_deployment(data):
    """Call from a deployment step (grafcetdeploy sends its plugin call
    payload with "source", the marker JSON in "marker_payload")."""
    if not isinstance(data, dict):
        return False
    marker = data.get("marker_payload")
    return (
        data.get("source") == "grafcetdeploy"
        or (isinstance(marker, dict) and marker.get("after_deployment") is True)
    )


def parse_os_release(text):
    values = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        values[key.strip()] = value
    return values


def family_of(release):
    """Package manager family from ID then ID_LIKE, None when unknown."""
    names = [release.get("ID") or ""] + (release.get("ID_LIKE") or "").split()
    for name in names:
        for family, members in FAMILIES:
            if name.lower() in members:
                return family
    return None


def parse_distro_info(text):
    """Rows of distro-info-data debian.csv (version, codename, series,
    created, release, eol, ...), empty values as ""."""
    return [
        {key: (value or "").strip() for key, value in row.items() if key}
        for row in csv.DictReader(io.StringIO(text))
    ]


def upgrade_target(rows, release, today):
    """Current release and the next major one, released by today (ISO date).
    rows None (no distro-info-data): no target, blocker "distro_info"."""
    codename = release.get("VERSION_CODENAME")
    current = {"version": release.get("VERSION_ID"), "codename": codename, "eol": None}
    if rows is None:
        return {"current": current, "target": None, "blockers": ["distro_info"]}
    row = next((row for row in rows if codename and row.get("series") == codename), None)
    if row is None:
        return {"current": current, "target": None, "blockers": []}
    current = {"version": row.get("version") or current["version"], "codename": codename,
               "eol": row.get("eol") or None}
    try:
        version = str(int(row.get("version")) + 1)
    except (TypeError, ValueError):
        # testing and unstable have no version
        return {"current": current, "target": None, "blockers": []}
    target = next(
        (
            {"version": item["version"], "codename": item["series"]}
            for item in rows
            if item.get("version") == version and item.get("series")
            and item.get("release") and item["release"] <= today
        ),
        None,
    )
    return {"current": current, "target": target, "blockers": []}


def ubuntu_target(output):
    """26.04 of do-release-upgrade -c (English output), None when nothing is offered."""
    match = UBUNTU_TARGET.search(output or "")
    return match.group(1) if match else None


def ubuntu_codename(rows, version):
    """Series of 26.04 in ubuntu.csv, whose versions read « 26.04 LTS »."""
    return next((row.get("series") or None for row in rows
                 if (row.get("version") or "").split(" ")[0] == version), None)


def almalinux_major(release):
    return (release.get("VERSION_ID") or "").split(".")[0] or None


def source_mentions(text, word):
    """A source line, not commented, names word."""
    pattern = re.compile(r"\b%s\b" % re.escape(word))
    return any(pattern.search(line.split("#", 1)[0]) for line in text.splitlines())


def backports_enabled(text, codename):
    return bool(codename) and source_mentions(text, codename + "-backports")


def sources_switched(text, current, target, backup):
    """The upgrade package already switched the sources: its own rule (RESUME)."""
    return source_mentions(text, target) and (backup or not source_mentions(text, current))


def apt_periodic_enabled(text):
    """apt-config dump line « APT::Periodic::Unattended-Upgrade "1"; »: 0 or
    absent disables it."""
    match = re.search(r'APT::Periodic::Unattended-Upgrade "([^"]*)"', text or "")
    return bool(match) and match.group(1) not in ("", "0")


# « Inst openssl [3.0.13-1~deb12u1] (3.0.15-1~deb12u1 Debian-Security:12/stable-security [amd64]) »
APT_INST = re.compile(r"^Inst (\S+) \[([^\]]+)\] \((\S+) (.*) \[([^\]]+)\]\)")


def parse_apt_simulation(text):
    """Upgrades of a simulated dist-upgrade; new installations (no current
    version, e.g. a new kernel) are not missing updates of the machine."""
    packages = []
    for line in text.splitlines():
        match = APT_INST.match(line)
        if not match:
            continue
        name, installed, available, origins, arch = match.groups()
        security = any(origin.endswith("-security") for origin in re.split(r"[ ,]+", origins))
        packages.append(
            package(name, arch, installed, available, origins, SECURITY if security else OTHER)
        )
    return packages


def package(name, arch, installed, available, repository, classification, severity=None,
            advisory=None):
    return {
        "name": name,
        "arch": arch,
        "installed": installed,
        "available": available,
        "repository": repository,
        "classification": classification,
        "severity": severity,
        "advisory": advisory,
    }


DNF_LINE = re.compile(r"^(\S+)\.(\S+)\s+(\S+)\s+(\S+)\s*$")


def parse_dnf_check_update(text):
    """{(name, arch): (version, repository)} of dnf check-update; stops at
    « Obsoleting Packages »."""
    available = {}
    for line in text.splitlines():
        if line.startswith("Obsoleting"):
            break
        match = DNF_LINE.match(line)
        if match:
            name, arch, version, repository = match.groups()
            available[(name, arch)] = (version, repository)
    return available


def parse_rpm_installed(text):
    installed = {}
    for line in text.splitlines():
        parts = line.split()
        if len(parts) == 2:
            version = parts[1][len("(none):"):] if parts[1].startswith("(none):") else parts[1]
            installed[parts[0]] = version
    return installed


# « RHSA-2024:1234 Important/Sec. openssl-1:3.0.7-27.el9.x86_64 »
DNF_ADVISORY = re.compile(r"^(\S+)\s+(\S+)\s+(\S+)$")


def parse_dnf_updateinfo(text):
    """{(name, arch): (advisory, type, severity)}, the most severe advisory."""
    advisories = {}
    for line in text.splitlines():
        match = DNF_ADVISORY.match(line.strip())
        if not match:
            continue
        advisory, kind, nevra = match.groups()
        severity, _, kind = kind.partition("/") if "/" in kind else (None, "", kind)
        name_arch = rpm_name_arch(nevra)
        if name_arch is None:
            continue
        current = advisories.get(name_arch)
        candidate = (advisory, kind, severity if severity in SEVERITIES else None)
        if current is None or severity_rank(candidate[2]) < severity_rank(current[2]):
            advisories[name_arch] = candidate
    return advisories


def rpm_name_arch(nevra):
    """(name, arch) of « name-[epoch:]version-release.arch »."""
    base, dot, arch = nevra.rpartition(".")
    parts = base.rsplit("-", 2)
    if not dot or len(parts) != 3:
        return None
    return parts[0], arch


def severity_rank(severity):
    return SEVERITIES.index(severity) if severity in SEVERITIES else len(SEVERITIES)


def dnf_packages(available, installed, advisories):
    packages = []
    for (name, arch), (version, repository) in sorted(available.items()):
        advisory = advisories.get((name, arch))
        security = advisory is not None and advisory[1].lower().startswith("sec")
        packages.append(
            package(
                name, arch, installed.get("%s.%s" % (name, arch)), version, repository,
                SECURITY if security else OTHER,
                advisory[2] if advisory else None,
                advisory[0] if advisory else None,
            )
        )
    return packages


def parse_zypper(updates_xml, patches_xml):
    """Packages of zypper list-updates; security when a needed security patch
    names the package."""
    security = zypper_security(patches_xml)
    packages = []
    try:
        root = ElementTree.fromstring(updates_xml)
    except ElementTree.ParseError:
        return packages
    for update in root.iter("update"):
        if update.get("kind") not in (None, "package"):
            continue
        name = update.get("name")
        source = update.find("source")
        severity, advisory = security.get(name, (None, None))
        packages.append(
            package(
                name, update.get("arch"), update.get("edition-old"), update.get("edition"),
                source.get("alias") if source is not None else None,
                SECURITY if name in security else OTHER, severity, advisory,
            )
        )
    return packages


def zypper_security(patches_xml):
    """{package name: (severity, patch name)} of the needed security patches."""
    security = {}
    try:
        root = ElementTree.fromstring(patches_xml or "")
    except ElementTree.ParseError:
        return security
    for update in root.iter("update"):
        if update.get("kind") != "patch" or update.get("category") != "security":
            continue
        severity = (update.get("severity") or "").capitalize()
        for item in update.iter("solvable"):
            security[item.get("name")] = (
                severity if severity in SEVERITIES else None, update.get("name")
            )
    return security


APT_PACKAGE = re.compile(r"([^\s:,]+):\S+ \(([^)]*)\)")
# Actions of history.log leaving a new version installed
APT_INSTALLS = ("Install", "Upgrade", "Downgrade", "Reinstall")


def parse_apt_history(text, since):
    """Transactions of an apt history.log started after since (timestamp)."""
    transactions = []
    for block in re.split(r"\n\s*\n", text):
        fields = {}
        for line in block.splitlines():
            key, _, value = line.partition(": ")
            fields[key.strip()] = value.strip()
        try:
            started = time.mktime(
                time.strptime(" ".join(fields.get("Start-Date", "").split()), "%Y-%m-%d %H:%M:%S")
            )
        except ValueError:
            continue
        if started < since:
            continue
        packages = []
        for key in APT_INSTALLS:
            for name, versions in APT_PACKAGE.findall(fields.get(key, "")):
                versions = [v.strip() for v in versions.split(",") if v.strip() != "automatic"]
                packages.append((name, versions[-1] if versions else ""))
        if packages:
            transactions.append(transaction(started, packages))
    return transactions


def parse_rpm_history(text, since):
    """Transactions rebuilt from the install times of rpm -qa."""
    installs = []
    for line in text.splitlines():
        parts = line.split()
        if len(parts) == 3 and parts[0].isdigit() and int(parts[0]) >= since:
            installs.append((int(parts[0]), parts[1], parts[2]))
    installs.sort()
    transactions, group, last = [], [], None
    for installed, name, version in installs:
        if group and installed - last > RPM_TRANSACTION_GAP:
            transactions.append(transaction(group[0][0], [item[1:] for item in group]))
            group = []
        group.append((installed, name, version))
        last = installed
    if group:
        transactions.append(transaction(group[0][0], [item[1:] for item in group]))
    return latest_transactions(transactions)


def transaction(started, packages):
    return {
        "date": iso_utc(started),
        "count": len(packages),
        "packages": [
            {"name": name, "version": version} for name, version in packages[:HISTORY_PACKAGES]
        ],
    }


def latest_transactions(transactions):
    transactions.sort(key=lambda item: item["date"], reverse=True)
    return transactions[:HISTORY_TRANSACTIONS]


def iso_utc(timestamp):
    if timestamp is None:
        return None
    moment = datetime.fromtimestamp(timestamp, timezone.utc)
    return moment.strftime("%Y-%m-%dT%H:%M:%SZ")
