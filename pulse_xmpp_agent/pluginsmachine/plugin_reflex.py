# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2026 Medulla, http://www.medulla-tech.io
# SPDX-License-Identifier: GPL-3.0-or-later
"""
Reflex machine plugin: collector registry.

The agent measures, the server evaluates and notifies. This plugin knows
nothing about thresholds, severities or recipients: it runs collectors and
returns values.

A collector is identified by a key held in probe_collectors.collector. That
key selects a function of the COLLECTORS registry below: an identifier
absent from the registry is refused and reported as unavailable. Most
collectors do run a system command, but always one written in this file.
Only script.sh and script.powershell run a command that comes from the
configuration, the one written in the console for a personal scripted probe,
passed to a shell and never to exec().

This module also receives the probe configuration pushed by the server and
stores it for the scheduler (scheduling_reflex.py).
"""

import codecs
import configparser
import json
import logging
import os
import platform
import re
import signal
import socket
import stat
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone

import psutil

from lib.agentconffile import conffilename, medullaPath
from lib.utils import set_logging_level, getRandomName, Setdirectorytempinfo

plugin = {"VERSION": "1.1", "NAME": "reflex", "TYPE": "machine"}  # fmt: skip

logger = logging.getLogger()

# Statuses of a measure, as accepted by probe_measures.status
STATUS_OK = "ok"
STATUS_WARNING = "warning"
STATUS_ERROR = "error"
STATUS_UNAVAILABLE = "unavailable"

# Normalised SMART states
SMART_OK = "OK"
SMART_WARNING = "WARNING"
SMART_FAILING = "FAILING"
SMART_UNKNOWN = "UNKNOWN"

CONFIG_FILENAME = "reflex_config.json"

# Every external call is bounded, so no collector can hold the cycle for
# ever. It does hold it meanwhile: the probes are measured one after the
# other, and these bounds say for how long.
DEFAULT_TIMEOUT = 20
LONG_TIMEOUT = 120
DNS_TIMEOUT = 2
# debsums and rpm -Va read and hash every packaged file of the machine. The
# scheduler measures the due probes one after the other: this bound is not
# the patience given to one probe, it is how long every other probe of the
# machine stops measuring. Hence 300, the worst case already accepted by
# update.win_session and update.softwareupdate, and an unavailable naming
# the duration rather than a silent hole in the cycle.
PACKAGE_VERIFY_TIMEOUT = 300

# Groups holding the local administrators, per system
UNIX_ADMIN_GROUPS = ("sudo", "wheel")
WINDOWS_ADMIN_SID = "S-1-5-32-544"

# Width of probe_measures.detail
MEASURE_DETAIL_LENGTH = 512


# =============================================================================
# Local state
# =============================================================================
def _log_once(key, level, message):
    """Log a message once per agent process.

    A module global would not hold that mark: the agent reloads every
    plugin_*.py each time it builds its registration (loadPluginList of
    agentxmpp), which resets the globals, and the module is imported under
    two names, plugin_reflex for the scheduler and pluginsmachine.plugin_
    reflex for the agent, each with its own. The mark is kept on the root
    logger, the single object the whole process shares.
    """
    marks = getattr(logger, "_reflex_logged_once", None)
    if marks is None:
        marks = set()
        logger._reflex_logged_once = marks
    if key in marks:
        return
    marks.add(key)
    logger.log(level, message)


def reflex_state_dir():
    """Directory holding the probe configuration, the schedule and the spool.

    Windows and macOS keep it in the install tree, whose ACLs already reserve
    it to the administrators. Under Linux medullaPath() answers "/", which
    would place in /var/tmp, writable by every account of the machine, a
    configuration that names commands run as root: the state goes into the
    directory of the agent instead, as the other plugins do.
    """
    path = None
    if not sys.platform.startswith("linux"):
        try:
            base = medullaPath()
        except Exception:
            base = None
        if base:
            path = os.path.join(base, "var", "tmp", "reflex")
    if path is None:
        try:
            path = os.path.join(Setdirectorytempinfo(), "reflex")
        except Exception as error:
            _log_once(
                "state-dir-missing",
                logging.ERROR,
                "reflex: no agent state directory: %s" % error,
            )
            path = os.path.abspath(
                os.path.join(
                    os.path.dirname(os.path.realpath(__file__)),
                    "..",
                    "INFOSTMP",
                    "reflex",
                )
            )
    _make_state_dir(path)
    _notice_legacy_state()
    return path


def _notice_legacy_state():
    """Name, once per process, the Linux directory the state used to live in.

    /var/tmp/reflex is writable by every account: what it holds is never read
    again. It is only named so an administrator can remove it, and naming it
    at every cycle would make a permanent warning out of a one off chore.
    """
    if not sys.platform.startswith("linux"):
        return
    legacy = os.path.join("/", "var", "tmp", "reflex")
    if os.path.isdir(legacy):
        _log_once(
            "legacy-state",
            logging.WARNING,
            "reflex: state left over in %s, no longer read, it can be removed"
            % legacy,
        )


def _make_state_dir(path):
    """Create the directory if it is missing. Whether it can then be used is
    not settled here: an existing path is left untouched and judged by
    _state_dir_refusal()."""
    try:
        os.makedirs(path, mode=0o700)
    except OSError as error:
        if not os.path.isdir(path):
            _log_once(
                "state-dir-create",
                logging.ERROR,
                "reflex: cannot create %s: %s" % (path, error),
            )


def _state_dir_refusal(path):
    """Reason not to trust the state directory, None when it can be used.

    The configuration held there names commands run as root. A symlink, a
    directory belonging to another account or one open to writing by others
    makes it untrustworthy. Windows mode bits say nothing, the ACLs of the
    install tree carry that guarantee.
    """
    try:
        info = os.lstat(path)
    except OSError as error:
        return "unreadable (%s)" % error
    if stat.S_ISLNK(info.st_mode):
        return "it is a symbolic link"
    if not stat.S_ISDIR(info.st_mode):
        return "it is not a directory"
    if sys.platform.startswith("win"):
        return None
    if info.st_uid not in (0, os.getuid()):
        return "it belongs to uid %d" % info.st_uid
    if info.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        return "it is writable by other accounts (mode %04o)" % stat.S_IMODE(
            info.st_mode
        )
    parent = os.path.dirname(os.path.normpath(path))
    try:
        above = os.lstat(parent)
    except OSError:
        return None
    if above.st_mode & stat.S_IWOTH and not above.st_mode & stat.S_ISVTX:
        return "%s is writable by every account" % parent
    return None


def usable_state_dir():
    """The state directory when it can be trusted, None otherwise.

    Refusing to measure is preferable to running a configuration a third
    party may have written. The refusal is logged once per process: repeated
    every cycle it would be read as noise rather than as a machine to fix.
    """
    path = reflex_state_dir()
    reason = _state_dir_refusal(path)
    if reason is None:
        return path
    _log_once(
        "state-dir-refused",
        logging.ERROR,
        "reflex: %s not used, %s. No probe is measured until it is put "
        "right." % (path, reason),
    )
    return None


def read_local_config():
    """Probe configuration received from the server, empty until it arrives."""
    empty = {"config_version": "", "probes": []}
    directory = usable_state_dir()
    if directory is None:
        return empty
    name = os.path.join(directory, CONFIG_FILENAME)
    if not os.path.isfile(name):
        return empty
    try:
        with open(name, "r") as handle:
            data = json.load(handle)
    except (IOError, OSError, ValueError) as error:
        logger.error("reflex: unreadable configuration %s: %s" % (name, error))
        return empty
    if not isinstance(data, dict):
        return empty
    probes = data.get("probes")
    if not isinstance(probes, list):
        probes = []
    return {
        "config_version": str(data.get("config_version") or ""),
        "probes": probes,
    }


def write_local_config(config_version, probes):
    """Store the configuration. Returns an error string, or an empty string."""
    directory = usable_state_dir()
    if directory is None:
        return "state directory not trustworthy"
    name = os.path.join(directory, CONFIG_FILENAME)
    payload = {
        "config_version": str(config_version or ""),
        "probes": probes if isinstance(probes, list) else [],
        "stored_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }
    try:
        with open(name, "w") as handle:
            json.dump(payload, handle, indent=2)
        return ""
    except (IOError, OSError) as error:
        logger.error("reflex: cannot write %s: %s" % (name, error))
        return "%s: %s" % (type(error).__name__, error)


# =============================================================================
# Operating system of the agent
# =============================================================================
def current_os():
    """OS key used in probe_collectors.os."""
    if sys.platform.startswith("win"):
        return "windows"
    if sys.platform.startswith("darwin"):
        return "darwin"
    if sys.platform.startswith("linux"):
        return "linux"
    return platform.system().lower()


# =============================================================================
# Bounded execution of an external command
# =============================================================================
_CONSOLE_ENCODING = None


def _console_encoding():
    """Code page a Windows command writes its output in, asked once.

    It is cp850 on a French system and cp437 on an English one: guessing it
    would mutilate every accented character of half the estate. Anything
    unexpected falls back on cp850, which decodes any byte.
    """
    global _CONSOLE_ENCODING
    if _CONSOLE_ENCODING is not None:
        return _CONSOLE_ENCODING
    encoding = "cp850"
    try:
        import ctypes

        codepage = int(ctypes.windll.kernel32.GetConsoleOutputCP())
        if codepage <= 0:
            codepage = int(ctypes.windll.kernel32.GetOEMCP())
        if codepage > 0:
            candidate = "cp%d" % codepage
            codecs.lookup(candidate)
            encoding = candidate
    except Exception:
        pass
    _CONSOLE_ENCODING = encoding
    return encoding


def _decode_output(raw):
    """Decode the output of a command, whatever it holds.

    UTF-8 first: Linux and macOS write it, and so does a Windows command
    that was told to. A Windows command that was not writes in the code
    page of the console, which reading as UTF-8 would mutilate. Bytes that
    are neither give a degraded string: a collector never raises.
    """
    if not raw:
        return ""
    if isinstance(raw, str):
        return raw
    if not isinstance(raw, bytes):
        try:
            raw = bytes(raw)
        except Exception:
            return ""
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        pass
    except Exception:
        return ""
    if sys.platform.startswith("win"):
        try:
            return raw.decode(_console_encoding(), "replace")
        except Exception:
            pass
    return raw.decode("utf-8", "replace")


def _run(argv, timeout=DEFAULT_TIMEOUT):
    """Run a command without a shell and return (returncode, output).

    The argument list is built by the collector itself, never by data coming
    from the server. A returncode of -1 means the binary is absent, -2 that it
    did not answer within the allowed time.
    """
    try:
        completed = subprocess.run(
            argv,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=timeout,
            shell=False,
        )
    except (OSError, IOError):
        return (-1, "")
    except subprocess.TimeoutExpired:
        return (-2, "")
    except Exception as error:
        logger.debug("reflex: %s failed: %s" % (argv[0], error))
        return (-1, "")
    return (completed.returncode, _decode_output(completed.stdout))


def _which(binary):
    """Whether a binary is reachable, without running it."""
    try:
        import shutil

        return shutil.which(binary) is not None
    except Exception:
        return False


def _powershell(script, timeout=DEFAULT_TIMEOUT):
    """Run a PowerShell snippet written in this file, never one received."""
    if not sys.platform.startswith("win"):
        return (-1, "")
    return _run(
        [
            "powershell",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            script,
        ],
        timeout=timeout,
    )


def _result(value=None, status=STATUS_OK, value_text=None, detail=None):
    """One raw collector result, before it becomes a measure."""
    item = {"value": value, "status": status}
    if value_text is not None:
        item["value_text"] = value_text
    # Wider than the column, the detail is dropped whole: a cut JSON reads
    # as nothing and a cut reason reads as another one.
    if detail and len(detail) <= MEASURE_DETAIL_LENGTH:
        item["detail"] = detail
    return item


def _unavailable(detail):
    return [_result(status=STATUS_UNAVAILABLE, detail=detail)]


def _command_failed(binary, code, output):
    """Unavailable naming why a command could not be believed.

    A command that fails says nothing about the machine: its empty output
    must never be read as a reassuring measure.
    """
    if code == -1:
        return _unavailable("%s could not be run" % binary)
    if code == -2:
        return _unavailable("%s did not answer in time" % binary)
    reason = ""
    for line in reversed((output or "").splitlines()):
        line = line.strip()
        if line:
            reason = line[:200]
            break
    detail = "%s failed (code %d)" % (binary, code)
    return _unavailable("%s: %s" % (detail, reason) if reason else detail)


# =============================================================================
# Collectors: system counters (psutil, available everywhere)
# =============================================================================
def collect_cpu_percent(params):
    """psutil.cpu_percent(interval=1), averaged over all logical cores."""
    return [_result(round(float(psutil.cpu_percent(interval=1)), 2))]


def collect_system_load_average(params):
    """Five minute load average, as a percentage of the logical cores."""
    if sys.platform.startswith("win"):
        return _unavailable("collector reserved to Linux and macOS")
    try:
        load = float(psutil.getloadavg()[1])
    except (AttributeError, NotImplementedError, OSError, IndexError,
            TypeError, ValueError) as error:
        return _unavailable("load average unavailable on this machine: %s"
                            % error)
    try:
        cores = psutil.cpu_count()
    except Exception as error:
        return _unavailable("logical core count unavailable: %s" % error)
    if not cores:
        return _unavailable("logical core count unknown")
    return [_result(round(load * 100.0 / float(cores), 2))]


def collect_mem_virtual(params):
    """Used memory as a percentage.

    On Linux and macOS the computation is made on available, not on total
    minus free: the disk cache is reclaimable and counting it as used would
    make the probe scream permanently on a healthy machine.
    """
    memory = psutil.virtual_memory()
    total = float(getattr(memory, "total", 0) or 0)
    if total <= 0:
        return [_result(status=STATUS_ERROR, detail="total memory reported as 0")]
    if sys.platform.startswith("win"):
        return [_result(round(float(memory.percent), 2))]
    available = getattr(memory, "available", None)
    if available is None:
        return [_result(round(float(memory.percent), 2))]
    percent = (total - float(available)) * 100.0 / total
    return [_result(round(percent, 2))]


def collect_mem_swap(params):
    """psutil.swap_memory().percent.

    A machine without swap reports 0 rather than nothing: an absent swap is
    not a failed measure.
    """
    swap = psutil.swap_memory()
    if float(getattr(swap, "total", 0) or 0) <= 0:
        return [_result(0.0, detail="no swap configured")]
    return [_result(round(float(swap.percent), 2))]


def collect_disk_usage(params):
    """Occupancy of every local mount point, one measure each.

    The mount point travels in value_text: it is what tells apart two
    measures of the same probe on the same machine.
    """
    excluded = params.get("exclude_fstypes") or []
    excluded = [str(f).lower() for f in excluded]
    results = []
    try:
        partitions = psutil.disk_partitions(all=False)
    except Exception as error:
        return [_result(status=STATUS_ERROR, detail=str(error))]

    for partition in partitions:
        fstype = str(getattr(partition, "fstype", "") or "").lower()
        opts = str(getattr(partition, "opts", "") or "").lower()
        mountpoint = getattr(partition, "mountpoint", "") or ""
        if not mountpoint or not fstype:
            continue
        if fstype in excluded:
            continue
        if "cdrom" in opts or fstype in ("iso9660", "udf"):
            continue
        # Removable and network volumes are not the responsibility of the
        # machine that happens to have them mounted.
        if sys.platform.startswith("win") and "removable" in opts:
            continue
        try:
            usage = psutil.disk_usage(mountpoint)
        except (OSError, PermissionError):
            continue
        except Exception:
            continue
        results.append(
            _result(round(float(usage.percent), 2), value_text=mountpoint)
        )
    if not results:
        return [_result(status=STATUS_UNAVAILABLE, detail="no local volume found")]
    return results


def collect_system_boot_time(params):
    """Seconds since the last boot."""
    boot = float(psutil.boot_time() or 0)
    if boot <= 0:
        return [_result(status=STATUS_ERROR, detail="boot time unknown")]
    return [_result(int(time.time() - boot))]


def collect_system_process_count(params):
    """Number of processes currently running on the machine."""
    try:
        return [_result(len(psutil.pids()))]
    except Exception as error:
        return _unavailable("process count unavailable on this machine: %s"
                            % error)


def collect_system_temperature(params):
    """Highest temperature reported by the sensors, in degrees Celsius."""
    if not hasattr(psutil, "sensors_temperatures"):
        return _unavailable("collector reserved to Linux")
    try:
        sensors = psutil.sensors_temperatures()
    except Exception as error:
        return _unavailable("temperature sensors unreadable: %s" % error)
    if not sensors:
        return _unavailable("no temperature sensor on this machine")
    temperatures = []
    for entries in sensors.values():
        # A sensor without a current reading is not a reading of zero.
        for entry in entries or []:
            current = getattr(entry, "current", None)
            if current is None:
                continue
            try:
                temperatures.append(float(current))
            except (TypeError, ValueError):
                continue
    if not temperatures:
        return _unavailable("no temperature sensor on this machine")
    return [_result(round(max(temperatures), 2))]


# =============================================================================
# Collectors: SMART state
# =============================================================================
def _normalise_smart(raw):
    """Map a vendor wording onto OK / WARNING / FAILING / UNKNOWN."""
    text = str(raw or "").strip().lower()
    if not text:
        return SMART_UNKNOWN
    if text in ("ok", "healthy", "verified", "passed", "pass", "good", "0"):
        return SMART_OK
    if text in ("warning", "degraded", "caution", "warn"):
        return SMART_WARNING
    if text in ("unhealthy", "failing", "failed", "fail", "predicted failure",
                "not supported", "bad"):
        return SMART_FAILING if "support" not in text else SMART_UNKNOWN
    if "fail" in text or "predict" in text:
        return SMART_FAILING
    if "warn" in text or "degrad" in text or "caution" in text:
        return SMART_WARNING
    if "ok" in text or "healthy" in text or "verified" in text or "pass" in text:
        return SMART_OK
    return SMART_UNKNOWN


SMART_VALUE_MAX = 255


def _smart_value(disks):
    """Worst state of a list of (name, state), naming the disks in it.

    A single failing disk decides. Unless every disk is OK, the value reads
    "<STATE> : <disk>, <disk>", cut at SMART_VALUE_MAX characters. A disk
    without a usable name is called "disque N", N being its rank; two disks
    sharing a name are told apart by a "#2", "#3"... suffix.
    """
    if not disks:
        return SMART_UNKNOWN
    states = [state for _name, state in disks]
    worst = SMART_OK
    for level in (SMART_FAILING, SMART_WARNING, SMART_UNKNOWN):
        if level in states:
            worst = level
            break
    if worst == SMART_OK:
        return SMART_OK
    names = []
    seen = {}
    for rank, (name, state) in enumerate(disks, 1):
        name = " ".join(str(name or "").split()) or "disque %d" % rank
        seen[name] = seen.get(name, 0) + 1
        if seen[name] > 1:
            name = "%s #%d" % (name, seen[name])
        if state == worst:
            names.append(name)
    value = "%s : %s" % (worst, ", ".join(names))
    if len(value) <= SMART_VALUE_MAX:
        return value
    ellipsis = "\u2026"
    value = "%s : " % worst
    for index, name in enumerate(names):
        piece = name if index == 0 else ", " + name
        if len(value) + len(piece) + len(", " + ellipsis) > SMART_VALUE_MAX:
            break
        value += piece
    if value.endswith(" : "):
        room = SMART_VALUE_MAX - len(value) - len(ellipsis)
        return value + names[0][:room] + ellipsis
    return value + ", " + ellipsis


def _split_name_state(output):
    """(name, state) from "name|state" lines; a name may hold a "|"."""
    pairs = []
    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue
        name, _sep, state = line.rpartition("|")
        pairs.append((name.strip(), state.strip()))
    return pairs


def collect_disk_smart_wmi(params):
    """Windows: Get-PhysicalDisk, then MSStorageDriver_FailurePredictStatus."""
    script = (
        "Get-PhysicalDisk | "
        "ForEach-Object { \"$($_.FriendlyName)|$($_.HealthStatus)\" }"
    )
    code, output = _powershell(script, timeout=60)
    disks = []
    if code == 0:
        for name, raw in _split_name_state(output):
            disks.append((name, _normalise_smart(raw)))
    if not disks:
        script = (
            "Get-CimInstance -Namespace root\\wmi "
            "-ClassName MSStorageDriver_FailurePredictStatus "
            "-ErrorAction SilentlyContinue | "
            "ForEach-Object { \"$($_.InstanceName)|$($_.PredictFailure)\" }"
        )
        code, output = _powershell(script, timeout=60)
        if code != 0:
            return _unavailable("neither Get-PhysicalDisk nor WMI answered")
        for name, raw in _split_name_state(output):
            failing = raw.lower() in ("true", "1")
            disks.append((name, SMART_FAILING if failing else SMART_OK))
    if not disks:
        return _unavailable("no physical disk reported a health status")
    return [_result(value_text=_smart_value(disks), value=None,
                    status=STATUS_OK)]


def collect_disk_smart_smartctl(params):
    """Linux: smartctl -H on every scanned device. Needs smartmontools."""
    if not _which("smartctl"):
        return _unavailable("smartmontools is not installed")
    code, output = _run(["smartctl", "--scan"], timeout=30)
    if code < 0:
        return _unavailable("smartctl did not answer")
    devices = []
    for line in output.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        devices.append(line.split()[0])
    if not devices:
        return _unavailable("smartctl scanned no device")

    disks = []
    for device in devices:
        code, output = _run(["smartctl", "-H", device], timeout=30)
        if code < 0:
            disks.append((device, SMART_UNKNOWN))
            continue
        state = SMART_UNKNOWN
        for line in output.splitlines():
            lowered = line.lower()
            if "overall-health self-assessment test result" in lowered \
                    or "smart health status" in lowered:
                state = _normalise_smart(line.split(":")[-1])
                break
        disks.append((device, state))
    return [_result(value_text=_smart_value(disks), value=None,
                    status=STATUS_OK)]


def collect_disk_smart_diskutil(params):
    """macOS: diskutil info -all, SMART Status field."""
    if not _which("diskutil"):
        return _unavailable("diskutil is not available")
    code, output = _run(["diskutil", "info", "-all"], timeout=60)
    if code < 0:
        return _unavailable("diskutil did not answer")
    disks = []
    device = None
    for line in output.splitlines():
        if line.strip().startswith("*****"):
            device = None
            continue
        key, _sep, value = line.partition(":")
        key = key.strip().lower()
        value = value.strip()
        if key == "device identifier":
            device = value
        elif key == "smart status":
            if value.lower() in ("not supported", "unsupported"):
                continue
            disks.append((device, _normalise_smart(value)))
    whole = [disk for disk in disks
             if not re.match(r"^disk\d+s\d+$", disk[0] or "")]
    if whole:
        disks = whole
    if not disks:
        return _unavailable("no disk reports a SMART status")
    return [_result(value_text=_smart_value(disks), value=None,
                    status=STATUS_OK)]


# =============================================================================
# Collectors: services
# =============================================================================
def collect_service_win_auto_stopped(params):
    """Windows: automatic services that are not running."""
    if not sys.platform.startswith("win"):
        return _unavailable("collector reserved to Windows")
    try:
        iterator = psutil.win_service_iter
    except AttributeError:
        iterator = None
    if iterator is not None:
        count = 0
        try:
            for service in iterator():
                try:
                    info = service.as_dict()
                except Exception:
                    continue
                start_type = str(info.get("start_type") or "").lower()
                status = str(info.get("status") or "").lower()
                if start_type.startswith("automatic") and status != "running":
                    count += 1
            return [_result(count)]
        except Exception as error:
            logger.debug("reflex: win_service_iter failed: %s" % error)

    script = (
        "@(Get-Service | Where-Object "
        "{ $_.StartType -eq 'Automatic' -and $_.Status -ne 'Running' }).Count"
    )
    code, output = _powershell(script, timeout=60)
    if code != 0:
        return _unavailable("no service inventory could be obtained")
    return [_result(_first_int(output, 0))]


def collect_service_systemd_failed(params):
    """Linux: number of systemd units in the failed state."""
    if not _which("systemctl"):
        return _unavailable("systemd is not in use on this machine")
    code, output = _run(
        ["systemctl", "--failed", "--no-legend", "--plain", "--no-pager"],
        timeout=30,
    )
    if code < 0:
        return _unavailable("systemctl did not answer")
    count = len([line for line in output.splitlines() if line.strip()])
    return [_result(count)]


def collect_service_launchd_failed(params):
    """macOS: launchd jobs whose last exit status is not zero."""
    if not _which("launchctl"):
        return _unavailable("launchctl is not available")
    code, output = _run(["launchctl", "list"], timeout=30)
    if code < 0:
        return _unavailable("launchctl did not answer")
    count = 0
    for line in output.splitlines()[1:]:
        parts = line.split()
        if len(parts) < 3:
            continue
        status = parts[1]
        if status in ("-", "0"):
            continue
        try:
            if int(status) != 0:
                count += 1
        except ValueError:
            continue
    return [_result(count)]


# =============================================================================
# Collectors: antivirus
# =============================================================================
def collect_security_win_securitycenter(params):
    """Windows: at least one active product in root/SecurityCenter2.

    That namespace does not exist on the Server editions, where an empty
    answer would read as no antivirus at all. The script tells a registry
    holding no product from a registry that is absent, and the absent one
    falls back on the status of Defender, present on those editions.
    """
    if not sys.platform.startswith("win"):
        return _unavailable("collector reserved to Windows")
    script = (
        "$ErrorActionPreference = 'Stop'; "
        "try { "
        "$p = @(Get-CimInstance -Namespace root/SecurityCenter2 "
        "-ClassName AntiVirusProduct); "
        "if ($p.Count -eq 0) { 'NOPRODUCT' } "
        "else { $p | ForEach-Object { $_.productState } } "
        "} catch { 'NOCENTER' }"
    )
    code, output = _powershell(script, timeout=60)
    if code != 0:
        return _unavailable("the Security Center did not answer")
    if "NOCENTER" in output:
        return _defender_realtime(
            "the Security Center is absent, as on the Server editions"
        )
    if "NOPRODUCT" in output:
        return [_result(0, detail="no antivirus product registered")]
    states = []
    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            states.append(int(line))
        except ValueError:
            continue
    if not states:
        return _unavailable("the Security Center returned an unreadable state")
    # Second byte of productState: 0x10 means the real time scanner is on.
    active = any(((state >> 8) & 0xFF) & 0x10 for state in states)
    return [_result(1 if active else 0)]


def _defender_realtime(reason):
    """Real time protection of Defender, when the Security Center is absent."""
    script = (
        "$s = Get-MpComputerStatus -ErrorAction SilentlyContinue; "
        "if ($s -eq $null) { 'NOSTATUS' } "
        "else { \"$($s.AMServiceEnabled);$($s.RealTimeProtectionEnabled)\" }"
    )
    code, output = _powershell(script, timeout=60)
    if code != 0 or "NOSTATUS" in output:
        return _unavailable("%s, and Defender reports no status" % reason)
    line = ""
    for candidate in output.splitlines():
        if ";" in candidate:
            line = candidate.strip()
            break
    parts = line.split(";") if line else []
    if len(parts) < 2:
        return _unavailable("%s, and Defender returned an unreadable status"
                            % reason)
    running = parts[0].strip().lower() in ("true", "1")
    realtime = parts[1].strip().lower() in ("true", "1")
    return [_result(1 if (running and realtime) else 0,
                    detail="%s: Defender read instead" % reason)]


def collect_security_clamav_status(params):
    """Linux: clamav-daemon or clamd reported active by systemd."""
    if not _which("systemctl"):
        return _unavailable("systemd is not in use on this machine")
    known = False
    for unit in ("clamav-daemon", "clamd", "clamd@scan"):
        code, output = _run(
            ["systemctl", "is-active", unit, "--quiet"], timeout=15
        )
        if code == 0:
            return [_result(1)]
        code, output = _run(
            ["systemctl", "is-enabled", unit], timeout=15
        )
        if code == 0 or "disabled" in (output or "").lower():
            known = True
    if not known:
        return _unavailable("clamav is not installed")
    return [_result(0, detail="clamav is installed but not running")]


def collect_security_win_defender_sig_age(params):
    """Windows: AntivirusSignatureAge of Get-MpComputerStatus, in days.

    A third party antivirus makes Defender idle: its signature age would then
    describe nothing, so the measure is reported unavailable rather than
    alarming on a machine that is in fact protected.
    """
    if not sys.platform.startswith("win"):
        return _unavailable("collector reserved to Windows")
    script = (
        "$s = Get-MpComputerStatus -ErrorAction SilentlyContinue; "
        "if ($s -eq $null) { 'NOSTATUS' } "
        "else { "
        "  \"$($s.AMServiceEnabled);$($s.AntivirusEnabled);"
        "$($s.AntivirusSignatureAge)\" }"
    )
    code, output = _powershell(script, timeout=60)
    if code != 0 or "NOSTATUS" in output:
        return _unavailable("Defender does not report a status on this machine")
    line = ""
    for candidate in output.splitlines():
        if ";" in candidate:
            line = candidate.strip()
            break
    if not line:
        return _unavailable("Defender returned an unreadable status")
    parts = line.split(";")
    if len(parts) < 3:
        return _unavailable("Defender returned an unreadable status")
    enabled = parts[1].strip().lower() in ("true", "1")
    if not enabled:
        return _unavailable("Defender is idle, a third party antivirus is active")
    try:
        return [_result(int(float(parts[2].strip())))]
    except ValueError:
        return _unavailable("unreadable signature age")


def collect_security_clamav_sig_age(params):
    """Linux: age in days of the newest signature file of /var/lib/clamav."""
    directory = params.get("directory") or "/var/lib/clamav"
    if not os.path.isdir(directory):
        return _unavailable("clamav-freshclam is not installed")
    newest = 0.0
    try:
        for name in os.listdir(directory):
            if not name.endswith((".cvd", ".cld")):
                continue
            try:
                mtime = os.path.getmtime(os.path.join(directory, name))
            except OSError:
                continue
            newest = max(newest, mtime)
    except OSError as error:
        return _unavailable("%s unreadable: %s" % (directory, error))
    if newest <= 0:
        return _unavailable("no signature file in %s" % directory)
    return [_result(int((time.time() - newest) / 86400))]


# =============================================================================
# Collectors: firewall
# =============================================================================
def collect_security_win_firewall(params):
    """Windows: every profile of Get-NetFirewallProfile must be enabled."""
    if not sys.platform.startswith("win"):
        return _unavailable("collector reserved to Windows")
    script = (
        "Get-NetFirewallProfile -ErrorAction SilentlyContinue | "
        "Select-Object -ExpandProperty Enabled"
    )
    code, output = _powershell(script, timeout=60)
    if code != 0:
        return _unavailable("Get-NetFirewallProfile did not answer")
    values = [line.strip().lower() for line in output.splitlines() if line.strip()]
    if not values:
        return _unavailable("no firewall profile reported")
    enabled = all(value in ("true", "1") for value in values)
    return [_result(1 if enabled else 0)]


def collect_security_linux_firewall(params):
    """Linux: ufw, then firewalld, then the input policy of nft or iptables.

    A non empty ruleset is not a firewall: Docker and libvirt install rules
    on every machine they run on, without filtering what comes in. Only an
    input chain that does not accept by default is a host policy.
    """
    if _which("ufw"):
        code, output = _run(["ufw", "status"], timeout=15)
        lowered = (output or "").lower()
        if code == 0 and "status:" in lowered:
            return [_result(1 if "status: active" in lowered else 0)]
    if _which("firewall-cmd"):
        # Installed but stopped says nothing, the ruleset is read below.
        code, output = _run(["firewall-cmd", "--state"], timeout=15)
        if (output or "").strip().lower() == "running":
            return [_result(1)]
    has_iptables = _which("iptables")
    if _which("nft"):
        code, output = _run(["nft", "list", "ruleset"], timeout=15)
        if code != 0 and not has_iptables:
            return _command_failed("nft", code, output)
        if code == 0 and output.strip():
            verdict = _nft_input_verdict(output)
            if verdict is not None:
                return verdict
            if not has_iptables:
                return [_result(0, detail="the ruleset holds no input chain")]
    if has_iptables:
        code, output = _run(["iptables", "-S"], timeout=15)
        if code != 0:
            return _command_failed("iptables", code, output)
        return _iptables_input_verdict(output)
    return _unavailable("no firewall tool found on this machine")


# Words opening a match expression: a verdict preceded by one of them holds
# for a kind of traffic, not for everything that comes in.
_NFT_MATCH_WORDS = (
    "iif", "iifname", "oif", "oifname", "ip", "ip6", "tcp", "udp", "icmp",
    "icmpv6", "ct", "meta", "th", "sport", "dport", "saddr", "daddr",
)


def _nft_input_verdict(output):
    """Verdict read from an nftables ruleset, None when it holds no input
    chain to judge."""
    chains = _nft_input_chains(output)
    if not chains:
        return None
    for body in chains:
        for line in body:
            if "hook input" in line and "policy drop" in line:
                return [_result(1)]
    for body in chains:
        for line in body:
            if _nft_catch_all(line):
                return [_result(1)]
    return [_result(0, detail="the input chain accepts by default")]


def _nft_input_chains(output):
    """Bodies of the base chains hooked on input."""
    chains = []
    body = None
    for raw in (output or "").splitlines():
        line = raw.strip()
        if body is None:
            if line.startswith("chain ") and line.endswith("{"):
                body = []
            continue
        if line == "}":
            if any("hook input" in item for item in body):
                chains.append(body)
            body = None
            continue
        body.append(line)
    return chains


def _nft_catch_all(line):
    """A drop or a reject matching everything, closing an input chain."""
    line = line.split("#")[0].strip().rstrip(";")
    if line.startswith("drop") or line.startswith("reject"):
        return True
    words = line.split()
    if not words or words[-1] not in ("drop", "reject"):
        return False
    return not any(word in _NFT_MATCH_WORDS for word in words)


def _iptables_input_verdict(output):
    """Verdict read from iptables -S: the policy of INPUT, or a catch all."""
    policy = ""
    catch_all = False
    for raw in (output or "").splitlines():
        line = raw.strip()
        if line.startswith("-P INPUT "):
            policy = line.split()[-1].upper()
        elif line.startswith("-A INPUT -j "):
            if line.split()[3].upper() in ("DROP", "REJECT"):
                catch_all = True
    if policy in ("DROP", "REJECT") or catch_all:
        return [_result(1)]
    if not policy:
        return _unavailable("iptables reports no policy for INPUT")
    return [_result(0, detail="the INPUT chain accepts by default")]


def collect_security_macos_firewall(params):
    """macOS: socketfilterfw --getglobalstate."""
    binary = "/usr/libexec/ApplicationFirewall/socketfilterfw"
    if not os.path.isfile(binary):
        return _unavailable("socketfilterfw is not present")
    code, output = _run([binary, "--getglobalstate"], timeout=15)
    if code < 0:
        return _unavailable("socketfilterfw did not answer")
    lowered = output.lower()
    if "enabled" in lowered and "disabled" not in lowered:
        return [_result(1)]
    if "state = 1" in lowered or "state = 2" in lowered:
        return [_result(1)]
    return [_result(0)]


# =============================================================================
# Collectors: disk encryption
# =============================================================================
def collect_security_bitlocker(params):
    """Windows: ProtectionStatus of the system volume."""
    if not sys.platform.startswith("win"):
        return _unavailable("collector reserved to Windows")
    script = (
        "$v = Get-BitLockerVolume -MountPoint $env:SystemDrive "
        "-ErrorAction SilentlyContinue; "
        "if ($v -eq $null) { 'NOVOLUME' } "
        "else { \"$($v.ProtectionStatus);$($v.VolumeStatus)\" }"
    )
    code, output = _powershell(script, timeout=60)
    if code != 0 or "NOVOLUME" in output:
        return _unavailable("BitLocker is not available on this machine")
    line = ""
    for candidate in output.splitlines():
        if ";" in candidate:
            line = candidate.strip()
            break
    if not line:
        return _unavailable("BitLocker returned an unreadable status")
    protection = line.split(";")[0].strip().lower()
    protected = protection in ("on", "1")
    return [_result(1 if protected else 0)]


def collect_security_luks(params):
    """Linux: a dm-crypt layer under the root filesystem.

    A type of lvm says nothing about encryption: a plain LVM install would
    read as encrypted. The chain of parents of the device carrying / is
    walked down to the disk, and only a crypt layer counts.
    """
    if not _which("lsblk"):
        return _unavailable("lsblk is not available")
    code, output = _run(
        ["lsblk", "-P", "-o", "NAME,TYPE,FSTYPE,MOUNTPOINT,PKNAME"], timeout=20
    )
    if code != 0:
        return _unavailable("lsblk did not answer")
    devices, roots = _lsblk_tree(output)
    if not devices:
        return _unavailable("lsblk returned an unreadable device list")
    if not roots:
        return _unavailable("no block device found carrying /")
    has_luks = any(
        device["fstype"] == "crypto_LUKS" for device in devices.values()
    )
    for name in roots:
        if _under_crypt(devices, name):
            return [_result(1)]
    if has_luks:
        # A LUKS container exists but the root does not sit on it: reported as
        # not encrypted, with the reason, rather than silently as encrypted.
        return [_result(0, detail="a LUKS container exists but not under /")]
    return [_result(0)]


def _lsblk_tree(output):
    """Devices of lsblk -P keyed by name, and those carrying /.

    A device with several parents is printed once per parent, so the parents
    are gathered rather than overwritten.
    """
    devices = {}
    roots = []
    for line in output.splitlines():
        name = _lsblk_field(line, "NAME")
        if not name:
            continue
        device = devices.setdefault(
            name,
            {
                "type": _lsblk_field(line, "TYPE"),
                "fstype": _lsblk_field(line, "FSTYPE"),
                "parents": set(),
            },
        )
        parent = _lsblk_field(line, "PKNAME")
        if parent:
            device["parents"].add(parent)
        if _lsblk_field(line, "MOUNTPOINT") == "/" and name not in roots:
            roots.append(name)
    return devices, roots


def _under_crypt(devices, name):
    """Whether a device or one of its ancestors is a dm-crypt mapping."""
    seen = set()
    pending = [name]
    while pending:
        current = pending.pop()
        if current in seen:
            continue
        seen.add(current)
        device = devices.get(current)
        if device is None:
            continue
        if device["type"] == "crypt" or device["fstype"] == "crypto_LUKS":
            return True
        pending.extend(device["parents"])
    return False


def _lsblk_field(line, field):
    match = re.search(r'%s="([^"]*)"' % field, line)
    return match.group(1) if match else ""


def collect_security_filevault(params):
    """macOS: fdesetup status."""
    if not os.path.isfile("/usr/bin/fdesetup"):
        return _unavailable("fdesetup is not present")
    code, output = _run(["/usr/bin/fdesetup", "status"], timeout=20)
    if code < 0:
        return _unavailable("fdesetup did not answer")
    return [_result(1 if "filevault is on" in output.lower() else 0)]


# =============================================================================
# Collectors: local administrators
# =============================================================================
def collect_security_local_admins(params):
    """Number of accounts member of the local administration group.

    The value stays the count; the names travel in the detail as a JSON
    object {"items": [...]}, where the console reads which accounts make
    it up.
    """
    if sys.platform.startswith("win"):
        return _local_admins_windows()
    if sys.platform.startswith("darwin"):
        return _local_admins_macos()
    return _local_admins_unix()


def _admin_names(raw):
    """Account names without their machine or domain prefix, sorted and unique.

    Windows answers ATH-W10-1\\Admin: the prefix is the same on every line and
    tells nothing. Removing it everywhere keeps the three systems readable the
    same way.
    """
    names = set()
    for item in raw or []:
        name = str(item or "").strip()
        if "\\" in name:
            name = name.rsplit("\\", 1)[-1]
        name = name.strip()
        if name:
            names.add(name)
    return sorted(names, key=lambda item: (item.lower(), item))


def _admin_detail(names):
    """Membership carried by the detail, as a JSON list of every account.

    All the names or none: a partial membership would read as the whole one.
    """
    if not names:
        return ""
    detail = json.dumps({"items": list(names)}, separators=(",", ":"))
    return detail if len(detail) <= MEASURE_DETAIL_LENGTH else ""


def _local_admins(names):
    return [_result(len(names), detail=_admin_detail(names))]


def _local_admins_unix():
    """Union of the sudo and wheel members: neither group is mandatory."""
    # grp does not exist on Windows, the import stays local to this branch.
    try:
        import grp
    except ImportError:
        return _unavailable("the group database is not readable on this system")
    members = set()
    known = False
    for name in UNIX_ADMIN_GROUPS:
        try:
            group = grp.getgrnam(name)
        except KeyError:
            continue
        except Exception as error:
            return _unavailable("group %s unreadable: %s" % (name, error))
        known = True
        members.update(member for member in (group.gr_mem or []) if member)
    if not known:
        return _unavailable("neither sudo nor wheel exists on this machine")
    return _local_admins(_admin_names(members))


def _local_admins_windows():
    """The group is named by its SID: it is Administrateurs on a French system."""
    script = (
        "$ProgressPreference = 'SilentlyContinue'; "
        "$m = @(Get-LocalGroupMember -SID '%s' -ErrorAction SilentlyContinue); "
        "if ($m.Count -eq 0) { 'NOGROUP' } "
        "else { $m | ForEach-Object { $_.Name } }"
        % WINDOWS_ADMIN_SID
    )
    code, output = _powershell(script, timeout=60)
    # The group always holds Administrator: an empty answer is a failed read.
    if code != 0 or "NOGROUP" in output:
        return _unavailable("the local administrators group could not be read")
    names = _admin_names(output.splitlines())
    if not names:
        return _unavailable("the local administrators group could not be read")
    return _local_admins(names)


def _local_admins_macos():
    """dscl . -read /Groups/admin GroupMembership."""
    binary = "/usr/bin/dscl"
    if not os.path.isfile(binary):
        return _unavailable("dscl is not present")
    code, output = _run([binary, ".", "-read", "/Groups/admin",
                         "GroupMembership"], timeout=20)
    if code < 0:
        return _unavailable("dscl did not answer")
    for line in output.splitlines():
        if line.strip().lower().startswith("groupmembership:"):
            members = [m for m in line.split(":", 1)[1].split() if m]
            return _local_admins(_admin_names(members))
    return _unavailable("the admin group reports no membership")


# =============================================================================
# Collectors: files altered since their package installed them
# =============================================================================
def collect_security_system_files_modified(params):
    """Linux: packaged files whose content differs from what was installed.

    Nothing to build as a reference, the package manager already holds one:
    debsums -c on Debian and its derivatives, rpm -Va elsewhere. debsums is
    not installed by default, and says so when it is missing. Windows is
    left out on purpose: sfc /verifyonly reads the whole disk and takes
    minutes, too costly for a periodic probe.

    Only an altered content counts. A size, date, permission or ownership
    drift alone leaves the content intact, a missing file is another matter,
    and a configuration file is meant to be edited by the administrator:
    counting them would make the probe shout on every configured machine.
    A rpm -Va line is therefore kept only when it carries the checksum flag
    (5), and dropped when the file is flagged configuration (c) or ghost (g).
    debsums leaves the configuration files out of its own report unless
    asked otherwise, so its side needs no such filter.

    The paths travel in the detail as {"items": [...]}, which _result()
    drops whole when it exceeds the column. The count always remains.
    """
    if not sys.platform.startswith("linux"):
        return _unavailable("collector reserved to Linux")
    if _which("dpkg") or os.path.isfile("/var/lib/dpkg/status"):
        if not _which("debsums"):
            return _unavailable("debsums is not installed")
        code, output = _run(["debsums", "-c"], timeout=PACKAGE_VERIFY_TIMEOUT)
        if code == -2:
            return _unavailable("debsums did not answer within %d seconds"
                                % PACKAGE_VERIFY_TIMEOUT)
        if code < 0:
            return _unavailable("debsums did not run")
        paths = _debsums_modified_paths(output)
        return [_result(len(paths), detail=_items_detail(paths))]
    if _which("rpm"):
        # rpm -Va answers non zero as soon as it reports a difference.
        code, output = _run(["rpm", "-Va"], timeout=PACKAGE_VERIFY_TIMEOUT)
        if code == -2:
            return _unavailable("rpm did not answer within %d seconds"
                                % PACKAGE_VERIFY_TIMEOUT)
        if code < 0:
            return _unavailable("rpm did not run")
        paths = _rpm_modified_paths(output)
        return [_result(len(paths), detail=_items_detail(paths))]
    return _unavailable("no supported package manager found on this machine")


DEBSUMS_FAILED_RE = re.compile(r"\s+FAILED\s*$")
RPM_VERIFY_RE = re.compile(r"^([SM5DLUGTP.?]{8,9})\s+(?:([cdglrn])\s+)?(/.+)$")


def _debsums_modified_paths(output):
    """Paths reported as changed by debsums -c.

    debsums writes its warnings and the files it found missing on the error
    stream, merged here with the report: only the lines holding a path are
    kept.
    """
    paths = set()
    for line in (output or "").splitlines():
        line = line.rstrip()
        if not line.startswith("/"):
            continue
        path = DEBSUMS_FAILED_RE.sub("", line).strip()
        if path:
            paths.add(path)
    return sorted(paths)


def _rpm_modified_paths(output):
    """Paths whose content differs, out of the rpm -Va report.

    A missing file carries "missing" in place of the flags and never matches.
    """
    paths = set()
    for line in (output or "").splitlines():
        match = RPM_VERIFY_RE.match(line.rstrip())
        if not match:
            continue
        flags, kind, path = match.groups()
        if "5" not in flags or kind in ("c", "g"):
            continue
        path = path.strip()
        if path:
            paths.add(path)
    return sorted(paths)


# =============================================================================
# Collectors: authentication failures over a sliding window
# =============================================================================
def _window_minutes(params, default=15):
    try:
        value = int(params.get("window_minutes") or default)
    except (TypeError, ValueError):
        value = default
    return value if value > 0 else default


def collect_security_win_eventlog_4625(params):
    """Windows: Security event 4625 over the sliding window."""
    if not sys.platform.startswith("win"):
        return _unavailable("collector reserved to Windows")
    minutes = _window_minutes(params)
    script = (
        "$t = (Get-Date).AddMinutes(-%d); "
        "@(Get-WinEvent -FilterHashtable "
        "@{LogName='Security'; Id=4625; StartTime=$t} "
        "-ErrorAction SilentlyContinue).Count" % minutes
    )
    code, output = _powershell(script, timeout=LONG_TIMEOUT)
    if code != 0:
        return _unavailable("the Security log could not be read")
    return [_result(_first_int(output, 0))]


AUTH_FAILURE_PATTERNS = (
    "failed password",
    "authentication failure",
    "failed publickey",
    "invalid user",
    "failed su for",
    "incorrect password attempt",
    "auth could not identify password",
)


def collect_security_linux_authlog(params):
    """Linux: authentication failures over the sliding window.

    journalctl first, the auth files afterwards: a machine without systemd
    still has to answer.
    """
    minutes = _window_minutes(params)
    if _which("journalctl"):
        code, output = _run(
            [
                "journalctl",
                "--since",
                "%d min ago" % minutes,
                "--no-pager",
                "-o",
                "cat",
                "-t",
                "sshd",
                "-t",
                "sudo",
                "-t",
                "su",
                "-t",
                "login",
            ],
            timeout=60,
        )
        if code == 0:
            return [_result(_count_auth_failures(output))]

    for name in ("/var/log/auth.log", "/var/log/secure"):
        if not os.path.isfile(name):
            continue
        try:
            with open(name, "r", errors="replace") as handle:
                lines = handle.readlines()[-5000:]
        except (IOError, OSError):
            continue
        return [_result(_count_auth_failures(
            "".join(_filter_syslog_window(lines, minutes))))]
    return _unavailable("no authentication journal could be read")


def _filter_syslog_window(lines, minutes):
    """Keep the syslog lines of the last N minutes, best effort.

    A line whose date cannot be read is kept: undercounting authentication
    failures would be worse than counting one too many.
    """
    now = datetime.now()
    limit = time.time() - minutes * 60
    kept = []
    for line in lines:
        stamp = line[:15]
        try:
            parsed = datetime.strptime(stamp, "%b %d %H:%M:%S")
            parsed = parsed.replace(year=now.year)
            if parsed > now:
                parsed = parsed.replace(year=now.year - 1)
            if parsed.timestamp() >= limit:
                kept.append(line)
        except ValueError:
            kept.append(line)
    return kept


def _count_auth_failures(text):
    count = 0
    for line in (text or "").splitlines():
        lowered = line.lower()
        if any(pattern in lowered for pattern in AUTH_FAILURE_PATTERNS):
            count += 1
    return count


def collect_security_macos_unified_log(params):
    """macOS: authentication failures of the unified log over the window."""
    if not _which("log"):
        return _unavailable("the log command is not available")
    minutes = _window_minutes(params)
    predicate = (
        'eventMessage CONTAINS[c] "authentication failure" '
        'OR eventMessage CONTAINS[c] "failed to authenticate" '
        'OR eventMessage CONTAINS[c] "Failed password"'
    )
    code, output = _run(
        [
            "log",
            "show",
            "--style",
            "compact",
            "--last",
            "%dm" % minutes,
            "--predicate",
            predicate,
        ],
        timeout=LONG_TIMEOUT,
    )
    if code < 0:
        return _unavailable("the unified log did not answer")
    count = 0
    for line in output.splitlines():
        lowered = line.lower()
        if "authentication failure" in lowered or "failed to authenticate" in lowered \
                or "failed password" in lowered:
            count += 1
    return [_result(count)]


# =============================================================================
# Collectors: journal events over a sliding window
#
# Five probes built the same way: the value counts the occurrences of the
# window, and what happened travels in the detail as {"items": [...]}. All of
# them or none: _result() drops a detail wider than the column rather than
# cutting it, and a counter alone stays true.
# =============================================================================
def _items_detail(items):
    """Occurrences carried by the detail, as a JSON list."""
    if not items:
        return ""
    return json.dumps({"items": list(items)}, separators=(",", ":"))


def _dedup(items):
    """Unique values, ordered the same way from one measure to the next."""
    unique = set()
    for item in items or []:
        text = " ".join(str(item or "").split())
        if text:
            unique.add(text)
    return sorted(unique, key=lambda item: (item.lower(), item))


LOG_PREFIX_RE = re.compile(
    r"^(?:\d{4}-\d{2}-\d{2}T\S+|[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+\S+\s+"
)
LOG_TAG_PID_RE = re.compile(r"^([^\s:\[]+)\[\d+\]:")
KERNEL_STAMP_RE = re.compile(r"^\[\s*\d+\.\d+\]\s*")


def _log_message(line):
    """A journal line reduced to "identifier: message".

    The stamp, the host, the pid and the monotonic clock the kernel files
    carry go away: they differ from one occurrence to the next and would
    defeat the deduplication. The kernel identifier goes away too, it is the
    only one in a kernel journal.
    """
    text = " ".join(str(line or "").split())
    text = LOG_PREFIX_RE.sub("", text, count=1)
    text = LOG_TAG_PID_RE.sub(r"\1:", text, count=1)
    if text.startswith("kernel: "):
        text = text[8:]
    return KERNEL_STAMP_RE.sub("", text.strip(), count=1).strip()


def _journal_lines(output):
    """Entries of a journalctl output, its own markers left aside."""
    lines = []
    for line in (output or "").splitlines():
        text = line.strip()
        # "-- Logs begin at ... --", "-- No entries --", "-- Reboot --"
        if not text or text.startswith("-- "):
            continue
        lines.append(text)
    return lines


def _win_event_script(minutes, filters, selector, where=""):
    """Get-WinEvent snippet answering COUNT=<n> then one line per occurrence.

    The count line tells an empty window from a log that could not be read.
    """
    return (
        "$ProgressPreference='SilentlyContinue'; "
        "$t=(Get-Date).AddMinutes(-%d); "
        "$e=@(Get-WinEvent -FilterHashtable @{LogName='System'; %sStartTime=$t} "
        "-ErrorAction SilentlyContinue%s); "
        "'COUNT=' + $e.Count; "
        "$e | ForEach-Object { %s }" % (minutes, filters, where, selector)
    )


def _win_events(script, failure):
    """Count and occurrences of a Get-WinEvent snippet written above."""
    if not sys.platform.startswith("win"):
        return _unavailable("collector reserved to Windows")
    code, output = _powershell(script, timeout=LONG_TIMEOUT)
    if code != 0:
        return _unavailable(failure)
    count = None
    items = []
    for line in output.splitlines():
        text = " ".join(line.split())
        if not text:
            continue
        if text.startswith("COUNT="):
            try:
                count = int(text.split("=", 1)[1])
            except ValueError:
                return _unavailable(failure)
            continue
        items.append(text)
    if count is None:
        return _unavailable(failure)
    return [_result(count, detail=_items_detail(_dedup(items)))]


# Provider and identifier are what name a Windows event; the prefix every
# modern provider carries says nothing and eats the detail.
WIN_EVENT_SOURCE = (
    "'{0}/{1}' -f ($_.ProviderName -replace '^Microsoft-Windows-',''), $_.Id"
)

KERNEL_LOG_FILES = ("/var/log/kern.log", "/var/log/messages", "/var/log/syslog")
KERNEL_LOG_MAX_LINES = 20000

HARDWARE_ERROR_PATTERNS = (
    "hardware error",
    "machine check",
    "mce:",
    "edac",
    "uncorrected error",
    "corrected error",
    "aer:",
    "temperature above threshold",
    "thermal event",
)

FILESYSTEM_ERROR_PATTERNS = (
    "-fs error",
    "btrfs error",
    "btrfs critical",
    "xfs internal error",
    "metadata corruption",
    "corruption detected",
    "remounting filesystem read-only",
    "buffer i/o error",
    "i/o error, dev",
    "filesystem error",
)


def _kernel_log_lines(minutes):
    """Kernel messages of the window, or None when none can be read.

    journalctl first, the kernel files afterwards: a machine without systemd
    still has to answer.
    """
    if _which("journalctl"):
        code, output = _run(
            ["journalctl", "-k", "--since", "%d min ago" % minutes,
             "--no-pager", "-o", "short-iso"],
            timeout=LONG_TIMEOUT,
        )
        if code == 0:
            return _journal_lines(output)
    for name in KERNEL_LOG_FILES:
        if not os.path.isfile(name):
            continue
        try:
            with open(name, "r", errors="replace") as handle:
                lines = handle.readlines()[-KERNEL_LOG_MAX_LINES:]
        except (IOError, OSError):
            continue
        lines = _filter_syslog_window(lines, minutes)
        if not name.endswith("kern.log"):
            lines = [line for line in lines
                     if "kernel:" in line or "kernel[" in line]
        return lines
    return None


def _count_patterns(lines, patterns):
    """Occurrences matching one of the patterns, and what they said."""
    count = 0
    items = []
    for line in lines or []:
        message = _log_message(line)
        lowered = message.lower()
        if any(pattern in lowered for pattern in patterns):
            count += 1
            items.append(message)
    return (count, _dedup(items))


def collect_system_critical_log_events(params):
    """Critical events of the system journal over the sliding window."""
    minutes = _window_minutes(params)
    if sys.platform.startswith("win"):
        return _win_events(
            _win_event_script(minutes, "Level=1; ", WIN_EVENT_SOURCE),
            "the System log could not be read",
        )
    if sys.platform.startswith("darwin"):
        return _macos_critical_events(minutes)
    return _linux_critical_events(minutes)


def _linux_critical_events(minutes):
    """journalctl -p crit: crit, alert and emerg, whatever the unit.

    Without journalctl the machine is left unmeasured: the syslog files do
    not record the priority of a line, and counting the lines that look
    severe would answer another question under the same name.
    """
    if not _which("journalctl"):
        return _unavailable(
            "journalctl is absent: no journal carrying severity levels"
        )
    code, output = _run(
        ["journalctl", "--since", "%d min ago" % minutes, "-p", "crit",
         "--no-pager", "-o", "short-iso"],
        timeout=LONG_TIMEOUT,
    )
    if code != 0:
        return _unavailable("the system journal could not be read")
    messages = [_log_message(line) for line in _journal_lines(output)]
    return [_result(len(messages), detail=_items_detail(_dedup(messages)))]


UNIFIED_LOG_LINE_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d+\s+\S+\s+"
    r"(?P<process>[^\[]+)\[[^\]]*\]\s*"
    r"(?:\([^)]*\)\s*)?(?:\[[^\]]*\]\s*)?(?P<message>.*)$"
)


def _macos_critical_events(minutes):
    """Faults reported by the kernel, the only comparable severity here.

    The unified log has no critical level, and its fault level is not one: a
    healthy Mac emits hundreds of user space faults an hour, Apple daemons
    reporting their own internal accidents. Only the kernel answers the
    question the probe asks on the other two systems.
    """
    if not _which("log"):
        return _unavailable("the log command is not available")
    code, output = _run(
        ["log", "show", "--style", "compact", "--last", "%dm" % minutes,
         "--predicate", 'process == "kernel" AND messageType == 17'],
        timeout=LONG_TIMEOUT,
    )
    if code < 0:
        return _unavailable("the unified log did not answer")
    messages = []
    for line in output.splitlines():
        match = UNIFIED_LOG_LINE_RE.match(line.strip())
        # A message spanning several lines is one occurrence: the stamped
        # line counts, the backtrace printed under it does not.
        if match:
            messages.append(" ".join(match.group("message").split()))
    return [_result(len(messages), detail=_items_detail(_dedup(messages)))]


SYSTEMD_FAILURE_PATTERNS = ("failed with result", "entered failed state")
SYSTEMD_UNIT_RE = re.compile(
    r"^(?P<unit>[^\s:]+\.(?:service|socket|mount|timer|path|scope|swap|target))"
    r":\s"
)
SYSTEMD_OLD_UNIT_RE = re.compile(r"^Unit (?P<unit>\S+) entered failed state")


def collect_service_unexpected_stops(params):
    """Services that stopped abnormally over the sliding window."""
    minutes = _window_minutes(params)
    if sys.platform.startswith("win"):
        # 7031 and 7034: the service terminated unexpectedly. The first
        # insertion string of both names the service that did.
        return _win_events(
            _win_event_script(
                minutes, "Id=7031,7034; ",
                "if ($_.Properties.Count -gt 0) "
                "{ [string]$_.Properties[0].Value }",
            ),
            "the System log could not be read",
        )
    if sys.platform.startswith("linux"):
        return _linux_unexpected_stops(minutes)
    return _unavailable("collector reserved to Windows and Linux")


def _linux_unexpected_stops(minutes):
    """Units systemd declared failed over the window, from its own journal.

    The state read by systemctl --failed is not that question: it is
    persistent, a unit that failed last week is still failed today, while
    Windows counts the stops of the window.
    """
    if not _which("journalctl"):
        return _unavailable("systemd is not in use on this machine")
    code, output = _run(
        ["journalctl", "--since", "%d min ago" % minutes, "--no-pager",
         "-o", "cat", "_PID=1"],
        timeout=LONG_TIMEOUT,
    )
    if code != 0:
        return _unavailable("the system journal could not be read")
    count = 0
    units = []
    for line in _journal_lines(output):
        lowered = line.lower()
        if not any(pattern in lowered for pattern in SYSTEMD_FAILURE_PATTERNS):
            continue
        count += 1
        match = SYSTEMD_UNIT_RE.match(line) or SYSTEMD_OLD_UNIT_RE.match(line)
        units.append(match.group("unit") if match else line)
    return [_result(count, detail=_items_detail(_dedup(units)))]


LAST_MONTHS = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
    "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}
LAST_STAMP_RE = re.compile(
    r"\b(?P<month>Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+"
    r"(?P<day>\d{1,2})\s+(?P<hour>\d{1,2}):(?P<minute>\d{2}):(?P<second>\d{2})"
    r"\s+(?P<year>\d{4})\b"
)


def _last_stamp(line):
    """Epoch of the first full date of a last(1) line, 0 when there is none.

    The month is read from a table rather than by strptime, which follows
    the locale of the process the agent happens to run in.
    """
    match = LAST_STAMP_RE.search(line)
    if not match:
        return 0.0
    try:
        moment = datetime(
            int(match.group("year")), LAST_MONTHS[match.group("month")],
            int(match.group("day")), int(match.group("hour")),
            int(match.group("minute")), int(match.group("second")),
        )
    except (KeyError, ValueError):
        return 0.0
    return moment.timestamp()


def collect_system_unexpected_reboots(params):
    """Reboots that followed no clean shutdown, over the sliding window."""
    minutes = _window_minutes(params, 1440)
    if sys.platform.startswith("win"):
        # 6008: the previous shutdown was unexpected, written at the boot
        # that follows it.
        return _win_events(
            _win_event_script(
                minutes, "Id=6008; ",
                "$_.TimeCreated.ToString('yyyy-MM-dd HH:mm')",
            ),
            "the System log could not be read",
        )
    if sys.platform.startswith("linux"):
        return _linux_unexpected_reboots(minutes)
    return _unavailable("collector reserved to Windows and Linux")


def _linux_unexpected_reboots(minutes):
    """wtmp: a boot with no shutdown record before it was not a clean one.

    wtmp rather than the journal: the question is asked the same way on a
    machine without systemd, and the record outlives the reboot it describes.
    """
    if not _which("last"):
        return _unavailable("last is not available on this machine")
    code, output = _run(
        ["env", "LC_ALL=C", "last", "-x", "-F", "reboot", "shutdown"],
        timeout=DEFAULT_TIMEOUT,
    )
    if code != 0:
        return _unavailable("the boot records could not be read")
    entries = []
    for line in output.splitlines():
        parts = line.split()
        if not parts or parts[0] not in ("reboot", "shutdown"):
            continue
        stamp = _last_stamp(line)
        if stamp:
            entries.append((stamp, parts[0]))
    if not entries:
        return _unavailable("wtmp holds no boot record")
    entries.sort()
    limit = time.time() - minutes * 60
    stamps = []
    for index, (stamp, kind) in enumerate(entries):
        if kind != "reboot" or stamp < limit:
            continue
        # The oldest record has nothing before it: wtmp was rotated, and an
        # unknown shutdown is not an unexpected one.
        if index == 0 or entries[index - 1][1] == "shutdown":
            continue
        stamps.append(time.strftime("%Y-%m-%d %H:%M", time.localtime(stamp)))
    return [_result(len(stamps), detail=_items_detail(_dedup(stamps)))]


def collect_system_hardware_errors(params):
    """Hardware errors reported over the sliding window."""
    minutes = _window_minutes(params, 1440)
    if sys.platform.startswith("win"):
        return _win_events(
            _win_event_script(
                minutes, "Level=1,2,3; ", WIN_EVENT_SOURCE,
                where=" | Where-Object { $_.ProviderName -match 'WHEA' }",
            ),
            "the System log could not be read",
        )
    if not sys.platform.startswith("linux"):
        return _unavailable("collector reserved to Windows and Linux")
    lines = _kernel_log_lines(minutes)
    if lines is None:
        return _unavailable("no kernel journal could be read")
    count, items = _count_patterns(lines, HARDWARE_ERROR_PATTERNS)
    return [_result(count, detail=_items_detail(items))]


def collect_storage_filesystem_errors(params):
    """Filesystem errors reported over the sliding window."""
    minutes = _window_minutes(params, 1440)
    if sys.platform.startswith("win"):
        return _win_events(
            _win_event_script(
                minutes, "Level=1,2,3; ", WIN_EVENT_SOURCE,
                where=" | Where-Object { $_.ProviderName -match "
                      "'^(Ntfs|Microsoft-Windows-Ntfs|disk|volmgr)$' }",
            ),
            "the System log could not be read",
        )
    if not sys.platform.startswith("linux"):
        return _unavailable("collector reserved to Windows and Linux")
    lines = _kernel_log_lines(minutes)
    if lines is None:
        return _unavailable("no kernel journal could be read")
    count, items = _count_patterns(lines, FILESYSTEM_ERROR_PATTERNS)
    return [_result(count, detail=_items_detail(items))]


# =============================================================================
# Collectors: pending updates
# =============================================================================
def collect_update_win_session(params):
    """Windows: updates found by Microsoft.Update.Session with IsInstalled=0."""
    if not sys.platform.startswith("win"):
        return _unavailable("collector reserved to Windows")
    script = (
        "try { "
        "$s = New-Object -ComObject Microsoft.Update.Session; "
        "$r = $s.CreateUpdateSearcher().Search("
        "\"IsInstalled=0 and IsHidden=0\"); "
        "$r.Updates.Count } catch { 'SEARCHFAILED' }"
    )
    code, output = _powershell(script, timeout=300)
    if code != 0 or "SEARCHFAILED" in output:
        return _unavailable("Windows Update did not answer")
    return [_result(_first_int(output, 0))]


def collect_update_apt_dnf(params):
    """Linux: apt, dnf, yum or zypper, whichever runs the machine.

    The package manager of the machine answers, or the measure is
    unavailable: broken sources, an interrupted dpkg or a held lock make the
    tool exit in error with no update line, which would otherwise be counted
    as nothing to install.
    """
    if _which("apt-get"):
        code, output = _run(["apt-get", "-s", "upgrade"], timeout=LONG_TIMEOUT)
        # apt-get exits 100 on error, and prints no Inst line either way.
        if code != 0:
            return _command_failed("apt-get", code, output)
        count = len([line for line in output.splitlines()
                     if line.startswith("Inst ")])
        return [_result(count)]
    if _which("dnf"):
        code, output = _run(["dnf", "--quiet", "check-update"],
                            timeout=LONG_TIMEOUT)
        # dnf answers 100 when updates are pending, 0 when there are none.
        if code not in (0, 100):
            return _command_failed("dnf", code, output)
        return [_result(_count_package_lines(output))]
    if _which("yum"):
        code, output = _run(["yum", "--quiet", "check-update"],
                            timeout=LONG_TIMEOUT)
        if code not in (0, 100):
            return _command_failed("yum", code, output)
        return [_result(_count_package_lines(output))]
    if _which("zypper"):
        code, output = _run(["zypper", "--quiet", "list-updates"],
                            timeout=LONG_TIMEOUT)
        # zypper keeps its codes above 100 for information, the rest are
        # errors: a broken repository or a held lock among them.
        if code not in (0, 100, 101, 102, 103):
            return _command_failed("zypper", code, output)
        count = len([line for line in output.splitlines()
                     if line.startswith("v |")])
        return [_result(count)]
    return _unavailable("no supported package manager found")


def _count_package_lines(output):
    count = 0
    for line in (output or "").splitlines():
        line = line.strip()
        if not line or line.startswith("Last metadata") \
                or line.lower().startswith("obsoleting"):
            continue
        if len(line.split()) >= 3:
            count += 1
    return count


def collect_update_softwareupdate(params):
    """macOS: softwareupdate -l."""
    if not _which("softwareupdate"):
        return _unavailable("softwareupdate is not available")
    code, output = _run(["softwareupdate", "-l"], timeout=300)
    if code < 0:
        return _unavailable("softwareupdate did not answer")
    if "no new software available" in output.lower():
        return [_result(0)]
    count = 0
    for line in output.splitlines():
        stripped = line.strip()
        if stripped.startswith("* ") or stripped.startswith("Label:"):
            count += 1
    return [_result(count)]


# =============================================================================
# Collectors: pending reboot
# =============================================================================
def collect_system_win_reboot_pending(params):
    """Windows: the registry keys left behind by a pending servicing."""
    if not sys.platform.startswith("win"):
        return _unavailable("collector reserved to Windows")
    try:
        import winreg
    except ImportError:
        return _unavailable("winreg is not available")

    keys = (
        (r"SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based "
         r"Servicing\RebootPending"),
        (r"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto "
         r"Update\RebootRequired"),
    )
    for path in keys:
        try:
            handle = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path)
            winreg.CloseKey(handle)
            return [_result(1)]
        except OSError:
            continue
        except Exception:
            continue
    return [_result(0)]


def collect_system_linux_reboot_required(params):
    """Linux: /var/run/reboot-required, then needs-restarting -r."""
    for name in ("/var/run/reboot-required", "/run/reboot-required"):
        if os.path.isfile(name):
            return [_result(1)]
    if _which("needs-restarting"):
        code, _ = _run(["needs-restarting", "-r"], timeout=60)
        if code == 0:
            return [_result(0)]
        if code == 1:
            return [_result(1)]
    if os.path.isdir("/var/run") or os.path.isdir("/run"):
        return [_result(0)]
    return _unavailable("no reboot indicator on this machine")


# =============================================================================
# Collectors: name resolution
# =============================================================================
def collect_network_dns_resolution(params):
    """Whether the XMPP server of the agent configuration still resolves."""
    name, reason = _xmpp_server_name()
    if not name:
        return _unavailable(reason)
    try:
        timeout = float(params.get("timeout") or DNS_TIMEOUT)
    except (TypeError, ValueError):
        timeout = DNS_TIMEOUT
    if timeout <= 0 or timeout > 5:
        timeout = DNS_TIMEOUT
    address, error = _resolve(name, timeout)
    if address:
        return [_result(1)]
    return [_result(0, detail="%s: %s" % (name, error))]


def _xmpp_server_name():
    """Server name of agentconf.ini, or the reason why there is none.

    A server written as an IP address goes through no resolver: it is skipped
    in favour of the next candidate rather than resolved to itself.
    """
    name = conffilename("machine")
    parser = configparser.ConfigParser()
    try:
        with open(name, "r") as handle:
            parser.read_file(handle)
    except (IOError, OSError, configparser.Error) as error:
        return ("", "agent configuration unreadable: %s" % error)
    for section, option in (("connection", "server"),
                            ("configuration_server", "confserver")):
        try:
            value = str(parser.get(section, option) or "").strip()
        except configparser.Error:
            continue
        if value and not _is_ip_literal(value):
            return (value, "")
    return ("", "no XMPP server name in the agent configuration")


def _is_ip_literal(value):
    for family in (socket.AF_INET, socket.AF_INET6):
        try:
            socket.inet_pton(family, value)
            return True
        except (OSError, ValueError):
            continue
    return False


def _resolve(name, timeout):
    """Resolve a name within the allowed time: the resolver has no short timeout."""
    outcome = {}

    def worker():
        try:
            outcome["address"] = socket.gethostbyname(name)
        except Exception as error:
            outcome["error"] = "%s: %s" % (type(error).__name__, error)

    thread = threading.Thread(target=worker)
    thread.daemon = True
    thread.start()
    thread.join(timeout)
    if thread.is_alive():
        return ("", "no answer within %ss" % timeout)
    return (outcome.get("address", ""), outcome.get("error", "unresolved"))


def _first_int(text, default=0):
    for line in (text or "").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            return int(float(line))
        except ValueError:
            continue
    return default


# =============================================================================
# Collectors: personal scripted probes
#
# The command is written by a console user allowed by the reflex ACLs. It is
# run as given, bounded in time, and only its first printed line is kept.
# =============================================================================
SCRIPT_TIMEOUT = 30
SCRIPT_VALUE_LENGTH = 255
SCRIPT_REASON_LENGTH = 200

TRUE_WORDS = ("oui", "yes", "true", "vrai", "1", "ok", "on")
FALSE_WORDS = ("non", "no", "false", "faux", "0", "off")


def _kill_tree(process):
    """Kill a process and every descendant it started."""
    try:
        parent = psutil.Process(process.pid)
        victims = parent.children(recursive=True) + [parent]
    except psutil.Error:
        victims = []
    if not sys.platform.startswith("win"):
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except (OSError, AttributeError):
            pass
    for victim in victims:
        try:
            victim.kill()
        except psutil.Error:
            pass
    psutil.wait_procs(victims, timeout=5)


def _first_line(text):
    for line in (text or "").splitlines():
        line = line.strip()
        if line:
            return line
    return None


def _run_script(argv, timeout):
    """Run a user command, return (returncode, stdout, stderr).

    returncode is None when the command did not finish in time; the process
    and its children are then killed.
    """
    options = {
        "stdin": subprocess.DEVNULL,
        "stdout": subprocess.PIPE,
        "stderr": subprocess.PIPE,
        "shell": False,
    }
    if sys.platform.startswith("win"):
        options["creationflags"] = getattr(subprocess, "CREATE_NO_WINDOW",
                                           0x08000000)
    else:
        options["start_new_session"] = True
    process = subprocess.Popen(argv, **options)
    try:
        stdout, stderr = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        _kill_tree(process)
        try:
            process.communicate(timeout=5)
        except Exception:
            for stream in (process.stdout, process.stderr):
                try:
                    stream.close()
                except Exception:
                    pass
        return (None, "", "")
    return (process.returncode, _decode_output(stdout), _decode_output(stderr))


def _convert_script_value(line, value_type):
    """One measure from the printed line, typed after the probe."""
    extract = line[:SCRIPT_REASON_LENGTH]
    if value_type == "text":
        return [_result(line)]
    if value_type == "boolean":
        word = line.lower()
        if word in TRUE_WORDS:
            return [_result(1)]
        if word in FALSE_WORDS:
            return [_result(0)]
        return _unavailable("unrecognised answer: %s" % extract)
    number = line
    if number.endswith("%"):
        number = number[:-1].strip()
    number = number.replace(",", ".")
    try:
        value = float(number)
    except ValueError:
        return _unavailable("not a number: %s" % extract)
    if value != value or value in (float("inf"), float("-inf")):
        return _unavailable("not a number: %s" % extract)
    return [_result(value)]


def _collect_script(argv_prefix, params, timeout=None):
    command = params.get("command")
    if not isinstance(command, str) or not command.strip():
        return _unavailable("no command to run")
    timeout = timeout or SCRIPT_TIMEOUT
    value_type = str(params.get("value_type") or "numeric").strip().lower()
    try:
        code, stdout, stderr = _run_script(argv_prefix + [command], timeout)
    except (OSError, IOError) as error:
        return _unavailable("%s could not be started: %s"
                            % (argv_prefix[0], error))
    if code is None:
        return _unavailable("timeout of %d s exceeded" % timeout)
    if code != 0:
        reason = "exit code %d" % code
        message = _first_line(stderr)
        if message:
            reason = "%s: %s" % (reason, message[:SCRIPT_REASON_LENGTH])
        return _unavailable(reason)
    line = _first_line(stdout)
    if line is None:
        reason = "no output"
        message = _first_line(stderr)
        if message:
            reason = "%s: %s" % (reason, message[:SCRIPT_REASON_LENGTH])
        return _unavailable(reason)
    return _convert_script_value(line[:SCRIPT_VALUE_LENGTH], value_type)


def collect_script_sh(params, timeout=None):
    """Linux and macOS: /bin/sh -c <command>."""
    if sys.platform.startswith("win"):
        return _unavailable("collector reserved to Linux and macOS")
    return _collect_script(["/bin/sh", "-c"], params, timeout)


def collect_script_powershell(params, timeout=None):
    """Windows: powershell.exe -Command <command>."""
    if not sys.platform.startswith("win"):
        return _unavailable("collector reserved to Windows")
    return _collect_script(
        ["powershell.exe", "-NoProfile", "-NonInteractive",
         "-ExecutionPolicy", "Bypass", "-Command"],
        params, timeout)


# =============================================================================
# Registry
#
# The only entry point to a collector. A key that is not here is refused:
# nothing outside this table can ever be run.
# =============================================================================
COLLECTORS = {
    "cpu.percent": collect_cpu_percent,
    "system.load_average": collect_system_load_average,
    "mem.virtual": collect_mem_virtual,
    "mem.swap": collect_mem_swap,
    "disk.usage": collect_disk_usage,
    "system.boot_time": collect_system_boot_time,
    "system.process_count": collect_system_process_count,
    "system.temperature": collect_system_temperature,
    "disk.smart_wmi": collect_disk_smart_wmi,
    "disk.smart_smartctl": collect_disk_smart_smartctl,
    "disk.smart_diskutil": collect_disk_smart_diskutil,
    "service.win_auto_stopped": collect_service_win_auto_stopped,
    "service.systemd_failed": collect_service_systemd_failed,
    "service.launchd_failed": collect_service_launchd_failed,
    "security.win_securitycenter": collect_security_win_securitycenter,
    "security.clamav_status": collect_security_clamav_status,
    "security.win_defender_sig_age": collect_security_win_defender_sig_age,
    "security.clamav_sig_age": collect_security_clamav_sig_age,
    "security.win_firewall": collect_security_win_firewall,
    "security.linux_firewall": collect_security_linux_firewall,
    "security.macos_firewall": collect_security_macos_firewall,
    "security.bitlocker": collect_security_bitlocker,
    "security.luks": collect_security_luks,
    "security.filevault": collect_security_filevault,
    "security.local_admins": collect_security_local_admins,
    "security.system_files_modified": collect_security_system_files_modified,
    "security.win_eventlog_4625": collect_security_win_eventlog_4625,
    "security.linux_authlog": collect_security_linux_authlog,
    "security.macos_unified_log": collect_security_macos_unified_log,
    "system.critical_log_events": collect_system_critical_log_events,
    "service.unexpected_stops": collect_service_unexpected_stops,
    "system.unexpected_reboots": collect_system_unexpected_reboots,
    "system.hardware_errors": collect_system_hardware_errors,
    "storage.filesystem_errors": collect_storage_filesystem_errors,
    "update.win_session": collect_update_win_session,
    "update.apt_dnf": collect_update_apt_dnf,
    "update.softwareupdate": collect_update_softwareupdate,
    "system.win_reboot_pending": collect_system_win_reboot_pending,
    "system.linux_reboot_required": collect_system_linux_reboot_required,
    "network.dns_resolution": collect_network_dns_resolution,
    "script.sh": collect_script_sh,
    "script.powershell": collect_script_powershell,
}

SCRIPT_COLLECTORS = ("script.sh", "script.powershell")


def known_collectors():
    """Collector keys this agent implements, reported to the server."""
    return sorted(COLLECTORS.keys())


def run_collector(collector, params=None):
    """Run one collector by key.

    An unknown key is refused here and nowhere else: this is the guard that
    keeps a database row from becoming an execution.
    """
    params = params if isinstance(params, dict) else {}
    function = COLLECTORS.get(str(collector or "").strip())
    if function is None:
        logger.warning(
            "reflex: collector '%s' is not implemented by this agent, refused"
            % collector
        )
        return _unavailable("collector '%s' unknown to the agent" % collector)
    try:
        results = function(params)
    except Exception as error:
        logger.error("reflex: collector %s failed: %s" % (collector, error))
        return [_result(status=STATUS_ERROR, detail="%s: %s"
                        % (type(error).__name__, error))]
    if not isinstance(results, list) or not results:
        return _unavailable("collector %s returned nothing" % collector)
    return results


# =============================================================================
# Probe to measures
# =============================================================================
def _collector_for_os(probe, os_key):
    """Collector row of the probe for this operating system, if there is one."""
    collectors = probe.get("collectors")
    if isinstance(collectors, dict):
        entry = collectors.get(os_key)
        if isinstance(entry, dict):
            return entry
        return None
    if isinstance(collectors, list):
        for entry in collectors:
            if isinstance(entry, dict) and str(entry.get("os")) == os_key:
                return entry
        return None
    # A configuration that already carries a single resolved collector.
    if probe.get("collector"):
        return {"collector": probe.get("collector"),
                "params_json": probe.get("params_json"),
                "requires": probe.get("requires")}
    return None


def _params_of(entry):
    raw = entry.get("params_json") if entry else None
    if isinstance(raw, dict):
        return raw
    if not raw:
        return {}
    try:
        parsed = json.loads(raw)
    except (TypeError, ValueError):
        return {}
    return parsed if isinstance(parsed, dict) else {}


def measurement_moment():
    """Instant of a measure, as an ISO 8601 text carrying its offset.

    UTC and never the local wall clock. What used to be sent was
    datetime.now() with no zone at all, which the server could only read in
    its own: a machine in another country, or a Linux left in UTC beside a
    server in Paris, reported measures dated hours away from their real
    instant and was flagged for a clock drift it did not have.

    The offset is written literally rather than with %z, which on the Python
    3.11 embedded with the Windows agent renders "+0000", without the colon
    ISO 8601 asks for. Building the two forms differently per platform would
    only give the server two spellings to read.
    """
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S") + "+00:00"


def collect_probe(probe, collected_at=None):
    """Measures produced by one probe, ready to be sent.

    A probe with no collector for this operating system reports unavailable
    rather than nothing: an absence has to be visible, not silent.
    """
    collected_at = collected_at or measurement_moment()
    probe_key = probe.get("probe_key") or ""
    metric_key = probe.get("metric_key") or ""
    unit = probe.get("unit")
    value_type = str(probe.get("value_type") or "numeric").lower()

    entry = _collector_for_os(probe, current_os())
    if entry is None:
        return [{
            "probe_id": probe.get("probe_id"),
            "probe_key": probe_key,
            "metric_key": metric_key,
            "value": None,
            "unit": unit,
            "status": STATUS_UNAVAILABLE,
            "detail": "no collector for %s" % current_os(),
            "collected_at": collected_at,
        }]

    collector = entry.get("collector")
    params = dict(_params_of(entry))
    if str(collector or "").strip() in SCRIPT_COLLECTORS:
        params["value_type"] = value_type
    results = run_collector(collector, params)

    measures = []
    for item in results:
        value = item.get("value")
        value_text = item.get("value_text")
        if value_type in ("text",) and value is None and value_text is not None:
            value = value_text
            value_text = None
        measure = {
            "probe_id": probe.get("probe_id"),
            "probe_key": probe_key,
            "metric_key": metric_key,
            "value": value,
            "unit": unit,
            "status": item.get("status", STATUS_OK),
            "collected_at": collected_at,
        }
        if value_text is not None:
            measure["value_text"] = value_text
        if item.get("detail"):
            measure["detail"] = item["detail"]
        measures.append(measure)
    return measures


# =============================================================================
# Reception of the configuration pushed by the server
# =============================================================================
@set_logging_level
def action(objectxmpp, action, sessionid, data, message, dataerreur):
    """Handle what the reflex substitute sends to this machine.

    The only subaction implemented is the distribution of the probe
    configuration. Nothing received here is executed: the probes name
    collectors, and unknown collectors are refused at collection time.
    """
    logger.debug("###################################################")
    logger.debug("call %s from %s session %s" % (plugin, message["from"], sessionid))
    logger.debug("###################################################")

    subaction = str(data.get("subaction") or "").lower()
    if subaction != "config":
        logger.warning("reflex: subaction '%s' ignored" % subaction)
        return

    config_version = str(data.get("config_version") or "")
    probes = data.get("probes")
    if not isinstance(probes, list):
        probes = []

    error = write_local_config(config_version, probes)
    unknown = sorted({
        str(_collector_for_os(probe, current_os()).get("collector"))
        for probe in probes
        if isinstance(probe, dict) and _collector_for_os(probe, current_os())
    } - set(COLLECTORS.keys()))
    if unknown:
        # Reported, not executed: the console has to see that this agent
        # cannot honour part of its configuration.
        logger.warning("reflex: unknown collectors refused: %s"
                       % ", ".join(unknown))
        detail = "unknown collectors: %s" % ", ".join(unknown)
        error = "%s; %s" % (error, detail) if error else detail

    logger.info("reflex: configuration %s applied, %d probe(s)"
                % (config_version or "(empty)", len(probes)))

    reply = {
        "action": "reflex_measures",
        "sessionid": sessionid or getRandomName(6, "reflex"),
        "base64": False,
        "ret": 0,
        "data": {
            "subaction": "configack",
            "config_version": config_version,
            "probe_count": len(probes),
            "platform": current_os(),
            "collectors": known_collectors(),
            "error": error or None,
            "date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        },
    }
    try:
        objectxmpp.send_message(
            mto=message["from"], mbody=json.dumps(reply), mtype="chat"
        )
    except Exception as sending_error:
        logger.error("reflex: acknowledgement not sent: %s" % sending_error)
