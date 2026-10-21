# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2026 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-3.0-or-later
# file : pulse_xmpp_agent/pluginsmachine/plugin_updates_windows.py

"""
Windows updates report: collects the update state of the machine
(read only) and sends it to the updates substitute.

Called by plugin_inventory, then every day by its own timer.
Data {"force": true} forces a new online search, as does the call made
by a Windows update package at the end of its deployment
(@@@PLUGIN_CALL_updates_windows@@@ step of grafcetdeploy).
"""

import base64
from datetime import datetime, timezone
import hashlib
import json
import logging
import math
import os
import platform
import re
import subprocess
import sys
import tempfile
import threading
import time
import traceback
import xml.etree.ElementTree as ElementTree

from lib import utils
from lib.agentconffile import medullaPath

logger = logging.getLogger()

plugin = {"VERSION": "1.13", "NAME": "updates_windows", "TYPE": "machine"}  # fmt: skip

REPORT_FORMAT = 1
REPORT_INTERVAL = 86400
SEARCH_MIN_INTERVAL = 20 * 3600
SEARCH_TIMEOUT = 600
# Post-deployment report waiting for a report already running
LOCK_TIMEOUT = 1800
SCRIPT_TIMEOUT = 120
DXDIAG_TIMEOUT = 120
LAST_SEARCH_FILE = "lastsearchupdates"
# Same convention as fingerprintinventory: what the last report sent
FINGERPRINT_FILE = "fingerprintupdates"
CURRENT_VERSION_KEY = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion"
# What the previous update engine left on the machine
LEGACY_REGISTRY_KEY = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Medulla Update Info"
LEGACY_TASK = "win11compatcheck"
PACKAGES_KEY = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\Packages"
MICROSOFT_UPDATE_SERVICE = "7971f918-a847-4430-9279-4a52d1efe18d"

# HKLM keys present while Windows waits for a restart
REBOOT_PENDING_KEYS = (
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired",
    r"SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending",
)
# Volatile key of setup.exe: SetupProgress 100 once an upgrade waits for its restart
SETUP_KEY = r"SYSTEM\Setup\MoSetup\Volatile"
SETUP_COMPLETE = 100

PAUSE_KEY = r"SOFTWARE\Microsoft\WindowsUpdate\UX\Settings"
PAUSE_VALUES = ("PauseUpdatesExpiryTime", "PauseQualityUpdatesEndTime")
PAUSE_DATE = re.compile(
    r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.\d+)?(Z|[+-]\d{2}:\d{2})?$"
)

DOTNET_KEY = r"SOFTWARE\Microsoft\NET Framework Setup\NDP"
# Lowest Release value of each .NET Framework 4 version (Microsoft documentation)
DOTNET4_RELEASES = (
    (533320, "4.8.1"),
    (528040, "4.8"),
    (461808, "4.7.2"),
    (461308, "4.7.1"),
    (460798, "4.7"),
    (394802, "4.6.2"),
    (394254, "4.6.1"),
    (393295, "4.6"),
    (379893, "4.5.2"),
    (378675, "4.5.1"),
    (378389, "4.5"),
)

# WUA errors meaning the search is not allowed on this machine
BLOCKING_HRESULTS = {
    0x80070422: "wuauserv service is disabled",
    0x8024002E: "Windows Update access is disabled by policy",
}

SYSTEM_SCRIPT = r"""
$cv = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
$architecture = $env:PROCESSOR_ARCHITECTURE
if ($env:PROCESSOR_ARCHITEW6432) { $architecture = $env:PROCESSOR_ARCHITEW6432 }
$language = [System.Globalization.CultureInfo]::InstalledUICulture.Name
if (-not $language) { $language = (Get-WinSystemLocale).Name }
[pscustomobject]@{
    product = $cv.ProductName
    edition = $cv.EditionID
    release = $cv.DisplayVersion
    release_id = $cv.ReleaseId
    build = $cv.CurrentBuild
    ubr = $cv.UBR
    installation_type = $cv.InstallationType
    architecture = $architecture
    language = $language
} | ConvertTo-Json -Compress
"""

ESU_SCRIPT = r"""
try {
    $products = @(Get-CimInstance SoftwareLicensingProduct -ErrorAction Stop `
        -Filter "Name LIKE '%ESU%' AND PartialProductKey IS NOT NULL")
    $active = @($products | Where-Object { $_.LicenseStatus -eq 1 })
    [pscustomobject]@{ licensed = ($active.Count -gt 0) } | ConvertTo-Json -Compress
} catch {
    [pscustomobject]@{ licensed = $null } | ConvertTo-Json -Compress
}
"""

INSTALLED_SCRIPT = r"""
$items = @()
try {
    $searcher = (New-Object -ComObject Microsoft.Update.Session).CreateUpdateSearcher()
    $count = $searcher.GetTotalHistoryCount()
    if ($count -gt 0) {
        foreach ($entry in $searcher.QueryHistory(0, $count)) {
            # Operation 1 = installation, ResultCode 2/3 = succeeded
            if ($entry.Operation -eq 1 -and $entry.ResultCode -in @(2, 3) -and $entry.Title -match 'KB(\d+)') {
                $items += [pscustomobject]@{ kb = [int]$Matches[1]; date = $entry.Date.ToString('yyyy-MM-dd') }
            }
        }
    }
} catch {}
try {
    foreach ($fix in Get-HotFix -ErrorAction Stop) {
        if ($fix.HotFixID -match 'KB(\d+)') {
            $date = $null
            if ($fix.InstalledOn) { $date = $fix.InstalledOn.ToString('yyyy-MM-dd') }
            $items += [pscustomobject]@{ kb = [int]$Matches[1]; date = $date }
        }
    }
} catch {}
ConvertTo-Json -InputObject @($items) -Compress
"""

POLICY_SCRIPT = r"""
$policies = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate'
$wu = Get-ItemProperty $policies -ErrorAction SilentlyContinue
$au = Get-ItemProperty "$policies\AU" -ErrorAction SilentlyContinue
$service = Get-CimInstance Win32_Service -Filter "Name='wuauserv'"
[pscustomobject]@{
    wsus_server = $wu.WUServer
    use_wsus_server = $au.UseWUServer
    no_auto_update = $au.NoAutoUpdate
    au_options = $au.AUOptions
    start_mode = $service.StartMode
    state = $service.State
} | ConvertTo-Json -Compress
"""

WINDOWS11_SCRIPT = r"""
$root = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\TargetVersionUpgradeExperienceIndicators'
$targets = @()
if (Test-Path $root) {
    foreach ($key in Get-ChildItem $root) {
        $values = Get-ItemProperty $key.PSPath
        $targets += [pscustomobject]@{
            target = $key.PSChildName
            dest_build = $values.DestBuildNum
            red_reason = $values.RedReason
            upg_ex = $values.UpgEx
        }
    }
}
$tpm = $null
try {
    $chip = Get-CimInstance -Namespace 'root\cimv2\Security\MicrosoftTpm' -ClassName Win32_Tpm -ErrorAction Stop
    if ($chip) { $tpm = ($chip.SpecVersion -split ',')[0].Trim() } else { $tpm = 'none' }
} catch {}
$firmware = $null
$firmwareType = (Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control' -ErrorAction SilentlyContinue).PEFirmwareType
if ($firmwareType -eq 1) { $firmware = 'bios' } elseif ($firmwareType -eq 2) { $firmware = 'uefi' }
$secureBoot = $null
try { $secureBoot = [bool](Confirm-SecureBootUEFI -ErrorAction Stop) }
catch [System.PlatformNotSupportedException] { $secureBoot = $false }
catch {}
$cpu = (Get-CimInstance Win32_Processor | Select-Object -First 1).Name
$memory = (Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory
$disk = Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='$env:SystemDrive'"
$monitors = @(Get-CimInstance -Namespace 'root\wmi' -ClassName WmiMonitorBasicDisplayParams -ErrorAction SilentlyContinue |
    Where-Object { $_.Active } |
    ForEach-Object { [pscustomobject]@{ width_cm = $_.MaxHorizontalImageSize; height_cm = $_.MaxVerticalImageSize } })
$videos = @(Get-CimInstance Win32_VideoController |
    Where-Object { $_.CurrentHorizontalResolution } |
    ForEach-Object { [pscustomobject]@{ width = $_.CurrentHorizontalResolution; height = $_.CurrentVerticalResolution; bits_per_pixel = $_.CurrentBitsPerPixel } })
[pscustomobject]@{
    monitors = $monitors
    videos = $videos
    targets = @($targets)
    tpm = $tpm
    secure_boot = $secureBoot
    firmware = $firmware
    cpu = $cpu
    ram_gb = [math]::Round($memory / 1GB)
    disk_free_gb = [math]::Floor($disk.FreeSpace / 1GB)
    disk_size_gb = [math]::Floor($disk.Size / 1GB)
} | ConvertTo-Json -Compress -Depth 3
"""

SEARCH_SCRIPT = r"""
$result = [ordered]@{ server = 'windows_update'; result_code = $null; hresult = $null; error = $null; missing = @() }
try {
    $session = New-Object -ComObject Microsoft.Update.Session
    $session.ClientApplicationID = 'Medulla'
    $searcher = $session.CreateUpdateSearcher()
    $serviceId = '%(service_id)s'
    $manager = New-Object -ComObject Microsoft.Update.ServiceManager
    if (@($manager.Services | Where-Object { $_.ServiceID -eq $serviceId }).Count -gt 0) {
        $searcher.ServerSelection = 3
        $searcher.ServiceID = $serviceId
        $result.server = 'microsoft_update'
    } else {
        $searcher.ServerSelection = 2
    }
    $found = $searcher.Search('IsInstalled=0 and IsHidden=0')
    $result.result_code = $found.ResultCode
    $result.missing = @(foreach ($update in $found.Updates) {
        $kb = $null
        $ids = @($update.KBArticleIDs)
        if ($ids.Count -gt 0) { $kb = [int]$ids[0] }
        [pscustomobject]@{ id = $update.Identity.UpdateID; kb = $kb; title = $update.Title }
    })
} catch {
    $exception = $_.Exception
    while ($exception.InnerException) { $exception = $exception.InnerException }
    $result.hresult = $exception.HResult
    $result.error = $exception.Message
}
ConvertTo-Json -InputObject ([pscustomobject]$result) -Compress -Depth 3
""" % {"service_id": MICROSOFT_UPDATE_SERVICE}


@utils.set_logging_level
def action(xmppobject, action, sessionid, data, message, dataerreur):
    if not sys.platform.startswith("win"):
        return
    deployment = after_deployment(data)
    force = deployment or (isinstance(data, dict) and data.get("force") is True)
    if not hasattr(xmppobject, "updates_windows_lock"):
        xmppobject.updates_windows_lock = threading.Lock()
        xmppobject.schedule(
            "updates_windows_report",
            REPORT_INTERVAL,
            start_report,
            (xmppobject,),
            repeat=True,
        )
    if deployment:
        # Never hold the deployment step or the XMPP event loop
        start_forced_report(xmppobject)
        return
    if isinstance(data, dict) and data.get("check") is True:
        # Scheduled check: a report only when the machine changed since the last one
        if state_changed():
            start_report(xmppobject)
        return
    send_report(xmppobject, force)


def start_forced_report(xmppobject):
    threading.Thread(
        target=send_report,
        args=(xmppobject, True, True),
        name="updates_windows",
        daemon=True,
    ).start()


def start_report(xmppobject):
    """Timer callback: never block the event loop."""
    threading.Thread(
        target=send_report,
        args=(xmppobject, False),
        name="updates_windows",
        daemon=True,
    ).start()


def send_report(xmppobject, force, wait=False):
    lock = xmppobject.updates_windows_lock
    if not (lock.acquire(timeout=LOCK_TIMEOUT) if wait else lock.acquire(False)):
        logger.debug("Windows updates report already running")
        return
    try:
        clean_legacy(xmppobject)
        fingerprint = state_fingerprint()
        report = build_report(force)
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
    except Exception:
        logger.error("Windows updates report failed\n%s" % traceback.format_exc())
    finally:
        xmppobject.updates_windows_lock.release()


def legacy_files(xmppobject):
    """The files by name: never a folder, nothing else."""
    scheduled = xmppobject.config.pathpluginsscheduled
    return [
        os.path.join(xmppobject.config.pathplugins, "plugin_updatemedullainfo.py"),
        os.path.join(scheduled, "scheduling_%s.py" % LEGACY_TASK),
        # manage_scheduler: <name without "scheduling_">.crontab, when persistent
        os.path.join(scheduled, "%s.crontab" % LEGACY_TASK),
        os.path.join(medullaPath(), "var", "log", "windows11_compatibility_report.json"),
        os.path.join(medullaPath(), "bin", "medulla_info_update.py"),
        os.path.join(medullaPath(), "bin", "uninstall_medulla_info_update_notification.py"),
    ]


def clean_legacy(xmppobject, registry=None):
    """Remove what exists of the previous engine; a failure never stops the report."""
    try:
        for path in legacy_files(xmppobject):
            remove_legacy_file(path)
    except Exception:
        logger.error("Legacy files not listed\n%s" % traceback.format_exc())
    remove_legacy_key(registry)
    forget_legacy_task(xmppobject)


def remove_legacy_file(path):
    try:
        if os.path.isfile(path):
            os.remove(path)
            logger.info("Legacy file removed: %s" % path)
    except OSError as error:
        logger.warning("Legacy file %s not removed: %s" % (path, error))


def remove_legacy_key(registry=None):
    try:
        if registry is None:
            import winreg as registry
        registry.DeleteKey(registry.HKEY_LOCAL_MACHINE, LEGACY_REGISTRY_KEY)
        logger.info("Legacy registry key removed: HKLM\\%s" % LEGACY_REGISTRY_KEY)
    except FileNotFoundError:
        pass
    except Exception as error:
        logger.warning("Legacy registry key not removed: %s" % error)


def forget_legacy_task(xmppobject):
    """A descriptor stays scheduled until the agent restarts, its file gone or not. The
    task list belongs to the XMPP event loop: changed from there."""
    try:
        tasks = xmppobject.manage_scheduler.taches

        def forget():
            tasks[:] = [task for task in tasks if task["name"] != LEGACY_TASK]

        if any(task["name"] == LEGACY_TASK for task in tasks):
            xmppobject.loop.call_soon_threadsafe(forget)
            logger.info("Legacy scheduled task stopped: %s" % LEGACY_TASK)
    except Exception as error:
        logger.warning("Legacy scheduled task not stopped: %s" % error)


def build_report(force):
    system = normalize_system(collect(SYSTEM_SCRIPT) or {})
    system["dotnet"] = dotnet_versions()
    policy = normalize_policy(collect(POLICY_SCRIPT) or {})
    policy["paused_until"] = paused_until()
    esu = collect(ESU_SCRIPT) or {"licensed": None}
    installed = collect(INSTALLED_SCRIPT)
    if installed is not None:
        installed = merge_installed(installed)

    windows11 = None
    if system.get("type") == "client":
        raw = collect(WINDOWS11_SCRIPT) or {}
        # dxdiag is slow: only needed when Windows gives no verdict
        graphics = None if latest_target(raw.get("targets")) else collect_graphics()
        windows11 = windows11_report(raw, graphics)

    path = last_search_path()
    last_search, searched_version = read_last_search(path)
    # An upgrade or a cumulative update makes the previous list obsolete
    version = system_version(system)
    if search_is_due(last_search, time.time(), force or searched_version != version):
        search = online_search(policy)
        # A failed search is tried again at the next report
        if search["status"] == "ok":
            write_last_search(path, time.time(), version)
    else:
        search = {
            "status": "skipped",
            "error": None,
            "server": None,
            "duration": None,
            "searched_at": iso_utc(last_search),
        }

    return {
        "format": REPORT_FORMAT,
        "system": system,
        "esu": {"licensed": esu.get("licensed")},
        "installed": installed,
        "search": search,
        "policy": policy,
        "windows11": windows11,
        "reboot_pending": reboot_pending(),
    }


def reboot_pending(registry=None):
    """True when a restart is pending, None when the registry is unreadable."""
    try:
        if registry is None:
            import winreg as registry
        access = registry.KEY_READ | registry.KEY_WOW64_64KEY
        for path in REBOOT_PENDING_KEYS:
            try:
                key = registry.OpenKey(registry.HKEY_LOCAL_MACHINE, path, 0, access)
            except FileNotFoundError:
                continue
            registry.CloseKey(key)
            return True
        return to_int(registry_value(registry, SETUP_KEY, "SetupProgress")) == SETUP_COMPLETE
    except Exception:
        logger.warning("Pending restart unknown\n%s" % traceback.format_exc())
        return None


def registry_value(registry, path, name):
    """Value of HKLM path (64-bit view), None when absent or unreadable."""
    try:
        access = registry.KEY_READ | registry.KEY_WOW64_64KEY
        key = registry.OpenKey(registry.HKEY_LOCAL_MACHINE, path, 0, access)
        try:
            return registry.QueryValueEx(key, name)[0]
        finally:
            registry.CloseKey(key)
    except FileNotFoundError:
        return None
    except Exception:
        logger.warning(
            "Registry value %s\\%s unreadable\n%s" % (path, name, traceback.format_exc())
        )
        return None


def paused_until(registry=None, now=None):
    """End of the Windows Update pause (UTC ISO 8601), None when not paused."""
    try:
        if registry is None:
            import winreg as registry
        for name in PAUSE_VALUES:
            value = registry_value(registry, PAUSE_KEY, name)
            if value:
                break
        else:
            return None
        match = PAUSE_DATE.match(str(value).strip())
        if not match:
            return None
        moment = datetime.strptime(match.group(1), "%Y-%m-%dT%H:%M:%S")
        offset = match.group(2)
        if offset and offset != "Z":
            moment = datetime.fromisoformat(match.group(1) + offset)
        else:
            moment = moment.replace(tzinfo=timezone.utc)
        end = moment.timestamp()
        if end <= (time.time() if now is None else now):
            return None
        return iso_utc(end)
    except Exception:
        logger.warning("Windows Update pause unknown\n%s" % traceback.format_exc())
        return None


def dotnet_versions(registry=None):
    """.NET Framework versions installed, None when the registry is unavailable."""
    if registry is None:
        try:
            import winreg as registry
        except ImportError:
            return None
    versions = []
    if to_int(registry_value(registry, DOTNET_KEY + r"\v3.5", "Install")) == 1:
        versions.append("3.5")
    release = to_int(registry_value(registry, DOTNET_KEY + r"\v4\Full", "Release"))
    if release is not None:
        versions.append(dotnet4_version(release))
    return versions


def collect(script):
    """Run a fact collecting script; None when it fails."""
    try:
        return run_powershell(script)
    except Exception:
        logger.error("PowerShell script failed\n%s" % traceback.format_exc())
        return None


def collect_graphics():
    """DirectX and WDDM levels read from a dxdiag XML export; None on failure."""
    path = os.path.join(tempfile.gettempdir(), "medulla_dxdiag_%s.xml" % os.getpid())
    try:
        if os.path.exists(path):
            os.remove(path)
        subprocess.run(["dxdiag", "/x", path], timeout=DXDIAG_TIMEOUT)
        # dxdiag may return before the file is fully written
        deadline = time.time() + DXDIAG_TIMEOUT
        while time.time() < deadline:
            try:
                with open(path, "rb") as handle:
                    return graphics_from_dxdiag(handle.read())
            except (OSError, ElementTree.ParseError):
                time.sleep(2)
        logger.error("dxdiag gave no readable report")
    except Exception:
        logger.error("dxdiag failed\n%s" % traceback.format_exc())
    finally:
        if os.path.exists(path):
            os.remove(path)
    return None


def run_powershell(script, timeout=SCRIPT_TIMEOUT):
    """Run a PowerShell script and return its JSON output (None on error).

    TimeoutExpired is raised to the caller."""
    script = (
        "$OutputEncoding = [Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)\n"
        + script
    )
    encoded = base64.b64encode(script.encode("utf-16-le")).decode("ascii")
    result = subprocess.run(
        [
            "powershell",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-EncodedCommand",
            encoded,
        ],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout,
    )
    output = (result.stdout or "").strip()
    if not output:
        logger.error(
            "PowerShell script returned nothing: %s" % (result.stderr or "").strip()
        )
        return None
    try:
        return json.loads(output)
    except ValueError:
        logger.error("PowerShell script returned invalid JSON: %s" % output[:500])
        return None


def online_search(policy):
    started = time.time()
    search = {
        "status": "ok",
        "error": None,
        "server": None,
        "duration": None,
        "searched_at": iso_utc(started),
        "missing": [],
    }
    if policy.get("service") == "disabled":
        search["status"] = "blocked"
        search["error"] = BLOCKING_HRESULTS[0x80070422]
        search["duration"] = 0
        return search
    try:
        raw = run_powershell(SEARCH_SCRIPT, timeout=SEARCH_TIMEOUT)
    except subprocess.TimeoutExpired:
        raw = None
        search["status"] = "timeout"
        search["error"] = "No answer after %s s" % SEARCH_TIMEOUT
    else:
        search.update(search_result(raw))
    search["duration"] = int(round(time.time() - started))
    if search["status"] != "ok":
        search.pop("missing", None)
    return search


def fingerprint_path():
    return os.path.join(utils.Setdirectorytempinfo(), FINGERPRINT_FILE)


def state_changed():
    fingerprint = state_fingerprint()
    if fingerprint is None:
        return False
    try:
        with open(fingerprint_path()) as handle:
            return handle.read().strip() != fingerprint
    except OSError:
        return True


def state_fingerprint(registry=None):
    """MD5 of what makes a report change (build, UBR, installed packages,
    pending restart), None when the registry is unreadable. Registry only:
    cheap enough to run every 30 minutes."""
    try:
        if registry is None:
            import winreg as registry
        packages = registry_subkeys(registry, PACKAGES_KEY)
        if packages is None:
            return None
        return fingerprint_text(
            registry_value(registry, CURRENT_VERSION_KEY, "CurrentBuildNumber"),
            registry_value(registry, CURRENT_VERSION_KEY, "UBR"),
            reboot_pending(registry),
            packages,
        )
    except Exception:
        logger.warning("Updates fingerprint unknown\n%s" % traceback.format_exc())
        return None


def registry_subkeys(registry, path):
    """Names of the subkeys of HKLM path (64-bit view), None when unreadable."""
    try:
        access = registry.KEY_READ | registry.KEY_WOW64_64KEY
        key = registry.OpenKey(registry.HKEY_LOCAL_MACHINE, path, 0, access)
    except OSError:
        return None
    names = []
    try:
        index = 0
        while True:
            try:
                names.append(registry.EnumKey(key, index))
            except OSError:
                return names
            index += 1
    finally:
        registry.CloseKey(key)


def last_search_path():
    return os.path.join(utils.Setdirectorytempinfo(), LAST_SEARCH_FILE)


def read_last_search(path):
    try:
        with open(path) as handle:
            return parse_last_search(handle.read())
    except OSError:
        return None, None


def write_last_search(path, timestamp, version):
    with open(path, "w") as handle:
        handle.write("%s %s" % (timestamp, version or ""))


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


def fingerprint_text(build, ubr, pending, packages):
    text = "%s.%s|%s|%s" % (build, ubr, pending, "\n".join(sorted(packages)))
    return hashlib.md5(text.encode("utf-8")).hexdigest()


def parse_last_search(text):
    parts = text.split()
    try:
        timestamp = float(parts[0])
    except (IndexError, ValueError):
        return None, None
    return timestamp, parts[1] if len(parts) > 1 else None


def system_version(system):
    if not system.get("build"):
        return None
    return "%s.%s" % (system["build"], system.get("ubr") or 0)


def search_is_due(last_search, now, force):
    if force or last_search is None:
        return True
    elapsed = now - last_search
    return elapsed < 0 or elapsed >= SEARCH_MIN_INTERVAL


def iso_utc(timestamp):
    if timestamp is None:
        return None
    moment = datetime.fromtimestamp(timestamp, timezone.utc)
    return moment.strftime("%Y-%m-%dT%H:%M:%SZ")


def to_int(value):
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def dotnet4_version(release):
    for lowest, version in DOTNET4_RELEASES:
        if release >= lowest:
            return version
    return "4.x"


def normalize_system(raw):
    build = to_int(raw.get("build"))
    product = raw.get("product")
    # Windows 11 still reports "Windows 10" as ProductName
    if product and build and build >= 22000:
        product = product.replace("Windows 10", "Windows 11")
    architecture = (raw.get("architecture") or "").upper()
    architecture = {"AMD64": "x64", "ARM64": "arm64", "X86": "x86"}.get(
        architecture, architecture.lower() or None
    )
    installation_type = (raw.get("installation_type") or "").lower()
    system_type = None
    if installation_type.startswith("server"):
        system_type = "server"
    elif installation_type:
        system_type = "client"
    return {
        # Same name as the rest of the agent; COMPUTERNAME is upper case
        "hostname": platform.node().split(".")[0],
        "product": product,
        "edition": raw.get("edition"),
        "release": raw.get("release") or raw.get("release_id"),
        "build": build,
        "ubr": to_int(raw.get("ubr")),
        "architecture": architecture,
        "language": (raw.get("language") or "").lower() or None,
        "type": system_type,
    }


def automatic_updates_state(no_auto_update, au_options):
    if to_int(no_auto_update) == 1:
        return "disabled"
    return {
        2: "notify",
        3: "auto_download",
        4: "scheduled",
        7: "notify",
    }.get(to_int(au_options), "not_configured")


def service_state(start_mode, state):
    if (start_mode or "").lower() == "disabled":
        return "disabled"
    if (state or "").lower() == "running":
        return "running"
    return "stopped"


def normalize_policy(raw):
    if not raw:
        return {"wsus_server": None, "automatic_updates": None, "service": None}
    wsus_server = None
    # WUServer is only used when UseWUServer = 1
    if to_int(raw.get("use_wsus_server")) == 1:
        wsus_server = raw.get("wsus_server") or None
    return {
        "wsus_server": wsus_server,
        "automatic_updates": automatic_updates_state(
            raw.get("no_auto_update"), raw.get("au_options")
        ),
        "service": service_state(raw.get("start_mode"), raw.get("state")),
    }


def merge_installed(items):
    """Deduplicate by KB, keeping the most recent known date."""
    if isinstance(items, dict):
        items = [items]
    dates = {}
    for item in items:
        kb = to_int(item.get("kb"))
        if kb is None:
            continue
        date = item.get("date")
        if kb not in dates or (date and (dates[kb] is None or date > dates[kb])):
            dates[kb] = date
    return [{"kb": kb, "date": dates[kb]} for kb in sorted(dates)]


def search_result(raw):
    """Turn the search script output into the report fields."""
    if not raw:
        return {"status": "failed", "error": "No result from the search script"}
    result = {"server": raw.get("server")}
    hresult = to_int(raw.get("hresult"))
    if hresult is not None:
        hresult &= 0xFFFFFFFF
        message = "0x%08X %s" % (hresult, (raw.get("error") or "").strip())
        if hresult in BLOCKING_HRESULTS:
            result["status"] = "blocked"
            result["error"] = "%s (%s)" % (BLOCKING_HRESULTS[hresult], message)
        else:
            result["status"] = "failed"
            result["error"] = message
        return result
    # OperationResultCode: 2 succeeded, 3 succeeded with errors
    if to_int(raw.get("result_code")) not in (2, 3):
        result["status"] = "failed"
        result["error"] = "Search result code %s" % raw.get("result_code")
        return result
    missing = raw.get("missing") or []
    if isinstance(missing, dict):
        missing = [missing]
    result["status"] = "ok"
    result["error"] = None
    result["missing"] = [
        {"id": item.get("id"), "kb": to_int(item.get("kb")), "title": item.get("title")}
        for item in missing
        if item.get("id")
    ]
    return result


RED_REASON_BLOCKERS = {
    "tpm": "tpm",
    "uefisecureboot": "secure_boot",
    "cpufms": "cpu",
    "cpumodel": "cpu",
    "memory": "ram",
    "systemdrivesize": "disk",
    "storage": "disk",
}


def registry_text(value):
    """Registry value as text: multi-string values (REG_MULTI_SZ) come as lists."""
    if isinstance(value, list):
        return " ".join(str(item) for item in value if item)
    return value or ""


def red_reason_blockers(red_reason):
    blockers = []
    for token in registry_text(red_reason).replace(",", " ").replace("|", " ").split():
        if token.lower() == "none":
            continue
        blocker = RED_REASON_BLOCKERS.get(token.lower(), token.lower())
        if blocker not in blockers:
            blockers.append(blocker)
    return blockers


def latest_target(targets):
    """The most recent upgrade target known by Windows, or None."""
    if isinstance(targets, dict):
        targets = [targets]
    targets = [target for target in targets or [] if target.get("upg_ex")]
    if not targets:
        return None
    return max(
        targets, key=lambda t: (to_int(t.get("dest_build")) or 0, t.get("target") or "")
    )


def tpm_too_old(tpm):
    if tpm == "none":
        return True
    try:
        return float(tpm) < 2.0
    except (TypeError, ValueError):
        return False


def facts_blockers(facts):
    blockers = []
    if tpm_too_old(facts.get("tpm")):
        blockers.append("tpm")
    if facts.get("secure_boot") is False or facts.get("firmware") == "bios":
        blockers.append("secure_boot")
    if facts.get("ram_gb") is not None and facts["ram_gb"] < 4:
        blockers.append("ram")
    if facts.get("disk_size_gb") is not None and facts["disk_size_gb"] < 64:
        blockers.append("disk")
    for name in ("graphics", "display"):
        if facts.get(name) and facts[name]["ok"] is False:
            blockers.append(name)
    return blockers


def version_tuple(text):
    """Leading "major.minor" of a text as a tuple, None if absent."""
    match = re.search(r"(\d+)(?:\.(\d+))?", text or "")
    if not match:
        return None
    return int(match.group(1)), int(match.group(2) or 0)


def graphics_from_dxdiag(xml):
    """Best DirectX/WDDM pair of the display devices; raises ParseError."""
    root = ElementTree.fromstring(xml)
    best = None
    for device in root.iter("DisplayDevice"):
        directx = version_tuple(device.findtext("DDIVersion"))
        wddm = version_tuple(device.findtext("DriverModel"))
        if directx and wddm and (best is None or (directx, wddm) > best):
            best = (directx, wddm)
    if best is None:
        return None
    directx, wddm = best
    return {
        "directx": directx[0],
        "wddm": "%s.%s" % wddm,
        "ok": directx >= (12, 0) and wddm >= (2, 0),
    }


def display_report(monitors, videos):
    """Largest active monitor with the highest current resolution, or None."""
    if isinstance(monitors, dict):
        monitors = [monitors]
    if isinstance(videos, dict):
        videos = [videos]
    sizes = [
        (to_int(item.get("width_cm")), to_int(item.get("height_cm")))
        for item in monitors or []
    ]
    sizes = [size for size in sizes if size[0] and size[1]]
    modes = [
        (
            to_int(item.get("width")),
            to_int(item.get("height")),
            to_int(item.get("bits_per_pixel")),
        )
        for item in videos or []
    ]
    modes = [mode for mode in modes if mode[0] and mode[1] and mode[2]]
    if not sizes or not modes:
        return None
    diagonal = round(max(math.hypot(*size) for size in sizes) / 2.54, 1)
    width, height, bits_per_pixel = max(modes, key=lambda mode: mode[0] * mode[1])
    return {
        "width": width,
        "height": height,
        "diagonal_inches": diagonal,
        "bits_per_pixel": bits_per_pixel,
        # 24 bits per pixel or more = 8 bits per color channel
        "ok": max(width, height) >= 1280
        and min(width, height) >= 720
        and diagonal >= 9
        and bits_per_pixel >= 24,
    }


def windows11_report(raw, graphics=None):
    report = {
        "eligible": None,
        "blockers": [],
        "source": "facts",
        "tpm": raw.get("tpm"),
        "secure_boot": raw.get("secure_boot"),
        "firmware": raw.get("firmware"),
        "cpu": (raw.get("cpu") or "").strip() or None,
        "ram_gb": to_int(raw.get("ram_gb")),
        "disk_free_gb": to_int(raw.get("disk_free_gb")),
        "disk_size_gb": to_int(raw.get("disk_size_gb")),
        "graphics": graphics,
        "display": display_report(raw.get("monitors"), raw.get("videos")),
    }
    target = latest_target(raw.get("targets"))
    if target:
        report["source"] = "windows"
        verdict = registry_text(target.get("upg_ex")).lower()
        if verdict == "red":
            report["eligible"] = False
            report["blockers"] = red_reason_blockers(target.get("red_reason"))
        elif verdict in ("green", "yellow"):
            report["eligible"] = True
        return report
    # Without the Windows verdict the CPU cannot be judged: never eligible
    report["blockers"] = facts_blockers(report)
    if report["blockers"]:
        report["eligible"] = False
    return report
