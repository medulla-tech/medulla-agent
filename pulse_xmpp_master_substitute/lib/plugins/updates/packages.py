# -*- coding: utf-8; -*-
# SPDX-FileCopyrightText: 2026 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-3.0-or-later
# file : pulse_xmpp_master_substitute/lib/plugins/updates/packages.py

"""
Medulla deployment packages of the approved Windows updates.

One package per set of files: updates sharing the same files share
the package. Only the language-neutral files are packaged.

One DISM call per package. With .msu files, DISM is given the target
.msu (the one named after the KB) and applies first the checkpoint
cumulative updates lying in the same folder (Windows 11 24H2+); given the
folder, it would install each .msu on its own and the target would fail
(0x80070228). Packages of .cab files only are installed by folder.

One media package per Microsoft ESD and edition (machine_upgrades.media_file):
the installation media rebuilt with wimlib, install.esd holding only that
edition, then setup.exe compatibility scan and upgrade.
"""

import base64
from contextlib import contextmanager
from datetime import datetime
import hashlib
import json
import logging
import os
import re
import shutil
import subprocess
import threading
import traceback
from urllib.parse import urlsplit
import uuid

import requests

from lib.plugins.updates.upgrades import POSTPONED_COMMENT, RESTART_FIRST_CODE, enablement_update_sql

logger = logging.getLogger()

# Updates in one share, upgrades (Windows media, Linux release) in the other
SHARE = "winupdates"
MAJOR_SHARE = "winupdatesmajor"
PACKAGES_DIR = "/var/lib/pulse2/packages"
DOWNLOAD_TIMEOUT = (30, 300)
CHUNK_SIZE = 1024 * 1024
# Proxy towards Microsoft, from loadupdates.ini; None = direct
PROXIES = None
# wusa/DISM first run a full applicability scan: 1h49 seen for 4.7 GB
INSTALL_TIMEOUT = "14400"
SESSIONS_TIMEOUT = "120"
PRECHECK_TIMEOUT = "1200"
# Under the 600 s the agent waits for the question window
QUESTION_TIMEOUT = "300"
# setup.exe /compat scanonly: 3 to 10 minutes seen
SCAN_TIMEOUT = "3600"
WIMLIB = "wimlib-imagex"
WIMLIB_TIMEOUT = 7200

KINDS = ("msu", "cab")
EXE_COMMAND = '"@@@PACKAGE_DIRECTORY_ABS_MACHINE@@@\\%s"%s'
# The agent substitutes the folder without a trailing separator
INSTALL_COMMAND = (
    "dism.exe /Online /Add-Package"
    ' /PackagePath:"@@@PACKAGE_DIRECTORY_ABS_MACHINE@@@%s" /Quiet /NoRestart'
)
# Installed, restart needed: 3010 also as HRESULT 0x80070BC2, unsigned and
# signed
INSTALLED_CODES = (3010, 1641, 2147945410, -2147021886)
# Nothing to restart: installed without restart (0) or not applicable
# (0x800F081E, unsigned and signed)
SKIPPED_CODES = (0, 2148468766, -2146498530)
# Machine plugin sending a fresh report (forced search) once installed or
# failed. grafcetdeploy only reads the payload of the Linux update marker:
# the plugin detects the call by its "source", the JSON is informative.
REPORT_COMMAND = '@@@PLUGIN_CALL_updates_windows@@@ {"after_deployment": true}'
LINUX_REPORT_COMMAND = '@@@PLUGIN_CALL_updates_linux@@@ {"after_deployment": true}'

# Linux: one package per package manager family; the packages to upgrade come
# with the deployment ({"packages": [...]} in the command parameters). The agent
# cannot ask under Linux yet: an open session keeps the restart pending.
LINUX_FAMILIES = ("apt", "dnf", "zypper")
LINUX_RESTART_NEEDED = {
    "apt": "[ -e /var/run/reboot-required ]",
    "dnf": "dnf -q needs-restarting -r >/dev/null 2>&1; [ $? -eq 1 ]",
    "zypper": "zypper needs-rebooting >/dev/null 2>&1; [ $? -eq 102 ]",
}
LINUX_SESSIONS_SCRIPT = r"""if ! { %(restart_needed)s; }; then
    echo "No restart needed"
    exit 12
fi
if [ "$(systemctl get-default 2>/dev/null)" != "graphical.target" ]; then
    echo "No desktop: no restart"
    exit 12
fi
if ! SESSIONS=$(loginctl list-sessions --no-legend 2>/dev/null); then
    echo "Sessions unknown: no restart"
    exit 12
fi
for ID in $(echo "$SESSIONS" | awk '{print $1}'); do
    if ! CLASS=$(loginctl show-session "$ID" -p Class --value 2>/dev/null); then
        echo "Session $ID unknown: no restart"
        exit 12
    fi
    if [ "$CLASS" = "user" ] && [ "$(loginctl show-session "$ID" -p Service --value 2>/dev/null)" != "sshd" ]; then
        echo "Open session: restart pending"
        exit 11
    fi
done
echo "No session: restart"
exit 10
"""
LINUX_PACKAGES_SCRIPT = r"""PACKAGES=$(echo '@@@DYNAMIC_PARAM_DEPLOY_B64@@@' | base64 -d | python3 -c '
import json, re, sys
names = json.load(sys.stdin).get("packages") or []
print(" ".join(n for n in names if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9.+_:-]*", str(n))))
')
if [ -z "$PACKAGES" ]; then
    echo "No package to upgrade"
    exit 0
fi
echo "Packages: $PACKAGES"
"""
LINUX_INSTALL_COMMANDS = {
    # Waits for the lock held by unattended-upgrades instead of failing
    "apt": "DEBIAN_FRONTEND=noninteractive apt-get install --only-upgrade -y -q"
           " -o DPkg::Lock::Timeout=1200"
           " -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold $PACKAGES",
    "dnf": "dnf upgrade -y $PACKAGES",
    "zypper": "zypper --non-interactive update $PACKAGES",
}

# Debian release upgrade, one package for every release: the target comes with
# the deployment ({"release": "<codename>"}). Procedure of the Debian release
# notes (chapter 4): sources to the next release, minimal upgrade, kernel
# metapackage, full upgrade. No restart: the machine reports a pending restart.
DEBIAN_UPGRADE = "debian-upgrade"
UBUNTU_UPGRADE = "ubuntu-upgrade"
ALMALINUX_UPGRADE = "almalinux-upgrade"
# Package of the release upgrade of a distribution (ID of os-release)
LINUX_UPGRADES = {"debian": DEBIAN_UPGRADE, "ubuntu": UBUNTU_UPGRADE, "almalinux": ALMALINUX_UPGRADE}
LINUX_UPGRADE_NAMES = {DEBIAN_UPGRADE: "Debian upgrade", UBUNTU_UPGRADE: "Ubuntu upgrade",
                       ALMALINUX_UPGRADE: "AlmaLinux upgrade"}
# Packages that stop on upgrades.RESTART_FIRST_CODE
RESTART_FIRST_UPGRADES = (UBUNTU_UPGRADE, ALMALINUX_UPGRADE)
RELEASE_TIMEOUT = "14400"
# The agent doubles every backslash of the file it runs: inside double quotes only.
# Exit 113 (no space) and 114 (anything else): stopped, the machine as it was, its
# sources original, nothing from the target installed (upgrades.PRECHECK_CODES).
# Exit 115: a restart is needed first, nothing of the upgrade begun (upgrades.RESTART_FIRST_CODE).
# Exit 112 (no space) and 1: the upgrade began, it has to be resumed.
UPGRADE_PARAMETER = r"""# Without python3: a resume may start with it half configured
RELEASE=$(echo '@@@DYNAMIC_PARAM_DEPLOY_B64@@@' | base64 -d | grep -oE '"release": *"[a-z]+"' | cut -d'"' -f4)
. /etc/os-release
"""
UPGRADE_APT = r"""export DEBIAN_FRONTEND=noninteractive
export APT_LISTCHANGES_FRONTEND=none
export NEEDRESTART_SUSPEND=1
export UCF_FORCE_CONFFOLD=1
APT_OPTIONS="-y -q -o DPkg::Lock::Timeout=1200 -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold"
"""
# %s: the distribution
UPGRADE_INHIBIT = r"""# Asleep, the machine needs someone to wake it up, and the agent restarts on waking
INHIBIT=""
if systemd-inhibit --list >/dev/null 2>&1; then
    INHIBIT="systemd-inhibit --what=sleep:shutdown --who=Medulla --why=%s-upgrade"
fi
"""
UPGRADE_AGENT = r"""AGENT_SERVICE=pulse-xmpp-agent-machine.service
AGENT_PYTHON=$(systemctl cat $AGENT_SERVICE 2>/dev/null | awk -F'[= ]' '$1 == "ExecStart" && $2 != "" {print $2; exit}')
AGENT_PACKAGES=""
case "$AGENT_PYTHON" in
    */python3*) AGENT_PACKAGES="|(lib)?$(basename "$(readlink -f "$AGENT_PYTHON")")(-minimal|-stdlib)?" ;;
    *) AGENT_PYTHON="" ;;
esac
"""
UPGRADE_DISK = r"""free_of() {
    df -Pm "$1" 2>/dev/null | awk 'NR == 2 {print $4}'
}
mount_of() {
    df -Pm "$1" 2>/dev/null | awk 'NR == 2 {print $6}'
}
enough() {
    FREE=$(free_of "$1")
    echo "Space on $1: $2 MB needed, ${FREE:-?} MB free"
    [ -z "$FREE" ] || [ "$FREE" -ge "$2" ]
}
# Debian 13 release notes, 5.1.5: 768 MB at least, about 300 MB free
boot_fits() {
    [ -d /boot ] || return 0
    enough /boot 300 || return 1
    [ "$(mount_of /boot)" = /boot ] || return 0
    SECTORS=$(cat "/sys/dev/block/$(mountpoint -d /boot 2>/dev/null)/size" 2>/dev/null)
    if [ -n "$SECTORS" ] && [ $((SECTORS * 512 / 1000000)) -lt 768 ]; then
        echo "/boot is smaller than 768 MB"
        return 1
    fi
}
"""
UPGRADE_END = r"""# An installation that failed on a file system left almost full
install_failed() {
    if df -Pm / /var /boot 2>/dev/null | awk 'NR > 1 && $4 < 100 {low = 1} END {exit !low}'; then
        echo "Not enough space: the upgrade stopped, free some space, then launch it again"
        exit 112
    fi
    exit 1
}
not_ready() {
    echo "No restart: $1"
    exit 1
}
"""
# Same floor as the report (plugin updates_linux); the upgrade tool has the last word
UPGRADE_SPACE = r"""if ! { boot_fits && enough / 1000 && enough /var 1000; }; then
    echo "Not enough space for the upgrade: free some space, then launch it again"
    exit 113
fi
"""

# The upgrade runs in its own transient unit, out of the agent's control group and with its
# output in a file: a restart of the agent or a cut of the network neither stops it nor closes
# its output. The step only waits. A run while the unit is active waits for it instead of
# starting a second one; once finished, its result stays until the next run. The agent ends the
# step at RELEASE_TIMEOUT: the unit stops just before (exit 1), so that the step reports it.
UPGRADE_UNIT_START = r"""exec </dev/null
UNIT=medulla-release-upgrade.service
UNIT_SCRIPT=/var/lib/medulla/release-upgrade.sh
UNIT_RESULT=/var/lib/medulla/release-upgrade.result
UNIT_LOG=/var/log/pulse/release-upgrade.log
unit_running() {
    case "$(systemctl is-active "$UNIT" 2>/dev/null)" in
        active|activating|deactivating|reloading) return 0 ;;
    esac
    return 1
}
# This run only: the file keeps the previous ones
unit_output() {
    FROM=$(grep -an '^Medulla release upgrade: ' "$UNIT_LOG" 2>/dev/null | tail -n 1 | cut -d: -f1)
    tail -n +"${FROM:-1}" "$UNIT_LOG" 2>/dev/null | tail -n 30
}
write_unit_script() {
    mkdir -p "$(dirname "$UNIT_SCRIPT")" "$(dirname "$UNIT_LOG")" || return 1
    cat > "$UNIT_SCRIPT.new" <<'MEDULLA_UNIT_SCRIPT' || return 1
exec >> /var/log/pulse/release-upgrade.log 2>&1
echo "Medulla release upgrade: $(date)"
(
"""
UPGRADE_UNIT_END = r""")
CODE=$?
echo "Medulla release upgrade over, exit $CODE: $(date)"
echo "$CODE" > /var/lib/medulla/release-upgrade.result.new
mv -f /var/lib/medulla/release-upgrade.result.new /var/lib/medulla/release-upgrade.result
"""
UPGRADE_UNIT_WAIT = r"""exit "$CODE"
MEDULLA_UNIT_SCRIPT
    mv -f "$UNIT_SCRIPT.new" "$UNIT_SCRIPT"
}

if unit_running; then
    echo "Release upgrade already running: waiting for its end"
else
    rm -f "$UNIT_RESULT"
    if ! write_unit_script; then
        echo "$UNIT_SCRIPT not written: the release upgrade is not launched"
        exit 1
    fi
    systemctl reset-failed "$UNIT" 2>/dev/null
    if ! systemd-run --unit="$UNIT" --description="Medulla release upgrade" --property=RuntimeMaxSec=@@RUNTIME@@ /bin/bash "$UNIT_SCRIPT" && ! unit_running; then
        echo "systemd-run failed: the release upgrade is not launched"
        exit 1
    fi
fi
# Only a state systemd gave ends the wait: it restarts during the upgrade
while [ ! -e "$UNIT_RESULT" ]; do
    case "$(systemctl is-active "$UNIT" 2>/dev/null)" in
        inactive|failed)
            [ ! -e "$UNIT_RESULT" ] || break
            unit_output
            echo "The release upgrade stopped without a result, see $UNIT_LOG"
            exit 1
            ;;
    esac
    sleep 10
done
unit_output
CODE=$(cat "$UNIT_RESULT")
case "$CODE" in
    ''|*[!0-9]*) exit 1 ;;
esac
exit "$CODE"
""".replace("@@RUNTIME@@", str(int(RELEASE_TIMEOUT) - 300))


def upgrade_in_unit(script, after=""):
    return UPGRADE_UNIT_START + script + UPGRADE_UNIT_END + after + UPGRADE_UNIT_WAIT


# The agent still holds the previous glibc: a new service loads it and sends the report,
# once the step, which polls the result every 10 s, has ended the deployment. The restart of
# the machine stays with the admin (reboot_pending).
UPGRADE_AGENT_RESTART = r"""if [ "$CODE" = 0 ]; then
    systemd-run --on-active=300 systemctl restart pulse-xmpp-agent-machine.service || echo "The Medulla agent restart was not planned"
fi
"""

DEBIAN_UPGRADE_SCRIPT = upgrade_in_unit(r"""exec </dev/null
""" + UPGRADE_PARAMETER + r"""CURRENT="$VERSION_CODENAME"
if [ -z "$RELEASE" ] || [ -z "$CURRENT" ]; then
    echo "No target release"
    [ ! -d "/var/backups/medulla-apt-$CURRENT" ] || exit 1
    exit 114
fi
""" + UPGRADE_APT + UPGRADE_INHIBIT % "Debian" + UPGRADE_AGENT + r"""# Not a Debian value: what apt and dpkg need on top of the simulated sizes
SPACE_MARGIN=500

SOURCES=$(ls /etc/apt/sources.list /etc/apt/sources.list.d/*.list /etc/apt/sources.list.d/*.sources 2>/dev/null)
if [ -z "$SOURCES" ]; then
    echo "No apt sources"
    [ ! -d "/var/backups/medulla-apt-$CURRENT" ] || exit 1
    exit 114
fi
BACKUP="/var/backups/medulla-apt-$CURRENT"
STARTED="$BACKUP/target-install-started"
mentions() {
    grep -qE "^[^#]*\b$1\b" $SOURCES
}

# Exists only complete: written beside then renamed, before the sources change.
# After the first install from the target, the upgrade only goes forward
restore_sources() {
    [ -d "$BACKUP" ] && [ ! -e "$STARTED" ] || return 0
    if ! grep -qE "^[^#]*\b$CURRENT\b" $(ls "$BACKUP"/sources.list "$BACKUP"/sources.list.d/*.list "$BACKUP"/sources.list.d/*.sources 2>/dev/null) </dev/null; then
        echo "Backup $BACKUP not valid: sources left as they are"
        return 1
    fi
    if [ -d "$BACKUP/sources.list.d" ]; then
        rm -rf /etc/apt/sources.list.d.medulla
        if ! cp -a "$BACKUP/sources.list.d" /etc/apt/sources.list.d.medulla; then
            echo "Sources not restored: copy from $BACKUP failed"
            return 1
        fi
        rm -rf /etc/apt/sources.list.d
        mv /etc/apt/sources.list.d.medulla /etc/apt/sources.list.d
    fi
    [ ! -e "$BACKUP/sources.list" ] || cp -a "$BACKUP/sources.list" /etc/apt/
    if [ -e "$BACKUP/sources.list" ] && ! diff "$BACKUP/sources.list" /etc/apt/sources.list >/dev/null; then
        echo "Sources not restored: see $BACKUP"
        return 1
    fi
    if [ -d "$BACKUP/sources.list.d" ] && ! diff -r "$BACKUP/sources.list.d" /etc/apt/sources.list.d >/dev/null; then
        echo "Sources not restored: see $BACKUP"
        return 1
    fi
    # The sources are the original ones again: the next attempt saves them as they are then
    rm -rf "/var/backups/medulla-apt-$CURRENT"
    BEGUN=""
    apt-get update -q >/dev/null 2>&1
    echo "Sources restored"
}

""" + UPGRADE_DISK + r"""no_space() {
    echo "Not enough space for the upgrade: free some space, then launch it again"
    restore_sources
    [ -z "$BEGUN" ] || exit 112
    exit 113
}
stopped() {
    [ -z "$BEGUN" ] || exit 1
    exit 114
}
""" + UPGRADE_END + r"""
# A stopped upgrade: the release already announced, or the sources already switched
RESUME=""
if [ "$CURRENT" = "$RELEASE" ]; then
    RESUME=1
elif mentions "$RELEASE" && { [ -d "$BACKUP" ] || ! mentions "$CURRENT"; }; then
    RESUME=1
fi
BEGUN="$RESUME"
[ ! -e "$STARTED" ] || BEGUN=1
if [ -n "$RESUME" ]; then
    echo "Resuming the upgrade to $RELEASE"
    $INHIBIT dpkg --force-confdef --force-confold --configure -a
    if [ -n "$(dpkg --audit)" ]; then
        $INHIBIT apt-get -f install $APT_OPTIONS
    fi
fi
if [ -n "$(dpkg --audit)" ]; then
    echo "dpkg --audit reports packages to fix:"
    dpkg --audit
    stopped
fi

if [ -z "$RESUME" ]; then
    HELD=$(apt-mark showhold)
    if [ -n "$HELD" ]; then
        echo "Held packages: $HELD"
        stopped
    fi
    if mentions "$CURRENT-backports"; then
        echo "$CURRENT-backports is enabled: remove it before the upgrade"
        stopped
    fi
    boot_fits || no_space
    echo "Pending updates of $CURRENT"
    apt-get update -q -o DPkg::Lock::Timeout=1200 || stopped
    $INHIBIT apt-get upgrade $APT_OPTIONS || install_failed
fi

if [ "$CURRENT" != "$RELEASE" ] && mentions "$CURRENT"; then
    if [ ! -d "$BACKUP" ]; then
        rm -rf "/var/backups/medulla-apt-$CURRENT.new"
        if ! { mkdir -p "$BACKUP.new" && cp -a $(ls -d /etc/apt/sources.list /etc/apt/sources.list.d 2>/dev/null) "$BACKUP.new"/ && mv "$BACKUP.new" "$BACKUP"; }; then
            echo "Backup of the sources failed: nothing changed"
            rm -rf "/var/backups/medulla-apt-$CURRENT.new"
            stopped
        fi
    fi
    echo "Sources: $CURRENT -> $RELEASE"
    BEGUN=1
    if ! sed -i -E "s/\b$CURRENT(-updates|-security)?\b/$RELEASE\1/g" $SOURCES; then
        echo "Sources not switched"
        restore_sources
        stopped
    fi
fi

if ! apt-get update -q -o DPkg::Lock::Timeout=1200; then
    echo "apt-get update failed for $RELEASE"
    restore_sources
    stopped
fi

# Nothing comes from the target before these checks
SIMULATION=$(LC_ALL=C apt-get -s -q full-upgrade 2>&1)
if [ $? -ne 0 ]; then
    echo "$SIMULATION" | tail -n 10
    echo "The full upgrade cannot be simulated: nothing installed"
    restore_sources
    stopped
fi
# apt-get update ends well even when a repository did not answer
if [ "$CURRENT" != "$RELEASE" ] && ! echo "$SIMULATION" | grep -q '^Inst base-files '; then
    echo "Debian $RELEASE not available from the repositories: nothing installed"
    restore_sources
    stopped
fi
REMOVED=$(echo "$SIMULATION" | grep -E "^Remv (openssh-server|network-manager|ifupdown$AGENT_PACKAGES)[ :]" | awk '{print $2}')
if [ -n "$REMOVED" ]; then
    echo "The upgrade would remove what keeps the machine reachable: "$REMOVED
    restore_sources
    stopped
fi
if [ ! -e "$STARTED" ] && [ "$CURRENT" != "$RELEASE" ]; then
    boot_fits || no_space
fi

# Space: apt prints what it would download and add, without doing it
SIZES=$(LC_ALL=C apt-get -o DPkg::Lock::Timeout=1200 -o APT::Get::Trivial-Only=true full-upgrade 2>&1)
if echo "$SIZES" | grep '^E:' | grep -qv 'Trivial Only'; then
    echo "$SIZES" | tail -n 10
    echo "The space needed is unknown: nothing installed"
    restore_sources
    stopped
fi
SPACE=$(echo "$SIZES" | LC_ALL=C awk '
function mb(value, unit) {
    gsub(",", "", value)
    sub("/.*", "", unit)
    value *= unit == "GB" ? 1000 : unit == "MB" ? 1 : unit == "kB" ? 0.001 : 0.000001
    return int(value) + (value > int(value))
}
/^Need to get / {download = mb($4, $5)}
/^After this operation, .* of additional/ {added = mb($4, $5)}
END {print download + 0, added + 0}
')
DOWNLOAD=${SPACE% *}
ADDED=${SPACE#* }
echo "Simulation: $DOWNLOAD MB to download, $ADDED MB more once installed"
if [ "$DOWNLOAD" -gt 0 ] || [ "$ADDED" -gt 0 ]; then
    if [ "$(mount_of /var/cache/apt/archives)" = "$(mount_of /usr)" ]; then
        enough /usr $((DOWNLOAD + ADDED + SPACE_MARGIN)) || no_space
    else
        enough /var/cache/apt/archives $((DOWNLOAD + SPACE_MARGIN)) || no_space
        enough /usr $((ADDED + SPACE_MARGIN)) || no_space
    fi
    enough / $SPACE_MARGIN || no_space
    enough /var $SPACE_MARGIN || no_space
fi

if [ -d "$BACKUP" ] && [ "$CURRENT" != "$RELEASE" ]; then
    if ! : > "$STARTED"; then
        restore_sources
        stopped
    fi
fi
echo "Minimal upgrade"
$INHIBIT apt-get upgrade --without-new-pkgs $APT_OPTIONS || install_failed

# A kernel metapackage avoids a system without a bootable kernel
KERNELS=$(dpkg -l 'linux-image-*' 2>/dev/null | grep '^ii')
if [ -n "$KERNELS" ] && ! echo "$KERNELS" | grep -qi meta; then
    echo "Kernel metapackage"
    $INHIBIT apt-get install $APT_OPTIONS "linux-image-$(dpkg --print-architecture)" || install_failed
fi

echo "Full upgrade"
$INHIBIT apt-get full-upgrade $APT_OPTIONS || $INHIBIT apt-get full-upgrade $APT_OPTIONS -o APT::Immediate-Configure=0 || install_failed

# Any exit but 0 goes to REPORT_ERROR: the restart step is never reached
if [ -n "$(dpkg --audit)" ]; then
    dpkg --audit
    not_ready "dpkg --audit reports packages to fix"
fi
. /etc/os-release
if [ "$VERSION_CODENAME" != "$RELEASE" ]; then
    not_ready "still on $VERSION_CODENAME"
fi
# No kernel package: a container
if dpkg -l 'linux-image-*' 2>/dev/null | grep -q '^ii'; then
    NEWEST=$(ls /boot/vmlinuz-* 2>/dev/null | sort -V | tail -n 1)
    KERNEL=${NEWEST#/boot/vmlinuz-}
    if [ ! -s "$NEWEST" ] || [ ! -s "/boot/initrd.img-$KERNEL" ]; then
        not_ready "no kernel with its initrd in /boot"
    fi
    if dpkg -l grub2-common 2>/dev/null | grep -q '^ii' && ! grep -qF "vmlinuz-$KERNEL" /boot/grub/grub.cfg; then
        not_ready "GRUB does not know the kernel $KERNEL"
    fi
fi
if dpkg -l openssh-server 2>/dev/null | grep -q '^ii'; then
    sshd -t || not_ready "sshd refuses its configuration"
    systemctl is-active --quiet ssh ssh.socket || not_ready "SSH is not running"
fi
if [ -n "$AGENT_PYTHON" ]; then
    "$AGENT_PYTHON" -c "import ssl, ctypes, sqlite3, slixmpp" || not_ready "the Medulla agent would not start again"
    systemctl is-enabled --quiet $AGENT_SERVICE || not_ready "the Medulla agent is not enabled at startup"
fi
echo "Now on $PRETTY_NAME, restart pending"
exit 0
""", UPGRADE_AGENT_RESTART)

# do-release-upgrade with its non-interactive frontend: answers yes, never restarts.
# The target comes from the machine (Prompt of release-upgrades); {"release": "<codename>"}
# only tells a machine already there, whose last packages are left to install.
# RemoveObsoletes=no: the agent runs on a python3 from a PPA the upgrade would remove.
# Exit codes of the Debian package; its pending updates do not begin the upgrade.
UBUNTU_UPGRADE_SCRIPT = upgrade_in_unit(r"""exec </dev/null
""" + UPGRADE_PARAMETER + r"""CURRENT="$VERSION_ID"
""" + UPGRADE_APT + r"""export RELEASE_UPGRADER_NO_SCREEN=1
""" + UPGRADE_INHIBIT % "Ubuntu" + UPGRADE_AGENT + UPGRADE_DISK + UPGRADE_END + r"""stopped() {
    [ -z "$RESUME" ] || exit 1
    exit 114
}
CONFIG=/etc/update-manager/release-upgrades.d/medulla.cfg
trap 'rm -f "$CONFIG"' EXIT

RESUME=""
if [ -n "$RELEASE" ] && [ "$VERSION_CODENAME" = "$RELEASE" ]; then
    RESUME=1
    echo "Resuming the upgrade to $RELEASE"
    $INHIBIT dpkg --force-confdef --force-confold --configure -a
    if [ -n "$(dpkg --audit)" ]; then
        $INHIBIT apt-get -f install $APT_OPTIONS
    fi
fi
if [ -n "$(dpkg --audit)" ]; then
    echo "dpkg --audit reports packages to fix:"
    dpkg --audit
    stopped
fi
if [ -z "$RESUME" ]; then
    HELD=$(apt-mark showhold)
    if [ -n "$HELD" ]; then
        echo "Held packages: $HELD"
        stopped
    fi
""" + UPGRADE_SPACE + r"""fi

echo "Pending updates"
apt-get update -q -o DPkg::Lock::Timeout=1200 || stopped
$INHIBIT apt-get dist-upgrade $APT_OPTIONS || install_failed

if [ -z "$RESUME" ]; then
    # What do-release-upgrade itself refuses before a restart
    if grep -qE '^(libc6|linux-base|linux-image-.*)$' /var/run/reboot-required.pkgs 2>/dev/null; then
        echo "A restart is needed first: the upgrade goes on after it"
        exit 115
    fi
    if ! { mkdir -p "$(dirname "$CONFIG")" && { echo "[Distro]"; echo "RemoveObsoletes=no"; } > "$CONFIG"; }; then
        echo "$CONFIG not written"
        exit 114
    fi
    echo "Release upgrade"
    $INHIBIT do-release-upgrade -f DistUpgradeViewNonInteractive || install_failed
fi

. /etc/os-release
if [ -n "$AGENT_PYTHON" ]; then
    "$AGENT_PYTHON" -c 'import ssl' || not_ready "the Medulla agent would not start again"
fi
if [ -z "$RESUME" ] && [ "$VERSION_ID" = "$CURRENT" ]; then
    not_ready "still on $VERSION_ID"
fi
echo "Now on $PRETTY_NAME, restart pending"
exit 0
""", UPGRADE_AGENT_RESTART)

# leapp removes python3.11 and the agent runs on it: the agent moves to its own copy before
# the upgrade. The el9 interpreter runs on el10 (tried on 10.2). In the linker configuration
# for the agent, the kiosk and whatever starts them; leapp reports it (HIGH), without refusing.
# Its folder holds that library alone, nothing else of the system can resolve to it.
# Exit 114: the machine as it was, nothing left of the copy.
ALMALINUX_AGENT_PYTHON = r"""MEDULLA=/opt/medulla
AGENT_LINK=$MEDULLA/bin/python3.11
VENV_CONFIG=$MEDULLA/pyvenv.cfg
OWN_PYTHON=$MEDULLA/python3.11
OWN_BACKUP=$MEDULLA/python-before-upgrade
LINKER_CONFIG=/etc/ld.so.conf.d/medulla-python.conf
agent_python_ok() {
    # From the copy, not from the system's python still there before the upgrade
    [ "$("$AGENT_LINK" -c 'import sys; print(sys.base_prefix)')" = "$OWN_PYTHON" ] || return 1
    ldconfig -p | grep -qF "$OWN_PYTHON/lib64/libpython3.11.so.1.0" || return 1
    "$AGENT_LINK" -c 'import ssl,ctypes,sqlite3;import slixmpp,pulse_xmpp_agent'
}
copy_agent_python() {
    rm -rf "$OWN_PYTHON.new"
    mkdir -p "$OWN_PYTHON.new/bin" "$OWN_PYTHON.new/lib64" || return 1
    cp -aL /usr/bin/python3.11 "$OWN_PYTHON.new/bin/" || return 1
    cp -aL /usr/lib64/libpython3.11.so.1.0 "$OWN_PYTHON.new/lib64/" || return 1
    cp -a /usr/lib64/python3.11 "$OWN_PYTHON.new/lib64/" || return 1
    rm -rf "$OWN_PYTHON.new/lib64/python3.11/site-packages" "$OWN_PYTHON.new/lib64/python3.11/test" "$OWN_PYTHON.new/lib64/python3.11"/config-3.11*
    find "$OWN_PYTHON.new/lib64/python3.11" -name '*.opt-?.pyc' -delete
    rm -rf "$OWN_PYTHON"
    mv "$OWN_PYTHON.new" "$OWN_PYTHON"
}
# Exists only complete and never rewritten: it stays the state before the first attempt
switch_agent_python() {
    if [ ! -d "$OWN_BACKUP" ]; then
        rm -rf "$OWN_BACKUP.new"
        mkdir -p "$OWN_BACKUP.new" || return 1
        cp -a "$VENV_CONFIG" "$AGENT_LINK" "$OWN_BACKUP.new"/ || return 1
        mv "$OWN_BACKUP.new" "$OWN_BACKUP" || return 1
    fi
    echo "$OWN_PYTHON/lib64" > "$LINKER_CONFIG" || return 1
    ldconfig || return 1
    sed -e "s|^home *=.*|home = $OWN_PYTHON/bin|" -e "s|^executable *=.*|executable = $OWN_PYTHON/bin/python3.11|" "$OWN_BACKUP/pyvenv.cfg" > "$VENV_CONFIG.new" || return 1
    mv -f "$VENV_CONFIG.new" "$VENV_CONFIG" || return 1
    rm -f "$AGENT_LINK.new"
    ln -s "$OWN_PYTHON/bin/python3.11" "$AGENT_LINK.new" || return 1
    mv -f "$AGENT_LINK.new" "$AGENT_LINK"
}
restore_agent_python() {
    if [ -d "$OWN_BACKUP" ]; then
        if ! { cp -a "$OWN_BACKUP/python3.11" "$AGENT_LINK.new" && mv -f "$AGENT_LINK.new" "$AGENT_LINK" &&
               cp -a "$OWN_BACKUP/pyvenv.cfg" "$VENV_CONFIG.new" && mv -f "$VENV_CONFIG.new" "$VENV_CONFIG"; }; then
            echo "Agent python not restored: see $OWN_BACKUP"
            return 1
        fi
    fi
    if [ -e "$LINKER_CONFIG" ]; then
        rm -f "$LINKER_CONFIG"
        ldconfig
    fi
    rm -rf "$OWN_PYTHON" "$OWN_PYTHON.new" "$OWN_BACKUP"
}
keep_agent_python() {
    if [ "$(readlink "$AGENT_LINK")" = "$OWN_PYTHON/bin/python3.11" ] && agent_python_ok; then
        echo "Agent python already in $OWN_PYTHON"
        return 0
    fi
    if [ ! -e "$AGENT_LINK" ] || [ ! -f "$VENV_CONFIG" ] || [ ! -x /usr/bin/python3.11 ]; then
        echo "Agent python not found: the upgrade would remove it, nothing changed"
        python_state
        exit 114
    fi
    if ! { copy_agent_python && switch_agent_python && agent_python_ok; }; then
        echo "The agent would not run on its own python: the upgrade is not launched"
        restore_agent_python || exit 1
        python_state
        exit 114
    fi
    echo "Agent python moved to $OWN_PYTHON"
}
"""

# What leapp removes and the agent cannot reinstall: plugin_updateglpiagent stops on Linux
# before its download, and nothing installs Perl. Only on the target system, once, without
# order against the agent; its result is in the log. The server is the one of the agent's
# downloads (update_server in lib/configuration.py), read now: crudini may be gone after.
# leapp leaves SELinux permissive and leaves it to the admin (Red Hat, Upgrading from RHEL 9 to
# RHEL 10, Applying security policies): back to enforcing only if it was, and if nothing says
# otherwise. ausearch answers 1 on no match: only its "<no matches>" means none, and without
# auditd running the log proves nothing. The agent runs in the same transaction: it is not ordered
# against this unit, which a blocking restart relies on. Not oneshot: leapp_resume starts after
# default.target, which a oneshot still running would hold back.
ALMALINUX_AFTER_UPGRADE = r"""AFTER_UNIT=/etc/systemd/system/medulla-after-upgrade.service
AFTER_SCRIPT=/var/lib/medulla/after-upgrade.sh
SELINUX_BEFORE=/var/lib/medulla/selinux-before-upgrade
SELINUX_LEFT=/var/lib/medulla/selinux-left-permissive
AGENT_SITE=$MEDULLA/lib/python3.11/site-packages/pulse_xmpp_agent
glpi_url() {
    rpm -q glpi-agent >/dev/null 2>&1 || return 0
    GLPI_SERVER=$("$AGENT_LINK" -c '
import configparser
config = configparser.ConfigParser(interpolation=None)
config.read(["/etc/pulse-xmpp-agent/agentconf.ini", "/etc/pulse-xmpp-agent/agentconf.ini.local"])
server = config.get("connection", "server", fallback="")
print(config.get("updateagent", "updateserver", fallback="") or (server and "http://" + server))
')
    GLPI_VERSION=$(awk -F'"' '/^GLPIAGENTVERSION/ {print $2; exit}' "$AGENT_SITE/pluginsmachine/plugin_updateglpiagent.py" 2>/dev/null)
    [ -n "$GLPI_VERSION" ] || GLPI_VERSION=$(rpm -q --qf '%{VERSION}' glpi-agent)
    if [ -z "$GLPI_SERVER" ] || [ -z "$GLPI_VERSION" ]; then
        echo "GLPI agent: no download server known, not reinstalled after the upgrade" >&2
        return 0
    fi
    case "$GLPI_SERVER$GLPI_VERSION" in
        *[!A-Za-z0-9:/._-]*)
            echo "GLPI agent: download server not valid, not reinstalled after the upgrade" >&2
            return 0
            ;;
    esac
    echo "$GLPI_SERVER/downloads/lin/downloads/glpi-agent-$GLPI_VERSION-linux-installer.pl"
}
prepare_after_upgrade() {
    GLPI_URL=$(glpi_url)
    mkdir -p "$(dirname "$AFTER_SCRIPT")" || return 1
    # Not rewritten: stays the state before the first attempt
    [ -e "$SELINUX_BEFORE" ] || getenforce > "$SELINUX_BEFORE" 2>/dev/null
    rm -f "$SELINUX_LEFT"
    {
        echo "#!/bin/sh"
        echo "SOURCE_RELEASE='${VERSION_ID%%.*}'"
        echo "GLPI_URL='$GLPI_URL'"
        cat <<'AFTER_UPGRADE'
AGENT=pulse-xmpp-agent-machine.service
AGENT_RESTARTED=""
SELINUX_CONFIG=/etc/selinux/config
selinux_stays() {
    echo "SELinux stays permissive, it was enforcing before the upgrade: $2"
    echo "$1" > /var/lib/medulla/selinux-left-permissive
}
selinux_config() {
    sed -i.medulla "s/^SELINUX=.*/SELINUX=$1/" "$SELINUX_CONFIG" && rm -f "$SELINUX_CONFIG.medulla" &&
        grep -q "^SELINUX=$1" "$SELINUX_CONFIG"
}
leapp_running() {
    [ ! -e /.autorelabel ] || return 0
    systemctl cat leapp_resume.service >/dev/null 2>&1
}
selinux_denials() {
    command -v ausearch >/dev/null 2>&1 || return 1
    systemctl is-active --quiet auditd.service || return 1
    DENIALS=$(ausearch --input-logs -m AVC,USER_AVC -ts boot 2>&1) && return 0
    [ "$DENIALS" = "<no matches>" ] || return 1
    DENIALS=""
}
# Restart=always: between two crashes the service reads active, its process does not stay
agent_holds() {
    AGENT_PID=$(systemctl show -p MainPID --value "$AGENT")
    [ -n "$AGENT_PID" ] && [ "$AGENT_PID" != 0 ] || return 1
    for SAMPLE in 1 2 3 4 5 6; do
        sleep 5
        [ "$(systemctl is-active "$AGENT")" = active ] || return 1
        [ "$(systemctl show -p MainPID --value "$AGENT")" = "$AGENT_PID" ] || return 1
    done
}
selinux_after_upgrade() {
    [ "$(cat /var/lib/medulla/selinux-before-upgrade 2>/dev/null)" = Enforcing ] || return 0
    if [ "$(getenforce 2>/dev/null)" = Enforcing ]; then
        echo "SELinux already enforcing"
        return 0
    fi
    WAITED=0
    while leapp_running; do
        if [ "$WAITED" -ge 2700 ]; then
            selinux_stays unknown "leapp or the relabel did not finish"
            return 0
        fi
        sleep 10
        WAITED=$((WAITED + 10))
    done
    if ! selinux_denials; then
        selinux_stays unknown "the audit log could not be read"
        return 0
    fi
    AGENT_DENIALS=$(echo "$DENIALS" | grep -F -e python3.11 -e /opt/medulla -e sshd)
    if [ -n "$AGENT_DENIALS" ]; then
        echo "$AGENT_DENIALS" | head -n 20
        selinux_stays agent_denials "refusals about the agent, see ausearch -m AVC,USER_AVC -ts boot"
        return 0
    fi
    [ -z "$DENIALS" ] || echo "SELinux refusals, none about the agent: see ausearch -m AVC,USER_AVC -ts boot"
    if selinux_config enforcing && setenforce 1 && systemctl restart "$AGENT" && agent_holds; then
        AGENT_RESTARTED=1
        echo "SELinux enforcing again, the agent is running"
        return 0
    fi
    selinux_config permissive
    setenforce 0
    selinux_stays not_held "enforcing not applied, or the agent did not hold"
}
. /etc/os-release
[ "${VERSION_ID%%.*}" != "$SOURCE_RELEASE" ] || exit 0
mkdir -p /var/log/pulse
exec >> /var/log/pulse/after-upgrade.log 2>&1
echo "After the upgrade to $PRETTY_NAME"
ldconfig
dnf install -y perl wget
dnf install -y x11vnc
if [ -n "$GLPI_URL" ]; then
    INSTALLER="/tmp/medulla/$(basename "$GLPI_URL")"
    mkdir -p /tmp/medulla
    wget -O "$INSTALLER" "$GLPI_URL" && perl "$INSTALLER" --reinstall --silent --no-question --force --no-httpd
    echo "GLPI agent: exit $?"
fi
selinux_after_upgrade
systemctl disable medulla-after-upgrade.service
rm -f /etc/systemd/system/medulla-after-upgrade.service /var/lib/medulla/after-upgrade.sh /var/lib/medulla/selinux-before-upgrade
systemctl daemon-reload
[ -n "$AGENT_RESTARTED" ] || systemctl --no-block restart pulse-xmpp-agent-machine.service
exit 0
AFTER_UPGRADE
    } > "$AFTER_SCRIPT" || return 1
    cat > "$AFTER_UNIT" <<AFTER_UNIT_FILE || return 1
[Unit]
Description=Medulla: reinstall what the release upgrade removed
Wants=network-online.target
After=network-online.target

[Service]
Type=exec
ExecStart=/bin/sh $AFTER_SCRIPT

[Install]
WantedBy=multi-user.target
AFTER_UNIT_FILE
    systemctl enable medulla-after-upgrade.service
}
remove_after_upgrade() {
    rm -f "$SELINUX_BEFORE"
    [ -e "$AFTER_UNIT" ] || return 0
    systemctl disable medulla-after-upgrade.service
    rm -f "$AFTER_UNIT" "$AFTER_SCRIPT"
    systemctl daemon-reload
}
"""

# ELevate quickstart guide. leapp decides, nothing is answered for it: what it refuses
# stops here with its titles (exit 114). It only ends at the restart: the marker, version
# and boot, tells the plugin updates_linux, which removes it after that boot. The same marker
# tells a restart leapp asks for and dnf does not see: only a pending restart stops the retries.
ALMALINUX_UPGRADE_SCRIPT = upgrade_in_unit(r"""exec </dev/null
. /etc/os-release
""" + UPGRADE_INHIBIT % "AlmaLinux" + UPGRADE_AGENT + UPGRADE_DISK + UPGRADE_END + r"""REPORT=/var/log/leapp/leapp-report.txt
MARKER=/var/lib/medulla/leapp-upgrade
# Last: only the last lines of the script reach the deployment log
python_state() {
    echo "Agent python: ${AGENT_PYTHON:-unknown}, ${PYTHON_PACKAGE:-$(rpm -q python3.11 2>&1)}"
    echo "leapp report on python3.11:"
    grep -F python3.11 "$REPORT" 2>/dev/null | head -n 5
}
inhibited() {
    grep -q '^Risk Factor:.*inhibitor' "$REPORT" 2>/dev/null
}
leapp_refusals() {
    awk '/^Risk Factor:/ {hit = /inhibitor/} /^Title:/ && hit' "$REPORT" 2>/dev/null
}
write_marker() {
    BOOT=$(cat /proc/sys/kernel/random/boot_id) && mkdir -p "$(dirname "$MARKER")" && echo "$VERSION_ID $BOOT" > "$MARKER"
}
restart_first() {
    echo "A restart is needed first: the upgrade goes on after it"
    exit 115
}
leapp_refused() {
    echo "leapp refuses the upgrade, see $REPORT:"
    leapp_refusals
    undo_preparation || exit 1
    python_state
    if [ "$(leapp_refusals)" = "Title: Newest installed kernel not in use" ]; then
        write_marker || echo "$MARKER not written"
        restart_first
    fi
    exit 114
}

""" + ALMALINUX_AGENT_PYTHON + ALMALINUX_AFTER_UPGRADE + r"""undo_preparation() {
    remove_after_upgrade
    restore_agent_python
}

""" + UPGRADE_SPACE + r"""
echo "Pending updates"
$INHIBIT dnf upgrade -y || install_failed
if """ + LINUX_RESTART_NEEDED["dnf"] + r"""; then
    restart_first
fi
dnf install -y http://repo.almalinux.org/elevate/elevate-release-latest-el$(rpm --eval %rhel).noarch.rpm || exit 114
dnf install -y leapp-upgrade leapp-data-almalinux || exit 114
PYTHON_PACKAGE=$(rpm -q python3.11 2>&1)

$INHIBIT leapp preupgrade
if [ $? -ne 0 ] || inhibited; then
    leapp_refused
fi
rm -f "$MARKER"
keep_agent_python
prepare_after_upgrade || echo "Reinstallation after the upgrade not prepared: the upgrade goes on"
if ! $INHIBIT leapp upgrade; then
    if inhibited; then
        leapp_refused
    fi
    undo_preparation
    python_state
    install_failed
fi
if ! write_marker; then
    not_ready "$MARKER not written"
fi
python_state
echo "Upgrade to the next release prepared, restart pending"
exit 0
""")

LINUX_UPGRADE_SCRIPTS = {DEBIAN_UPGRADE: DEBIAN_UPGRADE_SCRIPT, UBUNTU_UPGRADE: UBUNTU_UPGRADE_SCRIPT,
                         ALMALINUX_UPGRADE: ALMALINUX_UPGRADE_SCRIPT}

SETUP_OPTIONS = "/quiet /noreboot /eula accept /dynamicupdate disable"
# Without /auto upgrade the scan has no install choice: 0xC1900204 « selected
# install choice is not available » (29/10, ath-w10-1)
SCAN_COMMAND = '"@@@PACKAGE_DIRECTORY_ABS_MACHINE@@@\\setup.exe" /auto upgrade /compat scanonly ' + SETUP_OPTIONS
UPGRADE_COMMAND = '"@@@PACKAGE_DIRECTORY_ABS_MACHINE@@@\\setup.exe" /auto upgrade ' + SETUP_OPTIONS
# 0xC1900210: no compatibility issue, unsigned and signed. Anything else stops:
# 0xC1900208 application, 0xC1900200 / 0xC1900202 hardware, 0xC190020E space
SCAN_PASSED_CODES = (0xC1900210, 0xC1900210 - 2**32)

UPGRADES = "Upgrades"
# Enablement package of a version: the small cab of its upgrade entry, named after a
# KB that has no catalog entry of its own (the cumulative, stack and .NET ones have)
ENABLEMENT_NAME = re.compile(r"windows1[01]\.0-kb(\d+)-(x64|arm64|x86)\.cab$", re.IGNORECASE)

FILE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+-]*$")
UUID_NAMESPACE = uuid.uuid5(uuid.NAMESPACE_URL, "medulla:updates:packages")

QUESTION_TITLE = "Windows Update"
QUESTION_MESSAGE = (
    "Medulla has changed Windows updates. A restart is required"
    " to apply the change. Restart now?\n\n"
    "Medulla a modifié les mises à jour Windows."
    " Un redémarrage est nécessaire pour appliquer la modification."
    " Redémarrer maintenant ?"
)
RESTART_FIRST_MESSAGE = (
    "Windows updates are waiting for a restart. Medulla installs the next ones"
    " after it. Restart now?\n\n"
    "Des mises à jour Windows attendent un redémarrage. Medulla installe"
    " les suivantes ensuite. Redémarrer maintenant ?"
)


# Exit 20: restart pending, 21: servicing busy (TiWorker runs while CBS
# works, TrustedInstaller stays started idle), 0: ready; any failure is
# 1, the installation then goes on. 64-bit registry view: the agent may
# run a 32-bit PowerShell.
PRECHECK_SCRIPT = r"""$ErrorActionPreference = "Stop"
try {
    $hklm = [Microsoft.Win32.RegistryKey]::OpenBaseKey("LocalMachine", "Registry64")
    $keys = @(
        "SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending",
        "SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired"
    )
    foreach ($path in $keys) {
        $key = $hklm.OpenSubKey($path)
        if ($key) {
            $key.Close()
            Write-Output ("HKLM\{0}" -f $path)
            Write-Output "Installation postponed: a restart is pending"
            exit 20
        }
    }
    $setup = $hklm.OpenSubKey("SYSTEM\Setup\MoSetup\Volatile")
    if ($setup) {
        $progress = $setup.GetValue("SetupProgress")
        $setup.Close()
        if ($progress -eq 100) {
            Write-Output "HKLM\SYSTEM\Setup\MoSetup\Volatile SetupProgress=100"
            Write-Output "Installation postponed: a restart is pending"
            exit 20
        }
    }
    $deadline = (Get-Date).AddMinutes(15)
    while (Get-Process -Name TiWorker -ErrorAction SilentlyContinue) {
        if ((Get-Date) -ge $deadline) {
            Write-Output "Installation postponed: Windows servicing busy for 15 minutes"
            exit 21
        }
        Start-Sleep -Seconds 30
    }
    Write-Output "No pending restart, Windows servicing idle"
    exit 0
} catch {
    Write-Output ("Precheck failed, installing anyway: {0}" -f $_.Exception.Message)
    exit 1
}
"""


# Exit 0: removed, 3010: removed, restart needed, 13: no installed package
# of the KB, anything else: DISM's code. A standalone update is
# Package_for_KB<kb>; a cumulative is Package_for_RollupFix named after its
# build, not its KB (wusa /uninstall does not remove a combined SSU + LCU).
# Matched on the revision only: the versions sharing a cumulative (24H2,
# 25H2, 26H2) keep the build number of their common base in that name.
# English output so that "Package Identity" can be read; 64-bit DISM even
# from a 32-bit PowerShell.
UNINSTALL_SCRIPT = r"""$ErrorActionPreference = "Stop"
try {
    $dism = Join-Path $env:windir "sysnative\dism.exe"
    if (-not (Test-Path $dism)) { $dism = Join-Path $env:windir "system32\dism.exe" }
    $patterns = @("Package_for_KB%(kb)s~*")
    if ("%(revision)s") { $patterns += "Package_for_RollupFix~*~~*.%(revision)s.*" }
    $found = @(& $dism /Online /English /Get-Packages /Format:List | ForEach-Object {
        if ($_ -match "^Package Identity : (\S+)") {
            $name = $Matches[1]
            if (@($patterns | Where-Object { $name -like $_ }).Count) { $name }
        }
    })
    if (-not $found.Count) {
        Write-Output "KB%(kb)s: no installed package to remove"
        exit 13
    }
    $restart = $false
    foreach ($name in $found) {
        Write-Output ("Removing {0}" -f $name)
        & $dism /Online /Remove-Package /PackageName:$name /Quiet /NoRestart
        if ($LASTEXITCODE -eq 3010) {
            $restart = $true
        } elseif ($LASTEXITCODE -ne 0) {
            Write-Output ("DISM exit code {0}" -f $LASTEXITCODE)
            exit $LASTEXITCODE
        }
    }
    if ($restart) { exit 3010 }
    exit 0
} catch {
    Write-Output ("Uninstall failed: {0}" -f $_.Exception.Message)
    exit 1
}
"""
# Build and revision in the catalog title of a cumulative, e.g. "(26100.4349)"
TITLE_BUILD = re.compile(r"\(\d{5}\.(\d+)\)")

# Exit 1: no platform folder or no MpCmdRun.exe, anything else: its code. The
# folders are versions, some with a "-0" suffix; "CurrentVersion" is not one.
DEFENDER_REVERT_SCRIPT = r"""$ErrorActionPreference = "Stop"
try {
    $root = Join-Path $env:ProgramData "Microsoft\Windows Defender\Platform"
    $latest = Get-ChildItem -Path $root -Directory |
        Where-Object { $_.Name -match '^\d+(\.\d+){1,3}(-\d+)?$' } |
        Sort-Object { [version]($_.Name -replace '-\d+$', '') }, { [int](($_.Name -split '-')[1]) } |
        Select-Object -Last 1
    if (-not $latest) {
        Write-Output ("No platform folder under {0}" -f $root)
        exit 1
    }
    $tool = Join-Path $latest.FullName "MpCmdRun.exe"
    if (-not (Test-Path $tool)) {
        Write-Output ("{0} not found" -f $tool)
        exit 1
    }
    Write-Output ("Reverting with {0}" -f $tool)
    & $tool -RevertPlatform
    exit $LASTEXITCODE
} catch {
    Write-Output ("Revert failed: {0}" -f $_.Exception.Message)
    exit 1
}
"""

# Each catalog line of the platform carries its .exe for every architecture. The
# file names match the architecture names, the case aside. The agent may be
# 32-bit: PROCESSOR_ARCHITECTURE then says x86, PROCESSOR_ARCHITEW6432 the machine.
DEFENDER_PLATFORM_COMMAND = (
    "if defined PROCESSOR_ARCHITEW6432"
    ' ("@@@PACKAGE_DIRECTORY_ABS_MACHINE@@@\\UpdatePlatform.%PROCESSOR_ARCHITEW6432%fre.exe")'
    " else"
    ' ("@@@PACKAGE_DIRECTORY_ABS_MACHINE@@@\\UpdatePlatform.%PROCESSOR_ARCHITECTURE%fre.exe")'
)

# Updates delivered as an .exe run directly, by KB. Anything else than the
# done_codes and restart_codes is an error. options: of the only .exe of the
# package; command: the whole command instead, the package keeping all its .exe.
# uninstall_script: None without an uninstall section.
EXE_UPDATES = {
    # Malicious Software Removal Tool, exit codes of KB891716: 0 no infection, 10
    # and 13 removal done with a restart required; 6 (infection found) is an error
    "890830": {
        "options": " /Q",
        "done_codes": (0,),
        "restart_codes": (10, 13),
        "uninstall_script": None,
    },
    # Defender platform: measured on Windows 10, 0 without a pending restart
    "4052623": {
        "command": DEFENDER_PLATFORM_COMMAND,
        "done_codes": (0,),
        "restart_codes": (),
        "uninstall_script": DEFENDER_REVERT_SCRIPT,
    },
}


# Exit 10: workstation without user session, 11: one session and it is
# active, 12: anything else; any failure is 12 (no restart when unsure)
SESSIONS_SCRIPT = r"""$ErrorActionPreference = "Stop"
try {
    $os = Get-WmiObject -Class Win32_OperatingSystem
    if ($os.ProductType -ne 1) {
        Write-Output "Server: no restart"
        exit 12
    }
    Add-Type -TypeDefinition @"
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
public static class MedullaSessions {
    [StructLayout(LayoutKind.Sequential)]
    struct SessionInfo { public int SessionId; public IntPtr WinStationName; public int State; }
    [DllImport("wtsapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern bool WTSEnumerateSessions(IntPtr server, int reserved, int version, out IntPtr sessions, out int count);
    [DllImport("wtsapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern bool WTSQuerySessionInformation(IntPtr server, int sessionId, int infoClass, out IntPtr buffer, out int bytes);
    [DllImport("wtsapi32.dll")]
    static extern void WTSFreeMemory(IntPtr memory);
    // { user sessions, active user sessions }
    public static int[] Count() {
        IntPtr sessions;
        int count;
        if (!WTSEnumerateSessions(IntPtr.Zero, 0, 1, out sessions, out count))
            throw new Win32Exception();
        int users = 0, active = 0;
        try {
            int size = Marshal.SizeOf(typeof(SessionInfo));
            for (int i = 0; i < count; i++) {
                SessionInfo info = (SessionInfo)Marshal.PtrToStructure(
                    new IntPtr(sessions.ToInt64() + i * size), typeof(SessionInfo));
                IntPtr buffer;
                int bytes;
                // 5 = WTSUserName
                if (!WTSQuerySessionInformation(IntPtr.Zero, info.SessionId, 5, out buffer, out bytes))
                    throw new Win32Exception();
                string user = Marshal.PtrToStringUni(buffer);
                WTSFreeMemory(buffer);
                if (String.IsNullOrEmpty(user))
                    continue;
                users++;
                // 0 = WTSActive
                if (info.State == 0)
                    active++;
            }
        } finally {
            WTSFreeMemory(sessions);
        }
        return new int[] { users, active };
    }
}
"@
    $users, $active = [MedullaSessions]::Count()
    Write-Output ("User sessions: {0}, active: {1}" -f $users, $active)
    if ($users -eq 0) { exit 10 }
    if ($users -eq 1 -and $active -eq 1) { exit 11 }
    exit 12
} catch {
    Write-Output ("Sessions unknown: {0}" -f $_.Exception.Message)
    exit 12
}
"""


class BuildFailed(Exception):
    pass


def files_hash(files):
    """SHA1 hex of the sorted SHA1 of the files: identifies a file set."""
    return hashlib.sha1(
        "\n".join(sorted(f["sha1"] for f in files)).encode()
    ).hexdigest()


def package_uuid(digest):
    return str(uuid.uuid5(UUID_NAMESPACE, digest))


def file_kind(file):
    kind = file.get("kind") or os.path.splitext(file["name"])[1]
    return kind.lower().lstrip(".")


def unsupported_reason(files, kb=None):
    """Why these files of the KB cannot be packaged, None when they can."""
    if not files:
        return "no language-neutral file"
    exe = exe_update(kb)
    names = set()
    for file in files:
        if not FILE_NAME.match(file["name"] or ""):
            return "unsafe file name %r" % file["name"]
        if file["name"].lower() in names:
            return "duplicate file name %s" % file["name"]
        names.add(file["name"].lower())
        if file_kind(file) != "exe" if exe else file_kind(file) not in KINDS:
            return "unsupported file kind %s (%s)" % (file_kind(file), file["name"])
    if exe and "command" not in exe and len(files) > 1:
        return "one .exe expected for KB%s, %d files" % (kb_number(kb), len(files))
    return None


def enablement_files(files, entry_kb, own_kbs, shared=frozenset()):
    """The enablement cab among the files of an upgrade entry ([] when none).
    shared: ids of the files other versions carry too (cumulative, stack)."""
    found = []
    for file in files:
        match = ENABLEMENT_NAME.search(file["name"] or "")
        if match and int(match.group(1)) not in own_kbs | {entry_kb} and file.get("id") not in shared:
            found.append(dict(file, enablement_kb=int(match.group(1))))
    return found


def kb_number(kb):
    return re.sub(r"(?i)^kb", "", str(kb).strip())


def exe_update(kb):
    return EXE_UPDATES.get(kb_number(kb))


def install_target(names, kb):
    """File given to DISM: the .msu named after the KB, the only .msu, or
    None for the folder (no .msu). The only .exe of an update run directly, None
    when its command chooses. BuildFailed when no file can be chosen."""
    exe = exe_update(kb)
    if exe and "command" in exe:
        return None
    if exe:
        exes = sorted(name for name in names if name.lower().endswith(".exe"))
        if len(exes) != 1:
            raise BuildFailed("%d .exe files for KB%s: %s" % (len(exes), kb_number(kb), ", ".join(exes)))
        return exes[0]
    msus = sorted(name for name in names if name.lower().endswith(".msu"))
    if not msus:
        return None
    if len(msus) == 1:
        return msus[0]
    pattern = re.compile(r"kb%s(?!\d)" % re.escape(kb_number(kb)), re.IGNORECASE)
    named = [name for name in msus if pattern.search(name)]
    if len(named) != 1:
        raise BuildFailed(
            "%s .msu files named after KB%s among %s"
            % ("no" if not named else "several", kb_number(kb), ", ".join(msus))
        )
    return named[0]


def install_command(target):
    return INSTALL_COMMAND % ("\\" + target if target else "")


def b64(text):
    return base64.b64encode(text.encode("utf-8")).decode("ascii")


def package_name(update):
    return " ".join((update["title"] or "").split()) or "KB%s" % update["kb"]


def package_description(update):
    description = "Windows update KB%s" % update["kb"]
    if update.get("classification"):
        description += " (%s)" % update["classification"]
    return description[:255]


def media_name(media):
    return "Windows media %s %s %s %s" % (
        media.get("base_build") or "", media["edition"],
        media.get("language_code") or "", media.get("architecture") or "")


def media_description(media):
    return ("Windows installation media %s, edition %s" % (media["file_name"], media["edition"]))[:255]


def configuration(package_id, update, now):
    return base_configuration(package_id, package_name(update), package_description(update), now)


def media_configuration(package_id, media, now):
    return base_configuration(package_id, media_name(media), media_description(media), now,
                              share=MAJOR_SHARE)


def base_configuration(package_id, name, description, now, targetos="win", share=SHARE):
    date = now.strftime("%Y-%m-%d %H:%M:%S")
    empty = {"command": "", "name": ""}
    return {
        "id": package_id,
        "name": name,
        "description": description,
        "version": "1.0",
        "targetos": targetos,
        "entity_id": "0",
        "sub_packages": [],
        "reboot": 0,
        "inventory": {
            "associateinventory": "0",
            "licenses": "",
            "queries": {"Qsoftware": "", "Qvendor": "", "boolcnd": "", "Qversion": ""},
        },
        "commands": {
            name: dict(empty)
            for name in (
                "postCommandSuccess",
                "command",
                "postCommandFailure",
                "installInit",
                "preCommand",
            )
        },
        "localisation_server": share,
        "previous_localisation_server": share,
        "metagenerator": "manual",
        "creator": "automate_medulla",
        "edition": "automate_medulla",
        "editor": "",
        "creation_date": date,
        "edition_date": date,
        "urlpath": "",
    }


def precheck_step(next_label="INSTALL", label="PRECHECK", restart_label="POSTPONED"):
    """restart_label: where a pending restart leads."""
    return {
        "action": "actionprocessscriptfile",
        "step": 0,
        "codereturn": "",
        "actionlabel": label,
        "typescript": "powershell",
        "script": b64(PRECHECK_SCRIPT),
        "timeout": PRECHECK_TIMEOUT,
        "10@lastlines": "10@lastlines",
        "gotoreturncode@=0": next_label,
        "gotoreturncode@=20": restart_label,
        "gotoreturncode@=21": "POSTPONED",
        # A failing precheck never blocks the installation
        "gotoreturncode@OUT20,21": next_label,
    }


def postponed_step():
    """Must stay right before REPORT_ERROR: action_comment goes on to the next step."""
    return {
        "action": "action_comment",
        "step": 0,
        "actionlabel": "POSTPONED",
        "comment": POSTPONED_COMMENT,
    }


def batch_install_step(command, restart_codes, done_codes):
    install = {
        "action": "actionprocessscriptfile",
        "step": 0,
        "codereturn": "",
        "actionlabel": "INSTALL",
        "typescript": "Batch",
        "script": b64(command),
        "timeout": INSTALL_TIMEOUT,
        "30@lastlines": "30@lastlines",
    }
    for code in restart_codes:
        install["gotoreturncode@=%d" % code] = "CHECK_SESSIONS"
    for code in done_codes:
        install["gotoreturncode@=%d" % code] = "REPORT_SUCCESS"
    # Explicit: an unmatched code would fall through to the next step
    install["gotoreturncode@!=0"] = "REPORT_ERROR"
    return install


def install_step(target, restart=False):
    install = batch_install_step(install_command(target), INSTALLED_CODES, SKIPPED_CODES)
    if restart:
        # An enablement package answers 0 but only takes effect at the restart
        install["gotoreturncode@=0"] = "CHECK_SESSIONS"
    return install


def exe_step(target, exe):
    command = exe.get("command") or EXE_COMMAND % (target, exe["options"])
    return batch_install_step(command, exe["restart_codes"], exe["done_codes"])


def sessions_step(label="CHECK_SESSIONS", restart="REBOOT", ask="ASK_REBOOT", none="REPORT_SUCCESS"):
    """none: where no restart leads (a server, or a failed check)."""
    return {
        "action": "actionprocessscriptfile",
        "step": 0,
        "codereturn": "",
        "actionlabel": label,
        "typescript": "powershell",
        "script": b64(SESSIONS_SCRIPT),
        "timeout": SESSIONS_TIMEOUT,
        "10@lastlines": "10@lastlines",
        "gotoreturncode@=10": restart,
        "gotoreturncode@=11": ask,
        "gotoreturncode@=12": none,
        # Unmatched codes, 0 included, would fall through to the question
        "gotoreturncode@OUT10,12": none,
    }


def question_step(label, message, restart, refused):
    # No gotonouser: action_question would follow gototimeout,
    # without a user the next step (the restart) is taken
    return {
        "action": "action_question",
        "step": 0,
        "codereturn": "",
        "actionlabel": label,
        "titlemessage": b64(QUESTION_TITLE),
        "sizeheader": "15",
        "message": b64(message),
        "sizemessage": "10",
        "textbuttonyes": "Yes",
        "textbuttonno": "No",
        "gotoyes": restart,
        "gotono": refused,
        "gototimeout": refused,
        "timeout": QUESTION_TIMEOUT,
    }


def restart_step(label="REBOOT"):
    """The agent resumes on the next step: REPORT_SUCCESS, or the second precheck."""
    return {
        "action": "actionrestart",
        "step": 0,
        "actionlabel": label,
        "targetrestart": "MA",
    }


def restart_first_steps(next_label):
    """A restart is pending before the installation: taken as after one (alone without a
    session, asked with one), then the installation goes on. Reached by jumps only; a
    restart still pending after it postpones the installation."""
    return [
        sessions_step("RESTART_FIRST", "RESTART_FIRST_REBOOT", "RESTART_FIRST_ASK", "POSTPONED"),
        question_step("RESTART_FIRST_ASK", RESTART_FIRST_MESSAGE, "RESTART_FIRST_REBOOT", "POSTPONED"),
        restart_step("RESTART_FIRST_REBOOT"),
        precheck_step(next_label, "PRECHECK_AGAIN"),
    ]


def uninstall_steps(kb, title):
    """Section played by a deployment of section "uninstall"."""
    build = TITLE_BUILD.search(title or "")
    script = UNINSTALL_SCRIPT % {"kb": kb_number(kb), "revision": build.group(1) if build else ""}
    return uninstall_section(script, INSTALLED_CODES)


def uninstall_section(script, restart_codes=()):
    uninstall = {
        "action": "actionprocessscriptfile",
        "step": 0,
        "codereturn": "",
        "actionlabel": "UNINSTALL",
        "typescript": "powershell",
        "script": b64(script),
        "timeout": INSTALL_TIMEOUT,
        "30@lastlines": "30@lastlines",
        "gotoreturncode@=0": "REPORT_SUCCESS",
    }
    for code in restart_codes:
        uninstall["gotoreturncode@=%d" % code] = "CHECK_SESSIONS"
    uninstall["gotoreturncode@!=0"] = "REPORT_ERROR"
    return [
        {"action": "action_section_uninstall", "step": 0, "actionlabel": "SECTION_UNINSTALL"},
        uninstall,
    ]


def report_step(label, end, command=REPORT_COMMAND):
    # The plugin call is not run as a command and always ends with code 0
    return {
        "action": "actionprocessscript",
        "step": 0,
        "codereturn": "",
        "actionlabel": label,
        "command": b64(command),
        "gotoreturncode@=0": end,
        "gotoreturncode@!=0": end,
    }


def scan_step():
    scan = {
        "action": "actionprocessscriptfile",
        "step": 0,
        "codereturn": "",
        "actionlabel": "SCAN",
        "typescript": "Batch",
        "script": b64(SCAN_COMMAND),
        "timeout": SCAN_TIMEOUT,
        "10@lastlines": "10@lastlines",
    }
    for code in SCAN_PASSED_CODES:
        scan["gotoreturncode@=%d" % code] = "UPGRADE"
    # 0 is not a scan result; unmatched, it would end in success
    scan["gotoreturncode@=0"] = "REPORT_ERROR"
    scan["gotoreturncode@!=0"] = "REPORT_ERROR"
    return scan


def upgrade_step():
    # Prepared with code 0, installed at the restart
    return {
        "action": "actionprocessscriptfile",
        "step": 0,
        "codereturn": "",
        "actionlabel": "UPGRADE",
        "typescript": "Batch",
        "script": b64(UPGRADE_COMMAND),
        "timeout": INSTALL_TIMEOUT,
        "30@lastlines": "30@lastlines",
        "gotoreturncode@=0": "CHECK_SESSIONS",
        "gotoreturncode@!=0": "REPORT_ERROR",
    }


def windows_sequence(target, restart=False, kb=None, title=None):
    exe = exe_update(kb)
    if exe:
        script = exe["uninstall_script"]
        return update_sequence([exe_step(target, exe)], uninstall_section(script) if script else [])
    # Runs only when asked for; jumps back to the steps above
    return update_sequence([install_step(target, restart)], uninstall_steps(kb, title) if kb else [])


def media_sequence():
    # A pending restart may be the one of this very upgrade: nothing runs after it
    return update_sequence([scan_step(), upgrade_step()], resume="POSTPONED")


def update_sequence(work, tail=(), resume=None):
    """Section update: precheck, work, restart and report.
    resume: where the installation goes on after a restart taken first (the work by default)."""
    sequence = [
        {"action": "action_section_update", "step": 0, "actionlabel": "SECTION_UPDATE"},
        precheck_step(work[0]["actionlabel"], restart_label="RESTART_FIRST"),
    ] + list(work) + [
        sessions_step(),
        question_step("ASK_REBOOT", QUESTION_MESSAGE, "REBOOT", "REPORT_SUCCESS"),
        restart_step(),
        report_step("REPORT_SUCCESS", "END_SUCCESS"),
        {
            "action": "actionsuccescompletedend",
            "step": 0,
            "actionlabel": "END_SUCCESS",
            "clear": "True",
            "inventory": "forced",
        },
        postponed_step(),
        # END_ERROR cannot run an inventory
        report_step("REPORT_ERROR", "END_ERROR"),
        {"action": "actionerrorcompletedend", "step": 0, "actionlabel": "END_ERROR"},
    ] + restart_first_steps(resume or work[0]["actionlabel"]) + list(tail)
    for index, step in enumerate(sequence):
        step["step"] = index
    return sequence


def windows_section(sequence):
    return {
        "win": {"sequence": sequence},
        "metaparameter": {
            "win": {"label": {step["actionlabel"]: step["step"] for step in sequence}},
            "os": ["win"],
        },
    }


def descriptor(package_id, update, now, target=None, restart=False):
    """xmppdeploy.json of the package."""
    data = descriptor_info(package_id, package_name(update), package_description(update), now)
    data["info"]["meta_update_kb"] = str(update["kb"])
    data.update(windows_section(windows_sequence(target, restart, update["kb"], update["title"])))
    return data


def media_descriptor(package_id, media, now):
    """xmppdeploy.json of a media package: no KB, no uninstall section."""
    data = descriptor_info(package_id, media_name(media), media_description(media), now, MAJOR_SHARE)
    data.update(windows_section(media_sequence()))
    return data


def linux_install_step(family):
    """family: a package manager family, or a key of LINUX_UPGRADE_SCRIPTS."""
    if family in LINUX_UPGRADE_SCRIPTS:
        script, timeout = LINUX_UPGRADE_SCRIPTS[family], RELEASE_TIMEOUT
    else:
        script, timeout = LINUX_PACKAGES_SCRIPT + LINUX_INSTALL_COMMANDS[family] + "\n", INSTALL_TIMEOUT
    step = {
        "action": "actionprocessscriptfile",
        "step": 0,
        "codereturn": "",
        "actionlabel": "INSTALL",
        "typescript": "Batch",
        "script": b64(script),
        "timeout": timeout,
        "30@lastlines": "30@lastlines",
        # Release upgrade: the restart stays with the admin, as under Windows
        "gotoreturncode@=0": "REPORT_SUCCESS" if family in LINUX_UPGRADE_SCRIPTS else "CHECK_SESSIONS",
    }
    if family in RESTART_FIRST_UPGRADES:
        step["gotoreturncode@=%d" % RESTART_FIRST_CODE] = "POSTPONED"
    # Last: the first matching condition jumps
    step["gotoreturncode@!=0"] = "REPORT_ERROR"
    return step


def linux_sessions_step(family):
    needed = LINUX_RESTART_NEEDED[family]
    return {
        "action": "actionprocessscriptfile",
        "step": 0,
        "codereturn": "",
        "actionlabel": "CHECK_SESSIONS",
        "typescript": "Batch",
        "script": b64(LINUX_SESSIONS_SCRIPT % {"restart_needed": needed}),
        "timeout": SESSIONS_TIMEOUT,
        "10@lastlines": "10@lastlines",
        "gotoreturncode@=10": "REBOOT",
        "gotoreturncode@!=10": "REPORT_SUCCESS",
    }


def linux_sequence(family):
    sequence = [
        {"action": "action_section_update", "step": 0, "actionlabel": "SECTION_UPDATE"},
        linux_install_step(family),
    ] + ([] if family in LINUX_UPGRADE_SCRIPTS else [linux_sessions_step(family), restart_step()]) + [
        report_step("REPORT_SUCCESS", "END_SUCCESS", LINUX_REPORT_COMMAND),
        {
            "action": "actionsuccescompletedend",
            "step": 0,
            "actionlabel": "END_SUCCESS",
            "clear": "True",
            "inventory": "forced",
        },
    ] + ([postponed_step()] if family in RESTART_FIRST_UPGRADES else []) + [
        report_step("REPORT_ERROR", "END_ERROR", LINUX_REPORT_COMMAND),
        {"action": "actionerrorcompletedend", "step": 0, "actionlabel": "END_ERROR"},
    ]
    for index, step in enumerate(sequence):
        step["step"] = index
    return sequence


def linux_package_name(family):
    return LINUX_UPGRADE_NAMES.get(family) or "Linux updates (%s)" % family


def linux_share(family):
    return MAJOR_SHARE if family in LINUX_UPGRADE_NAMES else SHARE


def linux_package_id(family):
    """Identifier from the content: a changed sequence is a new package."""
    content = json.dumps(linux_sequence(family), sort_keys=True)
    return package_uuid("linux:%s:%s" % (family, hashlib.sha1(content.encode("utf-8")).hexdigest()))


def linux_descriptor(package_id, family, now):
    name = linux_package_name(family)
    data = descriptor_info(package_id, name, name, now, linux_share(family))
    sequence = linux_sequence(family)
    data["linux"] = {"sequence": sequence}
    data["metaparameter"] = {
        "linux": {"label": {step["actionlabel"]: step["step"] for step in sequence}},
        "os": ["linux"],
    }
    return data


def descriptor_info(package_id, name, description, now, share=SHARE):
    date = now.strftime("%Y-%m-%d %H:%M:%S")
    return {
        "info": {
            "name": name,
            "description": description,
            "packageUuid": package_id,
            "localisation_server": share,
            "previous_localisation_server": share,
            "methodetransfert": "pushrsync",
            "transferfile": True,
            "type_section": "update",
            "spooling": "ordinary",
            "limit_rate_ko": "",
            "creator": "automate_medulla",
            "edition": "automate_medulla",
            "editor": "automate_medulla",
            "creation_date": date,
            "edition_date": date,
            "licenses": "1.0",
            "version": "1.0",
            "metagenerator": "expert",
            "targetrestart": "MA",
            "inventory": "forced",
            "typescript": "Batch",
            "Dependency": [],
            "url": "",
            "urlpath": "",
            "software": "templated",
            "launcher": "",
        },
    }


def set_proxy(proxy):
    global PROXIES
    PROXIES = {"http": proxy, "https": proxy} if proxy else None


def download(url, path):
    """Download url into path; return (sha1, sha256, size), raw digests."""
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()
    size = 0
    host = urlsplit(url).hostname
    try:
        response = requests.get(url, stream=True, timeout=DOWNLOAD_TIMEOUT, proxies=PROXIES)
    except requests.RequestException as error:
        via = " through the proxy" if PROXIES else ""
        raise BuildFailed("cannot reach %s%s (%s)" % (host, via, type(error).__name__))
    with response:
        if response.status_code != 200:
            raise BuildFailed("HTTP %s from %s" % (response.status_code, host))
        with open(path, "wb") as output:
            for chunk in response.iter_content(CHUNK_SIZE):
                output.write(chunk)
                sha1.update(chunk)
                sha256.update(chunk)
                size += len(chunk)
    return sha1.digest(), sha256.digest(), size


def raw_digest(value):
    """Digest given in hex or in base64, as bytes."""
    value = (value or "").strip()
    if re.match(r"^[0-9A-Fa-f]{64}$", value):
        return bytes.fromhex(value)
    return base64.b64decode(value)


def media_digest(media):
    """Identity of a media package: the ESD and the edition taken from it."""
    identity = "media\n%s\n%s\n%s" % (media["file_name"], media["edition"], media.get("sha256") or "")
    return hashlib.sha1(identity.encode()).hexdigest()


def media_unsupported_reason(media):
    if not media.get("edition"):
        return "no edition"
    if not media.get("url"):
        return "no download address"
    if not media.get("sha256"):
        return "no SHA-256"
    return None


def run_wimlib(arguments):
    """Output of wimlib-imagex, BuildFailed with its last lines on failure."""
    try:
        completed = subprocess.run(
            [WIMLIB] + list(arguments),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=WIMLIB_TIMEOUT,
        )
    except FileNotFoundError:
        raise BuildFailed("%s not found (Debian package wimtools)" % WIMLIB)
    except subprocess.TimeoutExpired:
        raise BuildFailed("%s %s: no end after %d s" % (WIMLIB, arguments[0], WIMLIB_TIMEOUT))
    output = completed.stdout.decode("utf-8", "replace")
    if completed.returncode:
        lines = [line.strip() for line in re.split(r"[\r\n]+", output) if line.strip()]
        raise BuildFailed("%s %s exit %d: %s" % (
            WIMLIB, arguments[0], completed.returncode, " | ".join(lines[-3:])))
    return output


def wim_images(info):
    """Images listed by wimlib-imagex info: [{"Index": "1", "Edition ID": ...}]."""
    images = []
    for line in info.splitlines():
        key, separator, value = line.partition(":")
        if not separator:
            continue
        key, value = key.strip(), value.strip()
        if key == "Index":
            images.append({})
        if images:
            images[-1][key] = value
    return images


# Image 1: setup media, 2: Windows PE, 3: Windows Setup, then the editions
MEDIA_IMAGE, PE_IMAGE, SETUP_IMAGE = 1, 2, 3


def edition_index(images, edition):
    """Index of the one image of the edition; BuildFailed when none or several."""
    found = [
        image["Index"] for image in images
        if image.get("Index", "").isdigit() and int(image["Index"]) > SETUP_IMAGE
        and image.get("Edition ID", "").lower() == edition.lower()
    ]
    if len(found) != 1:
        editions = sorted({image.get("Edition ID") or "?" for image in images})
        raise BuildFailed("%s images of edition %s in the ESD (%s)" % (
            "no" if not found else len(found), edition, ", ".join(editions)))
    return found[0]


def pkgs_row(conf, size, share_id):
    """Row of pkgs.packages, as install_package() of
    medulla-mariadb-move-update-package.py builds it."""
    inventory = conf["inventory"]
    commands = conf["commands"]
    return {
        "label": conf["name"],
        "description": conf["description"],
        "uuid": conf["id"],
        "version": conf["version"],
        "os": conf["targetos"],
        "metagenerator": conf["metagenerator"],
        "entity_id": conf["entity_id"],
        "sub_packages": json.dumps(conf["sub_packages"]),
        "reboot": conf["reboot"],
        "inventory_associateinventory": inventory["associateinventory"],
        "inventory_licenses": inventory["licenses"],
        "Qversion": inventory["queries"]["Qversion"],
        "Qvendor": inventory["queries"]["Qvendor"],
        "Qsoftware": inventory["queries"]["Qsoftware"],
        "boolcnd": inventory["queries"]["boolcnd"],
        "postCommandSuccess_command": commands["postCommandSuccess"]["command"],
        "postCommandSuccess_name": commands["postCommandSuccess"]["name"],
        "installInit_command": commands["installInit"]["command"],
        "installInit_name": commands["installInit"]["name"],
        "postCommandFailure_command": commands["postCommandFailure"]["command"],
        "postCommandFailure_name": commands["postCommandFailure"]["name"],
        "command_command": commands["command"]["command"],
        "command_name": commands["command"]["name"],
        "preCommand_command": commands["preCommand"]["command"],
        "preCommand_name": commands["preCommand"]["name"],
        "pkgs_share_id": share_id,
        "edition_status": 1,
        "conf_json": json.dumps(conf),
        "size": size,
    }


def register_package(conf, size):
    """Declare the package in pkgs.packages, never replacing a row."""
    from sqlalchemy import text
    from lib.plugins.pkgs import PkgsDatabase

    pkgs = PkgsDatabase()
    if not pkgs.is_activated:
        raise BuildFailed("pkgs database not activated")
    with pkgs.engine_pkgsmmaster_base.begin() as connection:
        share = conf["localisation_server"]
        share_id = connection.execute(
            text("SELECT id FROM pkgs_shares WHERE name = :name LIMIT 1"),
            {"name": share},
        ).scalar()
        if share_id is None:
            raise BuildFailed("pkgs share %s missing" % share)
        row = pkgs_row(conf, size, share_id)
        connection.execute(
            text(
                "INSERT IGNORE INTO packages (%s) VALUES (%s)"
                % (
                    ", ".join("`%s`" % column for column in row),
                    ", ".join(":%s" % column for column in row),
                )
            ),
            row,
        )


def write_json(path, data):
    with open(path, "w") as output:
        json.dump(data, output, indent=4)


def directory_size(path):
    return sum(
        os.path.getsize(os.path.join(root, name))
        for root, _, names in os.walk(path)
        for name in names
    )


def not_built_sql(update_id):
    return (
        " LEFT JOIN update_packages l ON l.update_id = " + update_id +
        " LEFT JOIN packages p ON p.uuid = l.package_uuid"
        " WHERE " + update_id + " IS NOT NULL AND (p.uuid IS NULL"
        " OR (:retry AND p.state IN ('failed', 'building')))"
    )


class PackageStore(object):
    """SQL of the packages, inside the caller's transaction."""

    def __init__(self, store):
        self.store = store

    def needed_updates(self, retry_failed):
        """Approved updates, and the steps of the upgrades launched by the admin
        (launching an upgrade approves its cumulative and enablement package)."""
        retry = {"retry": int(retry_failed)}
        rows = self.store.execute(
            "SELECT n.update_id FROM ("
            " SELECT update_id FROM approved_updates"
            " UNION SELECT (" + enablement_update_sql("m.target_build", "mr.architecture") + ")"
            " FROM machine_upgrades m JOIN machine_reports mr ON mr.jid = m.jid"
            " WHERE m.launched_at IS NOT NULL AND FIND_IN_SET('enablement', m.steps)"
            ") n" + not_built_sql("n.update_id"),
            retry,
        ).fetchall()
        cumulatives = self.store.launched_cumulatives()
        if cumulatives:
            rows += self.store.execute_in(
                "SELECT n.id FROM updates n" + not_built_sql("n.id") + " AND n.id IN :ids",
                dict(retry, ids=sorted(cumulatives)),
                "ids",
            ).fetchall()
        return sorted({row[0] for row in rows})

    def update(self, update_id):
        row = self.store.execute(
            "SELECT id, kb, title, classification FROM updates WHERE id = :id",
            {"id": update_id},
        ).fetchone()
        if row is None:
            return None
        return {"id": row[0], "kb": row[1], "title": row[2], "classification": row[3]}

    def own_kbs(self, kbs):
        """KBs among kbs that have a catalog entry of their own (not an upgrade)."""
        if not kbs:
            return set()
        rows = self.store.execute_in(
            "SELECT DISTINCT kb FROM updates WHERE kb IN :kbs AND classification <> :upgrades",
            {"kbs": sorted(kbs), "upgrades": UPGRADES},
            "kbs",
        )
        return {row[0] for row in rows}

    def files_of_other_releases(self, update_id):
        """Ids of the files of the update that an entry of another version carries too."""
        rows = self.store.execute(
            "SELECT DISTINCT uf.file_id FROM update_files uf"
            " JOIN updates u ON u.id = :id"
            " JOIN update_files other ON other.file_id = uf.file_id"
            " JOIN updates o ON o.id = other.update_id AND NOT o.release_id <=> u.release_id"
            " WHERE uf.update_id = :id",
            {"id": update_id},
        )
        return {row[0] for row in rows}

    def update_files(self, update_id):
        rows = self.store.execute(
            "SELECT f.id, f.sha1, f.sha256, f.name, f.size, f.url, f.kind"
            " FROM update_files uf JOIN files f ON f.id = uf.file_id"
            " WHERE uf.update_id = :id AND uf.language IS NULL ORDER BY f.id",
            {"id": update_id},
        )
        columns = ("id", "sha1", "sha256", "name", "size", "url", "kind")
        return [dict(zip(columns, row)) for row in rows]

    def package(self, digest):
        row = self.store.execute(
            "SELECT uuid, state FROM packages WHERE files_hash = :hash",
            {"hash": digest},
        ).fetchone()
        return {"uuid": row[0], "state": row[1]} if row else None

    def save_package(self, package_id, digest, state, error=None, size=None, share=SHARE):
        self.store.execute(
            "INSERT INTO packages (uuid, files_hash, share, state, error, size,"
            " created_at, ready_at)"
            " VALUES (:uuid, :hash, :share, :state, :error, :size, NOW(),"
            " IF(:state = 'ready', NOW(), NULL))"
            " ON DUPLICATE KEY UPDATE state = VALUES(state), error = VALUES(error),"
            " size = VALUES(size), ready_at = VALUES(ready_at)",
            {
                "uuid": package_id,
                "hash": digest,
                "share": share,
                "state": state,
                "error": error[:255] if error else None,
                "size": size,
            },
        )

    def link(self, update_id, package_id):
        self.store.execute(
            "INSERT INTO update_packages (update_id, package_uuid)"
            " VALUES (:update_id, :uuid)"
            " ON DUPLICATE KEY UPDATE package_uuid = VALUES(package_uuid)",
            {"update_id": update_id, "uuid": package_id},
        )

    def needed_media(self, retry_failed):
        """Media (ESD and edition) of the upgrades launched with a scan or media step."""
        columns = ("file_name", "edition", "base_build", "architecture", "language_code",
                   "size", "sha256", "url")
        rows = self.store.execute(
            "SELECT DISTINCT %s FROM machine_upgrades m"
            " JOIN machine_reports mr ON mr.jid = m.jid"
            " JOIN media_files f ON f.file_name = m.media_file AND f.edition = mr.edition"
            " LEFT JOIN media_packages l ON l.file_name = f.file_name AND l.edition = f.edition"
            " LEFT JOIN packages p ON p.uuid = l.package_uuid"
            " WHERE m.launched_at IS NOT NULL"
            " AND (FIND_IN_SET('scan', m.steps) OR FIND_IN_SET('media', m.steps))"
            " AND (p.uuid IS NULL OR (:retry AND p.state IN ('failed', 'building')))"
            " ORDER BY f.file_name, f.edition"
            % ", ".join("f.%s" % column for column in columns),
            {"retry": int(retry_failed)},
        )
        return [dict(zip(columns, row)) for row in rows]

    def link_media(self, media, package_id):
        self.store.execute(
            "INSERT INTO media_packages (file_name, edition, package_uuid)"
            " VALUES (:file_name, :edition, :uuid)"
            " ON DUPLICATE KEY UPDATE package_uuid = VALUES(package_uuid)",
            {"file_name": media["file_name"], "edition": media["edition"], "uuid": package_id},
        )


def database_store(database):
    @contextmanager
    def open_store():
        with database.store() as store:
            yield PackageStore(store)

    return open_store


class Builder(object):
    def __init__(
        self,
        open_store,
        downloader=download,
        register=register_package,
        packages_dir=PACKAGES_DIR,
        wimlib=run_wimlib,
    ):
        self.open_store = open_store
        self.downloader = downloader
        self.register = register
        self.wimlib = wimlib
        self.packages_dir = packages_dir
        self.share_dir = os.path.join(packages_dir, "sharing", SHARE)
        self.major_dir = os.path.join(packages_dir, "sharing", MAJOR_SHARE)

    def run(self, retry_failed=False):
        with self.open_store() as store:
            update_ids = store.needed_updates(retry_failed)
        attempted = set()
        for update_id in update_ids:
            try:
                self.build_update(update_id, retry_failed, attempted)
            except Exception:
                logger.error(
                    "Package of update %s not built\n%s"
                    % (update_id, traceback.format_exc())
                )
        with self.open_store() as store:
            media_rows = store.needed_media(retry_failed)
        for media in media_rows:
            try:
                self.build_media(media, retry_failed, attempted)
            except Exception:
                logger.error(
                    "Media package of %s %s not built\n%s"
                    % (media["file_name"], media["edition"], traceback.format_exc())
                )

    def build_update(self, update_id, retry_failed, attempted):
        with self.open_store() as store:
            update = store.update(update_id)
            files = store.update_files(update_id)
            if update is not None and update["classification"] == UPGRADES:
                # Only the enablement package: the rest of the entry is the full image
                kbs = {int(m.group(1)) for m in (ENABLEMENT_NAME.search(f["name"] or "") for f in files) if m}
                files = enablement_files(
                    files, update["kb"], store.own_kbs(kbs), store.files_of_other_releases(update_id))
                if files:
                    update = dict(update, kb=files[0]["enablement_kb"])
                else:
                    update = dict(update, unsupported="no enablement package in the upgrade entry")
        if update is None:
            return
        digest = files_hash(files)
        package_id = package_uuid(digest)
        with self.open_store() as store:
            existing = store.package(digest)
            if existing and (
                existing["state"] in ("ready", "unsupported")
                or not retry_failed
                or digest in attempted
            ):
                store.link(update_id, existing["uuid"])
                return
            reason = update.get("unsupported") or unsupported_reason(files, update["kb"])
            state = "unsupported" if reason else "building"
            store.save_package(package_id, digest, state, reason)
            store.link(update_id, package_id)
        if reason:
            logger.warning(
                "Package %s unsupported for KB%s: %s"
                % (package_id, update["kb"], reason)
            )
            return
        attempted.add(digest)
        try:
            size = self.build(package_id, update, files)
        except Exception as error:
            with self.open_store() as store:
                store.save_package(package_id, digest, "failed", str(error))
            logger.warning(
                "Package %s failed for KB%s: %s" % (package_id, update["kb"], error)
            )
            return
        with self.open_store() as store:
            store.save_package(package_id, digest, "ready", size=size)
        logger.info("Package %s ready for KB%s" % (package_id, update["kb"]))

    def build(self, package_id, update, files):
        """Publish the package in the share and declare it; return its size."""
        target_file = install_target([f["name"] for f in files], update["kb"])
        if not os.path.isdir(self.share_dir):
            raise BuildFailed("share directory %s missing" % self.share_dir)
        target = os.path.join(self.share_dir, package_id)
        # Renamed in one go: an existing target is a complete build
        if not os.path.isdir(target):
            work = os.path.join(self.share_dir, ".build-" + package_id)
            if os.path.lexists(work):
                shutil.rmtree(work)
            os.mkdir(work)
            try:
                for file in files:
                    self.fetch(file, os.path.join(work, file["name"]))
                now = datetime.now()
                write_json(
                    os.path.join(work, "conf.json"),
                    configuration(package_id, update, now),
                )
                write_json(
                    os.path.join(work, "xmppdeploy.json"),
                    descriptor(
                        package_id, update, now, target_file,
                        restart=update["classification"] == UPGRADES,
                    ),
                )
                os.rename(work, target)
            except Exception:
                shutil.rmtree(work, ignore_errors=True)
                raise
        return self.publish(package_id, target)

    def publish(self, package_id, target):
        link = os.path.join(self.packages_dir, package_id)
        if not os.path.lexists(link):
            os.symlink(target, link)
        with open(os.path.join(target, "conf.json")) as source:
            conf = json.load(source)
        size = directory_size(target)
        self.register(conf, size)
        return size

    def fetch(self, file, path):
        sha1, sha256, size = self.downloader(file["url"], path)
        if sha1 != base64.b64decode(file["sha1"]):
            raise BuildFailed("SHA1 mismatch for %s" % file["name"])
        if file.get("sha256") and sha256 != base64.b64decode(file["sha256"]):
            raise BuildFailed("SHA256 mismatch for %s" % file["name"])
        if file.get("size") and size != file["size"]:
            raise BuildFailed("size mismatch for %s" % file["name"])

    def build_media(self, media, retry_failed, attempted):
        digest = media_digest(media)
        package_id = package_uuid(digest)
        name = "%s %s" % (media["file_name"], media["edition"])
        with self.open_store() as store:
            existing = store.package(digest)
            if existing and (
                existing["state"] in ("ready", "unsupported")
                or not retry_failed
                or digest in attempted
            ):
                store.link_media(media, existing["uuid"])
                return
            reason = media_unsupported_reason(media)
            store.save_package(package_id, digest, "unsupported" if reason else "building", reason,
                               share=MAJOR_SHARE)
            store.link_media(media, package_id)
        if reason:
            logger.warning("Media package %s unsupported for %s: %s" % (package_id, name, reason))
            return
        attempted.add(digest)
        try:
            size = self.build_media_package(package_id, media)
        except Exception as error:
            with self.open_store() as store:
                store.save_package(package_id, digest, "failed", str(error), share=MAJOR_SHARE)
            logger.warning("Media package %s failed for %s: %s" % (package_id, name, error))
            return
        with self.open_store() as store:
            store.save_package(package_id, digest, "ready", size=size, share=MAJOR_SHARE)
        logger.info("Media package %s ready for %s" % (package_id, name))

    def linux_package(self, family):
        """Package of a Linux family, written and registered once; its identifier."""
        package_id = linux_package_id(family)
        share_dir = self.major_dir if linux_share(family) == MAJOR_SHARE else self.share_dir
        target = os.path.join(share_dir, package_id)
        if not os.path.isdir(target):
            if not os.path.isdir(share_dir):
                raise BuildFailed("share directory %s missing" % share_dir)
            work = os.path.join(share_dir, ".build-" + package_id)
            if os.path.lexists(work):
                shutil.rmtree(work)
            os.mkdir(work)
            now = datetime.now()
            name = linux_package_name(family)
            write_json(os.path.join(work, "conf.json"),
                       base_configuration(package_id, name, name, now, "linux", linux_share(family)))
            write_json(os.path.join(work, "xmppdeploy.json"), linux_descriptor(package_id, family, now))
            os.rename(work, target)
        size = self.publish(package_id, target)
        with self.open_store() as store:
            store.save_package(package_id, hashlib.sha1(package_id.encode()).hexdigest(), "ready",
                               size=size, share=linux_share(family))
        return package_id

    def build_media_package(self, package_id, media):
        """Installation media of one edition from the ESD; the ESD is not kept."""
        if not os.path.isdir(self.major_dir):
            raise BuildFailed("share directory %s missing" % self.major_dir)
        target = os.path.join(self.major_dir, package_id)
        if not os.path.isdir(target):
            work = os.path.join(self.major_dir, ".build-" + package_id)
            if os.path.lexists(work):
                shutil.rmtree(work)
            os.mkdir(work)
            try:
                source = os.path.join(work, "source.esd")
                folder = os.path.join(work, "media")
                self.fetch_media(media, source)
                index = edition_index(wim_images(self.wimlib(["info", source])), media["edition"])
                os.mkdir(folder)
                self.wimlib(["apply", source, str(MEDIA_IMAGE), folder])
                sources = os.path.join(folder, "sources")
                if not os.path.isfile(os.path.join(folder, "setup.exe")) or not os.path.isdir(sources):
                    raise BuildFailed("image %d of %s is not a setup media" % (MEDIA_IMAGE, media["file_name"]))
                boot = os.path.join(sources, "boot.wim")
                install = os.path.join(sources, "install.esd")
                for path in (boot, install):
                    if os.path.lexists(path):
                        raise BuildFailed("%s already in image %d" % (os.path.basename(path), MEDIA_IMAGE))
                # Windows PE then Windows Setup, as in the Microsoft media
                for image in (PE_IMAGE, SETUP_IMAGE):
                    self.wimlib(["export", source, str(image), boot, "--compress=LZX"])
                self.wimlib(["export", source, index, install, "--compress=LZMS", "--solid"])
                # Never another edition than the machine one
                images = wim_images(self.wimlib(["info", install]))
                if [image.get("Edition ID", "").lower() for image in images] != [media["edition"].lower()]:
                    raise BuildFailed("install.esd does not hold edition %s alone" % media["edition"])
                os.remove(source)
                now = datetime.now()
                write_json(os.path.join(folder, "conf.json"), media_configuration(package_id, media, now))
                write_json(os.path.join(folder, "xmppdeploy.json"), media_descriptor(package_id, media, now))
                os.rename(folder, target)
                os.rmdir(work)
            except Exception:
                shutil.rmtree(work, ignore_errors=True)
                raise
        return self.publish(package_id, target)

    def fetch_media(self, media, path):
        _, sha256, size = self.downloader(media["url"], path)
        if sha256 != raw_digest(media["sha256"]):
            raise BuildFailed("SHA256 mismatch for %s" % media["file_name"])
        if media.get("size") and size != media["size"]:
            raise BuildFailed("size mismatch for %s" % media["file_name"])


# One build at a time; a request during a build runs it again afterwards
state_lock = threading.Lock()
state = {"running": False, "requested": False, "retry_failed": False}


def build_loop(builder):
    while True:
        with state_lock:
            retry_failed = state["retry_failed"]
            state["retry_failed"] = False
            state["requested"] = False
        try:
            builder.run(retry_failed)
        except Exception:
            logger.error("Updates packages build failed\n%s" % traceback.format_exc())
        with state_lock:
            if not state["requested"]:
                state["running"] = False
                return


def start_build(database, retry_failed=False, builder=None):
    """Build the missing packages in the background.

    retry_failed: also rebuild the failed packages (once per hourly run)."""
    with state_lock:
        state["retry_failed"] = state["retry_failed"] or retry_failed
        if state["running"]:
            state["requested"] = True
            return
        state["running"] = True
    threading.Thread(
        target=build_loop,
        args=(builder or Builder(database_store(database)),),
        name="updates_packages",
        daemon=True,
    ).start()
