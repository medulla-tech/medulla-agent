#!/bin/bash
#
# (c) 2016-2023 Siveo, http://www.siveo.net
# (c) 2024-2026 Medulla, http://www.medulla-tech.io
#
# This file is part of MMC, http://www.medulla-tech.io
#
# MMC is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# any later version.
#
# This script uninstalls the Medulla XMPP agent and all components
# installed by the Medulla installer.
#
# Supports: debian, ubuntu, zorin, linuxmint, raspbian, kali,
#           alpine, almalinux, fedora, nixos
# Architectures: x86_64, aarch64, armv7l
#
# Options:
#   --remove-python    : also uninstall Python 3.11 package (default: no)
#   --remove-glpi      : also uninstall GLPI Agent (default: no)
#   --help             : show this help

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------
REMOVE_PYTHON=0
REMOVE_GLPI=0
LOG_FILE="/var/log/medulla-uninstall.log"

# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------
display_usage() {
    echo ""
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  --remove-python    Uninstall Python 3.11 package installed by Medulla"
    echo "  --remove-glpi      Uninstall GLPI Agent"
    echo "  --help             Show this help"
    echo ""
}

for arg in "$@"; do
    case "$arg" in
        --remove-python) REMOVE_PYTHON=1 ;;
        --remove-glpi)   REMOVE_GLPI=1 ;;
        --help)          display_usage; exit 0 ;;
        *)
            echo "[x] Unknown option: $arg"
            display_usage
            exit 1
            ;;
    esac
done

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
log() {
    local msg="[$(date '+%Y-%m-%d %H:%M:%S')] $*"
    echo "$msg"
    echo "$msg" >> "${LOG_FILE}" 2>/dev/null || true
}

log_ok()   { log "[v] $*"; }
log_warn() { log "[!] $*"; }
log_err()  { log "[x] $*"; }

check_root() {
    if [ "$(id -u)" != "0" ]; then
        log_err "This script must be run as root"
        exit 1
    fi
}

check_distro() {
    ARCH=$(uname -m)
    if [ ! -e /etc/os-release ]; then
        log_err "Cannot determine Linux distribution"
        exit 1
    fi
    DISTRO=$(grep ^ID= /etc/os-release | cut -f2 -d'=' | sed 's/"//g')
    VERSION=$(grep ^VERSION_ID= /etc/os-release | cut -f2 -d'=' | sed 's/"//g')
    log "Detected distribution: ${DISTRO} ${VERSION} (${ARCH})"
}

# ---------------------------------------------------------------------------
# Package manager detection
# ---------------------------------------------------------------------------
detect_pkg_manager() {
    if command -v apt-get >/dev/null 2>&1; then
        PKG_MANAGER="apt"
    elif command -v dnf >/dev/null 2>&1; then
        PKG_MANAGER="dnf"
    elif command -v yum >/dev/null 2>&1; then
        PKG_MANAGER="yum"
    elif command -v apk >/dev/null 2>&1; then
        PKG_MANAGER="apk"
    elif [ "$DISTRO" = "nixos" ] || command -v nix-env >/dev/null 2>&1; then
        PKG_MANAGER="nix"
    else
        PKG_MANAGER="unknown"
    fi
    log "Detected package manager: ${PKG_MANAGER}"
}

# ---------------------------------------------------------------------------
# Step 0 - Restore python3 update-alternatives BEFORE any package operation
#
# The install script runs:
#   update-alternatives --install /usr/bin/python3 python3 /usr/bin/python3.11 1
#   update-alternatives --set python3 /usr/bin/python3.11
#
# This makes python3.11 the system-wide /usr/bin/python3. Tools like apt,
# unattended-upgrades and apt hooks rely on /usr/bin/python3 pointing to the
# distribution's own Python. If python3.11 is removed (or its venv wiped)
# while still set as the alternative, those tools break with
# "required file not found".
#
# This step ALWAYS removes the Medulla-added alternative and restores
# automatic mode, regardless of the --remove-python flag.
# ---------------------------------------------------------------------------
restore_python_alternatives() {
    log "--- Step 0: Restore python3 update-alternatives ---"

    local UA_CMD=""
    if command -v update-alternatives >/dev/null 2>&1; then
        UA_CMD="update-alternatives"
    elif command -v alternatives >/dev/null 2>&1; then
        UA_CMD="alternatives"   # RHEL / AlmaLinux name
    else
        log_warn "update-alternatives not available, skipping"
        return
    fi

    # Remove the python3.11 entry that Medulla added to the alternatives system
    if [ -x /usr/bin/python3.11 ]; then
        "${UA_CMD}" --remove python3 /usr/bin/python3.11 2>/dev/null && \
            log_ok "Removed python3 alternative for /usr/bin/python3.11" || \
            log_warn "Could not remove python3 alternative for /usr/bin/python3.11 (may not exist)"
    else
        log_warn "/usr/bin/python3.11 not found, skipping alternative removal"
    fi

    # Switch to automatic mode: the system picks the highest-priority remaining entry
    "${UA_CMD}" --auto python3 2>/dev/null && \
        log_ok "python3 alternative restored to auto mode" || \
        log_warn "Could not set python3 to auto mode"

    # Safety check: if /usr/bin/python3 is still broken, try to repair it
    local CURRENT_PY3
    CURRENT_PY3=$(readlink -f /usr/bin/python3 2>/dev/null || true)
    if [ -z "${CURRENT_PY3}" ] || [ ! -x "${CURRENT_PY3}" ]; then
        log_warn "/usr/bin/python3 is broken or missing, attempting repair..."
        # Find the best available system python3 (e.g. python3.10, python3.12)
        local FALLBACK_PY3
        FALLBACK_PY3=$(ls /usr/bin/python3.* 2>/dev/null \
            | grep -E '/usr/bin/python3\.[0-9]+$' \
            | grep -v python3.11 \
            | sort -V | tail -1 || true)
        if [ -n "${FALLBACK_PY3}" ] && [ -x "${FALLBACK_PY3}" ]; then
            "${UA_CMD}" --install /usr/bin/python3 python3 "${FALLBACK_PY3}" 1 2>/dev/null
            "${UA_CMD}" --set python3 "${FALLBACK_PY3}" 2>/dev/null && \
                log_ok "Restored python3 -> ${FALLBACK_PY3}" || \
                log_warn "Could not restore python3 alternative to ${FALLBACK_PY3}"
        else
            log_warn "No fallback python3 found. /usr/bin/python3 may remain broken."
        fi
    else
        log_ok "python3 is now -> ${CURRENT_PY3}"
    fi

    log_ok "Step 0 done"
}

# ---------------------------------------------------------------------------
# Step 1 - Stop and disable the Medulla agent service
# ---------------------------------------------------------------------------
stop_service() {
    log "--- Step 1: Stop and disable Medulla agent service ---"

    if [ "$DISTRO" = "nixos" ]; then
        systemctl stop pulse-xmpp-agent-machine.service 2>/dev/null || true
        systemctl disable pulse-xmpp-agent-machine.service 2>/dev/null || true
        # Remove NixOS module
        if [ -f /etc/nixos/medulla-agent.nix ]; then
            rm -f /etc/nixos/medulla-agent.nix
            sed -i 's|./medulla-agent.nix||' /etc/nixos/configuration.nix 2>/dev/null || true
            nixos-rebuild switch --no-build-output 2>/dev/null || \
                log_warn "nixos-rebuild switch failed, manual cleanup may be required"
            log_ok "NixOS medulla-agent.nix module removed"
        fi
        rm -f /run/systemd/system/pulse-xmpp-agent-machine.service
    else
        systemctl stop pulse-xmpp-agent-machine.service 2>/dev/null && \
            log_ok "Service stopped" || log_warn "Service was not running"
        systemctl disable pulse-xmpp-agent-machine.service 2>/dev/null && \
            log_ok "Service disabled" || log_warn "Service was not enabled"
    fi

    systemctl daemon-reload 2>/dev/null || true

    # Remove service unit files
    for svc_file in \
        /usr/lib/systemd/system/pulse-xmpp-agent-machine.service \
        /etc/systemd/system/pulse-xmpp-agent-machine.service \
        /run/systemd/system/pulse-xmpp-agent-machine.service
    do
        if [ -f "${svc_file}" ]; then
            rm -f "${svc_file}"
            log_ok "Removed ${svc_file}"
        fi
    done

    systemctl daemon-reload 2>/dev/null || true
    log_ok "Step 1 done"
}

# ---------------------------------------------------------------------------
# Step 2 - Uninstall Medulla XMPP agent (venv + config)
# ---------------------------------------------------------------------------
remove_agent() {
    log "--- Step 2: Uninstall Medulla XMPP agent ---"

    if [ -d /opt/medulla ]; then
        rm -rf /opt/medulla
        log_ok "Removed /opt/medulla (venv)"
    else
        log_warn "/opt/medulla not found, skipped"
    fi

    if [ -d /etc/pulse-xmpp-agent ]; then
        rm -rf /etc/pulse-xmpp-agent
        log_ok "Removed /etc/pulse-xmpp-agent"
    else
        log_warn "/etc/pulse-xmpp-agent not found, skipped"
    fi

    if [ -d /var/log/pulse ]; then
        rm -rf /var/log/pulse
        log_ok "Removed /var/log/pulse"
    else
        log_warn "/var/log/pulse not found, skipped"
    fi

    rm -rf /tmp/medulla /tmp/medulla-config
    log_ok "Step 2 done"
}

# ---------------------------------------------------------------------------
# Step 3 - Remove CA certificates installed by Medulla
# ---------------------------------------------------------------------------
remove_certificates() {
    log "--- Step 3: Remove Medulla CA certificates ---"

    case "$DISTRO" in
        almalinux|fedora)
            local CERT_DIR="/etc/pki/ca-trust/source/anchors"
            rm -f "${CERT_DIR}/medulla-ca-chain.cert.pem" \
                  "${CERT_DIR}/medulla-rootca.cert.pem"
            update-ca-trust extract 2>/dev/null || true
            log_ok "CA certificates removed (RPM-based)"
            ;;
        nixos)
            rm -rf /opt/medulla/certs 2>/dev/null || true
            rm -f /etc/ssl/certs/medulla-ca-chain.cert.pem \
                  /etc/ssl/certs/medulla-rootca.cert.pem 2>/dev/null || true
            sed -i '/SSL_CERT_DIR.*medulla/d' /etc/environment 2>/dev/null || true
            log_ok "CA certificates removed (NixOS)"
            ;;
        *)
            local CERT_DIR="/usr/local/share/ca-certificates"
            rm -f "${CERT_DIR}/medulla-ca-chain.cert.pem" \
                  "${CERT_DIR}/medulla-ca-chain.crt" \
                  "${CERT_DIR}/medulla-rootca.cert.pem" \
                  "${CERT_DIR}/medulla-rootca.crt"
            update-ca-certificates --fresh 2>/dev/null || true
            log_ok "CA certificates removed (Debian-based)"
            ;;
    esac

    log_ok "Step 3 done"
}

# ---------------------------------------------------------------------------
# Step 4 - Remove pulseuser and SSH configuration
# ---------------------------------------------------------------------------
remove_pulseuser() {
    log "--- Step 4: Remove pulseuser and SSH configuration ---"

    if [ -f /etc/sudoers.d/pulseuser ]; then
        rm -f /etc/sudoers.d/pulseuser
        log_ok "Removed /etc/sudoers.d/pulseuser"
    fi

    if id -u pulseuser >/dev/null 2>&1; then
        userdel -r pulseuser 2>/dev/null || userdel pulseuser 2>/dev/null || true
        rm -rf /home/pulseuser
        log_ok "Removed pulseuser"
    else
        log_warn "pulseuser not found, skipped"
    fi

    if [ -f /etc/ssh/sshd_config.d/medulla.conf ]; then
        rm -f /etc/ssh/sshd_config.d/medulla.conf
        log_ok "Removed /etc/ssh/sshd_config.d/medulla.conf"
        case "$DISTRO" in
            almalinux|fedora|nixos) systemctl restart sshd 2>/dev/null || true ;;
            *) systemctl restart ssh 2>/dev/null || true ;;
        esac
    fi

    log_ok "Step 4 done"
}

# ---------------------------------------------------------------------------
# Step 5 - Remove packages installed for Medulla
# ---------------------------------------------------------------------------
remove_packages_apt() {
    log "Removing Medulla-specific apt packages..."
    local PKGS="x11vnc xrdp syncthing"
    apt-get remove -y --purge ${PKGS} 2>/dev/null || true
    apt-get autoremove -y 2>/dev/null || true
    log_ok "apt packages removed: ${PKGS}"

    if [ "${REMOVE_PYTHON}" -eq 1 ]; then
        log "Removing Python 3.11 package (--remove-python)..."
        apt-get remove -y --purge \
            python3.11 python3.11-venv python3.11-dev python3.11-distutils 2>/dev/null || true
        apt-get autoremove -y 2>/dev/null || true
        # Remove deadsnakes PPA if it was added (Ubuntu)
        rm -f /etc/apt/sources.list.d/deadsnakes-ubuntu-ppa-noble.sources 2>/dev/null || true
        apt-get update 2>/dev/null || true
        log_ok "Python 3.11 package removed"
    else
        log_warn "Python 3.11 package kept (use --remove-python to uninstall)"
    fi

    if [ "${REMOVE_GLPI}" -eq 1 ]; then
        log "Removing GLPI Agent (--remove-glpi)..."
        apt-get remove -y --purge glpi-agent 2>/dev/null || true
        apt-get autoremove -y 2>/dev/null || true
        log_ok "GLPI Agent removed"
    else
        log_warn "GLPI Agent kept (use --remove-glpi to uninstall)"
    fi
}

remove_packages_dnf() {
    log "Removing Medulla-specific dnf packages..."
    local PKGS="x11vnc xrdp syncthing"
    dnf remove -y ${PKGS} 2>/dev/null || true
    log_ok "dnf packages removed: ${PKGS}"

    if [ "${REMOVE_PYTHON}" -eq 1 ]; then
        log "Removing Python 3.11 package (--remove-python)..."
        dnf remove -y python3.11 python3.11-devel 2>/dev/null || true
        log_ok "Python 3.11 package removed"
    else
        log_warn "Python 3.11 package kept (use --remove-python to uninstall)"
    fi

    if [ "${REMOVE_GLPI}" -eq 1 ]; then
        log "Removing GLPI Agent (--remove-glpi)..."
        dnf remove -y glpi-agent 2>/dev/null || true
        log_ok "GLPI Agent removed"
    else
        log_warn "GLPI Agent kept (use --remove-glpi to uninstall)"
    fi
}

remove_packages_apk() {
    log "Removing Medulla-specific apk packages..."
    local PKGS="xrdp syncthing x11vnc"
    apk del ${PKGS} 2>/dev/null || true
    log_ok "apk packages removed: ${PKGS}"

    if [ "${REMOVE_PYTHON}" -eq 1 ]; then
        log "Removing Python 3.11 package (--remove-python)..."
        apk del python3.11 2>/dev/null || true
        log_ok "Python 3.11 package removed"
    else
        log_warn "Python 3.11 package kept (use --remove-python to uninstall)"
    fi

    if [ "${REMOVE_GLPI}" -eq 1 ]; then
        log "Removing GLPI Agent (--remove-glpi)..."
        apk del glpi-agent 2>/dev/null || true
        log_ok "GLPI Agent removed"
    else
        log_warn "GLPI Agent kept (use --remove-glpi to uninstall)"
    fi
}

remove_packages_nixos() {
    log "Removing Medulla-specific nix packages..."
    for pkg in x11vnc xrdp syncthing; do
        nix-env -e "${pkg}" 2>/dev/null && log_ok "Removed nix package: ${pkg}" \
            || log_warn "nix package not found (skipped): ${pkg}"
    done

    if [ -f /etc/nixos/configuration.nix ]; then
        sed -i '/services.xrdp.enable/d' /etc/nixos/configuration.nix 2>/dev/null || true
        sed -i '/services.openssh/d'     /etc/nixos/configuration.nix 2>/dev/null || true
    fi

    if [ "${REMOVE_PYTHON}" -eq 1 ]; then
        log "Removing Python 3.11 (--remove-python)..."
        nix-env -e python311 2>/dev/null || true
        log_ok "Python 3.11 removed from nix profile"
    else
        log_warn "Python 3.11 kept (use --remove-python to uninstall)"
    fi

    if [ "${REMOVE_GLPI}" -eq 1 ]; then
        log "Removing GLPI Agent (--remove-glpi)..."
        nix-env -e glpi-agent 2>/dev/null || true
        rpm -e glpi-agent 2>/dev/null || true
        log_ok "GLPI Agent removed"
    else
        log_warn "GLPI Agent kept (use --remove-glpi to uninstall)"
    fi

    nixos-rebuild switch --no-build-output 2>/dev/null || \
        log_warn "nixos-rebuild switch failed, manual cleanup may be required"
}

remove_packages() {
    log "--- Step 5: Remove packages ---"

    case "${PKG_MANAGER}" in
        apt)     remove_packages_apt    ;;
        dnf|yum) remove_packages_dnf   ;;
        apk)     remove_packages_apk   ;;
        nix)     remove_packages_nixos ;;
        *)       log_warn "No supported package manager found (${PKG_MANAGER}), skipping package removal" ;;
    esac

    log_ok "Step 5 done"
}

# ---------------------------------------------------------------------------
# Step 6 - Remove GLPI temp files
# ---------------------------------------------------------------------------
remove_glpi_temp() {
    rm -f /tmp/medulla/"@@GLPI_AGENT_FILENAME@@" 2>/dev/null || true
    rm -f /tmp/medulla/"@@GLPI_AGENT_DEB_FILENAME@@" 2>/dev/null || true
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
check_root
check_distro
detect_pkg_manager

log "================================================"
log " Medulla Agent Uninstall - Start"
log " Log: ${LOG_FILE}"
log "================================================"
log ""

# Step 0 MUST run first: restores /usr/bin/python3 BEFORE any apt/dnf call
restore_python_alternatives
stop_service
remove_agent
remove_certificates
remove_pulseuser
remove_packages
remove_glpi_temp

log ""
log "================================================"
log " Medulla Agent Uninstall - DONE"
log " Full log: ${LOG_FILE}"
log "================================================"
