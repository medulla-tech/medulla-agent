#!/bin/bash
# -*- coding: utf-8 -*-
#
# (c) 2017 siveo, http://www.siveo.net
# (c) 2024-2025 Medulla, http://www.medulla-tech.io
#
# This file is part of Medulla, http://www.medulla-tech.io
#
# Medulla is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This script generates a .pkg installer for the Medulla XMPP agent on macOS.
# Target: ARM64 (Apple Silicon: M1, M2, M3, M4)
# It runs on the Medulla server (Linux) and produces a .pkg that can be deployed on Macs.
# The user just double-clicks the .pkg, enters admin password, and the agent is installed.
#
# Requirements on the server:
#   - xar + mkbom (for building .pkg on Linux)
#   - Python wheels in /var/lib/pulse2/clients/mac/downloads/python_modules/
#   - Agent code in /usr/lib/python3/dist-packages/pulse_xmpp_agent/
#   - Certificates in /var/lib/pulse2/clients/medulla-{rootca,ca-chain}.cert.pem
#   - Config in /var/lib/pulse2/clients/config/agentconf.ini

AGENT_VERSION="5.6.1"
PYTHON_VERSION="3.11"
GLPI_AGENT_VERSION="1.17"

# Go to own folder
cd "$(dirname $0)"

# Paths
CLIENTS_DIR="/var/lib/pulse2/clients"
MAC_DIR="${CLIENTS_DIR}/mac"
WHEELS_DIR="${MAC_DIR}/downloads/python_modules"
CONFIG_DIR="${CLIENTS_DIR}/config"
AGENT_SRC="/usr/lib/python3/dist-packages/pulse_xmpp_agent"
BUILD_DIR="/tmp/medulla-mac-build"
DMG_STAGING="${BUILD_DIR}/dmg"
# ARM64 = Apple Silicon (M1, M2, M3, M4)
# Pour Mac Intel, utiliser des wheels x86_64 et changer en Medulla-Agent-mac-x86_64
PKG_NAME="Medulla-Agent-mac-ARM64"

# ============================================================
# Arguments (same interface as win/linux generate scripts)
# ============================================================
display_usage() {
    echo "Usage: $0 --minimal [options]"
    echo "  --conf-xmppserver=<server>    XMPP server (read from config if not set)"
    echo "  --conf-xmppport=<port>        XMPP port (default: 5222)"
    echo "  --conf-xmpppasswd=<passwd>    XMPP password"
    echo "  --aes-key=<key>               AES key (32 chars)"
    echo "  --xmpp-passwd=<passwd>        XMPP connection password"
    echo "  --chat-domain=<domain>        XMPP domain (default: pulse)"
    echo "  --base-url=<url>              Base URL for downloads"
    echo "  --inventory-tag=<tag>         Inventory tag"
    echo "  --minimal                     Minimal install (required)"
}

check_arguments() {
    for i in "$@"; do
        case $i in
            --conf-xmppserver=*)  CONF_SERVER="${i#*=}" ;;
            --conf-xmppport=*)    CONF_PORT="${i#*=}" ;;
            --conf-xmpppasswd=*)  CONF_PASSWORD="${i#*=}" ;;
            --aes-key=*)          AES_KEY="${i#*=}" ;;
            --xmpp-passwd=*)      XMPP_PASSWORD="${i#*=}" ;;
            --chat-domain=*)      CONF_DOMAIN="${i#*=}" ;;
            --base-url=*)         BASE_URL="${i#*=}" ;;
            --inventory-tag=*)    INVENTORY_TAG="${i#*=}" ;;
            --minimal*)           MINIMAL=1 ;;
            --disable-vnc*)       ;;
            --vnc-port*)          ;;
            --vnc-password*)      ;;
            --ssh-port*)          ;;
            --disable-rdp*)       ;;
            --disable-inventory*) ;;
            --enable-geoloc*)     ;;
            --disable-geoloc*)    ;;
            --linux-distros*)     ;;
            --updateserver*)      ;;
            --help|-h)            display_usage; exit 0 ;;
            *)                    ;;
        esac
    done

    # Read defaults from existing config if not provided
    if [ -f "${CONFIG_DIR}/agentconf.ini" ]; then
        [ -z "$CONF_SERVER" ] && CONF_SERVER=$(grep "^confserver" "${CONFIG_DIR}/agentconf.ini" | cut -d= -f2 | tr -d ' ')
        [ -z "$CONF_PORT" ] && CONF_PORT=$(grep "^confport" "${CONFIG_DIR}/agentconf.ini" | cut -d= -f2 | tr -d ' ')
        [ -z "$CONF_PASSWORD" ] && CONF_PASSWORD=$(grep "^confpassword" "${CONFIG_DIR}/agentconf.ini" | cut -d= -f2 | tr -d ' ')
        [ -z "$CONF_DOMAIN" ] && CONF_DOMAIN=$(grep "^confdomain" "${CONFIG_DIR}/agentconf.ini" | cut -d= -f2 | tr -d ' ')
        [ -z "$AES_KEY" ] && AES_KEY=$(grep "^keyAES32" "${CONFIG_DIR}/agentconf.ini" | cut -d= -f2 | tr -d ' ')
        [ -z "$XMPP_PASSWORD" ] && XMPP_PASSWORD=$(grep "^password" "${CONFIG_DIR}/agentconf.ini" | head -1 | cut -d= -f2 | tr -d ' ')
    fi

    [ -z "$CONF_PORT" ] && CONF_PORT="5222"
    [ -z "$CONF_DOMAIN" ] && CONF_DOMAIN="pulse"
    [ -z "$XMPP_PASSWORD" ] && XMPP_PASSWORD="$CONF_PASSWORD"
}

colored_echo() {
    local color=$1; shift
    case $(echo $color | tr '[:upper:]' '[:lower:]') in
        red) tput setaf 1 2>/dev/null ;; green) tput setaf 2 2>/dev/null ;;
        blue) tput setaf 4 2>/dev/null ;; yellow) tput setaf 3 2>/dev/null ;;
    esac
    echo "$@"
    tput sgr0 2>/dev/null
}

# ============================================================
# Build the DMG contents
# ============================================================
build_dmg_contents() {
    colored_echo blue "Preparing DMG contents..."

    rm -rf ${BUILD_DIR}
    mkdir -p ${DMG_STAGING}

    # -- 1. Wheels (hidden) --
    if [ -d "${WHEELS_DIR}" ]; then
        cp -r "${WHEELS_DIR}" "${DMG_STAGING}/.wheels"
        colored_echo green "  Wheels: $(ls ${DMG_STAGING}/.wheels/ | wc -l) files"
    else
        colored_echo red "  ERROR: No wheels in ${WHEELS_DIR}"
        exit 1
    fi

    # -- 2. Agent code (hidden) --
    if [ -d "${AGENT_SRC}" ]; then
        cp -r "${AGENT_SRC}" "${DMG_STAGING}/.pulse_xmpp_agent"
        # Create setup.py so pip install -e works (registers pulse_xmpp_agent as a package)
        cat > "${DMG_STAGING}/.setup.py" <<'SETUPEOF'
from setuptools import setup
setup(name="pulse_xmpp_agent", version="5.5.0", packages=["pulse_xmpp_agent"])
SETUPEOF
        # Pre-install only bootstrap plugins (server sends the rest via installplugin)
        BASEPLUGINS="/var/lib/pulse2/xmpp_baseplugin"
        if [ -d "$BASEPLUGINS" ]; then
            cp ${BASEPLUGINS}/plugin_installplugin.py "${DMG_STAGING}/.pulse_xmpp_agent/pluginsmachine/" 2>/dev/null
            cp ${BASEPLUGINS}/plugin_installpluginscheduled.py "${DMG_STAGING}/.pulse_xmpp_agent/pluginsmachine/" 2>/dev/null
            colored_echo green "  Agent code: OK (with bootstrap plugins)"
        else
            colored_echo green "  Agent code: OK"
        fi
    else
        colored_echo red "  ERROR: Agent code not found in ${AGENT_SRC}"
        exit 1
    fi

    # -- 2b. Python 3.11 pkg (embedded, installed if missing) --
    PYTHON_PKG="${MAC_DIR}/downloads/python-3.11.9-macos11.pkg"
    if [ -f "$PYTHON_PKG" ]; then
        cp "$PYTHON_PKG" "${DMG_STAGING}/.python3.11.pkg"
        colored_echo green "  Python 3.11: embedded"
    else
        colored_echo yellow "  WARN: Python pkg not found at ${PYTHON_PKG}"
    fi

    # -- 2c. GLPI Agent pkg (embedded, not downloaded at install) --
    GLPI_PKG="${MAC_DIR}/downloads/GLPI-Agent-${GLPI_AGENT_VERSION}_arm64.pkg"
    if [ -f "$GLPI_PKG" ]; then
        cp "$GLPI_PKG" "${DMG_STAGING}/.glpi-agent.pkg"
        colored_echo green "  GLPI Agent: embedded"
    else
        colored_echo yellow "  WARN: GLPI Agent pkg not found at ${GLPI_PKG}"
    fi

    # -- 3. Certificates (hidden) --
    mkdir -p "${DMG_STAGING}/.certs"
    for cert in medulla-rootca.cert.pem medulla-ca-chain.cert.pem; do
        if [ -f "${CLIENTS_DIR}/${cert}" ]; then
            cp "${CLIENTS_DIR}/${cert}" "${DMG_STAGING}/.certs/"
        fi
    done
    colored_echo green "  Certificates: $(ls ${DMG_STAGING}/.certs/ 2>/dev/null | wc -l) files"

    # -- 4. Configuration (hidden) --
    mkdir -p "${DMG_STAGING}/.config"
    for ini in agentconf.ini agentconf.ini.tpl inventory.ini manage_scheduler_machine.ini \
               start_machine.ini startupdate.ini updatebackupclient.ini am___server_tcpip.ini; do
        [ -f "${CONFIG_DIR}/${ini}" ] && cp "${CONFIG_DIR}/${ini}" "${DMG_STAGING}/.config/"
    done
    # Override server in agentconf.ini if provided
    if [ -n "$CONF_SERVER" ] && [ -f "${DMG_STAGING}/.config/agentconf.ini" ]; then
        sed -i'' "s/^server =.*/server = ${CONF_SERVER}/" "${DMG_STAGING}/.config/agentconf.ini"
    fi
    colored_echo green "  Config: $(ls ${DMG_STAGING}/.config/ | wc -l) files"

    # -- 5. Volume icon --
    if [ -f "${MAC_DIR}/downloads/VolumeIcon.icns" ]; then
        cp "${MAC_DIR}/downloads/VolumeIcon.icns" "${DMG_STAGING}/.VolumeIcon.icns"
    fi

    # -- 6. Postinstall script --
    mkdir -p "${DMG_STAGING}/.scripts"
    generate_install_script "${DMG_STAGING}/.scripts"
    # Rename to postinstall (convention .pkg)
    mv "${DMG_STAGING}/.scripts/install-medulla-agent.sh" "${DMG_STAGING}/.scripts/postinstall"
    colored_echo green "  Postinstall script: OK"
}

# ============================================================
# Generate a clickable .app wrapper (double-click to install)
# ============================================================
generate_installer_app() {
    APP_DIR="${DMG_STAGING}/Installer Medulla Agent.app"
    mkdir -p "${APP_DIR}/Contents/MacOS"
    mkdir -p "${APP_DIR}/Contents/Resources"

    # Copy icon if available
    if [ -f "${DMG_STAGING}/.VolumeIcon.icns" ]; then
        cp "${DMG_STAGING}/.VolumeIcon.icns" "${APP_DIR}/Contents/Resources/AppIcon.icns"
    fi

    # Info.plist
    cat > "${APP_DIR}/Contents/Info.plist" <<PLISTEOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleExecutable</key>
    <string>launcher</string>
    <key>CFBundleIdentifier</key>
    <string>io.medulla.agent.installer</string>
    <key>CFBundleName</key>
    <string>Installer Medulla Agent</string>
    <key>CFBundleVersion</key>
    <string>${AGENT_VERSION}</string>
    <key>CFBundleShortVersionString</key>
    <string>${AGENT_VERSION}</string>
    <key>CFBundleIconFile</key>
    <string>AppIcon</string>
    <key>LSMinimumSystemVersion</key>
    <string>11.0</string>
    <key>NSHighResolutionCapable</key>
    <true/>
</dict>
</plist>
PLISTEOF

    # Launcher script - asks for admin password via osascript then runs install
    cat > "${APP_DIR}/Contents/MacOS/launcher" <<'LAUNCHEOF'
#!/bin/bash
# Find the DMG mount point (parent of the .app)
DMG_DIR="$(cd "$(dirname "$0")/../../.." && pwd)"
INSTALL_SCRIPT="$(dirname "$0")/../Resources/install-medulla-agent.sh"

if [ ! -f "$INSTALL_SCRIPT" ]; then
    osascript -e 'display alert "Erreur" message "Script introuvable." as critical'
    exit 1
fi

# Run install with admin privileges, passing the DMG path
osascript <<EOF
do shell script "bash '${INSTALL_SCRIPT}' '${DMG_DIR}'" with administrator privileges
EOF

if [ $? -eq 0 ]; then
    osascript -e 'display alert "Installation terminee" message "L'\''agent Medulla a ete installe avec succes." as informational'
else
    osascript -e 'display alert "Erreur" message "L'\''installation a echoue. Consultez les logs dans /var/log/medulla/" as critical'
fi
LAUNCHEOF

    chmod +x "${APP_DIR}/Contents/MacOS/launcher"

    # Put the install script inside the .app Resources
    generate_install_script "${APP_DIR}/Contents/Resources"
}

# ============================================================
# Generate the install script (runs on the Mac)
# ============================================================
generate_install_script() {
    local DEST_DIR="${1:-${DMG_STAGING}}"
    cat > "${DEST_DIR}/install-medulla-agent.sh" <<'INSTALLEOF'
#!/bin/bash
# Medulla Agent macOS ARM64 - Installer
# Called by the .app launcher with the DMG path as $1

INSTALL_DIR="/opt/medulla"
CONF_DIR="/etc/medulla"
LOG_DIR="/var/log/medulla"
PLIST_PATH="/Library/LaunchDaemons/io.medulla.agent.plist"
PYTHON_VERSION="3.11"
GLPI_AGENT_VERSION="@@GLPI_AGENT_VERSION@@"

[ "$(id -u)" -ne 0 ] && echo "Lancez avec: sudo bash $0" && exit 1
[ "$(uname)" != "Darwin" ] && echo "macOS uniquement" && exit 1

# Le .pkg installe les fichiers dans /opt/medulla/ (pkg_install_location)
DIR="${INSTALL_DIR}"
log() { echo "[Medulla] $1"; }

# ---- Stop existing ----
launchctl bootout system/io.medulla.agent 2>/dev/null
killall -9 Python 2>/dev/null
sleep 1

# ---- Xcode Command Line Tools (needed to compile netifaces, slixmpp) ----
if ! xcode-select -p &>/dev/null; then
    log "Installation des Xcode Command Line Tools..."
    touch /tmp/.com.apple.dt.CommandLineTools.installondemand.in-progress
    XCODE_PKG=$(softwareupdate -l 2>/dev/null | grep -o ".*Command Line Tools.*" | head -1 | sed 's/^[* ]*//')
    if [ -n "$XCODE_PKG" ]; then
        softwareupdate -i "$XCODE_PKG" 2>/dev/null
    fi
    rm -f /tmp/.com.apple.dt.CommandLineTools.installondemand.in-progress
fi

# ---- Homebrew + Python 3.11 (native ARM64, required for ARM64 wheels) ----
export PATH="/opt/homebrew/bin:/usr/local/bin:$PATH"

# Install Homebrew if missing
if [ ! -x /opt/homebrew/bin/brew ] && [ ! -x /usr/local/bin/brew ]; then
    log "Installation de Homebrew..."
    # Homebrew cannot install as root, find the console user
    CONSOLE_USER=$(stat -f "%Su" /dev/console 2>/dev/null)
    if [ -n "$CONSOLE_USER" ] && [ "$CONSOLE_USER" != "root" ]; then
        sudo -u "$CONSOLE_USER" /bin/bash -c 'NONINTERACTIVE=1 /bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"' 2>&1 | tail -3
    fi
fi

# Install Python 3.11 via Homebrew if missing
PYTHON_BIN=""
for p in /opt/homebrew/opt/python@${PYTHON_VERSION}/bin/python${PYTHON_VERSION} \
         /opt/homebrew/bin/python${PYTHON_VERSION} \
         /usr/local/opt/python@${PYTHON_VERSION}/bin/python${PYTHON_VERSION}; do
    [ -x "$p" ] && PYTHON_BIN="$p" && break
done
if [ -z "$PYTHON_BIN" ]; then
    log "Installation de Python ${PYTHON_VERSION} via Homebrew..."
    CONSOLE_USER=$(stat -f "%Su" /dev/console 2>/dev/null)
    if [ -n "$CONSOLE_USER" ] && [ "$CONSOLE_USER" != "root" ]; then
        sudo -u "$CONSOLE_USER" /opt/homebrew/bin/brew install python@${PYTHON_VERSION} 2>&1 | tail -3
    fi
    for p in /opt/homebrew/opt/python@${PYTHON_VERSION}/bin/python${PYTHON_VERSION} \
             /opt/homebrew/bin/python${PYTHON_VERSION}; do
        [ -x "$p" ] && PYTHON_BIN="$p" && break
    done
fi

# Install Python from embedded pkg or download from python.org
if [ -z "$PYTHON_BIN" ]; then
    if [ -f "${DIR}/.python3.11.pkg" ]; then
        log "Installation de Python ${PYTHON_VERSION} depuis le pkg embarque..."
        installer -pkg "${DIR}/.python3.11.pkg" -target / 2>/dev/null
    else
        log "Telechargement de Python ${PYTHON_VERSION} depuis python.org..."
        PYTHON_DL="/tmp/python-${PYTHON_VERSION}.pkg"
        curl -sLo "$PYTHON_DL" "https://www.python.org/ftp/python/3.11.9/python-3.11.9-macos11.pkg"
        [ -f "$PYTHON_DL" ] && [ -s "$PYTHON_DL" ] && installer -pkg "$PYTHON_DL" -target / 2>/dev/null
        rm -f "$PYTHON_DL"
    fi
    PYTHON_BIN="/Library/Frameworks/Python.framework/Versions/${PYTHON_VERSION}/bin/python${PYTHON_VERSION}"
fi

if [ ! -x "$PYTHON_BIN" ]; then
    log "ERREUR: Python ${PYTHON_VERSION} introuvable"
    exit 1
fi
log "Python: $PYTHON_BIN"

# ---- Create medullauser (same as Linux) ----
if ! id -u medullauser >/dev/null 2>&1; then
    log "Creation de l'utilisateur medullauser..."
    sysadminctl -addUser medullauser -fullName "Medulla User" -shell /bin/bash -home /var/lib/medulla 2>/dev/null || \
    dscl . -create /Users/medullauser 2>/dev/null
    dscl . -create /Users/medullauser UserShell /bin/bash 2>/dev/null
    dscl . -create /Users/medullauser NFSHomeDirectory /var/lib/medulla 2>/dev/null
    dscl . -create /Users/medullauser UniqueID 499 2>/dev/null
    dscl . -create /Users/medullauser PrimaryGroupID 20 2>/dev/null
fi
# Ensure shell is /bin/bash (needed for rsync/SSH)
dscl . -change /Users/medullauser UserShell /usr/bin/false /bin/bash 2>/dev/null
# Allow SSH access for medullauser
dseditgroup -o edit -a medullauser -t user com.apple.access_ssh 2>/dev/null
dseditgroup -o edit -a medullauser -t user com.apple.access_screensharing 2>/dev/null
mkdir -p /var/lib/medulla/.ssh
touch /var/lib/medulla/.ssh/authorized_keys
chmod 700 /var/lib/medulla/.ssh
chmod 600 /var/lib/medulla/.ssh/authorized_keys
chown -R medullauser:staff /var/lib/medulla/.ssh 2>/dev/null

# ---- Directories ----
log "Creation de l'arborescence..."
mkdir -p ${INSTALL_DIR}/{var/log,tmp,etc,certs,packages}
mkdir -p ${INSTALL_DIR}/pulse_xmpp_agent/lib/INFOSTMP
chmod 777 ${INSTALL_DIR}/pulse_xmpp_agent/lib/INFOSTMP
chown medullauser:staff ${INSTALL_DIR}/packages
mkdir -p ${CONF_DIR} ${LOG_DIR}
# INSTALL_DIR is already /opt/medulla, no symlink needed

# ---- Copy config (from pkg payload to /etc) ----
log "Installation de la configuration..."
for ini in "${DIR}"/config/*.ini "${DIR}"/config/*.tpl; do
    [ -f "$ini" ] && cp "$ini" ${CONF_DIR}/
done
ln -sf ${CONF_DIR}/* ${INSTALL_DIR}/etc/ 2>/dev/null

# ---- Copy certificates ----
log "Installation des certificats..."
cp "${DIR}"/certs/*.pem ${INSTALL_DIR}/certs/ 2>/dev/null

# ---- Venv + dependencies ----
log "Creation du venv Python..."
rm -rf ${INSTALL_DIR}/venv 2>/dev/null
# Force ARM64 architecture (pkg sandbox may run under Rosetta x86_64)
arch -arm64 ${PYTHON_BIN} -m venv ${INSTALL_DIR}/venv
chmod -R 755 ${INSTALL_DIR}/venv
PIP="${INSTALL_DIR}/venv/bin/pip"
arch -arm64 ${PIP} install --upgrade pip setuptools wheel 2>/dev/null

log "Installation des dependances..."
# Force ARM64 for all pip operations (pkg sandbox may use Rosetta)
APIP="arch -arm64 ${PIP}"
# Install wheels one by one with --no-deps to avoid dependency conflicts
WHEEL_COUNT=0
for whl in ${DIR}/wheels/*.whl; do
    [ -f "$whl" ] && ${APIP} install --no-deps "$whl" 2>/dev/null && WHEEL_COUNT=$((WHEEL_COUNT+1))
done
log "Installed $WHEEL_COUNT wheels from package"
# Source packages (slixmpp - needs compilation)
for src in ${DIR}/wheels/*.tar.gz; do
    [ -f "$src" ] && ${APIP} install "$src" 2>&1 | tail -2
done
# Install sub-dependencies not included in wheels (--no-deps skipped them)
${APIP} install --upgrade pip setuptools 2>/dev/null
${APIP} install certifi requests urllib3 charset-normalizer idna cherrypy 2>/dev/null
# Verify and fallback from PyPI if needed
MISSING=""
for mod in psutil Crypto yaml lxml cherrypy croniter netaddr lmdb posix_ipc requests OpenSSL configparser distro netifaces slixmpp pycurl wakeonlan aiofiles websockets; do
    arch -arm64 ${INSTALL_DIR}/venv/bin/python3 -c "import $mod" 2>/dev/null || MISSING="$MISSING $mod"
done
if [ -n "$MISSING" ]; then
    log "Modules manquants:$MISSING - installation depuis PyPI..."
    ${APIP} install psutil pycryptodome PyYAML lxml cherrypy croniter netaddr \
        lmdb posix_ipc requests pyOpenSSL configparser distro netifaces-plus \
        slixmpp==1.8.5 pycurl wakeonlan aiofiles websockets 2>&1 | tail -5
fi
log "Dependances installees ($(${PIP} list 2>/dev/null | wc -l | tr -d ' ') packages)"

# Register pulse_xmpp_agent as a Python package (same as deb does with setup.py install)
if [ -f "${INSTALL_DIR}/setup.py" ]; then
    ${APIP} install -e "${INSTALL_DIR}" --no-deps 2>/dev/null
    log "Package pulse_xmpp_agent enregistre"
fi

# System Python: install deps if using Homebrew Python (subprocess uses sys.executable)
SYSPIP=""
for sp in /opt/homebrew/opt/python@${PYTHON_VERSION}/bin/pip${PYTHON_VERSION} \
          /opt/homebrew/bin/pip${PYTHON_VERSION}; do
    [ -x "$sp" ] && SYSPIP="$sp" && break
done
if [ -n "$SYSPIP" ]; then
    log "Installation dependances systeme (Homebrew)..."
    ${SYSPIP} install slixmpp==1.8.5 pycryptodome pyyaml lxml cherrypy \
        croniter netaddr lmdb posix_ipc netifaces psutil requests pyOpenSSL 2>/dev/null || true
fi

# ---- Certificates in trust store ----
log "Ajout des certificats au trust store..."

# 1. Create the OpenSSL cert.pem if missing (python.org installer doesn't include it)
OPENSSL_DIR="/Library/Frameworks/Python.framework/Versions/${PYTHON_VERSION}/etc/openssl"
OPENSSL_CERT="${OPENSSL_DIR}/cert.pem"
if [ -d "$OPENSSL_DIR" ] && [ ! -f "$OPENSSL_CERT" ]; then
    # Copy certifi bundle as base, then append Medulla certs
    CERTIFI_SRC=$(${INSTALL_DIR}/venv/bin/python3 -c "import certifi; print(certifi.where())" 2>/dev/null)
    if [ -n "$CERTIFI_SRC" ] && [ -f "$CERTIFI_SRC" ]; then
        cp "$CERTIFI_SRC" "$OPENSSL_CERT"
        log "Cree $OPENSSL_CERT depuis certifi"
    fi
fi

# 2. Add Medulla certs to all known CA locations
for CA_FILE in \
    "$OPENSSL_CERT" \
    $(${INSTALL_DIR}/venv/bin/python3 -c "import certifi; print(certifi.where())" 2>/dev/null) \
    /opt/homebrew/etc/openssl@3/cert.pem \
    /etc/ssl/cert.pem; do
    if [ -n "$CA_FILE" ] && [ -f "$CA_FILE" ] && ! grep -qi "medulla" "$CA_FILE" 2>/dev/null; then
        for cert in ${INSTALL_DIR}/certs/*.pem; do
            echo "" >> "$CA_FILE"
            echo "# Medulla CA - $(basename $cert)" >> "$CA_FILE"
            cat "$cert" >> "$CA_FILE"
        done
        log "Certificats ajoutes a $CA_FILE"
    fi
done

# 3. Try macOS keychain
for cert in ${INSTALL_DIR}/certs/*.pem; do
    security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain "$cert" 2>/dev/null || true
done

# ---- GLPI Agent ----
log "Installation de GLPI Agent ${GLPI_AGENT_VERSION}..."
if [ ! -f "/Applications/GLPI-Agent/bin/glpi-agent" ]; then
    GLPI_SRC="${DIR}/.glpi-agent.pkg"
    if [ -f "$GLPI_SRC" ]; then
        # Extract payload manually (installer -pkg fails inside pkg sandbox)
        GLPI_TMP=$(mktemp -d)
        cd "$GLPI_TMP"
        xar -xf "$GLPI_SRC" 2>/dev/null
        # Find the component pkg (GLPI-Agent-*_arm64.pkg/Payload)
        COMPONENT=$(find . -name "Payload" -path "*/GLPI-Agent*" | head -1)
        if [ -n "$COMPONENT" ]; then
            mkdir -p payload_root && cd payload_root
            cat "../${COMPONENT}" | gunzip -c | cpio -id 2>/dev/null
            # Copy to / (install-location is /)
            cp -R Applications/* /Applications/ 2>/dev/null
            log "GLPI Agent extrait et installe"
            # Run GLPI postinstall if exists
            GLPI_SCRIPTS=$(find "$GLPI_TMP" -name "Scripts" -path "*/GLPI-Agent*" | head -1)
            if [ -n "$GLPI_SCRIPTS" ]; then
                GLPI_SCRIPTS_DIR=$(mktemp -d)
                cd "$GLPI_SCRIPTS_DIR"
                cat "${GLPI_TMP}/$(dirname $COMPONENT)/Scripts" | gunzip -c | cpio -id 2>/dev/null
                [ -f postinstall ] && chmod +x postinstall && ./postinstall 2>/dev/null || true
                rm -rf "$GLPI_SCRIPTS_DIR"
            fi
        fi
        rm -rf "$GLPI_TMP"
    else
        # Fallback: download from GitHub
        GLPI_PKG="/tmp/glpi-agent-arm64.pkg"
        curl -sLo "$GLPI_PKG" \
            "https://github.com/glpi-project/glpi-agent/releases/download/${GLPI_AGENT_VERSION}/GLPI-Agent-${GLPI_AGENT_VERSION}_arm64.pkg"
        [ -f "$GLPI_PKG" ] && [ -s "$GLPI_PKG" ] && installer -pkg "$GLPI_PKG" -target / 2>/dev/null
        rm -f "$GLPI_PKG"
    fi
fi
mkdir -p /opt/fusioninventory-agent/bin
ln -sf /Applications/GLPI-Agent/bin/glpi-inventory /opt/fusioninventory-agent/bin/fusioninventory-inventory

# ---- Screen Sharing (VNC) ----
# macOS Tahoe+ : le partage d'ecran doit etre active manuellement
# Reglages > General > Partage > Partage d'ecran

# ---- Wrapper script (clean orphan processes before launch) ----
mkdir -p ${INSTALL_DIR}/bin
log "Creation du wrapper de demarrage..."
cat > ${INSTALL_DIR}/bin/medulla-agent.sh <<'WRAPEOF'
#!/bin/bash
exec /opt/medulla/venv/bin/python3 /opt/medulla/pulse_xmpp_agent/launcher.py -t machine
WRAPEOF
chmod +x ${INSTALL_DIR}/bin/medulla-agent.sh

# ---- Restart helper ----
cat > /usr/local/bin/medulla-restart <<'RESTEOF'
#!/bin/bash
killall -9 Python 2>/dev/null
sleep 1
launchctl kickstart -kp system/io.medulla.agent
RESTEOF
chmod +x /usr/local/bin/medulla-restart

# ---- LaunchDaemon ----
log "Creation du LaunchDaemon..."
cat > ${PLIST_PATH} <<PLISTEOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>EnvironmentVariables</key>
	<dict>
		<key>PATH</key>
		<string>${INSTALL_DIR}/venv/bin:/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin</string>
		<key>PYTHONPATH</key>
		<string>${INSTALL_DIR}</string>
		<key>VIRTUAL_ENV</key>
		<string>${INSTALL_DIR}/venv</string>
	</dict>
	<key>KeepAlive</key>
	<true/>
	<key>Label</key>
	<string>io.medulla.agent</string>
	<key>ProgramArguments</key>
	<array>
		<string>${INSTALL_DIR}/bin/medulla-agent.sh</string>
	</array>
	<key>RunAtLoad</key>
	<true/>
	<key>StandardErrorPath</key>
	<string>/var/log/medulla/medulla-agent.log</string>
	<key>StandardOutPath</key>
	<string>/var/log/medulla/medulla-agent.log</string>
	<key>ThrottleInterval</key>
	<integer>30</integer>
	<key>WorkingDirectory</key>
	<string>${INSTALL_DIR}</string>
</dict>
</plist>
PLISTEOF

# ---- Start ----
log "Demarrage du service..."
launchctl bootstrap system ${PLIST_PATH} 2>/dev/null
sleep 2
if ps aux | grep -q "[l]auncher.py -t machine"; then
    log "Agent demarre avec succes"
else
    log "WARN: L'agent ne semble pas demarrer. Verifiez: tail -f ${LOG_DIR}/medulla-agent.err"
fi

log "Installation terminee."
INSTALLEOF

    chmod +x "${DEST_DIR}/install-medulla-agent.sh"

    # Replace placeholders
    sed -i'' "s/@@GLPI_AGENT_VERSION@@/${GLPI_AGENT_VERSION}/g" "${DEST_DIR}/install-medulla-agent.sh"
}

# ============================================================
# Create the .dmg
# ============================================================
create_pkg() {
    colored_echo blue "Creating DMG..."

    if [ -n "${INVENTORY_TAG}" ]; then
        OUTPUT="${PKG_NAME}-${AGENT_VERSION}-${INVENTORY_TAG}.dmg"
    else
        OUTPUT="${PKG_NAME}-${AGENT_VERSION}.dmg"
    fi

    OUTPUT="${PKG_NAME}-${AGENT_VERSION}.pkg"
    if [ -n "${INVENTORY_TAG}" ]; then
        OUTPUT="${PKG_NAME}-${AGENT_VERSION}-${INVENTORY_TAG}.pkg"
    fi

    # Build flat .pkg with xar + mkbom
    TMPDIR=$(mktemp -d)
    PAYLOAD_ROOT="${TMPDIR}/root"
    mkdir -p "${PAYLOAD_ROOT}"

    # Payload: files installed to /opt/medulla/
    for d in .wheels .pulse_xmpp_agent .certs .config; do
        [ -d "${DMG_STAGING}/${d}" ] && cp -R "${DMG_STAGING}/${d}" "${PAYLOAD_ROOT}/${d#.}"
    done
    # Python + GLPI Agent pkgs + setup.py
    [ -f "${DMG_STAGING}/.python3.11.pkg" ] && cp "${DMG_STAGING}/.python3.11.pkg" "${PAYLOAD_ROOT}/.python3.11.pkg"
    [ -f "${DMG_STAGING}/.glpi-agent.pkg" ] && cp "${DMG_STAGING}/.glpi-agent.pkg" "${PAYLOAD_ROOT}/.glpi-agent.pkg"
    [ -f "${DMG_STAGING}/.setup.py" ] && cp "${DMG_STAGING}/.setup.py" "${PAYLOAD_ROOT}/setup.py"

    # Payload cpio.gz
    (cd "${PAYLOAD_ROOT}" && find . | cpio -o --format odc 2>/dev/null | gzip -c > "${TMPDIR}/Payload")

    # Scripts cpio.gz
    mkdir -p "${TMPDIR}/scripts_root"
    cp "${DMG_STAGING}/.scripts/postinstall" "${TMPDIR}/scripts_root/postinstall"
    chmod 755 "${TMPDIR}/scripts_root/postinstall"
    (cd "${TMPDIR}/scripts_root" && find . | cpio -o --format odc 2>/dev/null | gzip -c > "${TMPDIR}/Scripts")

    # Bom
    mkbom "${PAYLOAD_ROOT}" "${TMPDIR}/Bom" 2>/dev/null

    # PackageInfo
    PAYLOAD_KB=$(du -sk "${PAYLOAD_ROOT}" | awk '{print $1}')
    NUM_FILES=$(find "${PAYLOAD_ROOT}" -type f | wc -l)
    cat > "${TMPDIR}/PackageInfo" <<PKGEOF
<?xml version="1.0" encoding="utf-8"?>
<pkg-info format-version="2" identifier="io.medulla.agent" version="${AGENT_VERSION}" install-location="/opt/medulla" auth="root">
    <payload installKBytes="${PAYLOAD_KB}" numberOfFiles="${NUM_FILES}"/>
    <scripts>
        <postinstall file="./postinstall"/>
    </scripts>
</pkg-info>
PKGEOF

    # Distribution XML (required for macOS Installer to recognize the .pkg)
    cat > "${TMPDIR}/Distribution" <<DISTEOF
<?xml version="1.0" encoding="utf-8"?>
<installer-gui-script minSpecVersion="2">
    <title>Medulla Agent ${AGENT_VERSION}</title>
    <options customize="never" require-scripts="false"/>
    <domains enable_localSystem="true"/>
    <choices-outline>
        <line choice="default">
            <line choice="io.medulla.agent"/>
        </line>
    </choices-outline>
    <choice id="default"/>
    <choice id="io.medulla.agent" visible="false">
        <pkg-ref id="io.medulla.agent"/>
    </choice>
    <pkg-ref id="io.medulla.agent" version="${AGENT_VERSION}" installKBytes="${PAYLOAD_KB}" onConclusion="none">#io.medulla.agent.pkg</pkg-ref>
</installer-gui-script>
DISTEOF

    # Structure identique au GLPI Agent .pkg :
    # - Distribution (racine)
    # - io.medulla.agent.pkg/ (sous-dossier avec Bom, Payload, Scripts, PackageInfo)
    mkdir -p "${TMPDIR}/flat/io.medulla.agent.pkg"
    cp "${TMPDIR}/PackageInfo" "${TMPDIR}/Payload" "${TMPDIR}/Scripts" "${TMPDIR}/Bom" "${TMPDIR}/flat/io.medulla.agent.pkg/"
    cp "${TMPDIR}/Distribution" "${TMPDIR}/flat/"
    (cd "${TMPDIR}/flat" && xar --compression=gzip -cf "${TMPDIR}/output.pkg" Distribution io.medulla.agent.pkg)

    cp "${TMPDIR}/output.pkg" "${OUTPUT}"
    rm -rf "${TMPDIR}"

    chmod a+r "${OUTPUT}"
    colored_echo green "Generated: ${OUTPUT} ($(du -h "${OUTPUT}" | awk '{print $1}'))"

    # Symlink latest
    if [ -z "${INVENTORY_TAG}" ]; then
        ln -sf "${OUTPUT}" "${PKG_NAME}-latest.pkg" 2>/dev/null
    fi

    # Copy to downloads
    if [ -d "${MAC_DIR}/downloads" ]; then
        cp "${OUTPUT}" "${MAC_DIR}/downloads/"
        colored_echo green "Copied to ${MAC_DIR}/downloads/"
    fi

    rm -rf ${BUILD_DIR}
}

# ============================================================
# Main
# ============================================================
colored_echo blue "============================================"
colored_echo blue " Medulla Agent macOS ARM64 - Generator"
colored_echo blue " Version: ${AGENT_VERSION}"
colored_echo blue "============================================"

check_arguments "$@"
build_dmg_contents
create_pkg

echo ""
echo "To install on a Mac:"
echo "  1. Copy the .pkg to the Mac"
echo "  2. Double-click on the .pkg"
echo "  3. Follow the installer (enter admin password)"
echo ""
