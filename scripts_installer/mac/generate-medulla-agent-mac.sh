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
# This script generates .pkg installers for the Medulla XMPP agent on macOS.
# Target: macOS arm64 (Apple Silicon M1/M2/M3/M4) AND x86_64 (Intel Macs).
# Produces 2 .pkg per run: Medulla-Agent-mac-arm64-X.Y.Z.pkg + Medulla-Agent-mac-x86_64-X.Y.Z.pkg.
# It runs on the Medulla server (Linux) and produces the .pkg deployable on Macs.
# The user just double-clicks the .pkg, enters admin password, and the agent is installed.
#
# Requirements on the server:
#   - xar + mkbom shipped alongside this script in ./bin/ (packaged with pulse-agent-installers)
#   - Python wheels in /var/lib/pulse2/clients/mac/downloads/python_modules/
#   - Agent code in /usr/lib/python3/dist-packages/pulse_xmpp_agent/
#   - Certificates in /var/lib/pulse2/clients/medulla-{rootca,ca-chain}.cert.pem
#   - Config in /var/lib/pulse2/clients/config/agentconf.ini

# ============================================================================
# CONFIGURATION (versions à bumper quand on upgrade Python ou GLPI Agent)
# - PYTHON_VERSION        : major.minor utilisé pour les chemins Python.framework côté Mac
# - PYTHON_VERSION_FULL   : major.minor.patch utilisé pour télécharger le .pkg sur python.org
# - GLPI_AGENT_VERSION    : tag de release github.com/glpi-project/glpi-agent
# ============================================================================
AGENT_VERSION="5.6.1"
PYTHON_VERSION="3.11"
PYTHON_VERSION_FULL="3.11.9"
GLPI_AGENT_VERSION="1.17"
KIOSK_VERSION="2.1.0"
# PyQt6 pinné (PyQt6 ET PyQt6-Qt6 à la MÊME version, sinon ABI mismatch au
# runtime), aligné sur les installeurs win/linux.
PYQT6_VERSION="6.6.1"

# Go to own folder
cd "$(dirname $0)"

# Use the xar/mkbom shipped alongside this script (./bin/) in priority,
# fallback on system PATH if absent.
export PATH="$PWD/bin:$PATH"

# Paths
CLIENTS_DIR="/var/lib/pulse2/clients"
MAC_DIR="${CLIENTS_DIR}/mac"
WHEELS_DIR="${MAC_DIR}/downloads/python_modules"
CONFIG_DIR="${CLIENTS_DIR}/config"
AGENT_SRC="/usr/lib/python3/dist-packages/pulse_xmpp_agent"
# Tarball du kiosk (même source que l'installeur linux : servi sous BASE_URL,
# = racine de CLIENTS_DIR sur le serveur de build).
KIOSK_TARBALL="${CLIENTS_DIR}/kiosk-interface-${KIOSK_VERSION}.tar.gz"
# BUILD_DIR / DMG_STAGING / PKG_NAME / ARCH sont fixés par la boucle main (par archi).

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

    # -- 2b. Python pkg (embedded, auto-downloaded once, cached in downloads/) --
    PYTHON_PKG="${MAC_DIR}/downloads/python-${PYTHON_VERSION_FULL}-macos11.pkg"
    if [ ! -f "$PYTHON_PKG" ]; then
        colored_echo yellow "  Python ${PYTHON_VERSION_FULL} pkg not cached, downloading from python.org..."
        curl -fsSLo "$PYTHON_PKG" "https://www.python.org/ftp/python/${PYTHON_VERSION_FULL}/python-${PYTHON_VERSION_FULL}-macos11.pkg" || rm -f "$PYTHON_PKG"
    fi
    if [ -f "$PYTHON_PKG" ]; then
        cp "$PYTHON_PKG" "${DMG_STAGING}/.python${PYTHON_VERSION}.pkg"
        colored_echo green "  Python ${PYTHON_VERSION_FULL}: embedded"
    else
        colored_echo yellow "  WARN: Python pkg unavailable (download failed), Mac will fetch at install"
    fi

    # -- 2c. GLPI Agent pkg (embedded, auto-downloaded once par archi, cached in downloads/) --
    GLPI_PKG="${MAC_DIR}/downloads/GLPI-Agent-${GLPI_AGENT_VERSION}_${ARCH}.pkg"
    if [ ! -f "$GLPI_PKG" ]; then
        colored_echo yellow "  GLPI Agent ${GLPI_AGENT_VERSION} ${ARCH} pkg not cached, downloading from github..."
        curl -fsSLo "$GLPI_PKG" "https://github.com/glpi-project/glpi-agent/releases/download/${GLPI_AGENT_VERSION}/GLPI-Agent-${GLPI_AGENT_VERSION}_${ARCH}.pkg" || rm -f "$GLPI_PKG"
    fi
    if [ -f "$GLPI_PKG" ]; then
        cp "$GLPI_PKG" "${DMG_STAGING}/.glpi-agent.pkg"
        colored_echo green "  GLPI Agent ${ARCH}: embedded"
    else
        colored_echo yellow "  WARN: GLPI Agent ${ARCH} unavailable (download failed), Mac will fetch at install"
    fi

    # -- 2d. Kiosk interface tarball (hidden) --
    # Installé dans le venv de l'agent par le postinstall (PyQt6 + le kiosk),
    # pour que le scheduler puisse lancer le kiosk avec sys.executable.
    if [ -f "${KIOSK_TARBALL}" ]; then
        cp "${KIOSK_TARBALL}" "${DMG_STAGING}/.kiosk-interface.tar.gz"
        colored_echo green "  Kiosk ${KIOSK_VERSION}: embedded"
    else
        colored_echo yellow "  WARN: tarball kiosk introuvable (${KIOSK_TARBALL}), kiosk non embarque"
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

    # -- 5b. Uninstall helper (sera deplacé en /usr/local/bin/medulla-uninstall par le postinstall) --
    if [ -f "${MAC_DIR}/medulla-uninstall.sh" ]; then
        cp "${MAC_DIR}/medulla-uninstall.sh" "${DMG_STAGING}/medulla-uninstall.sh"
        chmod +x "${DMG_STAGING}/medulla-uninstall.sh"
        colored_echo green "  Uninstall helper: OK"
    else
        colored_echo yellow "  WARN: ${MAC_DIR}/medulla-uninstall.sh introuvable, helper non embarque"
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
# Medulla Agent macOS - Installer (cible : @@ARCH@@)
# Called by the .app launcher with the DMG path as $1

INSTALL_DIR="/opt/medulla"
CONF_DIR="/etc/medulla"
LOG_DIR="/var/log/medulla"
PLIST_PATH="/Library/LaunchDaemons/io.medulla.agent.plist"
ARCH="@@ARCH@@"
PYTHON_VERSION="@@PYTHON_VERSION@@"
PYTHON_VERSION_FULL="@@PYTHON_VERSION_FULL@@"
GLPI_AGENT_VERSION="@@GLPI_AGENT_VERSION@@"
KIOSK_VERSION="@@KIOSK_VERSION@@"
PYQT6_VERSION="@@PYQT6_VERSION@@"

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

# ---- Python ${PYTHON_VERSION_FULL} depuis le .pkg python.org embarque ----
PYTHON_BIN="/Library/Frameworks/Python.framework/Versions/${PYTHON_VERSION}/bin/python${PYTHON_VERSION}"

if [ ! -x "$PYTHON_BIN" ]; then
    if [ -f "${DIR}/.python${PYTHON_VERSION}.pkg" ]; then
        log "Installation de Python ${PYTHON_VERSION_FULL} depuis le pkg embarque..."
        installer -pkg "${DIR}/.python${PYTHON_VERSION}.pkg" -target / 2>/dev/null
    else
        # Fallback : pas de pkg embarque (cas anormal, le payload du .pkg le contient
        # toujours quand le serveur de build a du reseau). On telecharge depuis python.org.
        log "Telechargement de Python ${PYTHON_VERSION_FULL} depuis python.org (fallback)..."
        PYTHON_DL="/tmp/python-${PYTHON_VERSION_FULL}.pkg"
        curl -sLo "$PYTHON_DL" "https://www.python.org/ftp/python/${PYTHON_VERSION_FULL}/python-${PYTHON_VERSION_FULL}-macos11.pkg"
        [ -f "$PYTHON_DL" ] && [ -s "$PYTHON_DL" ] && installer -pkg "$PYTHON_DL" -target / 2>/dev/null
        rm -f "$PYTHON_DL"
    fi
fi

if [ ! -x "$PYTHON_BIN" ]; then
    log "ERREUR: Python ${PYTHON_VERSION} introuvable malgre l'install depuis le pkg embarque"
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
# Force native ${ARCH} (pkg sandbox may run under Rosetta sur Apple Silicon)
arch -${ARCH} ${PYTHON_BIN} -m venv ${INSTALL_DIR}/venv
chmod -R 755 ${INSTALL_DIR}/venv
PIP="${INSTALL_DIR}/venv/bin/pip"
arch -${ARCH} ${PIP} install --upgrade pip setuptools wheel 2>/dev/null

log "Installation des dependances..."
# Force native ${ARCH} for all pip operations (pkg sandbox may use Rosetta)
APIP="arch -${ARCH} ${PIP}"
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
    arch -${ARCH} ${INSTALL_DIR}/venv/bin/python3 -c "import $mod" 2>/dev/null || MISSING="$MISSING $mod"
done
if [ -n "$MISSING" ]; then
    log "Modules manquants:$MISSING - installation depuis PyPI..."
    ${APIP} install psutil pycryptodome PyYAML lxml cherrypy croniter netaddr \
        lmdb posix_ipc requests pyOpenSSL configparser distro netifaces-plus \
        slixmpp==1.8.5 pycurl wakeonlan aiofiles websockets 2>&1 | tail -5
fi

# pycurl sdist sur macOS compile par defaut sans backend SSL choisi ("none/other"),
# ce qui casse l'import au runtime (libcurl expose secure-transport+openssl mais
# pycurl ne sait pas lequel attaquer) et fait echouer le plugin
# applicationdeploymentjson. On force la recompilation contre SecureTransport
# (TLS Apple natif, deja disponible — pas de header openssl a installer).
log "Force pycurl backend SecureTransport (macOS natif)..."
PYCURL_SSL_LIBRARY=sectransp ${APIP} install --no-binary :all: --force-reinstall --no-deps pycurl 2>&1 | tail -3

log "Dependances installees ($(${PIP} list 2>/dev/null | wc -l | tr -d ' ') packages)"

# Register pulse_xmpp_agent as a Python package (same as deb does with setup.py install)
if [ -f "${INSTALL_DIR}/setup.py" ]; then
    ${APIP} install -e "${INSTALL_DIR}" --no-deps 2>/dev/null
    log "Package pulse_xmpp_agent enregistre"
fi

# ---- Medulla Kiosk (PyQt6 + kiosk dans le venv de l'agent) ----
# Le scheduler (scheduling_launch_kiosk) lance le kiosk avec l'interpreteur du
# venv (sys.executable) via `launchctl asuser <uid> sudo -u <user>`. Sur macOS,
# QSystemTrayIcon = barre des menus (demarrage discret, pas de fenetre auto,
# donc pas de .desktop a creer comme sous Linux).
KIOSK_SRC="${DIR}/.kiosk-interface.tar.gz"
if [ -f "$KIOSK_SRC" ]; then
    log "Installation du Medulla Kiosk ${KIOSK_VERSION}..."
    # PyQt6 ET PyQt6-Qt6 epingles a la MEME version, sinon ABI mismatch
    # ("undefined symbol ... version Qt_6") a l'import. PyQt6 = wheel universal2 ;
    # PyQt6-Qt6 = wheels separes arm64/x86_64, d'ou le `arch -${ARCH}` (via APIP)
    # qui force le bon interpreteur pour que pip prenne le wheel Qt6 de l'archi.
    ${APIP} install "PyQt6==${PYQT6_VERSION}" "PyQt6-Qt6==${PYQT6_VERSION}" 2>&1 | tail -2
    # Le tarball tire ses propres deps (setproctitle ; PyQt6 deja satisfait).
    ${APIP} install "$KIOSK_SRC" 2>&1 | tail -3
    if arch -${ARCH} ${INSTALL_DIR}/venv/bin/python3 -c "import kiosk_interface" 2>/dev/null; then
        log "Kiosk installe (import OK)"
    else
        log "WARN: le kiosk ne s'importe pas, verifiez PyQt6"
    fi
    # Active le lancement du kiosk par le scheduler. Le descripteur defaut deja
    # a True si l'option est absente, mais on l'ecrit explicitement.
    cat > ${CONF_DIR}/scheduling_launch_kiosk.ini <<'KIOSKINI'
[scheduling_launch_kiosk]
# Enable execution of kiosk
enable_kiosk = True
KIOSKINI
    ln -sf ${CONF_DIR}/scheduling_launch_kiosk.ini ${INSTALL_DIR}/etc/ 2>/dev/null
else
    log "WARN: tarball kiosk absent du payload, kiosk non installe"
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
        # Find the component pkg (GLPI-Agent-*_${ARCH}.pkg/Payload)
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
        # Fallback: download from GitHub (archi du Mac courant)
        GLPI_PKG="/tmp/glpi-agent-${ARCH}.pkg"
        curl -sLo "$GLPI_PKG" \
            "https://github.com/glpi-project/glpi-agent/releases/download/${GLPI_AGENT_VERSION}/GLPI-Agent-${GLPI_AGENT_VERSION}_${ARCH}.pkg"
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

# ---- Uninstall helper (script standalone embarqué dans le payload, source de vérité unique) ----
if [ -f "${INSTALL_DIR}/medulla-uninstall.sh" ]; then
    cp "${INSTALL_DIR}/medulla-uninstall.sh" /usr/local/bin/medulla-uninstall
    chmod +x /usr/local/bin/medulla-uninstall
    log "Uninstall helper installe a /usr/local/bin/medulla-uninstall"
fi

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
		<string>${INSTALL_DIR}/venv/bin:/usr/bin:/bin:/usr/sbin:/sbin</string>
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
    sed -i'' \
        -e "s/@@ARCH@@/${ARCH}/g" \
        -e "s/@@PYTHON_VERSION@@/${PYTHON_VERSION}/g" \
        -e "s/@@PYTHON_VERSION_FULL@@/${PYTHON_VERSION_FULL}/g" \
        -e "s/@@GLPI_AGENT_VERSION@@/${GLPI_AGENT_VERSION}/g" \
        -e "s/@@KIOSK_VERSION@@/${KIOSK_VERSION}/g" \
        -e "s/@@PYQT6_VERSION@@/${PYQT6_VERSION}/g" \
        "${DEST_DIR}/install-medulla-agent.sh"
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
    [ -f "${DMG_STAGING}/.python${PYTHON_VERSION}.pkg" ] && cp "${DMG_STAGING}/.python${PYTHON_VERSION}.pkg" "${PAYLOAD_ROOT}/.python${PYTHON_VERSION}.pkg"
    [ -f "${DMG_STAGING}/.glpi-agent.pkg" ] && cp "${DMG_STAGING}/.glpi-agent.pkg" "${PAYLOAD_ROOT}/.glpi-agent.pkg"
    [ -f "${DMG_STAGING}/.kiosk-interface.tar.gz" ] && cp "${DMG_STAGING}/.kiosk-interface.tar.gz" "${PAYLOAD_ROOT}/.kiosk-interface.tar.gz"
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
    <options customize="never" require-scripts="false" hostArchitectures="${ARCH}"/>
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
# Main : génère un .pkg par archi cible (arm64 + x86_64)
# ============================================================
check_arguments "$@"

for ARCH in arm64 x86_64; do
    PKG_NAME="Medulla-Agent-mac-${ARCH}"
    BUILD_DIR="/tmp/medulla-mac-build-${ARCH}"
    DMG_STAGING="${BUILD_DIR}/dmg"

    colored_echo blue "============================================"
    colored_echo blue " Medulla Agent macOS ${ARCH} - Generator"
    colored_echo blue " Version: ${AGENT_VERSION}"
    colored_echo blue "============================================"

    build_dmg_contents
    create_pkg
done

echo ""
echo "To install on a Mac:"
echo "  1. Copy the matching .pkg (arm64 for Apple Silicon, x86_64 for Intel) to the Mac"
echo "  2. Double-click on the .pkg"
echo "  3. Follow the installer (enter admin password)"
echo ""
