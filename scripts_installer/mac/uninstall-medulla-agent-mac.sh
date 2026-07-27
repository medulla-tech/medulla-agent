#!/bin/bash
# Désinstallation complète du Medulla Agent macOS.
# Retire tout ce que le .pkg a installé côté client (aligné sur uninstall Windows).
#
# Usage : sudo /opt/medulla/uninstall-medulla-agent-mac.sh
#
# Source de vérité : medulla-agent/scripts_installer/mac/uninstall-medulla-agent-mac.sh
# Disponible sur le serveur Medulla via http://<serveur>/downloads/mac/uninstall-medulla-agent-mac.sh
# Déposé côté client Mac uniquement dans /opt/medulla/uninstall-medulla-agent-mac.sh
# par le payload du .pkg. Aucun renommage, aucun symlink dans /usr/local/bin/.

[ "$(id -u)" -ne 0 ] && { echo "Lancer en root : sudo /opt/medulla/uninstall-medulla-agent-mac.sh"; exit 1; }

PLIST=/Library/LaunchDaemons/io.medulla.agent.plist
PYTHON_VERSION="3.11"

echo "[Medulla] === Etape 1 : arret du LaunchDaemon ==="
launchctl bootout system "$PLIST" 2>/dev/null
launchctl unload "$PLIST" 2>/dev/null

echo "[Medulla] === Etape 2 : arret des processus residuels ==="
killall -9 "Medulla Kiosk" 2>/dev/null
killall -9 Python 2>/dev/null
killall -9 syncthing 2>/dev/null
rm -f /tmp/kiosk.pid
sleep 1

echo "[Medulla] === Etape 3 : suppression du LaunchDaemon ==="
rm -f "$PLIST"

echo "[Medulla] === Etape 4 : desinstallation de GLPI Agent + bundle Medulla Kiosk.app ==="
[ -x /Applications/GLPI-Agent/uninstaller.sh ] && /Applications/GLPI-Agent/uninstaller.sh 2>/dev/null
rm -rf /Applications/GLPI-Agent
rm -rf "/Applications/Medulla Kiosk.app"

echo "[Medulla] === Etape 5 : desinstallation de Python ${PYTHON_VERSION} (framework installe par le pkg) ==="
rm -rf "/Library/Frameworks/Python.framework/Versions/${PYTHON_VERSION}"
# Nettoyage du symlink Current s'il pointait sur notre Python
if [ -L "/Library/Frameworks/Python.framework/Versions/Current" ] && \
   [ "$(readlink /Library/Frameworks/Python.framework/Versions/Current)" = "${PYTHON_VERSION}" ]; then
    rm -f "/Library/Frameworks/Python.framework/Versions/Current"
fi

echo "[Medulla] === Etape 6 : nettoyage des certificats CA Medulla dans les CA files ==="
for CA_FILE in \
    /etc/ssl/cert.pem \
    "/Library/Frameworks/Python.framework/Versions/${PYTHON_VERSION}/etc/openssl/cert.pem"; do
    if [ -f "$CA_FILE" ] && grep -qi "medulla" "$CA_FILE" 2>/dev/null; then
        # Supprime chaque bloc "# Medulla CA ..." jusqu'a "-----END CERTIFICATE-----"
        sed -i '' '/# Medulla CA/,/-----END CERTIFICATE-----/d' "$CA_FILE" 2>/dev/null
        echo "  Certificats Medulla retires de $CA_FILE"
    fi
done

echo "[Medulla] === Etape 7 : suppression de medullauser et de son home ==="
dscl . -delete /Users/medullauser 2>/dev/null
rm -rf /var/lib/medulla

echo "[Medulla] === Etape 8 : suppression des repertoires d'installation ==="
rm -rf /opt/medulla /etc/medulla /var/log/medulla
rm -f /usr/local/bin/restart-medulla-agent

echo "[Medulla] Desinstallation de l'agent Medulla terminee."
