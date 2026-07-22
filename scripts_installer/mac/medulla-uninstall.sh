#!/bin/bash
# Désinstallation du Medulla Agent macOS.
#
# Usage : sudo medulla-uninstall [--purge | --keep-data]
#   defaut       (cas client reel)  : retire l'agent, le LaunchDaemon, medullauser et /var/log/medulla.
#                                     Conserve /Applications/GLPI-Agent (produit tiers, peut servir seul).
#   --purge      (nettoyage complet) : retire AUSSI /Applications/GLPI-Agent.
#   --keep-data  (cycles dev/test)   : retire SEULEMENT l'agent + LaunchDaemon. Conserve medullauser,
#                                     /var/log/medulla, /Applications/GLPI-Agent (re-install rapide).
#
# Source de vérité : medulla-agent/scripts_installer/mac/medulla-uninstall.sh
# Disponible sur le serveur Medulla via http://<serveur>/downloads/mac/medulla-uninstall.sh
# Egalement deposé sur le Mac à /opt/medulla/medulla-uninstall.sh et /usr/local/bin/medulla-uninstall
# par le postinstall du .pkg.

[ "$(id -u)" -ne 0 ] && { echo "Lancer en root : sudo medulla-uninstall"; exit 1; }

MODE="default"
case "$1" in
    --purge)     MODE="purge" ;;
    --keep-data) MODE="keep-data" ;;
    "")          MODE="default" ;;
    *) echo "Usage: $0 [--purge | --keep-data]"; exit 1 ;;
esac

PLIST=/Library/LaunchDaemons/io.medulla.agent.plist

echo "[Medulla] Arret du demon..."
launchctl bootout system "$PLIST" 2>/dev/null
launchctl unload "$PLIST" 2>/dev/null
killall -9 Python 2>/dev/null
sleep 1

echo "[Medulla] Suppression de l'agent et du LaunchDaemon..."
rm -f "$PLIST"
rm -rf /opt/medulla /opt/fusioninventory-agent /etc/medulla
rm -f /usr/local/bin/medulla-restart

if [ "$MODE" != "keep-data" ]; then
    echo "[Medulla] Suppression de medullauser et /var/log/medulla..."
    rm -rf /var/log/medulla
    dscl . -delete /Users/medullauser 2>/dev/null
fi

if [ "$MODE" = "purge" ]; then
    echo "[Medulla] Mode --purge : suppression de /Applications/GLPI-Agent..."
    [ -x /Applications/GLPI-Agent/uninstaller.sh ] && /Applications/GLPI-Agent/uninstaller.sh 2>/dev/null
    rm -rf /Applications/GLPI-Agent
fi

echo "[Medulla] Desinstallation terminee."
case "$MODE" in
    default)   echo "Note : /Applications/GLPI-Agent conserve (produit tiers). Utiliser --purge pour le retirer." ;;
    keep-data) echo "Note : medullauser, logs et GLPI Agent conserves pour reinstall rapide." ;;
    purge)     echo "Note : tout a ete retire (agent + medullauser + logs + GLPI Agent)." ;;
esac

# Auto-suppression du script lui-meme (s'il est lance depuis /usr/local/bin/)
rm -f /usr/local/bin/medulla-uninstall
