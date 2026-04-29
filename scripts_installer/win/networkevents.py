#!/usr/bin/python3
# -*- coding: utf-8; -*-
# SPDX-FileCopyrightText: 2022-2023 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-3.0-or-later

"""Surveillance des changements d'interfaces reseau Windows pour Medulla.

Vue d'ensemble
==============
Ce programme observe les changements d'adresses IP locales sur Windows,
puis envoie un message JSON au serveur TCP local de l'agent Medulla.

Historique / evolution
======================
- Ancien fonctionnement : ecriture dans un pipe nomme Windows.
- Fonctionnement actuel : client TCP stateless vers le plugin serveur local.

Objectif operationnel
=====================
Quand une IP est ajoutee/supprimee sur la machine, produire une structure JSON
de diff:
        {
            "interface": [...],
            "additionalinterface": [...],
            "removedinterface": [...]
        }
et l'expedier au serveur TCP local configure dans agentconf.ini.

Robustesse reseau
=================
Si le serveur TCP local est indisponible temporairement:
- plusieurs tentatives sont faites,
- les evenements sont mis en tampon en memoire,
- le tampon est reemis automatiquement quand le serveur redevient disponible.

Maintenance long terme
======================
Les sections importantes a relire en priorite lors d'un retour sur ce code:
1. NetworkManager.register() : abonnement COM/SENS aux evenements reseau.
2. GetIpAddrTable()          : etat IP local de reference.
3. NetworkManager.send_message() : politique d'envoi TCP + buffer.
4. read_kiosk_port()         : resolution du port depuis la configuration.
5. main()                    : bootstrap service (log, pid, options).
"""

from collections import deque
import argparse
import configparser
import logging
from threading import Thread
import pythoncom
import time
import ctypes
import json
from win32com.server.policy import DesignatedWrapPolicy
from win32com.client import Dispatch
import win32api
import socket
import struct
from ctypes import windll
import os

from pulse_xmpp_agent.lib.agentconffile import conffilename, medullaPath

# ProgID COM du service d'evenements Windows (SENS).
# Ces constantes sont stables historiquement sous Windows.
PROGID_EventSystem = "EventSystem.EventSystem"
PROGID_EventSubscription = "EventSystem.EventSubscription"

# Snapshot des IP connues (format chaine CSV, ex: "10.0.0.1,192.168.1.10").
# Utilise comme etat precedent pour calculer le diff.
iplist = ""

# Valeurs SENS: (SubscriptionID, Nom humain, Methode callback COM).
# On enregistre plusieurs subscriptions pour couvrir les variantes d'evenements
# exposees selon versions/configurations Windows.

# Code message Win32 conserve pour reference historique.
# Non utilise directement dans la logique actuelle.
WM_QUIT = 0x12
service_logger = logging.getLogger()

SUBSCRIPTION_NETALIVE = (
    "{cd1dcbd6-a14d-4823-a0d2-8473afde360f}",
    "pulse Network Alive",
    "ConnectionMade",
)

SUBSCRIPTION_NETALIVE_NOQOC = (
    "{a82f0e80-1305-400c-ba56-375ae04264a1}",
    "pulse Net Alive No Info",
    "ConnectionMadeNoQOCInfo",
)

SUBSCRIPTION_NETLOST = (
    "{45233130-b6c3-44fb-a6af-487c47cee611}",
    "pulse Network Lost",
    "ConnectionLost",
)

SUBSCRIPTION_REACH = (
    "{4c6b2afa-3235-4185-8558-57a7a922ac7b}",
    "pulse Network Reach",
    "ConnectionMade",
)

SUBSCRIPTION_REACH_NOQOC = (
    "{db62fa23-4c3e-47a3-aef2-b843016177cf}",
    "pulse Network Reach No Info",
    "ConnectionMadeNoQOCInfo",
)

SUBSCRIPTION_REACH_NOQOC2 = (
    "{d4d8097a-60c6-440d-a6da-918b619ae4b7}",
    "pulse Network Reach No Info 2",
    "ConnectionMadeNoQOCInfo",
)

SUBSCRIPTIONS = [
    SUBSCRIPTION_NETALIVE,
    SUBSCRIPTION_NETALIVE_NOQOC,
    SUBSCRIPTION_NETLOST,
    SUBSCRIPTION_REACH,
    SUBSCRIPTION_REACH_NOQOC,
    SUBSCRIPTION_REACH_NOQOC2,
]

SENSGUID_EVENTCLASS_NETWORK = "{d5978620-5b9f-11d1-8dd2-00aa004abd5e}"
SENSGUID_PUBLISHER = "{5fee1bd6-5b9b-11d1-8dd2-00aa004abd5e}"

# UUID de l'interface COM ISesNetwork implementee ici.
IID_ISesNetwork = "{d597bab1-5b9f-11d1-8dd2-00aa004abd5e}"


def GetIpAddrTable():
    """Retourne les IP locales detectees par l'API Windows IP Helper.

    Note importante:
    - Le nom de fonction est conserve pour compatibilite/historique.
    - Le format de retour est une chaine CSV triee des IP (pas une table brute).

    Pourquoi une chaine CSV ?
    - Le code historique compare des snapshots sous forme de chaine.
    - Cela limite les changements structurels dans le reste du programme.
    """
    DWORD = ctypes.c_ulong
    USHORT = ctypes.c_ushort
    NULL = ""

    dwSize = DWORD(0)

    # Premier appel: l'API renseigne la taille requise dans dwSize.
    windll.iphlpapi.GetIpAddrTable(NULL, ctypes.byref(dwSize), 0)

    class MIB_IPADDRROW(ctypes.Structure):
        _fields_ = [
            ("dwAddr", DWORD),
            ("dwIndex", DWORD),
            ("dwMask", DWORD),
            ("dwBCastAddr", DWORD),
            ("dwReasmSize", DWORD),
            ("unused1", USHORT),
            ("wType", USHORT),
        ]

    class MIB_IPADDRTABLE(ctypes.Structure):
        _fields_ = [("dwNumEntries", DWORD), ("table", MIB_IPADDRROW * dwSize.value)]

    # Deuxieme appel: lecture effective de la table IP.
    ipTable = MIB_IPADDRTABLE()
    rc = windll.iphlpapi.GetIpAddrTable(ctypes.byref(ipTable), ctypes.byref(dwSize), 0)
    if rc != 0:
        raise OSError("GetIpAddrTable returned %d" % rc)

    table = []

    for i in range(ipTable.dwNumEntries):
        entry = socket.inet_ntoa(struct.pack("L", ipTable.table[i].dwAddr))
        table.append(str(entry))
    table.sort()
    # Snapshot canonique trie pour comparaison deterministe.
    return ",".join(table)


def diff_interface(oldinterface, newinterface):
    """Construit un diff d'interfaces entre deux snapshots IP.

    Args:
        oldinterface: liste des IP avant changement
        newinterface: liste des IP apres changement

    Returns:
        dict avec:
            - interface: IP communes
            - additionalinterface: IP ajoutees
            - removedinterface: IP supprimees
    """
    add_interface = []
    del_interface = []
    commun_interface = set()
    for t in oldinterface:
        if t not in newinterface:
            del_interface.append(t)
        else:
            commun_interface.add(t)
    for t in newinterface:
        if t not in oldinterface:
            add_interface.append(t)
        else:
            commun_interface.add(t)
    commun_interface = sorted(commun_interface)
    add_interface.sort()
    del_interface.sort()
    return {
        "interface": commun_interface,
        "additionalinterface": add_interface,
        "removedinterface": del_interface,
    }


class NetworkManager(DesignatedWrapPolicy):
    """Implementation COM de ISesNetwork + emission TCP des changements IP.

    Cette classe a deux responsabilites:
    1) S'abonner aux evenements reseau Windows (COM/SENS).
    2) Detecter le diff IP et l'envoyer au serveur TCP local de l'agent.
    """

    _com_interfaces_ = [IID_ISesNetwork]
    # event on interface
    # _public_methods_ = ['ConnectionMade',
    # 'ConnectionMadeNoQOCInfo',
    # 'ConnectionLost']
    _public_methods_ = ["ConnectionMadeNoQOCInfo"]
    _reg_clsid_ = "{41B032DA-86B5-4907-A7F7-958E59333010}"
    _reg_progid_ = "WaptService.NetworkManager"

    def __init__(self, connected_cb, disconnected_cb, send_kiosk, tcp_host, tcp_port):
        """Initialise le gestionnaire reseau.

        Args:
            connected_cb: callback appele sur evenement de connexion reseau
            disconnected_cb: callback appele sur evenement de deconnexion reseau
            send_kiosk: active/desactive l'envoi TCP des evenements
            tcp_host: hote serveur TCP local
            tcp_port: port serveur TCP local
        """
        self._wrap_(self)
        self.connected_cb = connected_cb
        self.disconnected_cb = disconnected_cb
        self.send_kiosk = send_kiosk
        self.tcp_host = tcp_host
        self.tcp_port = tcp_port
        # Buffer local en memoire (borné) pour ne pas perdre les evenements
        # pendant une indisponibilite courte du serveur local.
        # maxlen evite une croissance memoire non bornee en cas de panne longue.
        self.pending_messages = deque(maxlen=200)

        self.main_thread_id = win32api.GetCurrentThreadId()

    def ConnectionMade(self, *args):
        """Callback COM: un reseau est annonce disponible."""
        service_logger.info("Connection was made.")
        self.connected_cb()

    def ConnectionMadeNoQOCInfo(self, *args):
        """Callback COM: connexion disponible sans info QOC."""
        service_logger.info("Connection was made no info.")
        self.connected_cb()

    def ConnectionLost(self, *args):
        """Callback COM: perte de connectivite reseau."""
        service_logger.info("Connection was lost.")
        self.disconnected_cb()

    def register(self):
        """Enregistre toutes les subscriptions SENS requises.

        Cette methode est appelee dans le thread de supervision.
        CoInitialize est indispensable pour les operations COM dans ce thread.
        """
        # Initialise COM dans le thread courant.
        pythoncom.CoInitialize()
        # Wrapper COM expose comme SubscriberInterface.
        manager_interface = pythoncom.WrapObject(self)
        event_system = Dispatch(PROGID_EventSystem)
        # Enregistre plusieurs variantes d'evenements pour couvrir les
        # differences de comportement entre versions Windows.
        for current_event in SUBSCRIPTIONS:
            # Creation d'une subscription COM.
            event_subscription = Dispatch(PROGID_EventSubscription)
            event_subscription.EventClassId = SENSGUID_EVENTCLASS_NETWORK
            event_subscription.PublisherID = SENSGUID_PUBLISHER
            event_subscription.SubscriptionID = current_event[0]
            event_subscription.SubscriptionName = current_event[1]
            event_subscription.MethodName = current_event[2]
            event_subscription.SubscriberInterface = manager_interface
            event_subscription.PerUser = True
            # Persistance de la subscription dans EventSystem.
            try:
                event_system.Store(PROGID_EventSubscription, event_subscription)
            except pythoncom.com_error as e:
                # On loggue mais on continue: une subscription ratee ne doit pas
                # empecher le demarrage complet si d'autres passent.
                service_logger.error("Error registering to event %s", current_event[1])

    def poll_messages(self):
        """Pompe les messages COM en attente (API historique).

        Conserve pour debug/compatibilite; non central dans le flux actuel.
        """
        return pythoncom.PumpWaitingMessages()

    def _send_once(self, payload):
        """Effectue un envoi TCP unique d'un payload JSON."""
        data = json.dumps(payload, ensure_ascii=True).encode("utf-8")
        with socket.create_connection((self.tcp_host, self.tcp_port), timeout=2.0) as sock:
            sock.sendall(data)

    def _flush_pending(self):
        """Reemission FIFO des messages tamponnes.

        Hypothese: appelee seulement quand le serveur semble joignable.
        Si un envoi echoue ici, l'exception remonte vers send_message().
        """
        if not self.pending_messages:
            return

        service_logger.info(
            "TCP server available again, flushing %s buffered event(s)",
            len(self.pending_messages),
        )
        while self.pending_messages:
            payload = self.pending_messages[0]
            self._send_once(payload)
            self.pending_messages.popleft()

    def send_message(self, payload):
        """Envoie un evenement au serveur TCP avec strategie de resilience.

        Strategie:
        1. Tentative de vidage du buffer local.
        2. Tentative d'envoi du message courant.
        3. Retry court (3 fois).
        4. Si echec, bufferisation du message courant.
        """
        if not self.send_kiosk:
            return "nosend"

        # Le client TCP est stateless: chaque envoi ouvre une nouvelle connexion.
        # Si le serveur reapparait, l'envoi suivant se reconnecte automatiquement.
        last_error = None
        for _ in range(3):
            try:
                self._flush_pending()
                self._send_once(payload)
                return "sent"
            except OSError as exc:
                last_error = exc
                time.sleep(1)

        self.pending_messages.append(payload)
        service_logger.warning(
            "TCP send failed to %s:%s (%s). Event buffered (%s pending).",
            self.tcp_host,
            self.tcp_port,
            last_error,
            len(self.pending_messages),
        )
        return "buffered"

    def run(self):
        """Boucle principale de supervision reseau.

        Mecanisme:
        - attend un signal de changement (NotifyAddrChange),
        - relit l'etat IP,
        - compare avec le snapshot precedent,
        - publie le diff via send_message().

        Cette boucle est volontairement infinie pour un usage service.
        """
        global iplist
        self.register()
        service_logger.info("start listen network interface")
        while True:
            # Blocage jusqu'a notification de changement d'adresse reseau.
            ctypes.windll.iphlpapi.NotifyAddrChange(0, 0)
            try:
                iplistlocal = GetIpAddrTable()
            except Exception:
                service_logger.error("function get ip adress error")
                time.sleep(5)
                continue

            if iplistlocal != iplist:
                oldinterface = [x.strip() for x in iplist.split(",")]
                newinterface = [x.strip() for x in iplistlocal.split(",")]
                datainterface = diff_interface(oldinterface, newinterface)
                try:
                    # Construction d'une trace lisible pour le journal.
                    strchang = "Interface [%s] chang[" % (iplistlocal)
                    if len(datainterface["additionalinterface"]) > 0:
                        strchang = "%s+%s" % (
                            strchang,
                            datainterface["additionalinterface"],
                        )
                    if len(datainterface["removedinterface"]) > 0:
                        strchang = "%s-%s" % (
                            strchang,
                            datainterface["removedinterface"],
                        )
                    strchang = "%s]" % (strchang)
                    send_state = self.send_message(datainterface)
                    if send_state == "sent":
                        service_logger.info("[SEND] %s", strchang)
                    elif send_state == "buffered":
                        service_logger.info("[NC] %s (event buffered)", strchang)
                    else:
                        service_logger.info("[NOSEND] %s", strchang)
                except Exception as e:
                    err = str(e)
                    if "timed out" in err.lower():
                        service_logger.warning(
                            "TCP timeout while sending network event: "
                            "the local TCP server is probably not started yet. "
                            "Event will be retried/buffered. (%s)",
                            err,
                        )
                    else:
                        service_logger.error("%s" % err)
                    pass

                # Mise a jour du snapshot de reference apres traitement.
                iplist = iplistlocal
                # Petite temporisation pour eviter les rafales de notifications.
                time.sleep(5)


def iter_agent_conf_candidates():
    """Retourne les chemins candidats de agentconf.ini (ordre de priorite).

    Priorite explicite:
    1) C:/Program Files/Medulla/etc/agentconf.ini
    2) C:/PROGRA~1/Medulla/etc/agentconf.ini
    3) chemin retourne par conffilename("machine")
    4) agentconf.ini du repertoire courant
    """
    candidates = [
        os.path.join("C:\\", "Program Files", "Medulla", "etc", "agentconf.ini"),
        os.path.join("C:\\", "PROGRA~1", "Medulla", "etc", "agentconf.ini"),
    ]

    try:
        candidates.append(conffilename("machine"))
    except Exception:
        pass

    candidates.append(os.path.join(os.getcwd(), "agentconf.ini"))

    seen = set()
    for path in candidates:
        norm = os.path.normcase(path)
        if norm in seen:
            continue
        seen.add(norm)
        yield path


def read_kiosk_port(default_port=8765, config_file=None):
    """Lit [kiosk]/am_local_port depuis agentconf.ini.

    Si config_file est fourni, il est utilise en priorite.

    Returns:
        (port, source_path)
        - port: port entier retenu
        - source_path: fichier de conf utilise (ou conf de reference en fallback)
    """
    candidates = [config_file] if config_file else list(iter_agent_conf_candidates())

    for cfg_path in candidates:
        if not cfg_path:
            continue
        if not os.path.isfile(cfg_path):
            continue

        config = configparser.ConfigParser()
        try:
            config.read(cfg_path, encoding="utf-8")
        except Exception:
            continue

        try:
            if config.has_option("kiosk", "am_local_port"):
                return config.getint("kiosk", "am_local_port"), cfg_path
        except Exception:
            return default_port, cfg_path

        return default_port, cfg_path

    # Aucun fichier lisible: on conserve le port par defaut.
    # On expose quand meme la conf de reference attendue en mode auto pour
    # faciliter le diagnostic dans les logs.
    return (
        default_port,
        os.path.join("C:\\", "Program Files", "Medulla", "etc", "agentconf.ini"),
    )


def parse_args():
    """Definit et parse les options CLI.

    Le script est pense pour un usage service, mais les options permettent:
    - override ponctuel du host/port,
    - choix d'un fichier de conf alternatif,
    - activation debug log,
    - desactivation temporaire de l'envoi TCP.
    """
    parser = argparse.ArgumentParser(
        description=(
            "Surveillance des interfaces reseau Windows et envoi d'evenements "
            "vers le serveur TCP local de l'agent"
        )
    )
    parser.add_argument(
        "--host",
        default="127.0.0.1",
        help="Hote du serveur TCP local (defaut: 127.0.0.1)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=None,
        help="Port TCP (defaut: [kiosk]/am_local_port ou 8765)",
    )
    parser.add_argument(
        "--no-send-kiosk",
        action="store_true",
        help="Desactive l'envoi TCP des evenements",
    )
    parser.add_argument(
        "--config-file",
        default=None,
        help=(
            "Chemin vers agentconf.ini pour lire [kiosk]/am_local_port. "
            "Si non fourni, resolution automatique (priorite: "
            "C:/Program Files/Medulla/etc/agentconf.ini)."
        ),
    )
    parser.add_argument(
        "--log-level",
        default="INFO",
        choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
        help="Niveau de log (defaut: INFO)",
    )
    parser.add_argument(
        "--log-file",
        default=None,
        help="Fichier de log (defaut: <Medulla>/var/log/networkevents.log)",
    )
    return parser.parse_args()


def setup_file_logging(logfile, log_level):
    """Configure un logger fichier robuste, meme si logging est deja initialise.

    Pourquoi:
    - logging.basicConfig() est ignore si des handlers existent deja,
      ce qui peut donner "plus de logs" en contexte service.
    """
    log_dir = os.path.dirname(logfile)
    if log_dir:
        os.makedirs(log_dir, exist_ok=True)

    level = getattr(logging, log_level)
    formatter = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s")

    service_logger.setLevel(level)
    service_logger.propagate = False

    # Evite les doublons en cas de relance du script dans le meme process.
    for handler in list(service_logger.handlers):
        service_logger.removeHandler(handler)

    file_handler = logging.FileHandler(logfile, mode="a", encoding="utf-8")
    file_handler.setLevel(level)
    file_handler.setFormatter(formatter)
    service_logger.addHandler(file_handler)


def main():
    """Point d'entree principal.

    Etapes:
    1) Parse des options
    2) Initialisation log + pidfile
    3) Resolution de la cible TCP
    4) Snapshot IP initial
    5) Lancement du thread de supervision
    """
    args = parse_args()
    global iplist

    logfile = args.log_file or os.path.join(medullaPath(), "var", "log", "networkevents.log")

    program_dir = os.path.join(medullaPath(), "bin")
    pidfile = os.path.join(program_dir, ".PID_NETWORKS_ENVENTS")
    os.makedirs(program_dir, exist_ok=True)

    PID_PROGRAM = os.getpid()
    # Ecriture du PID pour supervision externe (service/watchdog).
    with open(pidfile, mode="w") as file:
        file.write("%s" % PID_PROGRAM)

    setup_file_logging(logfile, args.log_level)
    service_logger.info("***************************")
    configured_port, conf_source = read_kiosk_port(config_file=args.config_file)
    target_port = args.port if args.port is not None else configured_port

    service_logger.info(
        "networkevents TCP target %s:%s (source conf: %s)",
        args.host,
        target_port,
        conf_source if conf_source else "default",
    )

    iplist = GetIpAddrTable()
    service_logger.info("START NETWORKEVENT [PID %s] %s" % (PID_PROGRAM, iplist))

    def connected():
        service_logger.info("Connected")

    def disconnected():
        service_logger.info("Disconnected")

    manager = NetworkManager(
        connected,
        disconnected,
        send_kiosk=not args.no_send_kiosk,
        tcp_host=args.host,
        tcp_port=target_port,
    )
    # Thread non-daemon: le processus reste vivant tant que run() tourne.
    process = Thread(target=manager.run)
    process.start()
    process.join()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
