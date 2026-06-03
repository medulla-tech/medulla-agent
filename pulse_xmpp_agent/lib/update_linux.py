#!/usr/bin/env python3
# -*- coding: utf-8; -*-
# SPDX-FileCopyrightText: 2016-2023 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-3.0-or-later
# file pulse_xmpp_agent/lib/update_linux.py

import subprocess
import json
import re
import platform
from datetime import datetime, timezone
from pathlib import Path
import gzip
import base64
import zlib
from  lib.uuid_deterministic import DeterministicUUID
import logging
from abc import ABC, abstractmethod
import platform
import subprocess
import distro  # pip install distro
import socket
import uuid
from lib.uuid_deterministic import DeterministicUUID
from lib.utils import serialnumbermachine
logger = logging.getLogger(__name__)

# ######################################################################
#  familles Linux

# Famille	Debian/Ubuntu
# Classe possible	DebianSystem
# Manager	apt/dpkg
# Remarques   Security-only via changelog ou
              # -o APT::Default-Release=...-security


# Famille RedHat/CentOS/Fedora/Rocky
# Classe possible RedHatSystem ou FedoraSystem
# Manager dnf/rpm
# Remarques Security-only via dnf --security

# Famille Arch
# Classe possible ArchSystem
# Manager pacman
# Remarques Rolling release, pas de security-only officiel


# Famille openSUSE
# Classe possible SuseSystem
# Manager zypper
# Remarques Security-only via zypper patch --category security

# Famille Alpine
# Classe possible AlpineSystem
# Manager apk
# Remarques Très léger, adapté containers

# UpdateLinux pour dispatcher automatiquement entre :
#
# Debian/Ubuntu → DebianSystem
# RedHat/Fedora → RedHatSystem
# Arch → ArchSystem
# SUSE → SuseSystem
# Alpine → AlpineSystem
# …tout en gardant API uniforme
# (fetch_updates, update, maintenance, to_json, dry-run, policy-based update).


# API minimale
# Méthodes communes à toutes les distros
# Empêche l’instanciation implicite incomplète
# ####################################################################"

# ABC Abstract Base Class
class LinuxSystemBase(ABC):
    """
    Classe de base abstraite pour les systèmes Linux.
    Définit l'interface commune et les méthodes partagées par toutes les distributions.
    """

    def __init__(self, dry_run: bool = False):
        """
        Initialise les attributs communs à toutes les distributions.

        Args:
            dry_run (bool): Si True, les commandes sont simulées (mode "sec").
        """
        self.dry_run = dry_run
        self.system_info = {}
        self.counts = {
            "security": 0,
            "kernel": 0,
            "other": 0,
            "total": 0
        }
        self.reboot_required = False
        self.security_updates = []
        self.kernel_updates = []
        self.other_updates = []

    @staticmethod
    def _run(cmd: str) -> str:
        """
        Exécute une commande shell et retourne sa sortie.

        Args:
            cmd (str): Commande à exécuter.

        Returns:
            str: Sortie de la commande, nettoyée des espaces superflus.

        Raises:
            subprocess.CalledProcessError: Si la commande échoue.
        """
        logger.debug(cmd)
        return subprocess.check_output(cmd, shell=True, text=True).strip()

    def get_deterministic_uuid():
        hostname = socket.gethostname()

        # lire machine-id si disponible
        try:
            machine_id = pathlib.Path("/etc/machine-id").read_text().strip()
        except FileNotFoundError:
            machine_id = ""

        namespace = uuid.UUID("12345678-1234-5678-1234-567812345678")
        unique_string = f"{hostname}-{machine_id}"
        return str(uuid.uuid5(namespace, unique_string))

    def _get_hardware_uuid(self):
        try:
            result = subprocess.check_output(
                ["dmidecode", "-s", "system-uuid"],
                stderr=subprocess.DEVNULL,
                text=True
            ).strip()

            if not result or result == "00000000-0000-0000-0000-000000000000":
                return None

            return result.lower()

        except (subprocess.CalledProcessError, FileNotFoundError):
            return None

    def _get_best_machine_uuid(self):
        uuid_hw = self._get_hardware_uuid()
        if uuid_hw:
            return uuid_hw

        # fallback OS (machine-id)
        try:
            with open("/etc/machine-id") as f:
                return f.read().strip()
        except FileNotFoundError:
            return None


    def _get_system_info(self) -> dict:
        """
        Récupère les informations système (version, noyau, etc.).

        Returns:
            dict: Dictionnaire contenant les informations système.
        """
        info = {}
        try:
            out = self._run("lsb_release -a")
            for line in out.splitlines():
                if ":" in line:
                    k, v = line.split(":", 1)
                    info[k.strip()] = v.strip()
        except Exception:
            pass

        info["kernel_version"] = platform.release()
        return info

    @staticmethod
    def _reboot_required() -> bool:
        """
        Vérifie si un redémarrage est nécessaire après les mises à jour.

        Returns:
            bool: True si un redémarrage est nécessaire, False sinon.
        """
        return Path("/var/run/reboot-required").exists()


    def to_json(self, pretty: bool = True,
                base64_encode: bool = False,
                return_dict: bool = False):
        """
        Exporte les informations du système et des mises à jour au format JSON, base64 ou dictionnaire.

        Args:
            pretty (bool): Si True, formate le JSON de manière lisible.
            base64_encode (bool): Si True, encode le JSON en base64 (compressé).
            return_dict (bool): Si True, retourne un dictionnaire Python au lieu d'une chaîne.

        Returns:
            str|dict: Chaîne JSON (ou base64) ou dictionnaire représentant les informations du système.
        """
        data = {
            "generated_at": datetime.utcnow().isoformat() + "Z",
            "harduuid" : self.harduuid,
            "serialnumber": serialnumbermachine(),
            "system": self.system_info,
            "counts": self.counts,
            "security_updates": self.security_updates,
            "kernel_updates": self.kernel_updates,
            "other_updates": self.other_updates,
            "reboot_required": self.reboot_required,
        }

        if return_dict:
            return data

        raw = json.dumps(data, indent=4 if pretty else None)

        if base64_encode:
            return base64.b64encode(zlib.compress(raw.encode())).decode()

        return raw

    @staticmethod
    def from_base64(b64_string: str) -> dict:
        """
        Décode une chaîne JSON compressée et encodée en base64.

        Args:
            b64_string (str): Chaîne encodée en base64.

        Returns:
            dict: Dictionnaire décodé.
        """
        compressed = base64.b64decode(b64_string)
        return json.loads(zlib.decompress(compressed).decode("utf-8"))

    @abstractmethod
    def fetch_updates(self):
        """Récupère la liste des mises à jour disponibles."""
        pass

    @abstractmethod
    def update(self, policy: str = "all"):
        """Applique les mises à jour selon la politique spécifiée."""
        pass

    @abstractmethod
    def maintenance(self):
        """Effectue les tâches de maintenance système."""
        pass


class UpdateLinux:
    """
    Classe principale pour gérer les mises à jour des systèmes Linux.
    Agit comme une usine (Factory) et un proxy pour déléguer les actions à la classe système appropriée,
    en fonction de la distribution détectée. Fournit une API uniforme pour toutes les distributions supportées.

    Attributs:
        distro_name (str): Nom de la distribution détectée.
        system (LinuxSystemBase): Instance de la classe système spécifique à la distribution.
    """

    def __init__(self, **kwargs):
        """
        Initialise l'instance en détectant la distribution et en instanciant la classe système appropriée.

        Args:
            **kwargs: Arguments passés directement à la classe système (ex: dry_run, intranet_security, sources_name, etc.).
        """
        self.distro_name = self.detect_distribution()
        logger.info(f"Distribution détectée : {self.distro_name}")
        self.system = self._init_system(**kwargs)

    # ============================
    # Détection
    # ============================
    @staticmethod
    def detect_distribution():
        """
        Détecte et retourne le nom de la distribution Linux en cours d'exécution.

        Returns:
            str: Nom de la distribution en minuscules (ex: "ubuntu", "debian", "centos").
                Retourne le nom du système d'exploitation si la détection échoue.
        """
        try:
            return distro.id().lower()
        except Exception:
            return platform.system().lower()

    # ============================
    # Factory
    # ============================
    def _init_system(self, **kwargs):
        """
        Instancie et retourne la classe système appropriée en fonction de la distribution détectée.

        Args:
            **kwargs: Arguments passés à la classe système.

        Returns:
            LinuxSystemBase: Instance de la classe système spécifique à la distribution.

        Raises:
            NotImplementedError: Si la distribution n'est pas supportée.
        """
        # Debian / Ubuntu
        if self.distro_name in ("debian", "ubuntu"):
            return DebianSystem(**kwargs)

        # RedHat / CentOS / Rocky / AlmaLinux
        elif self.distro_name in ("rhel", "redhat", "centos", "rocky", "almalinux"):
            return RedHatSystem(**kwargs)

        # Fedora
        elif self.distro_name == "fedora":
            return FedoraSystem(**kwargs)

        # Arch Linux
        elif self.distro_name == "arch":
            return ArchSystem(**kwargs)

        else:
            raise NotImplementedError(
                f"Distribution non supportée : {self.distro_name}"
            )

    # ============================
    # Proxy des actions
    # ============================
    def fetch_updates(self):
        """
        Récupère la liste des mises à jour disponibles via la classe système spécifique.

        Returns:
            list: Liste des mises à jour disponibles.
        """
        return self.system.fetch_updates()

    def update(self, policy="all"):
        """
        Applique les mises à jour selon la politique spécifiée via la classe système spécifique.

        Args:
            policy (str, optional): Politique de mise à jour (défaut: "all").

        Returns:
            bool: True si la mise à jour a réussi, False sinon.
        """
        return self.system.update(policy=policy)

    def maintenance(self):
        """
        Effectue les tâches de maintenance système via la classe système spécifique.

        Returns:
            bool: True si la maintenance a réussi, False sinon.
        """
        return self.system.maintenance()

    def to_json(self, *args, **kwargs):
        """
        Exporte les informations du système au format JSON via la classe système spécifique.

        Args:
            *args: Arguments variables.
            **kwargs: Arguments optionnels (ex: pretty, base64_encode).

        Returns:
            str: Chaîne JSON représentant les informations du système.
        """
        return self.system.to_json(*args, **kwargs)

class DebianSystem(LinuxSystemBase):
    """
    Classe spécialisée pour la gestion des mises à jour et de la maintenance des systèmes Debian/Ubuntu.
    """

    def __init__(self, intranet_security: bool = False, sources_name: str | None = None, dry_run: bool = False):
        """
        Initialise une instance de DebianSystem.

        Args:
            intranet_security (bool): Active le mode intranet sécurisé si True.
            sources_name (str|None): Nom du fichier de sources APT pour le mode intranet.
            dry_run (bool): Si True, les commandes sont simulées (mode "sec").
        """
        super().__init__(dry_run)
        self.intranet_security = intranet_security
        self.sources_name = sources_name
        self.set_intranet_security(intranet_security, sources_name)
        self.system_info = self._get_system_info()
        self.harduuid = DeterministicUUID.get_deterministic_uuid()
        self.reboot_required = self._reboot_required()
        logger.info("DebianSystem initialisé")

    def _apt_base_opts(self) -> str:
        """Génère les options de base pour les commandes APT, en fonction du mode intranet."""
        opts = []
        if self.intranet_security and self.sources_name:
            opts.append(f"-o Dir::Etc::sourceparts=/etc/apt/sources.list.d/{self.sources_name}")
            opts.append("-o Dir::Etc::sourcelist=/dev/null")
        return " ".join(opts)

    def _apt_dry_run_opts(self) -> str:
        """Génère les options pour le mode 'sec' (simulation) des commandes APT."""
        return "--just-print" if self.dry_run else ""

    def _apt_security_opts(self) -> str:
        """Génère les options pour forcer l'utilisation du dépôt de sécurité."""
        release = self.system_info.get("Release", "")
        return f"-o APT::Default-Release={release}-security" if release else ""

    def set_intranet_security(self, enabled: bool, sources_name: str | None = None):
        """Active ou désactive le mode intranet sécurisé."""
        self.intranet_security = enabled
        if enabled:
            if not sources_name:
                raise ValueError("sources_name requis en mode intranet")
            sources_path = Path("/etc/apt/sources.list.d") / sources_name
            if not sources_path.exists():
                raise FileNotFoundError(f"{sources_path} introuvable")
            self.sources_name = sources_name
            logger.info("Mode intranet sécurisé ACTIVÉ")
        else:
            self.sources_name = None
            logger.info("Mode intranet sécurisé DÉSACTIVÉ")

    @staticmethod
    def _get_cve_from_changelog(pkg: str) -> list:
        """Extrait les identifiants CVE du changelog d'un paquet."""
        for p in (
            Path(f"/usr/share/doc/{pkg}/changelog.Debian.gz"),
            Path(f"/usr/share/doc/{pkg}/changelog.Debian"),
        ):
            if p.exists():
                data = (
                    gzip.open(p, "rt", errors="ignore").read()
                    if p.suffix == ".gz"
                    else p.read_text(errors="ignore")
                )
                return list(set(re.findall(r"CVE-\d{4}-\d{4,7}", data)))
        return []

    def fetch_updates(self):
        """Récupère la liste des mises à jour disponibles et les catégorise."""

        # -----------------------------
        # 1️⃣ Mettre à jour les dépôts APT
        # -----------------------------
        try:
            self._run(f"apt-get -qq update {self._apt_base_opts()}")
        except subprocess.CalledProcessError as e:
            # Certains dépôts peuvent échouer (code 100) sans compromettre les autres.
            # On log un warning et on continue pour exploiter les index partiellement rafraîchis.
            logger.warning(
                "apt-get update returned non-zero exit status (some repositories may be unavailable): %s",
                str(e),
            )

        # -----------------------------
        # 2️⃣ Récupérer la liste des mises à jour
        # -----------------------------
        output = self._run(f"apt-get --just-print upgrade {self._apt_base_opts()}")

        # -----------------------------
        # 3️⃣ Réinitialiser les listes
        # -----------------------------
        self.security_updates.clear()
        self.kernel_updates.clear()
        self.other_updates.clear()

        # -----------------------------
        # 4️⃣ Parcourir chaque ligne pour extraire package et version
        # -----------------------------
        for line in output.splitlines():
            if not line.startswith("Inst"):
                continue

            pkg_version = None
            m = re.search(r"\(([^)]+)\)", line)
            if m:
                inside = m.group(1)
                # version = premier mot dans les parenthèses
                parts_inside = inside.split()
                if parts_inside and parts_inside[0][0].isdigit():  # doit commencer par un chiffre
                    pkg_version = parts_inside[0]

            part = line.split()
            if len(part) < 2:
                continue  # sécurité
            pkg = part[1]

            entry = {"package": pkg, "version": pkg_version, "cve": []}

            # catégorisation
            if "security" in line.lower():
                entry["cve"] = self._get_cve_from_changelog(pkg)
                if pkg.startswith("linux-"):
                    self.kernel_updates.append(entry)
                else:
                    self.security_updates.append(entry)
            else:
                self.other_updates.append(entry)

        # -----------------------------
        # 5️⃣ Mettre à jour le compteur
        # -----------------------------
        self.counts["security"] = len(self.security_updates)
        self.counts["kernel"] = len(self.kernel_updates)
        self.counts["other"] = len(self.other_updates)
        self.counts["total"] = sum(self.counts.values())

        return True

    def update(self, policy: str = "all"):
        """Applique les mises à jour selon la politique spécifiée."""
        base = self._apt_base_opts()
        dry = self._apt_dry_run_opts()
        sec = self._apt_security_opts()
        self._run(f"apt-get -qq update {base}")

        if policy == "security-only":
            self._run(f"apt-get -qq upgrade -y {dry} {sec} {base}")
        elif policy == "kernel-only":
            self._run(f"apt-get -qq install --only-upgrade linux-image-amd64 -y {dry} {base}")
        elif policy == "applications-only":
            self._run(f"apt-get -qq upgrade -y {dry} {base}")
        elif policy == "all":
            self._run(f"apt-get -qq full-upgrade -y {dry} {base}")
        else:
            raise ValueError(f"Policy inconnue: {policy}")

    def maintenance(self):
        """Effectue les tâches de maintenance (nettoyage des paquets inutiles)."""
        base = self._apt_base_opts()
        dry = self._apt_dry_run_opts()
        self._run(f"apt-get -qq autoremove -y {dry} {base}")
        self._run(f"apt-get -qq autoclean {base}")

class RedHatSystem(LinuxSystemBase):
    """
    Gestion des mises à jour pour RedHat, CentOS, RockyLinux, AlmaLinux, Fedora.
    API identique à DebianSystem pour intégration dans UpdateLinux.
    """

    def __init__(self, dry_run: bool = False):
        """
        :param dry_run: simule les commandes sans les appliquer
        """
        self.dry_run = dry_run
        self.system_info = self._get_system_info()
        self.harduuid = DeterministicUUID.get_deterministic_uuid()
        self.security_updates = []
        self.kernel_updates = []
        self.other_updates = []
        self.counts = {
            "security": 0,
            "kernel": 0,
            "other": 0,
            "total": 0
        }
        self.reboot_required = self._reboot_required()
        logger.info("RedHatSystem initialisé")

    # ============================
    # Shell
    # ============================
    @staticmethod
    def _run(cmd: str):
        logger.debug(cmd)
        return subprocess.check_output(cmd, shell=True, text=True).strip()

    def _dnf_dry_run(self):
        return "--assumeno" if self.dry_run else ""

    # ============================
    # Infos système
    # ============================
    def _get_system_info(self):
        info = {}
        try:
            # Utilise lsb_release si présent, sinon fallback
            out = self._run("cat /etc/os-release")
            for line in out.splitlines():
                if "=" in line:
                    k, v = line.split("=", 1)
                    info[k.strip()] = v.strip().strip('"')
        except Exception:
            pass
        info["kernel_version"] = platform.release()
        return info

    # ============================
    # Reboot
    # ============================
    @staticmethod
    def _reboot_required():
        return Path("/var/run/reboot-required").exists() or Path("/run/reboot-required").exists()

    # ============================
    # CVE depuis rpm changelog
    # ============================
    @staticmethod
    def _get_cve_from_changelog(pkg):
        try:
            output = subprocess.check_output(
                f"rpm -q --changelog {pkg}", shell=True, text=True, errors="ignore"
            )
            return list(set(re.findall(r"CVE-\d{4}-\d{4,7}", output)))
        except subprocess.CalledProcessError:
            return []

    # ============================
    # Fetch updates
    # ============================
    def fetch_updates(self):
        """
        Analyse les mises à jour disponibles sans appliquer.
        """
        dry = self._dnf_dry_run()
        self.security_updates.clear()
        self.kernel_updates.clear()
        self.other_updates.clear()

        # lister les paquets disponibles
        output = self._run(f"dnf check-update {dry} || true")

        for line in output.splitlines():
            if not line or line.startswith(("Last metadata", "Obsoleting")):
                continue

            parts = line.split()
            if len(parts) < 2:
                continue
            logger.error("JFKJFK %s \n" % parts)
            pkg = parts[0]
            entry = {"package": pkg, "cve": []}

            # approximation : si security dans pkg ou nom
            if "kernel" in pkg.lower():
                self.kernel_updates.append(entry)
            elif "security" in line.lower() or "elrepo" in line.lower():
                entry["cve"] = self._get_cve_from_changelog(pkg)
                self.security_updates.append(entry)
            else:
                self.other_updates.append(entry)

        self.counts["security"] = len(self.security_updates)
        self.counts["kernel"] = len(self.kernel_updates)
        self.counts["other"] = len(self.other_updates)
        self.counts["total"] = sum(self.counts.values())

    # ============================
    # Policy-based update
    # ============================
    def update(self, policy="all"):
        dry = self._dnf_dry_run()

        if policy == "security-only":
            self._run(f"dnf -y update --security {dry}")
        elif policy == "kernel-only":
            self._run(f"dnf -y update kernel* {dry}")
        elif policy == "applications-only":
            self._run(f"dnf -y update {dry}")
        elif policy == "all":
            self._run(f"dnf -y upgrade {dry}")
        else:
            raise ValueError(f"Policy inconnue: {policy}")

    # ============================
    # Maintenance
    # ============================
    def maintenance(self):
        dry = self._dnf_dry_run()
        self._run(f"dnf -y autoremove {dry}")
        self._run(f"dnf clean all")

    # ============================
    # JSON
    # ============================
    def to_json(self, pretty=True, base64_encode=False):
        data = {
            "generated_at": datetime.utcnow().isoformat() + "Z",
            "system": self.system_info,
            "counts": self.counts,
            "security_updates": self.security_updates,
            "kernel_updates": self.kernel_updates,
            "other_updates": self.other_updates,
            "reboot_required": self.reboot_required
        }

        raw = json.dumps(data, indent=4 if pretty else None)

        if base64_encode:
            return base64.b64encode(zlib.compress(raw.encode())).decode()

        return raw

    @staticmethod
    def from_base64(b64_string: str) -> dict:
        compressed = base64.b64decode(b64_string)
        return json.loads(zlib.decompress(compressed).decode("utf-8"))

    @staticmethod
    def from_base64_str(b64_string: str) -> str:
        compressed = base64.b64decode(b64_string)
        return zlib.decompress(compressed).decode("utf-8")

class FedoraSystem(RedHatSystem):
    """Alias pour Fedora, utilise le même backend DNF que RedHat"""
    pass

class ArchSystem(LinuxSystemBase):
    """
    Classe spécialisée pour la gestion des mises à jour et de la maintenance des systèmes Arch Linux.
    """

    def __init__(self, dry_run: bool = False):
        """
        Initialise une instance de ArchSystem.

        Args:
            dry_run (bool): Si True, les commandes sont simulées (mode "sec").
        """
        super().__init__(dry_run=dry_run)
        self.system_info = self._get_system_info()
        self.harduuid = DeterministicUUID.get_deterministic_uuid()
        self.reboot_required = self._reboot_required()
        logger.info("ArchSystem initialisé")

    # ============================
    # Infos système
    # ============================
    def _get_system_info(self) -> dict:
        """
        Récupère les informations système spécifiques à Arch Linux.

        Returns:
            dict: Dictionnaire contenant les informations système.
        """
        info = {}
        try:
            out = self._run("cat /etc/os-release")
            for line in out.splitlines():
                if "=" in line:
                    k, v = line.split("=", 1)
                    info[k.strip()] = v.strip().strip('"')
        except Exception:
            pass
        info["kernel_version"] = platform.release()
        return info

    # ============================
    # Options Pacman
    # ============================
    def _pacman_dry_run_opts(self) -> str:
        """
        Génère les options pour le mode "sec" (simulation) des commandes Pacman.

        Returns:
            str: Option "-Qu" si dry_run est activé, sinon une chaîne vide.
        """
        return "-Qu" if self.dry_run else ""

    # ============================
    # Récupération des mises à jour
    # ============================
    def fetch_updates(self):
        """
        Récupère la liste des mises à jour disponibles pour Arch Linux et les catégorise.
        """
        dry_opts = self._pacman_dry_run_opts()
        self.security_updates.clear()
        self.kernel_updates.clear()
        self.other_updates.clear()

        # Lister les paquets à mettre à jour
        output = self._run(f"pacman -Sup {dry_opts} || true")

        for line in output.splitlines():
            pkg = line.strip()
            if not pkg:
                continue
            entry = {"package": pkg, "cve": []}

            if pkg.startswith("linux"):
                self.kernel_updates.append(entry)
            else:
                self.other_updates.append(entry)

        self.counts["security"] = len(self.security_updates)
        self.counts["kernel"] = len(self.kernel_updates)
        self.counts["other"] = len(self.other_updates)
        self.counts["total"] = sum(self.counts.values())

    # ============================
    # Mise à jour selon une politique
    # ============================
    def update(self, policy: str = "all"):
        """
        Applique les mises à jour selon la politique spécifiée pour Arch Linux.

        Args:
            policy (str): Politique de mise à jour ("kernel-only", "applications-only", "all").

        Raises:
            ValueError: Si la politique est inconnue.
        """
        dry = "--noconfirm" if not self.dry_run else "--print"
        if policy == "kernel-only":
            self._run(f"pacman -S {dry} linux")
        elif policy == "applications-only":
            self._run(f"pacman -Syu {dry}")
        elif policy == "all":
            self._run(f"pacman -Syu {dry}")
        else:
            raise ValueError(f"Policy inconnue: {policy}")

    # ============================
    # Maintenance
    # ============================
    def maintenance(self):
        """
        Effectue les tâches de maintenance spécifiques à Arch Linux.
        """
        self._run("pacman -Rns $(pacman -Qtdq) || true")
        self._run("pacman -Scc --noconfirm")


class SuseSystem(LinuxSystemBase):
    """
    Classe spécialisée pour la gestion des mises à jour et de la maintenance des systèmes openSUSE.
    """

    def __init__(self, dry_run: bool = False):
        """
        Initialise une instance de SuseSystem.

        Args:
            dry_run (bool): Si True, les commandes sont simulées (mode "sec").
        """
        super().__init__(dry_run=dry_run)
        self.system_info = self._get_system_info()
        self.harduuid = DeterministicUUID.get_deterministic_uuid()
        self.reboot_required = self._reboot_required()
        logger.info("SuseSystem initialisé")

    # ============================
    # Infos système
    # ============================
    def _get_system_info(self) -> dict:
        """
        Récupère les informations système spécifiques à openSUSE.

        Returns:
            dict: Dictionnaire contenant les informations système.
        """
        info = {}
        try:
            out = self._run("cat /etc/os-release")
            for line in out.splitlines():
                if "=" in line:
                    k, v = line.split("=", 1)
                    info[k.strip()] = v.strip().strip('"')
        except Exception:
            pass
        info["kernel_version"] = platform.release()
        return info

    # ============================
    # Redémarrage requis
    # ============================
    @staticmethod
    def _reboot_required() -> bool:
        """
        Vérifie si un redémarrage est nécessaire après les mises à jour pour openSUSE.

        Returns:
            bool: True si un redémarrage est nécessaire, False sinon.
        """
        return Path("/var/run/reboot-required").exists() or Path("/run/reboot-required").exists()

    # ============================
    # Options Zypper
    # ============================
    def _zypper_dry_run_opts(self) -> str:
        """
        Génère les options pour le mode "sec" (simulation) des commandes Zypper.

        Returns:
            str: Option "--dry-run" si dry_run est activé, sinon une chaîne vide.
        """
        return "--dry-run" if self.dry_run else ""

    # ============================
    # Récupération des mises à jour
    # ============================
    def fetch_updates(self):
        """
        Récupère la liste des mises à jour disponibles pour openSUSE et les catégorise.
        """
        dry_opts = self._zypper_dry_run_opts()
        self.security_updates.clear()
        self.kernel_updates.clear()
        self.other_updates.clear()

        output = self._run(f"zypper list-updates {dry_opts}")
        for line in output.splitlines():
            if not line or line.startswith(("S |", "i |")):
                continue
            pkg = line.split()[1]
            entry = {"package": pkg, "cve": []}
            if "kernel" in pkg.lower():
                self.kernel_updates.append(entry)
            elif "patch" in line.lower() or "security" in line.lower():
                self.security_updates.append(entry)
            else:
                self.other_updates.append(entry)

        self.counts["security"] = len(self.security_updates)
        self.counts["kernel"] = len(self.kernel_updates)
        self.counts["other"] = len(self.other_updates)
        self.counts["total"] = sum(self.counts.values())

    # ============================
    # Mise à jour selon une politique
    # ============================
    def update(self, policy: str = "all"):
        """
        Applique les mises à jour selon la politique spécifiée pour openSUSE.

        Args:
            policy (str): Politique de mise à jour ("security-only", "kernel-only", "applications-only", "all").

        Raises:
            ValueError: Si la politique est inconnue.
        """
        dry = self._zypper_dry_run_opts()
        if policy == "security-only":
            self._run(f"zypper patch --category security {dry}")
        elif policy == "kernel-only":
            self._run(f"zypper update kernel {dry}")
        elif policy == "applications-only":
            self._run(f"zypper update {dry}")
        elif policy == "all":
            self._run(f"zypper dup {dry}")
        else:
            raise ValueError(f"Policy inconnue: {policy}")

    # ============================
    # Maintenance
    # ============================
    def maintenance(self):
        """
        Effectue les tâches de maintenance spécifiques à openSUSE.
        """
        self._run("zypper clean -a")


class AlpineSystem(LinuxSystemBase):
    """
    Classe spécialisée pour la gestion des mises à jour et de la maintenance des systèmes Alpine Linux.
    """

    def __init__(self, dry_run: bool = False):
        """
        Initialise une instance de AlpineSystem.

        Args:
            dry_run (bool): Si True, les commandes sont simulées (mode "sec").
        """
        super().__init__(dry_run=dry_run)
        self.system_info = self._get_system_info()
        self.harduuid = DeterministicUUID.get_deterministic_uuid()
        self.reboot_required = self._reboot_required()
        logger.info("AlpineSystem initialisé")

    # ============================
    # Infos système
    # ============================
    def _get_system_info(self) -> dict:
        """
        Récupère les informations système spécifiques à Alpine Linux.

        Returns:
            dict: Dictionnaire contenant les informations système.
        """
        info = {}
        try:
            out = self._run("cat /etc/os-release")
            for line in out.splitlines():
                if "=" in line:
                    k, v = line.split("=", 1)
                    info[k.strip()] = v.strip().strip('"')
        except Exception:
            pass
        info["kernel_version"] = platform.release()
        return info

    # ============================
    # Options APK
    # ============================
    def _apk_dry_run_opts(self) -> str:
        """
        Génère les options pour le mode "sec" (simulation) des commandes APK.

        Returns:
            str: Option "-u --simulate" si dry_run est activé, sinon "-u".
        """
        return "-u --simulate" if self.dry_run else "-u"

    # ============================
    # Récupération des mises à jour
    # ============================
    def fetch_updates(self):
        """
        Récupère la liste des mises à jour disponibles pour Alpine Linux et les catégorise.
        """
        dry_opts = self._apk_dry_run_opts()
        self.security_updates.clear()
        self.kernel_updates.clear()
        self.other_updates.clear()

        output = self._run(f"apk version -l '<' {dry_opts}")
        for line in output.splitlines():
            pkg = line.split()[0]
            entry = {"package": pkg, "cve": []}
            if "linux" in pkg.lower():
                self.kernel_updates.append(entry)
            else:
                self.other_updates.append(entry)

        self.counts["security"] = len(self.security_updates)
        self.counts["kernel"] = len(self.kernel_updates)
        self.counts["other"] = len(self.other_updates)
        self.counts["total"] = sum(self.counts.values())

    # ============================
    # Mise à jour selon une politique
    # ============================
    def update(self, policy: str = "all"):
        """
        Applique les mises à jour selon la politique spécifiée pour Alpine Linux.

        Args:
            policy (str): Politique de mise à jour ("security-only", "kernel-only", "applications-only", "all").

        Raises:
            ValueError: Si la politique est inconnue.
        """
        dry_opts = self._apk_dry_run_opts()
        if policy == "kernel-only":
            self._run(f"apk upgrade linux {dry_opts}")
        elif policy in ("applications-only", "all"):
            self._run(f"apk upgrade {dry_opts}")
        elif policy == "security-only":
            self._run(f"apk upgrade --security {dry_opts}")
        else:
            raise ValueError(f"Policy inconnue: {policy}")

    # ============================
    # Maintenance
    # ============================
    def maintenance(self):
        """
        Effectue les tâches de maintenance spécifiques à Alpine Linux.
        """
        self._run("apk cache clean")


# ----------------------------
# Test si exécuté directement
# ----------------------------

if __name__ == "__main__":
    print("=== Test UpdateLinux multi-distro via proxy ===\n")
    # Liste des systèmes à tester
    systems = [
        "Debian",
        "RedHat",
        "Arch",
        "SUSE",
        "Alpine",
    ]
    # Création de l'updater (dry-run pour sécurité)
    # updater = UpdateLinux(dry_run=True)
    updater = UpdateLinux(
        dry_run=True,            # exécution réelle
        intranet_security=False   # dépôts normaux
    )
    print(f"Distribution détectée : {updater.distro_name}\n")


    print(f"Distribution détectée : {updater.distro_name}\n")

    # ============================
    # 1. Fetch updates
    # ============================
    print("[1] Recherche des mises à jour...")
    updater.fetch_updates()

    counts = updater.system.counts
    print(
        f"Updates trouvées -> "
        f"Security: {counts['security']}, "
        f"Kernel: {counts['kernel']}, "
        f"Other: {counts['other']}, "
        f"Total: {counts['total']}"
    )

    # ============================
    # 2. Mise à jour complète
    # ============================
    if counts["total"] > 0:
        print("\n[2] Application des mises à jour (policy=all)...")
        updater.update(policy="all")
    else:
        print("\n[2] Aucune mise à jour à appliquer")

    # ============================
    # 3. Maintenance
    # ============================
    print("\n[3] Maintenance système...")
    updater.maintenance()

    # ============================
    # 4. Export JSON
    # ============================
    print("\n[4] Export JSON...")
    json_report = updater.to_json(pretty=True)
    print(json_report)

    # ============================
    # 5. Reboot ?
    # ============================
    if updater.system.reboot_required:
        print("\n⚠️  Redémarrage requis")
    else:
        print("\n✅ Aucun redémarrage requis")

    print("\n=== Fin du test UpdateLinux ===")
