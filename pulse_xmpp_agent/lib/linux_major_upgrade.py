#!/usr/bin/env python3
# -*- coding: utf-8; -*-
# SPDX-FileCopyrightText: 2016-2023 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-3.0-or-later

import glob
import json
import logging
import shutil
import socket
import subprocess
from pathlib import Path

logger = logging.getLogger(__name__)


class DebianMajorUpgradeAudit:
    """Collect and validate data required for Debian major upgrade planning.

    This helper focuses on audit/precheck for major upgrades (example: 12 -> 13).
    It intentionally does not execute the upgrade.
    """

    OFFICIAL_DEBIAN_HOSTS = (
        "deb.debian.org",
        "security.debian.org",
        "ftp.debian.org",
    )

    MIGRATION_PATHS = {
        "10": {"target_version": "11", "target_codename": "bullseye"},
        "11": {"target_version": "12", "target_codename": "bookworm"},
        "12": {"target_version": "13", "target_codename": "trixie"},
    }

    REQUIRED_EXTERNAL_FIELDS = [
        "target_version",
        "target_codename",
        "repo_profile",
        "change_ticket",
    ]

    BLOCKING_REASON_MESSAGES = {
        "UNSUPPORTED_DISTRIBUTION": "Distribution non supportée: seuls les hôtes Debian sont éligibles.",
        "NOT_ENOUGH_DISK_ROOT": "Espace disque insuffisant sur / (minimum recommandé: 5 Go).",
        "NOT_ENOUGH_DISK_VAR": "Espace disque insuffisant sur /var (minimum recommandé: 5 Go).",
        "NOT_ENOUGH_DISK_BOOT": "Espace disque insuffisant sur /boot (minimum recommandé: 0.5 Go).",
        "BROKEN_PACKAGES": "Le système a des paquets cassés (dpkg --audit non vide).",
        "APT_CHECK_FAILED": "La commande 'apt-get check' a échoué. Corriger les dépendances APT avant upgrade.",
        "APT_UPDATE_FAILED": "La commande 'apt-get -qq update' a échoué. Un dépôt est probablement invalide/injoignable.",
        "THIRD_PARTY_REPOSITORIES": "Des dépôts tiers sont détectés et non autorisés par la politique.",
        "UNSUPPORTED_MIGRATION_PATH": "Le chemin de migration Debian demandé n'est pas supporté.",
        "TARGET_VERSION_MISMATCH": "La version cible fournie ne correspond pas au chemin de migration attendu.",
        "TARGET_CODENAME_MISMATCH": "Le codename cible fourni ne correspond pas au chemin de migration attendu.",
        "MISSING_REQUIRED_EXTERNAL_DATA": "Des champs obligatoires de pilotage sont manquants.",
    }

    WARNING_REASON_MESSAGES = {
        "APT_UPDATE_PARTIAL_FAILURE": "Un dépôt APT est en erreur, mais les anciens index sont utilisés. Upgrade autorisé avec avertissement.",
    }

    def __init__(self, payload=None):
        self.payload = payload if isinstance(payload, dict) else {}

    @staticmethod
    def _run(command):
        logger.debug("linux_major_upgrade command: %s", command)
        return subprocess.check_output(command, shell=True, text=True, stderr=subprocess.STDOUT).strip()

    @staticmethod
    def _read_os_release():
        data = {}
        try:
            for line in Path("/etc/os-release").read_text(encoding="utf-8", errors="ignore").splitlines():
                if "=" not in line:
                    continue
                key, value = line.split("=", 1)
                data[key.strip()] = value.strip().strip('"')
        except Exception:
            logger.debug("Unable to read /etc/os-release", exc_info=True)
        return data

    @staticmethod
    def _read_meminfo_mb():
        values = {
            "ram_total_mb": None,
            "ram_available_mb": None,
            "swap_total_mb": None,
        }
        try:
            for line in Path("/proc/meminfo").read_text(encoding="utf-8", errors="ignore").splitlines():
                if ":" not in line:
                    continue
                key, raw = line.split(":", 1)
                amount_kb = raw.strip().split()[0]
                if not amount_kb.isdigit():
                    continue
                amount_mb = int(amount_kb) // 1024
                if key == "MemTotal":
                    values["ram_total_mb"] = amount_mb
                elif key == "MemAvailable":
                    values["ram_available_mb"] = amount_mb
                elif key == "SwapTotal":
                    values["swap_total_mb"] = amount_mb
        except Exception:
            logger.debug("Unable to read /proc/meminfo", exc_info=True)
        return values

    @staticmethod
    def _disk_free_gb(paths):
        result = {}
        for path in paths:
            try:
                usage = shutil.disk_usage(path)
                result[path] = round(usage.free / (1024 ** 3), 2)
            except Exception:
                result[path] = None
        return result

    @staticmethod
    def _safe_int(text_value, default=0):
        try:
            return int(str(text_value).strip())
        except Exception:
            return default

    def _list_apt_sources(self):
        entries = []

        def _collect_file(path):
            try:
                content = Path(path).read_text(encoding="utf-8", errors="ignore")
            except Exception:
                return

            for line in content.splitlines():
                stripped = line.strip()
                if not stripped or stripped.startswith("#"):
                    continue
                if stripped.startswith("deb ") or stripped.startswith("URIs:"):
                    entries.append({"file": path, "line": stripped})

        _collect_file("/etc/apt/sources.list")
        for list_file in sorted(glob.glob("/etc/apt/sources.list.d/*.list")):
            _collect_file(list_file)
        for sources_file in sorted(glob.glob("/etc/apt/sources.list.d/*.sources")):
            _collect_file(sources_file)

        return entries

    def _detect_third_party_repositories(self, apt_sources):
        third_party = []
        for item in apt_sources:
            line = item.get("line", "")
            lowered = line.lower()
            if line.startswith("URIs:"):
                candidate = line.split(":", 1)[1].strip().lower()
            elif line.startswith("deb "):
                parts = line.split()
                candidate = parts[1].lower() if len(parts) > 1 else ""
            else:
                candidate = ""

            if candidate.startswith("["):
                candidate = ""

            if not candidate:
                continue

            if not any(host in lowered for host in self.OFFICIAL_DEBIAN_HOSTS):
                third_party.append({"file": item.get("file"), "source": line})

        return third_party

    @staticmethod
    def _command_error_payload(command, exc):
        """Return a compact, readable error payload for command failures."""
        output = str(getattr(exc, "output", "") or "").strip()
        tail_lines = output.splitlines()[-12:] if output else []
        return {
            "command": command,
            "returncode": getattr(exc, "returncode", None),
            "output_tail": "\n".join(tail_lines),
        }

    def _collect_package_state(self):
        upgradable_count = None
        held_packages = []
        broken_packages = False
        apt_check_ok = False
        apt_update_ok = False
        apt_check_error = {}
        apt_update_error = {}

        try:
            out = self._run("apt list --upgradable 2>/dev/null | tail -n +2 | wc -l")
            upgradable_count = self._safe_int(out, default=0)
        except Exception:
            logger.debug("Unable to count upgradable packages", exc_info=True)

        try:
            out = self._run("apt-mark showhold")
            held_packages = [line.strip() for line in out.splitlines() if line.strip()]
        except Exception:
            logger.debug("Unable to list held packages", exc_info=True)

        try:
            out = self._run("dpkg --audit")
            broken_packages = bool(out.strip())
        except Exception:
            # dpkg --audit returns 0/empty when healthy; any exception means uncertain state.
            broken_packages = True

        try:
            self._run("apt-get check")
            apt_check_ok = True
        except subprocess.CalledProcessError as exc:
            apt_check_ok = False
            apt_check_error = self._command_error_payload("apt-get check", exc)
        except Exception as exc:
            apt_check_ok = False
            apt_check_error = {"command": "apt-get check", "error": str(exc)}

        try:
            self._run("apt-get -qq update")
            apt_update_ok = True
        except subprocess.CalledProcessError as exc:
            apt_update_ok = False
            apt_update_error = self._command_error_payload("apt-get -qq update", exc)
        except Exception as exc:
            apt_update_ok = False
            apt_update_error = {"command": "apt-get -qq update", "error": str(exc)}

        return {
            "updates_available": upgradable_count,
            "held_packages": held_packages,
            "broken_packages": broken_packages,
            "apt_check_ok": apt_check_ok,
            "apt_update_ok": apt_update_ok,
            "apt_check_error": apt_check_error,
            "apt_update_error": apt_update_error,
        }

    @staticmethod
    def _is_non_blocking_apt_update_failure(package_state):
        """Return True when apt update failed but old indexes are usable (rc=100)."""
        error_payload = package_state.get("apt_update_error") or {}
        rc = error_payload.get("returncode")
        tail = str(error_payload.get("output_tail") or "").lower()
        if rc != 100:
            return False

        markers = [
            "old ones used instead",
            "they have been ignored",
            "le téléchargement de quelques fichiers d'index a échoué",
            "ont été ignorés",
            "some index files failed to download",
        ]
        return any(marker in tail for marker in markers)

    def _get_expected_target(self, current_version):
        return self.MIGRATION_PATHS.get(str(current_version).strip())

    def _normalize_external_spec(self):
        # Canonical key used internally
        spec = self.payload.get("upgrade_spec")
        if isinstance(spec, dict):
            return spec
        # Alias used by grafcet descriptors (upgradeparameter)
        spec = self.payload.get("upgradeparameter")
        if isinstance(spec, dict):
            return spec
        return self.payload

    def build(self):
        os_release = self._read_os_release()
        distro_id = (os_release.get("ID") or "").strip().lower()
        current_version = (os_release.get("VERSION_ID") or "").strip()
        current_codename = (os_release.get("VERSION_CODENAME") or "").strip().lower()

        external_spec = self._normalize_external_spec()
        provided = {
            "target_version": str(external_spec.get("target_version", "")).strip(),
            "target_codename": str(external_spec.get("target_codename", "")).strip().lower(),
            "repo_profile": str(external_spec.get("repo_profile", "")).strip(),
            "change_ticket": str(external_spec.get("change_ticket", "")).strip(),
            "allow_third_party_repositories": bool(external_spec.get("allow_third_party_repositories", False)),
        }

        missing_required = [name for name in self.REQUIRED_EXTERNAL_FIELDS if not provided.get(name)]

        disks = self._disk_free_gb(["/", "/boot", "/var"])
        memory = self._read_meminfo_mb()
        package_state = self._collect_package_state()
        apt_sources = self._list_apt_sources()
        third_party_repos = self._detect_third_party_repositories(apt_sources)

        expected_target = self._get_expected_target(current_version)

        blocking_reasons = []
        warning_reasons = []

        if distro_id != "debian":
            blocking_reasons.append("UNSUPPORTED_DISTRIBUTION")

        if disks.get("/") is not None and disks["/"] < 5:
            blocking_reasons.append("NOT_ENOUGH_DISK_ROOT")
        if disks.get("/var") is not None and disks["/var"] < 5:
            blocking_reasons.append("NOT_ENOUGH_DISK_VAR")
        if disks.get("/boot") is not None and disks["/boot"] < 0.5:
            blocking_reasons.append("NOT_ENOUGH_DISK_BOOT")

        if package_state.get("broken_packages"):
            blocking_reasons.append("BROKEN_PACKAGES")

        if not package_state.get("apt_check_ok"):
            blocking_reasons.append("APT_CHECK_FAILED")

        if not package_state.get("apt_update_ok"):
            if self._is_non_blocking_apt_update_failure(package_state):
                warning_reasons.append("APT_UPDATE_PARTIAL_FAILURE")
            else:
                blocking_reasons.append("APT_UPDATE_FAILED")

        if third_party_repos and not provided.get("allow_third_party_repositories"):
            blocking_reasons.append("THIRD_PARTY_REPOSITORIES")

        if expected_target is None:
            blocking_reasons.append("UNSUPPORTED_MIGRATION_PATH")
        else:
            if provided.get("target_version") and provided["target_version"] != expected_target["target_version"]:
                blocking_reasons.append("TARGET_VERSION_MISMATCH")
            if provided.get("target_codename") and provided["target_codename"] != expected_target["target_codename"]:
                blocking_reasons.append("TARGET_CODENAME_MISMATCH")

        if missing_required:
            blocking_reasons.append("MISSING_REQUIRED_EXTERNAL_DATA")

        blocking_reasons_details = [
            {
                "code": reason,
                "message": self.BLOCKING_REASON_MESSAGES.get(reason, reason),
            }
            for reason in blocking_reasons
        ]
        warning_reasons_details = [
            {
                "code": reason,
                "message": self.WARNING_REASON_MESSAGES.get(reason, reason),
            }
            for reason in warning_reasons
        ]

        upgrade_possible = len(blocking_reasons) == 0

        return {
            "schema": "linux-major-upgrade-audit/v1",
            "upgrade_possible": upgrade_possible,
            "blocking_reasons": blocking_reasons,
            "blocking_reasons_details": blocking_reasons_details,
            "warning_reasons": warning_reasons,
            "warning_reasons_details": warning_reasons_details,
            "required_external_fields": self.REQUIRED_EXTERNAL_FIELDS,
            "provided_external_data": provided,
            "missing_external_data": missing_required,
            "current_system": {
                "hostname": socket.gethostname(),
                "distribution": distro_id,
                "version": current_version,
                "codename": current_codename,
                "pretty_name": os_release.get("PRETTY_NAME", ""),
                "kernel": self._run("uname -r") if Path("/bin/uname").exists() or Path("/usr/bin/uname").exists() else "",
                "architecture": self._run("dpkg --print-architecture") if Path("/usr/bin/dpkg").exists() else "",
            },
            "expected_target": expected_target,
            "resources": {
                "disk_free_gb": disks,
                "memory": memory,
            },
            "packages": package_state,
            "repositories": {
                "third_party": third_party_repos,
                "sources_count": len(apt_sources),
            },
        }

    def to_json(self, pretty=True):
        payload = self.build()
        if pretty:
            return json.dumps(payload, indent=4, sort_keys=True)
        return json.dumps(payload, sort_keys=True)
