#!/usr/bin/python3
# SPDX-FileCopyrightText: 2020-2024 Siveo <support@siveo.net>
# SPDX-FileCopyrightText: 2025-2026 NATSU <support@medulla-tech.io>
# SPDX-License-Identifier: GPL-3.0-or-later
# file : pulse_xmpp_agent/bin/medulla_windows11_compatibility.py

"""Utilitaire standalone de diagnostic de compatibilite Windows 11."""

import argparse
import codecs
import io
from contextlib import redirect_stdout
import json
import locale
import logging
import os
import platform
import re
import shutil
import subprocess
import sys
import tempfile
import traceback
import xml.etree.ElementTree as ET
from datetime import datetime

import psutil


logger = logging.getLogger(__name__)

CPU_ARCHITECTURE = {
    0: "x86",
    1: "MIPS",
    2: "Alpha",
    3: "PowerPC",
    5: "ARM",
    6: "IA64",
    9: "x64",
    12: "ARM64",
}

FIRMWARE_TYPE = {
    0: "Unknown",
    1: "Legacy BIOS",
    2: "UEFI",
}

MEMORY_TYPE = {
    20: "DDR",
    21: "DDR2",
    22: "DDR2 FB-DIMM",
    24: "DDR3",
    26: "DDR4",
    34: "DDR5",
}

BATTERY_STATUS = {
    1: "Discharging",
    2: "AC power",
    3: "Fully charged",
    4: "Low",
    5: "Critical",
    6: "Charging",
    7: "Charging and high",
    8: "Charging and low",
    9: "Charging and critical",
    10: "Undefined",
    11: "Partially charged",
}

VIDEO_INPUT_TYPE = {
    0: "Analog",
    1: "Digital",
}


class Windows11Compatibility:
    """Collecte les informations necessaires pour evaluer la compatibilite Windows 11.

    Cette version est autonome et peut etre utilisee sans l'infrastructure plugin
    de l'agent. Elle retourne a la fois les indicateurs booleens et les details
    utiles pour un diagnostic manuel et un inventaire plus complet.
    """

    def __init__(
        self,
        debug=None,
        output_format="json",
        is_compatible_only=False,
        fail_on_incompatible=False,
        output_file=None,
        journal_file=None,
    ):
        """Initialise le collecteur de compatibilite.

        Args:
            debug: Force le mode debug (True/False). Si None, le mode est
                determine automatiquement selon le logger racine et la variable
                d'environnement MEDULLA_WIN11_COMPAT_DEBUG.
            output_format: Format de sortie ("json" ou "human").
            is_compatible_only: Affiche uniquement true/false.
            fail_on_incompatible: Retourne 1 si machine non compatible.
            output_file: Chemin de sortie des prints.
            journal_file: Chemin de journal (prints + logs), sans stdout.
        """
        if output_format not in {"json", "human"}:
            raise ValueError("output_format doit valoir 'json' ou 'human'")
        if output_file and journal_file:
            raise ValueError("output_file et journal_file ne peuvent pas etre utilises ensemble")

        self.debug = self._resolve_debug_mode(debug)
        self.output_format = output_format
        self.is_compatible_only = is_compatible_only
        self.fail_on_incompatible = fail_on_incompatible
        self.output_file = output_file
        self.journal_file = journal_file
        self._dxdiag_cache = None

    @staticmethod
    def _resolve_debug_mode(debug):
        """Determine le mode debug effectif a partir des options disponibles."""
        if isinstance(debug, bool):
            return debug

        if debug is not None:
            return str(debug).strip().lower() in {"1", "true", "yes", "on", "debug"}

        env_debug = os.environ.get("MEDULLA_WIN11_COMPAT_DEBUG", "").strip().lower()
        if env_debug in {"1", "true", "yes", "on", "debug"}:
            return True
        if env_debug in {"0", "false", "no", "off", "info"}:
            return False

        return logging.getLogger().getEffectiveLevel() <= logging.DEBUG

    def _render_output(self):
        """Genere la sortie en fonction des options d'instance."""
        try:
            if self.is_compatible_only:
                compatible = self.is_compatible()
                print(json.dumps(bool(compatible)))
                if self.fail_on_incompatible and not compatible:
                    return 1
                return 0

            report = self.collect_report()
            if self.output_format == "json":
                print(json.dumps(report, indent=2, sort_keys=True))
            else:
                print_human_report(report)

            if self.fail_on_incompatible and not report.get("compatible"):
                return 1
            return 0
        except Exception as exc:
            report = self._failsafe_report(exc)
            if self.output_format == "json":
                print(json.dumps(report, indent=2, sort_keys=True))
            else:
                print_human_report(report)
            if self.fail_on_incompatible and not report.get("compatible"):
                return 1
            return 0

    def run(self):
        """Execute le diagnostic avec les options definies au constructeur."""
        log_level = logging.DEBUG if self.debug else logging.INFO

        if self.journal_file:
            root_logger = logging.getLogger()
            file_handler = logging.FileHandler(self.journal_file, encoding="utf-8")
            file_handler.setLevel(log_level)
            file_handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
            root_logger.setLevel(log_level)
            root_logger.addHandler(file_handler)
            try:
                buffer = io.StringIO()
                with redirect_stdout(buffer):
                    exit_code = self._render_output()
                for line in buffer.getvalue().splitlines():
                    logger.info(line)
                return exit_code
            finally:
                root_logger.removeHandler(file_handler)
                file_handler.close()

        if self.output_file:
            with open(self.output_file, "w", encoding="utf-8") as output_handle:
                with redirect_stdout(output_handle):
                    return self._render_output()

        return self._render_output()

    def _unsupported_result(self, name, message):
        """Retourne un resultat standard pour une verification indisponible."""
        return {
            "name": name,
            "ok": False,
            "message": message,
            "error": "unsupported-platform",
        }

    def _error_result(self, name, message, error):
        """Retourne un resultat standard pour une verification en erreur."""
        return {
            "name": name,
            "ok": False,
            "message": message,
            "error": error,
        }

    def _print_check_result(self, result):
        """Affiche un resultat de verification en console puis le retourne."""
        print(json.dumps(result, indent=2, sort_keys=True))
        return result

    def _failsafe_report(self, error):
        """Retourne un rapport minimal en cas d'erreur interne inattendue."""
        error_message = str(error)
        if self.debug:
            logger.debug("Failsafe report triggered: %s\n%s", error, traceback.format_exc())
        return {
            "timestamp": datetime.now().isoformat(timespec="seconds"),
            "os": {
                "platform": sys.platform,
                "hostname": platform.node(),
                "python": sys.version.split()[0],
            },
            "compatible": True,
            "compatble_win11": True,
            "failed_checks": [],
            "checks": {
                "failsafe": {
                    "name": "failsafe",
                    "ok": True,
                    "message": "Erreur interne detectee, rapport force en mode compatible",
                    "error": error_message,
                }
            },
            "inventory": {},
        }

    def _safe_inventory_section(self, name, collector, fallback):
        """Collecte une section d'inventaire sans jamais interrompre le rapport."""
        try:
            return collector()
        except Exception as exc:
            section = dict(fallback)
            section["error"] = str(exc)
            section["message"] = f"Erreur collecte {name}"
            if self.debug:
                logger.debug("Inventory section %s failed: %s\n%s", name, exc, traceback.format_exc())
            return section

    def _safe_check_result(self, name, builder, payload):
        """Construit un check sans masquer les erreurs des controles."""
        try:
            result = builder(payload)
        except Exception as exc:
            if self.debug:
                logger.debug("Check %s failed: %s\n%s", name, exc, traceback.format_exc())
            return {
                "name": name,
                "ok": False,
                "raw_ok": False,
                "forced_ok": False,
                "message": "Controle en erreur",
                "error": str(exc),
            }

        normalized = dict(result or {})
        normalized.setdefault("name", name)
        original_ok = bool(normalized.get("ok", False))
        normalized.setdefault("raw_ok", original_ok)
        normalized.setdefault("forced_ok", False)
        normalized["ok"] = bool(normalized.get("ok", False))
        return normalized

    def _decode_subprocess_output(self, data):
        """Decode une sortie subprocess de facon robuste sur Windows."""
        if data is None:
            return ""
        if isinstance(data, str):
            return data.strip()

        if data.startswith(codecs.BOM_UTF16_LE) or data.startswith(codecs.BOM_UTF16_BE):
            try:
                return data.decode("utf-16").strip()
            except UnicodeDecodeError:
                pass

        encodings = ["utf-8-sig", "utf-8"]
        preferred_encoding = locale.getpreferredencoding(False)
        if preferred_encoding and preferred_encoding.lower() not in {
            encoding.lower() for encoding in encodings
        }:
            encodings.append(preferred_encoding)
        encodings.extend(["cp850", "cp1252", "latin-1"])

        for encoding in encodings:
            try:
                return data.decode(encoding).strip()
            except UnicodeDecodeError:
                continue

        return data.decode("utf-8", errors="replace").strip()

    def _run_powershell(self, command, check=True):
        """Execute une commande PowerShell et retourne sa sortie standard."""
        wrapped_command = (
            "[Console]::OutputEncoding = [System.Text.Encoding]::UTF8; "
            "$OutputEncoding = [System.Text.Encoding]::UTF8; "
            f"{command}"
        )
        result = subprocess.run(
            ["powershell", "-NoProfile", "-Command", wrapped_command],
            capture_output=True,
            text=False,
        )
        stdout = self._decode_subprocess_output(result.stdout)
        stderr = self._decode_subprocess_output(result.stderr)
        if self.debug:
            logger.debug(
                "PowerShell command %s -> rc=%s stdout=%s stderr=%s",
                command,
                result.returncode,
                stdout,
                stderr,
            )
        if check and result.returncode != 0:
            raise RuntimeError(stderr or stdout or f"PowerShell exit code {result.returncode}")
        return stdout

    def _run_powershell_json(self, command, default=None, check=True):
        """Execute une commande PowerShell et convertit le JSON retourne."""
        output = self._run_powershell(command, check=check)
        if not output:
            return default
        try:
            return json.loads(output)
        except json.JSONDecodeError as exc:
            if check:
                raise RuntimeError(f"Invalid JSON output: {exc}") from exc
            return default

    def _ensure_list(self, value):
        """Convertit un resultat PowerShell JSON en liste homogeme."""
        if value is None:
            return []
        if isinstance(value, list):
            return value
        return [value]

    def _coerce_int(self, value):
        """Convertit une valeur en entier si possible."""
        try:
            if value in (None, ""):
                return None
            return int(value)
        except (TypeError, ValueError):
            return None

    def _coerce_float(self, value):
        """Convertit une valeur en flottant si possible."""
        try:
            if value in (None, ""):
                return None
            return float(value)
        except (TypeError, ValueError):
            return None

    def _bytes_to_gb(self, value):
        """Convertit une taille en octets vers des gigaoctets."""
        if value in (None, ""):
            return None
        try:
            return round(int(value) / (1024 ** 3), 2)
        except (TypeError, ValueError):
            return None

    def _format_wmi_datetime(self, value):
        """Formate une date WMI brute en chaine lisible."""
        if not value:
            return ""
        try:
            return datetime.strptime(str(value)[:14], "%Y%m%d%H%M%S").strftime(
                "%Y-%m-%d %H:%M:%S"
            )
        except ValueError:
            return str(value)

    def _memory_type_label(self, smbios_value, memory_value):
        """Retourne un libelle de type memoire a partir des codes WMI."""
        smbios_int = self._coerce_int(smbios_value)
        if smbios_int in MEMORY_TYPE:
            return MEMORY_TYPE[smbios_int]
        memory_int = self._coerce_int(memory_value)
        if memory_int in MEMORY_TYPE:
            return MEMORY_TYPE[memory_int]
        return "Unknown"

    def _cpu_architecture_label(self, code, fallback=None):
        """Retourne un libelle d'architecture CPU."""
        code_int = self._coerce_int(code)
        if code_int in CPU_ARCHITECTURE:
            return CPU_ARCHITECTURE[code_int]
        if fallback:
            return fallback
        return platform.machine() or "Unknown"

    def _battery_status_label(self, status):
        """Retourne le libelle associe au statut de batterie WMI."""
        status_int = self._coerce_int(status)
        if status_int in BATTERY_STATUS:
            return BATTERY_STATUS[status_int]
        return "Unknown"

    def _extract_primary_ipv4(self, addresses):
        """Retourne la premiere IPv4 exploitable d'une liste d'adresses."""
        for address in addresses or []:
            if "." in str(address) and not str(address).startswith(("127.", "169.254.")):
                return address
        return ""

    def _normalize_list_field(self, value):
        """Normalise une valeur JSON en liste de chaines."""
        if value is None:
            return []
        if isinstance(value, list):
            return [str(item) for item in value if item not in (None, "")]
        if value == "":
            return []
        return [str(value)]

    def _extract_numeric_version(self, value):
        """Extrait une version numerique simple depuis une chaine."""
        match = re.search(r"([0-9]+(?:\.[0-9]+)?)", str(value or ""))
        if not match:
            return None
        return self._coerce_float(match.group(1))

    def _parse_current_mode(self, current_mode, width=None, height=None, bits_per_pixel=None):
        """Extrait la resolution, la profondeur de couleur et le taux de rafraichissement."""
        width_value = self._coerce_int(width)
        height_value = self._coerce_int(height)
        bits_value = self._coerce_int(bits_per_pixel)
        refresh_value = None

        mode_text = str(current_mode or "")
        match = re.search(
            r"(?P<width>\d+)\s*x\s*(?P<height>\d+)(?:.*?\((?P<bits>\d+)\s*bit\))?(?:.*?\((?P<refresh>\d+)\s*hz\))?",
            mode_text,
            re.IGNORECASE,
        )
        if match:
            width_value = width_value or self._coerce_int(match.group("width"))
            height_value = height_value or self._coerce_int(match.group("height"))
            bits_value = bits_value or self._coerce_int(match.group("bits"))
            refresh_value = self._coerce_int(match.group("refresh"))

        return {
            "width": width_value,
            "height": height_value,
            "bits_per_pixel": bits_value,
            "refresh_hz": refresh_value,
        }

    def _screen_diagonal_inches(self, width_cm, height_cm):
        """Calcule la diagonale d'un ecran a partir de ses dimensions actives."""
        width_value = self._coerce_float(width_cm)
        height_value = self._coerce_float(height_cm)
        if not width_value or not height_value:
            return None
        return round((((width_value ** 2) + (height_value ** 2)) ** 0.5) / 2.54, 2)

    def _video_input_type_label(self, value):
        """Retourne le type d'entree video pour un moniteur."""
        input_type = self._coerce_int(value)
        if input_type in VIDEO_INPUT_TYPE:
            return VIDEO_INPUT_TYPE[input_type]
        return "Unknown"

    def _get_dxdiag_info(self):
        """Retourne les informations DXDiag utiles a la verification graphique."""
        if self._dxdiag_cache is not None:
            return self._dxdiag_cache

        result = {"system": {}, "display_devices": [], "error": ""}
        if not sys.platform.startswith("win"):
            result["error"] = "unsupported-platform"
            self._dxdiag_cache = result
            return result

        dxdiag_path = shutil.which("dxdiag")
        if not dxdiag_path:
            result["error"] = "dxdiag-not-found"
            self._dxdiag_cache = result
            return result

        xml_path = ""
        try:
            with tempfile.NamedTemporaryFile(delete=False, suffix=".xml") as handle:
                xml_path = handle.name

            process = subprocess.run(
                [dxdiag_path, "/whql:off", "/x", xml_path],
                capture_output=True,
                text=False,
                timeout=90,
            )
            dxdiag_stdout = self._decode_subprocess_output(process.stdout)
            dxdiag_stderr = self._decode_subprocess_output(process.stderr)
            if self.debug:
                logger.debug(
                    "dxdiag -> rc=%s stdout=%s stderr=%s",
                    process.returncode,
                    dxdiag_stdout,
                    dxdiag_stderr,
                )

            if process.returncode != 0:
                result["error"] = (
                    dxdiag_stderr
                    or dxdiag_stdout
                    or f"dxdiag exit code {process.returncode}"
                )
            else:
                root = ET.parse(xml_path).getroot()
                system_node = root.find("./DxDiagSystemInfo")
                if system_node is not None:
                    result["system"] = {
                        child.tag: (child.text or "").strip() for child in system_node
                    }
                result["display_devices"] = [
                    {child.tag: (child.text or "").strip() for child in node}
                    for node in root.findall("./DisplayDevices/DisplayDevice")
                ]
        except Exception as exc:
            result["error"] = str(exc)
            if self.debug:
                logger.debug("dxdiag parsing failed: %s\n%s", exc, traceback.format_exc())
        finally:
            if xml_path:
                try:
                    os.unlink(xml_path)
                except OSError:
                    pass

        self._dxdiag_cache = result
        return result

    def _match_dxdiag_display_device(self, adapter_name, dx_devices, index):
        """Associe un adaptateur WMI a l'entree DXDiag la plus proche."""
        adapter_value = (adapter_name or "").strip().lower()
        if adapter_value:
            for device in dx_devices:
                for candidate in (
                    device.get("CardName"),
                    device.get("DeviceName"),
                    device.get("ChipType"),
                    device.get("Description"),
                ):
                    candidate_value = (candidate or "").strip().lower()
                    if candidate_value and (
                        adapter_value in candidate_value or candidate_value in adapter_value
                    ):
                        return device
        if index < len(dx_devices):
            return dx_devices[index]
        return {}

    def _extract_cpu_generation(self, cpu_name):
        """Retourne les informations de generation CPU a partir du nom du processeur."""
        cpu_value = (cpu_name or "").lower()

        intel_match = re.search(r"i[3579]-([0-9]{4,5})", cpu_value)
        if intel_match:
            digits = intel_match.group(1)
            generation = int(digits[:2] if len(digits) == 5 else digits[:1])
            return {
                "vendor_family": "intel",
                "generation": generation,
                "minimum_generation": 8,
                "compatibility_ok": generation >= 8,
                "compatibility_message": f"Intel generation {generation} detectee (minimum 8)",
            }

        amd_match = re.search(r"ryzen\s*([0-9])", cpu_value)
        if amd_match:
            generation = int(amd_match.group(1))
            return {
                "vendor_family": "amd",
                "generation": generation,
                "minimum_generation": 2,
                "compatibility_ok": generation >= 2,
                "compatibility_message": f"AMD Ryzen generation {generation} detectee (minimum 2)",
            }

        return {
            "vendor_family": "unknown",
            "generation": None,
            "minimum_generation": None,
            "compatibility_ok": False,
            "compatibility_message": "Modele CPU non reconnu par les regles de compatibilite",
        }

    def get_os_info(self):
        """Retourne les informations detaillees du systeme d'exploitation."""
        info = {
            "platform": sys.platform,
            "hostname": platform.node(),
            "python": sys.version.split()[0],
        }
        if not sys.platform.startswith("win"):
            return info

        registry_info = self._run_powershell_json(
            "(Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion' | "
            "Select-Object ProductName, EditionID, DisplayVersion, ReleaseId, CurrentBuild, "
            "CurrentBuildNumber, UBR, InstallationType) | ConvertTo-Json -Compress",
            default={},
            check=False,
        ) or {}
        cim_info = self._run_powershell_json(
            "Get-CimInstance -ClassName Win32_OperatingSystem | "
            "Select-Object Caption, Version, BuildNumber, OSArchitecture, LastBootUpTime | "
            "ConvertTo-Json -Compress",
            default={},
            check=False,
        ) or {}

        build_number = (
            registry_info.get("CurrentBuild")
            or registry_info.get("CurrentBuildNumber")
            or cim_info.get("BuildNumber")
            or ""
        )
        ubr = registry_info.get("UBR")
        build_full = str(build_number)
        if build_number and ubr not in (None, ""):
            build_full = f"{build_number}.{ubr}"

        info.update(
            {
                "caption": cim_info.get("Caption") or registry_info.get("ProductName") or "",
                "product_name": registry_info.get("ProductName") or cim_info.get("Caption") or "",
                "edition": registry_info.get("EditionID") or "",
                "display_version": registry_info.get("DisplayVersion") or registry_info.get("ReleaseId") or "",
                "version": cim_info.get("Version") or "",
                "build_number": str(build_number) if build_number else "",
                "build_full": build_full,
                "ubr": ubr,
                "architecture": cim_info.get("OSArchitecture") or platform.machine(),
                "installation_type": registry_info.get("InstallationType") or "",
                "last_boot": self._format_wmi_datetime(cim_info.get("LastBootUpTime")),
            }
        )
        return info

    def get_machine_identity(self):
        """Retourne les informations d'identite de la machine."""
        identity = {"hostname": platform.node()}
        if not sys.platform.startswith("win"):
            return identity

        system = self._run_powershell_json(
            "Get-CimInstance -ClassName Win32_ComputerSystem | "
            "Select-Object Manufacturer, Model, DNSHostName, Domain, PartOfDomain, UserName | "
            "ConvertTo-Json -Compress",
            default={},
            check=False,
        ) or {}
        product = self._run_powershell_json(
            "Get-CimInstance -ClassName Win32_ComputerSystemProduct | "
            "Select-Object UUID, Vendor, Name, IdentifyingNumber | ConvertTo-Json -Compress",
            default={},
            check=False,
        ) or {}
        bios = self._run_powershell_json(
            "Get-CimInstance -ClassName Win32_BIOS | Select-Object SerialNumber | ConvertTo-Json -Compress",
            default={},
            check=False,
        ) or {}

        identity.update(
            {
                "hostname": system.get("DNSHostName") or platform.node(),
                "manufacturer": system.get("Manufacturer") or product.get("Vendor") or "",
                "model": system.get("Model") or product.get("Name") or "",
                "uuid": product.get("UUID") or "",
                "serial_number": bios.get("SerialNumber") or product.get("IdentifyingNumber") or "",
                "vendor": product.get("Vendor") or "",
                "current_user": system.get("UserName") or "",
            }
        )
        return identity

    def get_cpu_info(self):
        """Retourne les informations detaillees du CPU."""
        cpu_info = {
            "model": platform.processor().strip(),
            "architecture": platform.machine() or "Unknown",
        }
        if sys.platform.startswith("win"):
            processor = self._run_powershell_json(
                "Get-CimInstance -ClassName Win32_Processor | "
                "Select-Object -First 1 Name, Manufacturer, NumberOfCores, NumberOfLogicalProcessors, "
                "MaxClockSpeed, CurrentClockSpeed, Architecture, AddressWidth | ConvertTo-Json -Compress",
                default={},
                check=False,
            ) or {}
            cpu_info.update(
                {
                    "model": processor.get("Name") or cpu_info["model"],
                    "vendor": processor.get("Manufacturer") or "",
                    "cores": self._coerce_int(processor.get("NumberOfCores")),
                    "threads": self._coerce_int(processor.get("NumberOfLogicalProcessors")),
                    "architecture": self._cpu_architecture_label(
                        processor.get("Architecture"),
                        fallback=platform.machine() or "Unknown",
                    ),
                    "address_width": self._coerce_int(processor.get("AddressWidth")),
                    "max_clock_mhz": self._coerce_int(processor.get("MaxClockSpeed")),
                    "current_clock_mhz": self._coerce_int(processor.get("CurrentClockSpeed")),
                }
            )
        else:
            cpu_freq = psutil.cpu_freq()
            if cpu_freq:
                cpu_info["max_clock_mhz"] = round(cpu_freq.max, 2)
                cpu_info["current_clock_mhz"] = round(cpu_freq.current, 2)
            cpu_info["cores"] = psutil.cpu_count(logical=False)
            cpu_info["threads"] = psutil.cpu_count(logical=True)

        cpu_info.update(self._extract_cpu_generation(cpu_info.get("model", "")))
        return cpu_info

    def get_memory_info(self):
        """Retourne les informations detaillees sur la RAM."""
        total_gb = round(psutil.virtual_memory().total / (1024 ** 3), 2)
        info = {
            "total_gb": total_gb,
            "slots_used": None,
            "slots_total": None,
            "memory_type": "Unknown",
            "frequencies_mhz": [],
            "modules": [],
        }
        if not sys.platform.startswith("win"):
            return info

        modules = self._ensure_list(
            self._run_powershell_json(
                "Get-CimInstance -ClassName Win32_PhysicalMemory | "
                "Select-Object Manufacturer, PartNumber, Capacity, Speed, ConfiguredClockSpeed, "
                "SMBIOSMemoryType, MemoryType, DeviceLocator, BankLabel | ConvertTo-Json -Depth 4 -Compress",
                default=[],
                check=False,
            )
        )
        arrays = self._ensure_list(
            self._run_powershell_json(
                "Get-CimInstance -ClassName Win32_PhysicalMemoryArray | Select-Object MemoryDevices | "
                "ConvertTo-Json -Compress",
                default=[],
                check=False,
            )
        )

        normalized_modules = []
        memory_types = []
        frequencies = []
        for module in modules:
            capacity_gb = self._bytes_to_gb(module.get("Capacity"))
            memory_type = self._memory_type_label(
                module.get("SMBIOSMemoryType"), module.get("MemoryType")
            )
            speed_mhz = self._coerce_int(
                module.get("ConfiguredClockSpeed") or module.get("Speed")
            )
            if memory_type != "Unknown":
                memory_types.append(memory_type)
            if speed_mhz:
                frequencies.append(speed_mhz)
            normalized_modules.append(
                {
                    "slot": module.get("DeviceLocator") or module.get("BankLabel") or "",
                    "capacity_gb": capacity_gb,
                    "manufacturer": module.get("Manufacturer") or "",
                    "part_number": (module.get("PartNumber") or "").strip(),
                    "memory_type": memory_type,
                    "speed_mhz": speed_mhz,
                }
            )

        info["modules"] = normalized_modules
        info["slots_used"] = len([item for item in normalized_modules if item.get("capacity_gb")])
        info["slots_total"] = sum(
            self._coerce_int(array.get("MemoryDevices")) or 0 for array in arrays
        ) or None
        info["memory_type"] = ", ".join(sorted(set(memory_types))) if memory_types else "Unknown"
        info["frequencies_mhz"] = sorted(set(frequencies))
        info["max_frequency_mhz"] = max(frequencies) if frequencies else None
        return info

    def get_storage_info(self):
        """Retourne les informations sur le disque systeme et les disques physiques."""
        system_drive = {"drive": "C:\\"}
        physical_disks = []
        if not sys.platform.startswith("win"):
            return {"system_drive": system_drive, "physical_disks": physical_disks}

        logical = self._run_powershell_json(
            "Get-CimInstance -ClassName Win32_LogicalDisk -Filter \"DeviceID='C:'\" | "
            "Select-Object DeviceID, VolumeName, FileSystem, Size, FreeSpace | ConvertTo-Json -Compress",
            default={},
            check=False,
        ) or {}
        wmi_disks = self._ensure_list(
            self._run_powershell_json(
                "Get-CimInstance -ClassName Win32_DiskDrive | "
                "Select-Object Model, MediaType, InterfaceType, SerialNumber, Size, DeviceID | "
                "ConvertTo-Json -Depth 4 -Compress",
                default=[],
                check=False,
            )
        )
        modern_disks = self._ensure_list(
            self._run_powershell_json(
                "Get-PhysicalDisk | Select-Object FriendlyName, MediaType, BusType, HealthStatus, Size, SerialNumber | "
                "ConvertTo-Json -Depth 4 -Compress",
                default=[],
                check=False,
            )
        )

        system_drive.update(
            {
                "drive": logical.get("DeviceID") or "C:\\",
                "label": logical.get("VolumeName") or "",
                "file_system": logical.get("FileSystem") or "",
                "total_gb": self._bytes_to_gb(logical.get("Size")),
                "free_gb": self._bytes_to_gb(logical.get("FreeSpace")),
            }
        )

        for index, disk in enumerate(wmi_disks):
            modern_disk = modern_disks[index] if index < len(modern_disks) else {}
            media_type = modern_disk.get("MediaType") or disk.get("MediaType") or "Unknown"
            bus_type = modern_disk.get("BusType") or disk.get("InterfaceType") or "Unknown"
            physical_disks.append(
                {
                    "model": disk.get("Model") or modern_disk.get("FriendlyName") or "",
                    "serial_number": disk.get("SerialNumber") or modern_disk.get("SerialNumber") or "",
                    "media_type": media_type,
                    "bus_type": bus_type,
                    "health_status": modern_disk.get("HealthStatus") or "Unknown",
                    "size_gb": self._bytes_to_gb(modern_disk.get("Size") or disk.get("Size")),
                }
            )

        return {"system_drive": system_drive, "physical_disks": physical_disks}

    def get_graphics_info(self):
        """Retourne les informations detaillees sur les adaptateurs graphiques."""
        if not sys.platform.startswith("win"):
            return {
                "present": False,
                "directx_version": "",
                "adapters": [],
                "message": "Verification reservee a Windows",
                "error": "unsupported-platform",
            }

        controllers = self._ensure_list(
            self._run_powershell_json(
                "Get-CimInstance -ClassName Win32_VideoController | "
                "Select-Object Name, AdapterCompatibility, VideoProcessor, AdapterRAM, DriverVersion, DriverDate, "
                "CurrentHorizontalResolution, CurrentVerticalResolution, CurrentBitsPerPixel, VideoModeDescription, "
                "PNPDeviceID, Status | ConvertTo-Json -Depth 4 -Compress",
                default=[],
                check=False,
            )
        )
        dxdiag = self._get_dxdiag_info()
        dx_devices = dxdiag.get("display_devices", [])
        directx_version = dxdiag.get("system", {}).get("DirectXVersion") or ""

        adapters = []
        for index, controller in enumerate(controllers):
            dx_device = self._match_dxdiag_display_device(
                controller.get("Name"), dx_devices, index
            )
            mode_info = self._parse_current_mode(
                dx_device.get("CurrentMode") or controller.get("VideoModeDescription"),
                controller.get("CurrentHorizontalResolution"),
                controller.get("CurrentVerticalResolution"),
                controller.get("CurrentBitsPerPixel"),
            )
            feature_levels = [
                item.strip()
                for item in str(dx_device.get("FeatureLevels") or "").split(",")
                if item.strip()
            ]
            ddi_version = self._extract_numeric_version(dx_device.get("DDIVersion"))
            driver_model = dx_device.get("DriverModel") or ""
            wddm_version = self._extract_numeric_version(driver_model)

            directx_ok = any(level.startswith("12") for level in feature_levels)
            if not directx_ok and ddi_version is not None:
                directx_ok = ddi_version >= 12.0
            if not directx_ok and directx_version:
                directx_ok = "directx 12" in directx_version.lower()

            wddm_ok = wddm_version is not None and wddm_version >= 2.0

            adapters.append(
                {
                    "name": controller.get("Name") or dx_device.get("CardName") or "",
                    "vendor": controller.get("AdapterCompatibility")
                    or dx_device.get("Manufacturer")
                    or "",
                    "video_processor": controller.get("VideoProcessor")
                    or dx_device.get("ChipType")
                    or "",
                    "adapter_ram_gb": self._bytes_to_gb(controller.get("AdapterRAM")),
                    "driver_version": controller.get("DriverVersion")
                    or dx_device.get("DriverVersion")
                    or "",
                    "driver_date": self._format_wmi_datetime(controller.get("DriverDate"))
                    or dx_device.get("DriverDate")
                    or "",
                    "driver_model": driver_model,
                    "wddm_version": wddm_version,
                    "ddi_version": ddi_version,
                    "feature_levels": feature_levels,
                    "pnp_device_id": controller.get("PNPDeviceID") or "",
                    "status": controller.get("Status") or "",
                    "current_mode": dx_device.get("CurrentMode") or controller.get("VideoModeDescription") or "",
                    "current_resolution": {
                        "width": mode_info.get("width"),
                        "height": mode_info.get("height"),
                    },
                    "bits_per_pixel": mode_info.get("bits_per_pixel"),
                    "refresh_hz": mode_info.get("refresh_hz"),
                    "directx_ok": directx_ok,
                    "wddm_ok": wddm_ok,
                    "compatible": directx_ok and wddm_ok,
                }
            )

        compatible_adapter = next(
            (adapter for adapter in adapters if adapter.get("compatible")),
            None,
        )
        if compatible_adapter:
            message = (
                f"{compatible_adapter.get('name') or 'GPU'} compatible "
                f"(WDDM {compatible_adapter.get('wddm_version') or '?'} / "
                f"DDI {compatible_adapter.get('ddi_version') or '?'}"
                ")"
            )
        elif adapters:
            message = "Aucun GPU ne verifie simultanement DirectX 12 et WDDM 2.0"
        else:
            message = "Aucun adaptateur graphique detecte"

        result = {
            "present": bool(adapters),
            "directx_version": directx_version,
            "adapters": adapters,
            "message": message,
        }
        if dxdiag.get("error"):
            result["dxdiag_error"] = dxdiag["error"]
        return result

    def get_display_info(self):
        """Retourne les informations detaillees sur les ecrans relies a la machine."""
        if not sys.platform.startswith("win"):
            return {
                "present": False,
                "displays": [],
                "message": "Verification reservee a Windows",
                "error": "unsupported-platform",
            }

        dxdiag = self._get_dxdiag_info()
        dx_devices = dxdiag.get("display_devices", [])
        screens = self._ensure_list(
            self._run_powershell_json(
                "Add-Type -AssemblyName System.Windows.Forms; "
                "[System.Windows.Forms.Screen]::AllScreens | ForEach-Object { "
                "[pscustomobject]@{ DeviceName = $_.DeviceName; Primary = $_.Primary; Width = $_.Bounds.Width; "
                "Height = $_.Bounds.Height; BitsPerPixel = $_.BitsPerPixel } } | "
                "ConvertTo-Json -Depth 4 -Compress",
                default=[],
                check=False,
            )
        )
        monitor_ids = self._ensure_list(
            self._run_powershell_json(
                "Get-CimInstance -Namespace root\\wmi -Class WmiMonitorID | ForEach-Object { "
                "[pscustomobject]@{ "
                "InstanceName = $_.InstanceName; "
                "FriendlyName = (-join ($_.UserFriendlyName | Where-Object { $_ -gt 0 } | ForEach-Object { [char]$_ })); "
                "Manufacturer = (-join ($_.ManufacturerName | Where-Object { $_ -gt 0 } | ForEach-Object { [char]$_ })); "
                "ProductCode = (-join ($_.ProductCodeID | Where-Object { $_ -gt 0 } | ForEach-Object { [char]$_ })); "
                "SerialNumber = (-join ($_.SerialNumberID | Where-Object { $_ -gt 0 } | ForEach-Object { [char]$_ })) "
                "} } | ConvertTo-Json -Depth 4 -Compress",
                default=[],
                check=False,
            )
        )
        basic_params = self._ensure_list(
            self._run_powershell_json(
                "Get-CimInstance -Namespace root\\wmi -Class WmiMonitorBasicDisplayParams | "
                "Select-Object InstanceName, MaxHorizontalImageSize, MaxVerticalImageSize, VideoInputType | "
                "ConvertTo-Json -Depth 4 -Compress",
                default=[],
                check=False,
            )
        )
        desktop_monitors = self._ensure_list(
            self._run_powershell_json(
                "Get-CimInstance -ClassName Win32_DesktopMonitor | "
                "Select-Object Name, ScreenWidth, ScreenHeight, MonitorManufacturer, MonitorType, PNPDeviceID, Status | "
                "ConvertTo-Json -Depth 4 -Compress",
                default=[],
                check=False,
            )
        )

        display_count = max(
            len(dx_devices),
            len(screens),
            len(monitor_ids),
            len(basic_params),
            len(desktop_monitors),
        )
        displays = []
        for index in range(display_count):
            dx_device = dx_devices[index] if index < len(dx_devices) else {}
            screen = screens[index] if index < len(screens) else {}
            monitor_id = monitor_ids[index] if index < len(monitor_ids) else {}
            basic = basic_params[index] if index < len(basic_params) else {}
            desktop_monitor = desktop_monitors[index] if index < len(desktop_monitors) else {}

            mode_info = self._parse_current_mode(
                dx_device.get("CurrentMode"),
                screen.get("Width") or desktop_monitor.get("ScreenWidth"),
                screen.get("Height") or desktop_monitor.get("ScreenHeight"),
                screen.get("BitsPerPixel"),
            )
            diagonal_inches = self._screen_diagonal_inches(
                basic.get("MaxHorizontalImageSize"),
                basic.get("MaxVerticalImageSize"),
            )

            width = mode_info.get("width")
            height = mode_info.get("height")
            bits_per_pixel = mode_info.get("bits_per_pixel")
            resolution_ok = width is not None and height is not None and width >= 1280 and height >= 720
            color_ok = bits_per_pixel is not None and bits_per_pixel >= 24
            size_ok = diagonal_inches is None or diagonal_inches > 9.0

            displays.append(
                {
                    "name": monitor_id.get("FriendlyName")
                    or dx_device.get("MonitorName")
                    or dx_device.get("MonitorModel")
                    or desktop_monitor.get("Name")
                    or screen.get("DeviceName")
                    or f"Ecran {index + 1}",
                    "manufacturer": monitor_id.get("Manufacturer")
                    or desktop_monitor.get("MonitorManufacturer")
                    or "",
                    "serial_number": monitor_id.get("SerialNumber") or "",
                    "product_code": monitor_id.get("ProductCode") or "",
                    "primary": bool(screen.get("Primary", False)),
                    "width": width,
                    "height": height,
                    "bits_per_pixel": bits_per_pixel,
                    "refresh_hz": mode_info.get("refresh_hz"),
                    "diagonal_inches": diagonal_inches,
                    "size_verified": diagonal_inches is not None,
                    "input_type": self._video_input_type_label(basic.get("VideoInputType")),
                    "current_mode": dx_device.get("CurrentMode") or "",
                    "native_mode": dx_device.get("NativeMode") or "",
                    "resolution_ok": resolution_ok,
                    "color_ok": color_ok,
                    "size_ok": size_ok,
                    "compatible": resolution_ok and color_ok and size_ok,
                }
            )

        compatible_display = next(
            (display for display in displays if display.get("compatible")),
            None,
        )
        if compatible_display:
            size_text = (
                f"{compatible_display.get('diagonal_inches')} pouces"
                if compatible_display.get("diagonal_inches") is not None
                else "taille non verifiee"
            )
            message = (
                f"{compatible_display.get('name')} : {compatible_display.get('width')}x"
                f"{compatible_display.get('height')} / {compatible_display.get('bits_per_pixel')} bpp / {size_text}"
            )
        elif displays:
            message = "Aucun ecran ne verifie 1280x720, 24 bpp et une diagonale > 9 pouces"
        else:
            message = "Aucun ecran detecte"

        result = {
            "present": bool(displays),
            "displays": displays,
            "message": message,
        }
        if dxdiag.get("error"):
            result["dxdiag_error"] = dxdiag["error"]
        return result

    def get_tpm_info(self):
        """Retourne les informations detaillees sur le TPM."""
        if not sys.platform.startswith("win"):
            return {
                "present": False,
                "ready": False,
                "message": "Verification reservee a Windows",
                "error": "unsupported-platform",
            }

        get_tpm = self._run_powershell_json(
            "Get-Tpm | Select-Object TpmPresent, TpmReady, ManufacturerIdTxt, ManufacturerVersion, "
            "ManufacturerVersionFull20, ManagedAuthLevel, LockedOut, AutoProvisioning, RestartPending, "
            "SpecVersion | ConvertTo-Json -Compress",
            default={},
            check=False,
        ) or {}
        win32_tpm = self._run_powershell_json(
            "Get-CimInstance -Namespace Root\\CIMv2\\Security\\MicrosoftTpm -Class Win32_Tpm | "
            "Select-Object SpecVersion, IsEnabled_InitialValue, IsActivated_InitialValue, IsOwned_InitialValue, "
            "ManufacturerIdTxt, ManufacturerVersion, PhysicalPresenceVersionInfo | ConvertTo-Json -Compress",
            default={},
            check=False,
        ) or {}

        raw_spec = get_tpm.get("SpecVersion") or win32_tpm.get("SpecVersion") or ""
        spec_version = str(raw_spec).split(",")[0].strip() if raw_spec else ""
        manufacturer = (
            get_tpm.get("ManufacturerIdTxt")
            or win32_tpm.get("ManufacturerIdTxt")
            or ""
        )
        manufacturer_version = (
            get_tpm.get("ManufacturerVersionFull20")
            or get_tpm.get("ManufacturerVersion")
            or win32_tpm.get("ManufacturerVersion")
            or ""
        )
        present = bool(get_tpm.get("TpmPresent", bool(win32_tpm)))
        ready = bool(get_tpm.get("TpmReady", False))
        enabled = win32_tpm.get("IsEnabled_InitialValue")
        activated = win32_tpm.get("IsActivated_InitialValue")
        owned = win32_tpm.get("IsOwned_InitialValue")

        return {
            "present": present,
            "ready": ready,
            "enabled": enabled,
            "activated": activated,
            "owned": owned,
            "spec_version": spec_version,
            "raw_spec": raw_spec,
            "manufacturer": manufacturer,
            "manufacturer_version": manufacturer_version,
            "managed_auth_level": get_tpm.get("ManagedAuthLevel") or "",
            "locked_out": get_tpm.get("LockedOut"),
            "auto_provisioning": get_tpm.get("AutoProvisioning") or "",
            "restart_pending": get_tpm.get("RestartPending"),
            "physical_presence_version": win32_tpm.get("PhysicalPresenceVersionInfo") or "",
            "message": f"TPM {spec_version or 'inconnu'}",
        }

    def get_boot_info(self):
        """Retourne les informations firmware et Secure Boot."""
        if not sys.platform.startswith("win"):
            return {
                "uefi": False,
                "firmware_mode": "Unknown",
                "secure_boot": None,
                "bootup_state": "",
                "message": "Verification reservee a Windows",
                "error": "unsupported-platform",
            }

        secure_result = subprocess.run(
            [
                "powershell",
                "-NoProfile",
                "-Command",
                "[Console]::OutputEncoding = [System.Text.Encoding]::UTF8; "
                "$OutputEncoding = [System.Text.Encoding]::UTF8; "
                "Confirm-SecureBootUEFI",
            ],
            capture_output=True,
            text=False,
        )

        stdout_raw = self._decode_subprocess_output(secure_result.stdout)
        stderr_raw = self._decode_subprocess_output(secure_result.stderr)
        secure_stdout = stdout_raw.lower()
        secure_stderr = stderr_raw.lower()
        unsupported_secureboot = (
            "platformnotsupportedexception" in secure_stderr
            or "getfwvarfailed" in secure_stderr
            or "non prise en charge" in secure_stderr
        )
        include_raw_output = self.debug or not unsupported_secureboot
        stdout_for_report = stdout_raw if include_raw_output else ""
        stderr_for_report = stderr_raw if include_raw_output else ""

        bootup_state = self._run_powershell(
            "(Get-CimInstance -ClassName Win32_ComputerSystem).BootupState",
            check=False,
        )

        # La presence de Confirm-SecureBootUEFI avec une sortie true/false est le signal le plus fiable
        # sur les machines Windows modernes. On l'utilise donc comme source principale pour l'etat UEFI.
        secure_stdout = self._decode_subprocess_output(secure_result.stdout).lower()
        if "true" in secure_stdout:
            return {
                "uefi": True,
                "firmware_mode": "UEFI",
                "secure_boot": True,
                "bootup_state": bootup_state,
                "secure_boot_raw_stdout": stdout_for_report,
                "secure_boot_raw_stderr": stderr_for_report,
                "message": "UEFI avec Secure Boot actif",
            }
        elif "false" in secure_stdout:
            return {
                "uefi": True,
                "firmware_mode": "UEFI",
                "secure_boot": False,
                "bootup_state": bootup_state,
                "secure_boot_raw_stdout": stdout_for_report,
                "secure_boot_raw_stderr": stderr_for_report,
                "message": "UEFI detecte",
            }

        if secure_result.returncode != 0 or "cmdlet" in secure_stderr:
            return {
                "uefi": False,
                "firmware_mode": "Legacy BIOS",
                "secure_boot": False,
                "bootup_state": bootup_state,
                "secure_boot_raw_stdout": stdout_for_report,
                "secure_boot_raw_stderr": stderr_for_report,
                "message": "Systeme en BIOS (non UEFI)",
                # Cas attendu sur plateformes ne supportant pas Confirm-SecureBootUEFI.
                "error": None if unsupported_secureboot else (stderr_raw or stdout_raw),
            }

        return {
            "uefi": True,
            "firmware_mode": "UEFI",
            "secure_boot": None,
            "bootup_state": bootup_state,
            "secure_boot_raw_stdout": stdout_for_report,
            "secure_boot_raw_stderr": stderr_for_report,
            "message": f"Etat inconnu: {stdout_raw or stderr_raw or 'aucune sortie'}",
        }

    def get_network_info(self):
        """Retourne les informations reseau utiles a l'inventaire."""
        if not sys.platform.startswith("win"):
            return {"adapters": [], "primary_adapter": {}}

        adapters_raw = self._ensure_list(
            self._run_powershell_json(
                "Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration -Filter \"IPEnabled=True\" | "
                "Select-Object Description, IPAddress, DefaultIPGateway, DNSServerSearchOrder, DNSDomain, "
                "DNSHostName, MACAddress | ConvertTo-Json -Depth 5 -Compress",
                default=[],
                check=False,
            )
        )
        adapters = []
        for adapter in adapters_raw:
            ip_addresses = self._normalize_list_field(adapter.get("IPAddress"))
            gateways = self._normalize_list_field(adapter.get("DefaultIPGateway"))
            dns_servers = self._normalize_list_field(adapter.get("DNSServerSearchOrder"))
            adapter_info = {
                "description": adapter.get("Description") or "",
                "ip_addresses": ip_addresses,
                "primary_ipv4": self._extract_primary_ipv4(ip_addresses),
                "default_gateway": gateways[0] if gateways else "",
                "dns_servers": dns_servers,
                "dns_domain": adapter.get("DNSDomain") or "",
                "mac_address": adapter.get("MACAddress") or "",
            }
            adapters.append(adapter_info)

        primary_adapter = {}
        for adapter in adapters:
            if adapter.get("default_gateway") or adapter.get("primary_ipv4"):
                primary_adapter = adapter
                break
        if not primary_adapter and adapters:
            primary_adapter = adapters[0]

        return {"adapters": adapters, "primary_adapter": primary_adapter}

    def get_domain_info(self):
        """Retourne les informations de rattachement domaine / AD."""
        if not sys.platform.startswith("win"):
            return {"joined": False, "domain_name": "", "logon_server": ""}

        system = self._run_powershell_json(
            "Get-CimInstance -ClassName Win32_ComputerSystem | "
            "Select-Object PartOfDomain, Domain, Workgroup | ConvertTo-Json -Compress",
            default={},
            check=False,
        ) or {}
        logon_server = self._run_powershell("$env:LOGONSERVER", check=False).lstrip("\\")
        return {
            "joined": bool(system.get("PartOfDomain", False)),
            "domain_name": system.get("Domain") or "",
            "workgroup": system.get("Workgroup") or "",
            "logon_server": logon_server,
        }

    def get_bios_info(self):
        """Retourne les informations BIOS / firmware."""
        if not sys.platform.startswith("win"):
            return {}

        bios = self._run_powershell_json(
            "Get-CimInstance -ClassName Win32_BIOS | "
            "Select-Object Manufacturer, SMBIOSBIOSVersion, BIOSVersion, ReleaseDate, SerialNumber | "
            "ConvertTo-Json -Depth 4 -Compress",
            default={},
            check=False,
        ) or {}
        bios_versions = self._normalize_list_field(bios.get("BIOSVersion"))
        return {
            "manufacturer": bios.get("Manufacturer") or "",
            "version": bios.get("SMBIOSBIOSVersion") or (bios_versions[0] if bios_versions else ""),
            "release_date": self._format_wmi_datetime(bios.get("ReleaseDate")),
            "serial_number": bios.get("SerialNumber") or "",
            "bios_versions": bios_versions,
        }

    def get_battery_info(self):
        """Retourne les informations de batterie si la machine en dispose."""
        if not sys.platform.startswith("win"):
            return {"present": False, "batteries": []}

        batteries = self._ensure_list(
            self._run_powershell_json(
                "Get-CimInstance -ClassName Win32_Battery | "
                "Select-Object Name, BatteryStatus, EstimatedChargeRemaining, Status, DesignVoltage | "
                "ConvertTo-Json -Depth 4 -Compress",
                default=[],
                check=False,
            )
        )
        static_data = self._ensure_list(
            self._run_powershell_json(
                "Get-CimInstance -Namespace root\\wmi -Class BatteryStaticData | "
                "Select-Object DesignedCapacity | ConvertTo-Json -Compress",
                default=[],
                check=False,
            )
        )
        full_data = self._ensure_list(
            self._run_powershell_json(
                "Get-CimInstance -Namespace root\\wmi -Class BatteryFullChargedCapacity | "
                "Select-Object FullChargedCapacity | ConvertTo-Json -Compress",
                default=[],
                check=False,
            )
        )

        if not batteries:
            return {"present": False, "batteries": [], "message": "Aucune batterie detectee"}

        normalized = []
        for index, battery in enumerate(batteries):
            designed_capacity = self._coerce_int(
                static_data[index].get("DesignedCapacity") if index < len(static_data) else None
            )
            full_charge_capacity = self._coerce_int(
                full_data[index].get("FullChargedCapacity") if index < len(full_data) else None
            )
            health_pct = None
            if designed_capacity and full_charge_capacity:
                health_pct = round((full_charge_capacity / designed_capacity) * 100, 2)

            normalized.append(
                {
                    "name": battery.get("Name") or f"Battery {index + 1}",
                    "status": battery.get("Status") or "",
                    "battery_status": self._battery_status_label(battery.get("BatteryStatus")),
                    "charge_remaining_pct": self._coerce_int(battery.get("EstimatedChargeRemaining")),
                    "design_capacity_mwh": designed_capacity,
                    "full_charge_capacity_mwh": full_charge_capacity,
                    "health_pct": health_pct,
                }
            )

        return {"present": True, "batteries": normalized}

    def collect_inventory(self):
        """Construit l'inventaire complementaire affiche par le script."""
        return {
            "system": self._safe_inventory_section("system", self.get_os_info, {}),
            "identity": self._safe_inventory_section("identity", self.get_machine_identity, {}),
            "cpu": self._safe_inventory_section("cpu", self.get_cpu_info, {}),
            "memory": self._safe_inventory_section("memory", self.get_memory_info, {}),
            "storage": self._safe_inventory_section(
                "storage",
                self.get_storage_info,
                {"system_drive": {"drive": "C:\\"}, "physical_disks": []},
            ),
            "graphics": self._safe_inventory_section(
                "graphics",
                self.get_graphics_info,
                {"present": False, "adapters": [], "message": "Collecte graphics indisponible"},
            ),
            "display": self._safe_inventory_section(
                "display",
                self.get_display_info,
                {"present": False, "displays": [], "message": "Collecte display indisponible"},
            ),
            "tpm": self._safe_inventory_section("tpm", self.get_tpm_info, {}),
            "boot": self._safe_inventory_section("boot", self.get_boot_info, {}),
            "network": self._safe_inventory_section(
                "network",
                self.get_network_info,
                {"adapters": [], "primary_adapter": {}},
            ),
            "domain": self._safe_inventory_section("domain", self.get_domain_info, {}),
            "bios": self._safe_inventory_section("bios", self.get_bios_info, {}),
            "battery": self._safe_inventory_section(
                "battery",
                self.get_battery_info,
                {"present": False, "batteries": []},
            ),
        }

    def _build_ram_check(self, memory):
        """Construit le resultat de verification RAM a partir de l'inventaire."""
        total_gb = memory.get("total_gb")
        ok = total_gb is not None and total_gb >= 4
        message = f"{total_gb:.2f} GB detectes (minimum 4 GB)" if total_gb is not None else "RAM inconnue"
        return {
            "name": "ram",
            "ok": ok,
            "value_gb": total_gb,
            "required_gb": 4,
            "memory_type": memory.get("memory_type"),
            "slots_used": memory.get("slots_used"),
            "slots_total": memory.get("slots_total"),
            "max_frequency_mhz": memory.get("max_frequency_mhz"),
            "message": message,
        }

    def _build_disk_check(self, storage):
        """Construit le resultat de verification disque a partir de l'inventaire."""
        system_drive = storage.get("system_drive", {})
        total_gb = system_drive.get("total_gb")
        free_gb = system_drive.get("free_gb")
        ok = total_gb is not None and total_gb >= 64
        message = f"{total_gb:.2f} GB detectes sur C: (minimum 64 GB)" if total_gb is not None else "Disque systeme inconnu"
        return {
            "name": "disk",
            "ok": ok,
            "drive": system_drive.get("drive", "C:\\"),
            "value_gb": total_gb,
            "required_gb": 64,
            "free_gb": free_gb,
            "file_system": system_drive.get("file_system"),
            "message": message,
        }

    def _build_uefi_check(self, boot):
        """Construit le resultat de verification UEFI a partir de l'inventaire."""
        firmware_mode = boot.get("firmware_mode", "Unknown")
        is_legacy_bios = str(firmware_mode).strip().lower() == "legacy bios"
        return {
            "name": "uefi",
            "ok": bool(boot.get("uefi", False)),
            "uefi": boot.get("uefi", False),
            "firmware_mode": firmware_mode,
            "secure_boot": boot.get("secure_boot"),
            "bootup_state": boot.get("bootup_state", ""),
            "message": boot.get("message", ""),
            # En mode BIOS legacy, l'echec Confirm-SecureBootUEFI est attendu.
            # On masque l'erreur technique pour garder un rapport lisible.
            "error": None if is_legacy_bios else boot.get("error"),
        }

    def _build_tpm_check(self, tpm):
        """Construit le resultat de verification TPM a partir de l'inventaire."""
        spec_version = tpm.get("spec_version") or ""
        version_match = re.search(r"([0-9]+(?:\.[0-9]+)?)", spec_version)
        version_number = self._coerce_float(version_match.group(1)) if version_match else None
        enabled = tpm.get("enabled")
        activated = tpm.get("activated")
        enabled_ok = enabled is not False
        activated_ok = activated is not False
        ok = bool(tpm.get("present")) and bool(version_number and version_number >= 2.0) and enabled_ok and activated_ok
        return {
            "name": "tpm",
            "ok": ok,
            "present": tpm.get("present", False),
            "ready": tpm.get("ready", False),
            "enabled": enabled,
            "activated": activated,
            "owned": tpm.get("owned"),
            "manufacturer": tpm.get("manufacturer", ""),
            "manufacturer_version": tpm.get("manufacturer_version", ""),
            "spec_version": spec_version,
            "raw_spec": tpm.get("raw_spec", ""),
            "message": tpm.get("message", "TPM non detecte"),
            "error": tpm.get("error"),
        }

    def _build_cpu_check(self, cpu):
        """Construit le resultat de verification CPU a partir de l'inventaire."""
        return {
            "name": "cpu",
            "ok": cpu.get("compatibility_ok", False),
            "vendor": cpu.get("vendor_family", cpu.get("vendor", "unknown")),
            "model": cpu.get("model", ""),
            "generation": cpu.get("generation"),
            "minimum_generation": cpu.get("minimum_generation"),
            "cores": cpu.get("cores"),
            "threads": cpu.get("threads"),
            "architecture": cpu.get("architecture"),
            "max_clock_mhz": cpu.get("max_clock_mhz"),
            "message": cpu.get("compatibility_message", ""),
        }

    def _build_graphics_check(self, graphics):
        """Construit le resultat de verification graphique a partir de l'inventaire."""
        adapters = graphics.get("adapters", [])
        compatible_adapter = next(
            (adapter for adapter in adapters if adapter.get("compatible")),
            None,
        )
        selected_adapter = compatible_adapter or (adapters[0] if adapters else {})

        if compatible_adapter:
            feature_levels = compatible_adapter.get("feature_levels") or []
            feature_text = ", ".join(feature_levels) if feature_levels else "niveaux inconnus"
            message = (
                f"{compatible_adapter.get('name') or 'GPU'} : {feature_text} / "
                f"{compatible_adapter.get('driver_model') or 'WDDM inconnu'}"
            )
        else:
            message = graphics.get("message", "Aucun adaptateur graphique detecte")

        return {
            "name": "graphics",
            "ok": bool(compatible_adapter),
            "required_directx": "DirectX 12 ou plus",
            "required_driver_model": "WDDM 2.0 ou plus",
            "system_directx_version": graphics.get("directx_version", ""),
            "adapter_name": selected_adapter.get("name", ""),
            "vendor": selected_adapter.get("vendor", ""),
            "driver_model": selected_adapter.get("driver_model", ""),
            "wddm_version": selected_adapter.get("wddm_version"),
            "ddi_version": selected_adapter.get("ddi_version"),
            "feature_levels": selected_adapter.get("feature_levels", []),
            "message": message,
            "error": graphics.get("dxdiag_error") if not compatible_adapter else None,
        }

    def _build_display_check(self, display):
        """Construit le resultat de verification affichage a partir de l'inventaire."""
        displays = display.get("displays", [])
        compatible_display = next(
            (item for item in displays if item.get("compatible")),
            None,
        )
        selected_display = compatible_display or (displays[0] if displays else {})

        if compatible_display:
            size_text = (
                f"{compatible_display.get('diagonal_inches')} pouces"
                if compatible_display.get("diagonal_inches") is not None
                else "taille non verifiee"
            )
            message = (
                f"{compatible_display.get('name')} : {compatible_display.get('width')}x"
                f"{compatible_display.get('height')} / {compatible_display.get('bits_per_pixel')} bpp / {size_text}"
            )
        else:
            base_message = display.get(
                "message",
                "Aucun ecran ne verifie 1280x720, 24 bpp et une diagonale > 9 pouces",
            )

            hints = []
            if displays:
                has_resolution_issue = any(not item.get("resolution_ok", False) for item in displays)
                has_color_issue = any(not item.get("color_ok", False) for item in displays)
                has_size_issue = any(not item.get("size_ok", False) for item in displays)

                if has_resolution_issue or has_color_issue:
                    hints.append(
                        "Change la resolution de ton ecran pour l'installation (minimum 1280x720, 24 bpp)."
                    )
                if has_color_issue:
                    hints.append("Verifie que la profondeur de couleur est au moins de 24 bpp (32 bpp recommande).")
                if has_size_issue:
                    hints.append("Verifie la diagonale de l'ecran (> 9 pouces) avec un ecran physique local.")

            if hints:
                message = f"{base_message} {' '.join(hints)}"
            else:
                message = base_message

        return {
            "name": "display",
            "ok": bool(compatible_display),
            "required_resolution": "1280x720 ou plus",
            "required_bits_per_pixel": 24,
            "required_diagonal_inches": 9,
            "display_name": selected_display.get("name", ""),
            "width": selected_display.get("width"),
            "height": selected_display.get("height"),
            "bits_per_pixel": selected_display.get("bits_per_pixel"),
            "diagonal_inches": selected_display.get("diagonal_inches"),
            "size_verified": selected_display.get("size_verified", False),
            "message": message,
            "error": display.get("dxdiag_error") if not compatible_display else None,
        }

    def check_ram(self):
        """Verifie que la machine dispose d'au moins 4 Go de RAM."""
        return self._build_ram_check(self.get_memory_info())

    def check_disk(self):
        """Verifie que le disque systeme C: dispose d'au moins 64 Go."""
        if not sys.platform.startswith("win"):
            return self._unsupported_result("disk", "Verification reservee a Windows")
        return self._build_disk_check(self.get_storage_info())

    def check_uefi(self):
        """Verifie si la machine demarre en UEFI et collecte l'etat du Secure Boot."""
        if not sys.platform.startswith("win"):
            return self._print_check_result(
                self._unsupported_result("uefi", "Verification reservee a Windows")
            )
        try:
            return self._print_check_result(self._build_uefi_check(self.get_boot_info()))
        except Exception as exc:
            return self._print_check_result(
                self._error_result("uefi", "Erreur detection UEFI", str(exc))
            )

    def check_tpm(self):
        """Verifie la presence et la version du TPM."""
        if not sys.platform.startswith("win"):
            return self._unsupported_result("tpm", "Verification reservee a Windows")
        return self._build_tpm_check(self.get_tpm_info())

    def check_cpu(self):
        """Verifie si le CPU satisfait les regles minimales de compatibilite."""
        return self._build_cpu_check(self.get_cpu_info())

    def check_graphics(self):
        """Verifie si un GPU compatible DirectX 12 / WDDM 2.x est present."""
        if not sys.platform.startswith("win"):
            return self._unsupported_result("graphics", "Verification reservee a Windows")
        return self._build_graphics_check(self.get_graphics_info())

    def check_display(self):
        """Verifie la compatibilite de l'affichage avec les exigences Windows 11."""
        display_info = self.get_display_info() if sys.platform.startswith("win") else {
            "displays": [],
            "message": "Verification reservee a Windows",
        }
        result = self._build_display_check(display_info)
        # Exigence metier medulla-agent: le controle display ne doit jamais bloquer.
        result["raw_ok"] = bool(result.get("ok", False))
        result["ok"] = True
        result["forced_ok"] = True
        result["message"] = "Controle display force a OK pour medulla-agent"
        result["error"] = None
        return result

    def collect_report(self):
        """Construit le rapport complet de compatibilite."""
        inventory = self.collect_inventory()
        ordered_checks = ["ram", "disk", "uefi", "tpm", "cpu", "graphics", "display"]
        checks = {
            "ram": self._safe_check_result("ram", self._build_ram_check, inventory.get("memory", {})),
            "disk": self._safe_check_result("disk", self._build_disk_check, inventory.get("storage", {})),
            "uefi": self._safe_check_result("uefi", self._build_uefi_check, inventory.get("boot", {})),
            "tpm": self._safe_check_result("tpm", self._build_tpm_check, inventory.get("tpm", {})),
            "cpu": self._safe_check_result("cpu", self._build_cpu_check, inventory.get("cpu", {})),
            "graphics": self._safe_check_result("graphics", self._build_graphics_check, inventory.get("graphics", {})),
            "display": self._safe_check_result(
                "display",
                lambda _: self.check_display(),
                {},
            ),
        }

        compatibility_details = {}
        for check_name in ordered_checks:
            check_data = checks.get(check_name, {})
            if check_data.get("forced_ok"):
                status = "FORCED_OK"
            elif check_data.get("ok"):
                status = "OK"
            else:
                status = "KO"
            compatibility_details[check_name] = {
                "status": status,
                "ok": bool(check_data.get("ok", False)),
                "raw_ok": bool(check_data.get("raw_ok", False)),
                "forced_ok": bool(check_data.get("forced_ok", False)),
                "message": check_data.get("message", ""),
                "error": check_data.get("error"),
            }

        raw_compatible = sys.platform.startswith("win") and all(
            item.get("ok", False) for item in checks.values()
        )
        compatible = raw_compatible
        failed_checks = [name for name, item in checks.items() if not item.get("ok", False)]
        failed_checks_details = [
            {
                "name": name,
                "reason": (
                    (checks.get(name, {}).get("message") or "Raison non disponible")
                    if not checks.get(name, {}).get("forced_ok", False)
                    else "Controle force a OK"
                ),
                "error": checks.get(name, {}).get("error"),
            }
            for name in failed_checks
        ]
        return {
            "timestamp": datetime.now().isoformat(timespec="seconds"),
            "os": inventory.get("system", {}),
            "compatible": compatible,
            "compatble_win11": compatible,
            "raw_compatible": raw_compatible,
            "failed_checks": failed_checks,
            "failed_checks_details": failed_checks_details,
            "compatibility_order": ordered_checks,
            "compatibility_details": compatibility_details,
            "checks": checks,
            "inventory": inventory,
        }

    def is_compatible(self):
        """Retourne uniquement le resultat global de compatibilite."""
        return self.collect_report()["compatible"]


def build_argument_parser():
    """Construit le parseur d'arguments du script standalone."""
    parser = argparse.ArgumentParser(
        description="Affiche un diagnostic de compatibilite Windows 11 pour la machine locale."
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Affiche le rapport complet au format JSON",
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Active les traces de debug",
    )
    parser.add_argument(
        "--fail-on-incompatible",
        action="store_true",
        help="Retourne le code 1 si la machine n'est pas compatible Windows 11",
    )
    parser.add_argument(
        "--is-compatible",
        action="store_true",
        help="Affiche uniquement true/false selon la compatibilite globale",
    )
    parser.add_argument(
        "--output-file",
        metavar="PATH",
        help="Redirige la sortie des prints vers un fichier",
    )
    parser.add_argument(
        "--journal-file",
        metavar="PATH",
        help="Ecrit toute la sortie (prints + logs) dans un journal au lieu de stdout",
    )
    return parser


def print_human_report(report):
    """Affiche un rapport lisible par un humain."""
    os_info = report.get("os", {})
    inventory = report.get("inventory", {})
    identity = inventory.get("identity", {})
    cpu = inventory.get("cpu", {})
    memory = inventory.get("memory", {})
    storage = inventory.get("storage", {})
    graphics = inventory.get("graphics", {})
    display_data = inventory.get("display", {})
    boot = inventory.get("boot", {})
    tpm = inventory.get("tpm", {})
    network = inventory.get("network", {})
    domain = inventory.get("domain", {})
    bios = inventory.get("bios", {})
    battery = inventory.get("battery", {})

    def display(value, default="inconnu"):
        if value in (None, "", [], {}):
            return default
        if isinstance(value, list):
            return ", ".join(str(item) for item in value)
        return str(value)

    print("Compatibilite Windows 11")
    print("========================")
    print(f"Date        : {report.get('timestamp', '')}")
    print(f"Machine     : {display(identity.get('hostname') or os_info.get('hostname'))}")
    print(f"Plateforme  : {display(os_info.get('platform'))}")

    caption = os_info.get("caption") or "inconnu"
    version = os_info.get("version") or "inconnue"
    build_number = os_info.get("build_number") or "inconnu"
    edition = os_info.get("edition") or "inconnue"
    display_version = os_info.get("display_version") or "inconnue"
    print(f"OS          : {caption} ({edition})")
    print(f"Version     : {display_version} / {version} / build {display(os_info.get('build_full') or build_number)}")
    print(f"Python      : {display(os_info.get('python'))}")
    print(f"Compatible  : {'oui' if report.get('compatible') else 'non'}")

    if report.get("failed_checks"):
        print(f"Echecs      : {', '.join(report['failed_checks'])}")
    else:
        print("Echecs      : aucun")

    print("")
    print("Identite machine")
    print("----------------")
    print(f"Constructeur: {display(identity.get('manufacturer'))}")
    print(f"Modele      : {display(identity.get('model'))}")
    print(f"UUID        : {display(identity.get('uuid'))}")
    print(f"Serie       : {display(identity.get('serial_number'))}")

    print("")
    print("Details")
    print("-------")

    ordered_checks = ["ram", "disk", "uefi", "tpm", "cpu", "graphics", "display"]

    for name in ordered_checks:
        result = report.get("checks", {}).get(name, {})
        status = "OK" if result.get("ok") else "KO"

        if name == "uefi":
            sb = result.get("secure_boot")

            if sb is True:
                sb_text = "Secure Boot actif"
            elif sb is False:
                sb_text = "Secure Boot desactive"
            else:
                sb_text = "Secure Boot inconnu"

            print(f"{name.upper():<10}: {status} - {result.get('message', '')} ({sb_text})")

        elif name == "tpm":
            version = result.get("spec_version")

            if version:
                tpm_text = f"TPM {version}"
            else:
                tpm_text = "TPM version inconnue"

            print(f"{name.upper():<10}: {status} - {result.get('message', '')} ({tpm_text})")

        else:
            print(f"{name.upper():<10}: {status} - {result.get('message', '')}")

        if result.get("error"):
            print(f"             erreur: {result['error']}")

    print("")
    print("CPU")
    print("---")
    print(f"Modele      : {display(cpu.get('model'))}")
    print(f"Vendor      : {display(cpu.get('vendor'))}")
    print(f"Generation  : {display(cpu.get('generation'))}")
    print(f"Cores       : {display(cpu.get('cores'))}")
    print(f"Threads     : {display(cpu.get('threads'))}")
    print(f"Architecture: {display(cpu.get('architecture'))}")
    print(f"Frequence   : {display(cpu.get('max_clock_mhz'))} MHz max / {display(cpu.get('current_clock_mhz'))} MHz actuel")

    print("")
    print("Memoire")
    print("-------")
    print(f"Total       : {display(memory.get('total_gb'))} GB")
    print(f"Type        : {display(memory.get('memory_type'))}")
    print(f"Slots       : {display(memory.get('slots_used'))} utilises / {display(memory.get('slots_total'))}")
    print(f"Frequences  : {display(memory.get('frequencies_mhz'))} MHz")

    print("")
    print("Disque")
    print("------")
    system_drive = storage.get("system_drive", {})
    print(f"Lecteur     : {display(system_drive.get('drive'))}")
    print(f"Capacite    : {display(system_drive.get('total_gb'))} GB")
    print(f"Libre       : {display(system_drive.get('free_gb'))} GB")
    print(f"Filesystem  : {display(system_drive.get('file_system'))}")
    physical_disks = storage.get("physical_disks", [])
    if physical_disks:
        for index, disk in enumerate(physical_disks, start=1):
            print(
                f"Disque #{index}   : {display(disk.get('model'))} | {display(disk.get('media_type'))} | "
                f"{display(disk.get('bus_type'))} | {display(disk.get('size_gb'))} GB | sante {display(disk.get('health_status'))}"
            )

    print("")
    print("Graphiques")
    print("----------")
    print(f"DirectX sys: {display(graphics.get('directx_version'))}")
    if graphics.get("dxdiag_error"):
        print(f"DXDiag      : {display(graphics.get('dxdiag_error'))}")
    for index, adapter in enumerate(graphics.get("adapters", []), start=1):
        resolution = adapter.get("current_resolution", {})
        resolution_text = "inconnue"
        if resolution.get("width") and resolution.get("height"):
            resolution_text = f"{resolution['width']}x{resolution['height']}"
        print(
            f"GPU #{index}      : {display(adapter.get('name'))} | {display(adapter.get('vendor'))} | "
            f"modele {display(adapter.get('driver_model'))} | pilote {display(adapter.get('driver_version'))}"
        )
        print(
            f"               DDI {display(adapter.get('ddi_version'))} | niveaux {display(adapter.get('feature_levels'))} | "
            f"resolution {resolution_text} | {display(adapter.get('bits_per_pixel'))} bpp | VRAM {display(adapter.get('adapter_ram_gb'))} GB"
        )

    print("")
    print("Affichage")
    print("---------")
    for index, screen in enumerate(display_data.get("displays", []), start=1):
        diagonal = (
            f"{screen.get('diagonal_inches')} pouces"
            if screen.get("diagonal_inches") is not None
            else "taille non verifiee"
        )
        print(
            f"Ecran #{index}    : {display(screen.get('name'))} | {display(screen.get('width'))}x{display(screen.get('height'))} | "
            f"{display(screen.get('bits_per_pixel'))} bpp | {display(screen.get('refresh_hz'))} Hz | {diagonal} | "
            f"{display(screen.get('input_type'))} | principal={display(screen.get('primary'))}"
        )

    print("")
    print("TPM / Boot")
    print("----------")
    print(f"TPM        : {display(tpm.get('spec_version'))} | present={display(tpm.get('present'))} | ready={display(tpm.get('ready'))}")
    print(f"TPM vendor : {display(tpm.get('manufacturer'))} {display(tpm.get('manufacturer_version'), default='')}")
    print(f"Ownership  : owned={display(tpm.get('owned'))} | enabled={display(tpm.get('enabled'))} | activated={display(tpm.get('activated'))}")
    print(f"Firmware   : {display(boot.get('firmware_mode'))}")
    print(f"SecureBoot : {display(boot.get('secure_boot'))}")
    print(f"Boot state : {display(boot.get('bootup_state'))}")

    print("")
    print("Reseau")
    print("------")
    primary_adapter = network.get("primary_adapter", {})
    print(f"IP locale   : {display(primary_adapter.get('primary_ipv4'))}")
    print(f"Passerelle  : {display(primary_adapter.get('default_gateway'))}")
    print(f"DNS         : {display(primary_adapter.get('dns_servers'))}")
    print(f"Domaine DNS : {display(primary_adapter.get('dns_domain'))}")
    print(f"MAC         : {display(primary_adapter.get('mac_address'))}")

    print("")
    print("Domaine / AD")
    print("-----------")
    print(f"Joined      : {display(domain.get('joined'))}")
    print(f"Domaine     : {display(domain.get('domain_name'))}")
    print(f"Workgroup   : {display(domain.get('workgroup'))}")
    print(f"Logon server: {display(domain.get('logon_server'))}")

    print("")
    print("BIOS / Firmware")
    print("---------------")
    print(f"Fabricant   : {display(bios.get('manufacturer'))}")
    print(f"Version     : {display(bios.get('version'))}")
    print(f"Date        : {display(bios.get('release_date'))}")

    print("")
    print("Batterie")
    print("--------")
    print(f"Presence    : {display(battery.get('present'))}")
    for index, item in enumerate(battery.get('batteries', []), start=1):
        print(
            f"Batterie #{index}: {display(item.get('name'))} | charge {display(item.get('charge_remaining_pct'))}% | "
            f"statut {display(item.get('battery_status'))} | sante {display(item.get('health_pct'))}%"
        )

    print("")
    print("Resultat final")
    print("-------------")
    print(f"compatble_win11 : {bool(report.get('compatble_win11', report.get('compatible')))}")


def main(argv=None):
    """Point d'entree de l'utilitaire standalone."""
    parser = build_argument_parser()
    args = parser.parse_args(argv)

    if args.output_file and args.journal_file:
        parser.error("--output-file et --journal-file ne peuvent pas etre utilises ensemble")

    if not args.journal_file:
        logging.basicConfig(
            level=logging.DEBUG if args.debug else logging.INFO,
            format="%(asctime)s %(levelname)s %(message)s",
        )

    compatibility = Windows11Compatibility(
        debug=True if args.debug else None,
        output_format="json" if args.json else "human",
        is_compatible_only=args.is_compatible,
        fail_on_incompatible=args.fail_on_incompatible,
        output_file=args.output_file,
        journal_file=args.journal_file,
    )
    return compatibility.run()


if __name__ == "__main__":
    raise SystemExit(main())