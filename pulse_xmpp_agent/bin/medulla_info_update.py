#!/usr/bin/env python3
# -*- coding: utf-8; -*-
# SPDX-FileCopyrightText: 2016-2023 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-3.0-or-later

# Référence pour les informations utilisées
# https://learn.microsoft.com/fr-fr/windows/win32/msi/msiarpsettingsidentifier

# Ce programme installe un programme pour permettre une remontée d'informations dans GLPI.
# Il ajoute dans les commentaires de Medulla Update les informations nécessaires manquantes dans GLPI.
# debug command cli
# "c:\Program Files\Python3\python.exe" "C:\Program Files\Medulla\bin\medulla_info_update.py"
# "c:\Program Files\Python3\python.exe" "C:\Program Files\Medulla\bin\uninstall_medulla_info_update_notification.py"
# Fonction pour lire une valeur dans le registre

# reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Medulla Update Info"
# reg query "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion"
import codecs
import locale
import platform
import winreg
import random
import string
from datetime import datetime
import os
import shutil
import subprocess
import psutil
import math
import re
import tempfile
import traceback
import xml.etree.ElementTree as ET
import json

import logging
import logging.handlers


class Compatibilite:
    def __init__(self, debug=False):
        """
        Initialize the Compatibilite class with an optional debug parameter.

        Parameters:
            debug (bool): If True, print debug information. Default is False.
        """
        self.debug = debug
        self._dxdiag_cache = None

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
            print(f"PowerShell rc={result.returncode}: {command} -> {stdout or stderr}")
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
        except json.JSONDecodeError:
            if check:
                raise
            return default

    def _ensure_list(self, value):
        """Normalise un resultat JSON PowerShell en liste."""
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

    def _extract_numeric_version(self, value):
        """Extrait une version numerique simple depuis une chaine."""
        match = re.search(r"([0-9]+(?:\.[0-9]+)?)", str(value or ""))
        if not match:
            return None
        return self._coerce_float(match.group(1))

    def _screen_diagonal_inches(self, width_cm, height_cm):
        """Calcule la diagonale d'un ecran a partir de ses dimensions actives."""
        width_value = self._coerce_float(width_cm)
        height_value = self._coerce_float(height_cm)
        if not width_value or not height_value:
            return None
        return round((((width_value ** 2) + (height_value ** 2)) ** 0.5) / 2.54, 2)

    def _get_dxdiag_info(self):
        """Retourne les informations DXDiag utiles aux verifications video."""
        if self._dxdiag_cache is not None:
            return self._dxdiag_cache

        result = {"system": {}, "display_devices": [], "error": ""}
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
            stdout = self._decode_subprocess_output(process.stdout)
            stderr = self._decode_subprocess_output(process.stderr)
            if process.returncode != 0:
                result["error"] = stderr or stdout or f"dxdiag exit code {process.returncode}"
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
        except Exception as e:
            result["error"] = str(e)
            if self.debug:
                print(f"DXDiag Error: {e}")
        finally:
            if xml_path:
                try:
                    os.unlink(xml_path)
                except OSError:
                    pass

        self._dxdiag_cache = result
        return result

    def is_uefi(self):
        """
        Check if the system is using UEFI.

        Returns:
            bool: True if UEFI is detected, False otherwise.
        """
        try:
            result = subprocess.run(
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
            stdout = self._decode_subprocess_output(result.stdout).lower()
            stderr = self._decode_subprocess_output(result.stderr).lower()
            unsupported_secureboot = (
                "platformnotsupportedexception" in stderr
                or "getfwvarfailed" in stderr
                or "non prise en charge" in stderr
            )

            if "true" in stdout or "false" in stdout:
                uefi_detected = True
            elif result.returncode != 0 or "cmdlet" in stderr:
                uefi_detected = False
            else:
                uefi_detected = True

            if self.debug:
                if unsupported_secureboot:
                    print("UEFI Check: secureboot platform not supported -> Legacy BIOS")
                print(f"UEFI Check: {uefi_detected}")
            return uefi_detected
        except Exception as e:
            if self.debug:
                print(f"UEFI Check Error: {e}")
            return False

    def has_tpm_2(self):
        """
        Check if the system has TPM version 2.0 or higher using PowerShell.

        Returns:
            bool: True if TPM 2.0 or higher is detected, False otherwise.
        """
        try:
            data = self._run_powershell_json(
                "Get-CimInstance -Namespace Root\\CIMv2\\Security\\MicrosoftTpm -Class Win32_Tpm | "
                "Select-Object SpecVersion, IsEnabled_InitialValue, IsActivated_InitialValue | ConvertTo-Json -Compress",
                default={},
                check=False,
            ) or {}

            spec = data.get("SpecVersion") or ""
            version = spec.split(",")[0].strip() if spec else ""
            version_number = self._coerce_float(version)
            tpm_2_detected = bool(
                version_number is not None
                and version_number >= 2.0
                and data.get("IsEnabled_InitialValue") is not False
                and data.get("IsActivated_InitialValue") is not False
            )
            if self.debug:
                print(f"TPM 2.0 Check: {tpm_2_detected}")
            return tpm_2_detected
        except Exception as e:
            if self.debug:
                print(f"TPM 2.0 Check Error: {e}")
            return False

    def has_more_than_4gb_ram(self):
        """
        Check if the system has more than 4GB of RAM.

        Returns:
            bool: True if more than 4GB of RAM is detected, False otherwise.
        """
        try:
            total_ram_bytes = psutil.virtual_memory().total
            total_ram_gb = math.ceil(total_ram_bytes / (1024 ** 3))
            result = total_ram_gb >= 4
            if self.debug:
                print(f"RAM Check: {result} (Total RAM: {total_ram_gb:.2f}GB)")
            return result
        except Exception as e:
            if self.debug:
                print(f"RAM Check Error: {e}")
            return False

    def is_disk_c_ge_80gb(self):
        """
        Check if the C: drive has a total capacity of 80GB or more.

        Returns:
            bool: True if the C: drive capacity is 80GB or more, False otherwise.
        """
        try:
            total_bytes, _, _ = shutil.disk_usage("C:\\")
            total_gb = total_bytes / (1024 ** 3)
            result = total_gb >= 80
            if self.debug:
                print(f"Disk C: Check: {result} (Total Disk Size: {total_gb:.2f}GB)")
            return result
        except Exception as e:
            if self.debug:
                print(f"Disk C: Check Error: {e}")
            return False

    def check_graphics(self):
        """Verifie la compatibilite du GPU avec DirectX 12 et WDDM 2.0.

        Si l'information manque ou n'est pas exploitable, on considere la verification comme OK.
        """
        try:
            dxdiag = self._get_dxdiag_info()
            devices = dxdiag.get("display_devices", [])
            directx_version = (dxdiag.get("system", {}).get("DirectXVersion") or "").lower()

            if not devices:
                if self.debug:
                    print("Graphics Check: OK par defaut (aucun resultat)")
                return True

            for device in devices:
                feature_levels = [
                    item.strip() for item in str(device.get("FeatureLevels") or "").split(",") if item.strip()
                ]
                ddi_version = self._extract_numeric_version(device.get("DDIVersion"))
                wddm_version = self._extract_numeric_version(device.get("DriverModel"))

                directx_ok = any(level.startswith("12") for level in feature_levels)
                if not directx_ok and ddi_version is not None:
                    directx_ok = ddi_version >= 12.0
                if not directx_ok and directx_version:
                    directx_ok = "directx 12" in directx_version

                # Si WDDM est non remonte, on ne bloque pas la compatibilite.
                wddm_ok = wddm_version is None or wddm_version >= 2.0

                if directx_ok and wddm_ok:
                    if self.debug:
                        print("Graphics Check: True")
                    return True

            if self.debug:
                print("Graphics Check: False")
            return False
        except Exception as e:
            if self.debug:
                print(f"Graphics Check Error: {e} -> OK par defaut")
            return True

    def check_display(self):
        """Verifie la compatibilite de l'affichage pour Windows 11.

        Si l'information manque ou n'est pas exploitable, on considere la verification comme OK.
        """
        try:
            screens = self._ensure_list(
                self._run_powershell_json(
                    "Add-Type -AssemblyName System.Windows.Forms; "
                    "[System.Windows.Forms.Screen]::AllScreens | ForEach-Object { "
                    "[pscustomobject]@{ Width = $_.Bounds.Width; Height = $_.Bounds.Height; BitsPerPixel = $_.BitsPerPixel } } | "
                    "ConvertTo-Json -Depth 4 -Compress",
                    default=[],
                    check=False,
                )
            )
            basic_params = self._ensure_list(
                self._run_powershell_json(
                    "Get-CimInstance -Namespace root\\wmi -Class WmiMonitorBasicDisplayParams | "
                    "Select-Object MaxHorizontalImageSize, MaxVerticalImageSize | ConvertTo-Json -Depth 4 -Compress",
                    default=[],
                    check=False,
                )
            )

            if not screens:
                if self.debug:
                    print("Display Check: OK par defaut (aucun resultat)")
                return True

            for index, screen in enumerate(screens):
                width = self._coerce_int(screen.get("Width"))
                height = self._coerce_int(screen.get("Height"))
                bits_per_pixel = self._coerce_int(screen.get("BitsPerPixel"))
                diagonal_inches = None
                if index < len(basic_params):
                    diagonal_inches = self._screen_diagonal_inches(
                        basic_params[index].get("MaxHorizontalImageSize"),
                        basic_params[index].get("MaxVerticalImageSize"),
                    )

                resolution_ok = width is None or height is None or (width >= 1280 and height >= 720)
                color_ok = bits_per_pixel is None or bits_per_pixel >= 24
                size_ok = diagonal_inches is None or diagonal_inches > 9.0

                if resolution_ok and color_ok and size_ok:
                    if self.debug:
                        print("Display Check: True")
                    return True

            if self.debug:
                print("Display Check: False")
            return False
        except Exception as e:
            if self.debug:
                print(f"Display Check Error: {e} -> OK par defaut")
            return True

    def system_meets_requirements(self):
        """
        Check if the system meets all the specified requirements.

        Returns:
            bool: True if all requirements are met, False otherwise.
        """
        result = all(self.collect_requirements_status().values())
        if self.debug:
            print(f"System Meets Requirements: {result}")
        return result

    def collect_requirements_status(self):
        """Retourne le detail des verifications de compatibilite Windows 11."""
        return {
            "disk": self.is_disk_c_ge_80gb(),
            "ram": self.has_more_than_4gb_ram(),
            "tpm": self.has_tpm_2(),
            "uefi": self.is_uefi(),
            "graphics": self.check_graphics(),
            "display": self.check_display(),
        }
# "0409": "EnglishInternational",
# Tableau de correspondance entre les codes Windows et les langues
language_codes = {
    "0401": "Arabic",
    "0402": "Bulgarian",
    "0405": "Czech",
    "0406": "Danish",
    "0407": "German",
    "0408": "Greek",
    "0809": "English_UK",
    "0409": "English_US",
    "040A": "Spanish",
    "080A": "Spanish_Mexico",
    "0425": "Estonian",
    "040B": "Finnish",
    "040C": "French",
    "0C0C": "FrenchCanadian",
    "040D": "Hebrew",
    "0439": "Hindi",
    "041A": "Croatian",
    "040E": "Hungarian",
    "0410": "Italian",
    "0411": "Japanese",
    "0412": "Korean",
    "0427": "Lithuanian",
    "0426": "Latvian",
    "0414": "Norwegian_Bokmal",
    "0413": "Dutch",
    "0415": "Polish",
    "0416": "Portuguese_Brazil",
    "0816": "Portuguese_Portugal",
    "0419": "Russian",
    "041D": "Swedish",
    "041E": "Thai",
    "041F": "Turkish",
    "0422": "Ukrainian",
    "0404": "Chinese_Traditional",
    "0804": "Chinese_Simplified",
    "7C04": "Chinese_HongKong"
}

# Tableau de correspondance entre les codes Windows et les textes de correspondance
correspondence_text = {
    "0401": "ar-SA",
    "0402": "bg-BG",
    "0405": "cs-CZ",
    "0406": "da-DK",
    "0407": "de-DE",
    "0408": "el-GR",
    "0809": "en-GB",
    "0409": "en-US",
    "040A": "es-ES",
    "080A": "es-MX",
    "0425": "et-EE",
    "040B": "fi-FI",
    "0C0C": "fr-CA",
    "040C": "fr-FR",
    "040D": "he-IL",
    "0439": "hi-IN",
    "041A": "hr-HR",
    "040E": "hu-HU",
    "0410": "it-IT",
    "0411": "ja-JP",
    "0412": "ko-KR",
    "0427": "lt-LT",
    "0426": "lv-LV",
    "0414": "nb-NO",
    "0413": "nl-NL",
    "0415": "pl-PL",
    "0416": "pt-BR",
    "0816": "pt-PT",
    "0419": "ru-RU",
    "041D": "sv-SE",
    "041E": "th-TH",
    "041F": "tr-TR",
    "0422": "uk-UA",
    "0404": "zh-TW",
    "0804": "zh-CN",
    "7C04": "zh-HK"
}
# Configuration de la journalisation
logger = logging.getLogger('MedullaUpdateLogger')
logger.setLevel(logging.DEBUG)

# Créer un gestionnaire pour le journal des événements Windows
event_handler = logging.handlers.NTEventLogHandler("MedullaUpdateApp")
logger.addHandler(event_handler)

def delete_subkey(key_path):
    try:
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall", 0, winreg.KEY_ALL_ACCESS)
        winreg.DeleteKey(key, "Medulla Update Info")
        logger.info(f"La sous-clé '{key_path}' a été supprimée avec succès.")
        return 0
    except FileNotFoundError:
        logger.warning(f"La sous-clé '{key_path}' n'existe pas.")
        return 0
    except PermissionError:
        logger.error(f"Vous n'avez pas les permissions nécessaires pour supprimer la sous-clé '{key_path}'.")
        return -1
    except Exception as e:
        logger.error(f"Une erreur s'est produite : {e}")
        return -1

def get_windows_info():
    base_key = r"SOFTWARE\Microsoft\Windows NT\CurrentVersion"

    product_name = read_reg_value(base_key, "ProductName", winreg.REG_SZ)
    display_version = read_reg_value(base_key, "DisplayVersion", winreg.REG_SZ)
    if not display_version:
        display_version = read_reg_value(base_key, "ReleaseId", winreg.REG_SZ)
    build = read_reg_value(base_key, "CurrentBuild", winreg.REG_SZ)
    edition = read_reg_value(base_key, "EditionID", winreg.REG_SZ)

    try:
        build = int(build)
    except Exception:
        build = 0

    # 🔥 Détection fiable Windows 10 / 11
    if build >= 22000:
        major = 11
    else:
        major = 10

    # 🔧 Correction du nom (Microsoft bug)
    if product_name and major == 11 and "Windows 10" in product_name:
        product_name = product_name.replace("Windows 10", "Windows 11")

    return {
        "name": product_name,
        "major": major,
        "build": build,
        "display_version": display_version,
        "edition": edition
    }
    

def read_reg_value(key_path, value_name, value_type,defaut_valeur=""):
    try:
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path)
        value, regtype = winreg.QueryValueEx(key, value_name)
        winreg.CloseKey(key)
        if regtype == value_type:
            return value
        else:
            logger.error(f"Erreur: Le type de la valeur {value_name} ne correspond pas à {value_type}.")
            return defaut_valeur
    except Exception as e:
        logger.error(f"Erreur lors de la lecture de la valeur {value_name}: {e}")
        return defaut_valeur

def generate_random_ascii_string(length):
    return ''.join(random.choices(string.printable, k=length))

def write_reg_value(key_path, value_name, value_data, value_type):
    try:
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path, 0, winreg.KEY_SET_VALUE)
        winreg.SetValueEx(key, value_name, 0, value_type, value_data)
        winreg.CloseKey(key)
    except Exception as e:
        logger.error(f"Erreur lors de l'écriture de la valeur {value_name}: {e}")

def create_reg_key(key_path):
    try:
        key = winreg.CreateKey(winreg.HKEY_LOCAL_MACHINE, key_path)
        winreg.CloseKey(key)
    except Exception as e:
        logger.error(f"Erreur lors de la création de la clé {key_path}: {e}")

def main():
    import re
    import platform
    from datetime import datetime
    import winreg

    compatibilite = Compatibilite(debug=False)
    checks = compatibilite.collect_requirements_status()
    compatiblew11 = all(checks.values())

    compatibleWin11 = 1
    major_name = 0
    iso_name = ""

    key_path = r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Medulla Update Info"
    delete_subkey(key_path)

    current_date = datetime.now().strftime("%Y%m%d")

    # ✅ Utilisation de la fonction fiable
    inf = get_windows_info()

    ProductName = inf.get("name", "")
    build = inf.get("build", 0)
    DisplayVersion = inf.get("display_version", "")

    # ------------------ DETECTION OS ------------------

    # Server detection
    is_server = "Server" in ProductName

    server_annee = None
    if is_server:
        match = re.search(r'\d{4}', ProductName)
        if match:
            server_annee = match.group()
            major_name = "MSO" + server_annee[-2:]
        else:
            major_name = "MSO"
    else:
        # Windows client detection via build
        if build >= 22000:
            major_name = 11
        else:
            major_name = 10

    # Win11 compatibility
    if major_name == 10:
        compatibleWin11 = compatiblew11

    # ------------------ ARCHITECTURE ------------------

    architecture = read_reg_value(
        r"System\CurrentControlSet\Control\Session Manager\Environment",
        "PROCESSOR_ARCHITECTURE",
        winreg.REG_SZ
    )

    archi = "unknown"
    if architecture == "AMD64":
        archi = "x64"

    # ------------------ LANGUAGES ------------------

    install_language = read_reg_value(
        r"SYSTEM\CurrentControlSet\Control\Nls\Language",
        "InstallLanguage",
        winreg.REG_SZ
    )

    install_language_fallback = install_language

    default_lang = read_reg_value(
        r"SYSTEM\CurrentControlSet\Control\Nls\Language",
        "Default",
        winreg.REG_SZ
    )

    # ------------------ LOG ------------------

    logger.info(f"ProductName: {ProductName}")
    logger.info(f"DisplayVersion: {DisplayVersion}")
    logger.info(f"Build: {build}")
    logger.info(f"InstallLanguage: {install_language}")
    logger.info(f"Default Language: {default_lang}")

    # ------------------ REGISTRY WRITE ------------------

    create_reg_key(r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Medulla Update Info")

    value_data = r'"C:\Program Files\Python3\python.exe" "C:\Program Files\Medulla\bin\uninstall_pulse2_update_notification.py"'

    write_reg_value(r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Medulla Update Info", "DisplayVersion", "1.0.0", winreg.REG_SZ)
    write_reg_value(r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Medulla Update Info", "Language", int(install_language, 16), winreg.REG_DWORD)
    write_reg_value(r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Medulla Update Info", "Publisher", "Medulla", winreg.REG_SZ)
    write_reg_value(r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Medulla Update Info", "UninstallString", value_data, winreg.REG_SZ)
    write_reg_value(r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Medulla Update Info", "DisplayIcon", r"C:\Program Files\Medulla\bin\install.ico", winreg.REG_SZ)
    write_reg_value(r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Medulla Update Info", "InstallLocation", r"C:\Program Files\Medulla\bin", winreg.REG_SZ)
    write_reg_value(r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Medulla Update Info", "URLInfoAbout", "http://www.siveo.net", winreg.REG_SZ)
    write_reg_value(r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Medulla Update Info", "NoModify", 1, winreg.REG_DWORD)
    write_reg_value(r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Medulla Update Info", "MajorVersion", "1", winreg.REG_SZ)
    write_reg_value(r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Medulla Update Info", "MinorVersion", "1", winreg.REG_SZ)
    write_reg_value(r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Medulla Update Info", "InstallDate", current_date, winreg.REG_SZ)
    write_reg_value(r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Medulla Update Info", "Readme", "", winreg.REG_SZ)

    # ------------------ FINAL STRING BUILD ------------------

    lang_iso = correspondence_text.get(install_language, "Unknown")
    lang_name = language_codes.get(install_language, "Unknown")

    warning = ""
    update = ""
    iso_name = ""

    # ------------------ MSO (SERVER) ------------------

    if isinstance(major_name, str) and major_name.startswith("MSO"):
        version_upper = (DisplayVersion or "").upper()

        if re.match(r"\d{2}H2", version_upper):
            target_version = version_upper
        else:
            target_version = "21H2" if build < 22000 else "24H2"
            warning = "UNKNOWN_SERVER_VERSION"

        update = f"{lang_iso}-10"
        iso_name = f"{major_name}_{target_version}_{lang_name}_{archi}"

    # ------------------ WINDOWS 10 ------------------

    elif major_name == 10:
        version_upper = (DisplayVersion or "").upper()

        if version_upper == "":
            DisplayVersion = "1906"
            version_upper = "1906"
            warning = "UNKNOWN_VERSION"

        if version_upper == "22H2":
            update = f"{lang_iso}-11"
            iso_name = f"Win11_24H2_{lang_name}_{archi}"
        else:
            update = f"{lang_iso}-10"
            iso_name = f"Win10_22H2_{lang_name}_{archi}"

    # ------------------ WINDOWS 11 ------------------

    elif major_name == 11:
        version_upper = (DisplayVersion or "").upper()

        if re.match(r"\d{2}H2", version_upper):
            target_version = version_upper
        else:
            target_version = "24H2"
            warning = "UNKNOWN_VERSION"

        update = f"{lang_iso}-11"
        iso_name = f"Win11_{target_version}_{lang_name}_{archi}"

    # ------------------ UNKNOWN ------------------

    else:
        warning = "UNKNOWN_OS"
        update = ""
        iso_name = f"Unknown_{lang_name}_{archi}"

    # ------------------ COMMENTS ------------------

    comments_value = f"{major_name}@{DisplayVersion}@{lang_iso}@{install_language}@{iso_name}@{compatibleWin11}@{update}"

    if warning:
        comments_value += f"@{warning}"

    medule_info = f"Medulla_{comments_value}"

    write_reg_value(r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Medulla Update Info", "DisplayName", medule_info, winreg.REG_SZ)
    write_reg_value(r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Medulla Update Info", "Comments", f"{comments_value}+{install_language_fallback}", winreg.REG_SZ)

    logger.info("Mise à jour du registre terminée.")

    # ------------------ OUTPUT ------------------

    print("Compatibilite Windows 11")
    print("========================")
    print(f"Disk      : {'OK' if checks.get('disk') else 'KO'}")
    print(f"RAM       : {'OK' if checks.get('ram') else 'KO'}")
    print(f"TPM       : {'OK' if checks.get('tpm') else 'KO'}")
    print(f"UEFI      : {'OK' if checks.get('uefi') else 'KO'}")
    print(f"Graphics  : {'OK' if checks.get('graphics') else 'KO'}")
    print(f"Display   : {'OK' if checks.get('display') else 'KO'}")
    print(f"Compatible: {'oui' if compatiblew11 else 'non'}")
    print("")
    print(f"DisplayName: {medule_info}")
    print(f"Comments   : {comments_value}+{install_language_fallback}")


if __name__ == "__main__":
    if platform.system() == "Windows":
        main()