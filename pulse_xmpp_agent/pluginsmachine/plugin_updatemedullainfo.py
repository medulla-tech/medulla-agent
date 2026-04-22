# SPDX-FileCopyrightText: 2020-2024 Siveo <support@siveo.net>
# SPDX-FileCopyrightText: 2025-2026 NATSU <support@medulla-tech.io>
# SPDX-License-Identifier: GPL-3.0-or-later

import sys
import os
import codecs
import locale
import logging
from lib import utils
import platform
import random
import string
from datetime import datetime

import shutil
import subprocess
import psutil
import math
import re
import json
import tempfile
import xml.etree.ElementTree as ET

import traceback
# Importer winreg uniquement si le système d'exploitation est Windows
if sys.platform.startswith("win"):
    import winreg

logger = logging.getLogger()


plugin = {"VERSION": "1.17", "NAME": "updatemedullainfo", "TYPE": "machine"}  # fmt: skip
LATEST_WIN10 = "22H2"
LATEST_WIN11 = "25H2"
LATEST_SERVER_ISO = "2025_24H2"

class Windows11Compatibility:

    def __init__(self, debug=False):
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

    def _run_powershell_json(self, command, default=None, check=True):
        """Execute une commande PowerShell et retourne le JSON decode."""
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
                "PowerShell rc=%s cmd=%s stdout=%s stderr=%s",
                result.returncode,
                command,
                stdout,
                stderr,
            )

        if check and result.returncode != 0:
            raise RuntimeError(stderr or stdout or f"PowerShell exit code {result.returncode}")
        if not stdout:
            return default
        try:
            return json.loads(stdout)
        except json.JSONDecodeError:
            if check:
                raise
            return default

    def _coerce_float(self, value):
        """Convertit une valeur en flottant si possible."""
        try:
            if value in (None, ""):
                return None
            return float(value)
        except (TypeError, ValueError):
            return None

    def _coerce_int(self, value):
        """Convertit une valeur en entier si possible."""
        try:
            if value in (None, ""):
                return None
            return int(value)
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
        except Exception as exc:
            result["error"] = str(exc)
            if self.debug:
                logger.debug("DXDiag Error: %s", exc)
        finally:
            if xml_path:
                try:
                    os.unlink(xml_path)
                except OSError:
                    pass

        self._dxdiag_cache = result
        return result

    def check_ram(self):
        try:
            ram_gb = psutil.virtual_memory().total / (1024 ** 3)
            result = ram_gb >= 4

            if self.debug:
                logger.debug(f"RAM check: {ram_gb:.2f} GB -> {result}")

            return result

        except Exception:
            logger.error("\n%s" % (traceback.format_exc()))
            return False

    def check_disk(self):
        try:
            total, _, _ = shutil.disk_usage("C:\\")
            disk_gb = total / (1024 ** 3)
            result = disk_gb >= 64

            if self.debug:
                logger.debug(f"Disk check: {disk_gb:.2f} GB -> {result}")

            return result

        except Exception:
            logger.error("\n%s" % (traceback.format_exc()))
            return False

    def check_uefi(self):
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

            if "true" in stdout or "false" in stdout:
                is_uefi = True
            elif result.returncode != 0 or "cmdlet" in stderr:
                is_uefi = False
            else:
                is_uefi = True

            if self.debug:
                logger.debug(f"UEFI check: stdout={stdout.strip()} stderr={stderr.strip()} -> {is_uefi}")

            return is_uefi

        except Exception:
            logger.error("\n%s" % (traceback.format_exc()))
            return False

    def check_tpm(self):
        try:
            tpm = self._run_powershell_json(
                "Get-CimInstance -Namespace Root\\CIMv2\\Security\\MicrosoftTpm -Class Win32_Tpm | "
                "Select-Object SpecVersion, IsEnabled_InitialValue, IsActivated_InitialValue | ConvertTo-Json -Compress",
                default={},
                check=False,
            ) or {}

            if not tpm:
                return False
            spec = tpm.get("SpecVersion", "")
            version = spec.split(",")[0].strip() if spec else ""
            version_number = self._coerce_float(version)
            tpm_ok = bool(
                version_number is not None
                and version_number >= 2.0
                and tpm.get("IsEnabled_InitialValue") is not False
                and tpm.get("IsActivated_InitialValue") is not False
            )

            if self.debug:
                logger.debug(
                    "TPM check: spec=%s enabled=%s activated=%s -> %s",
                    spec,
                    tpm.get("IsEnabled_InitialValue"),
                    tpm.get("IsActivated_InitialValue"),
                    tpm_ok,
                )

            return tpm_ok

        except Exception:
            logger.error("\n%s" % (traceback.format_exc()))
            return False

    def check_cpu(self):
        try:
            cpu = platform.processor().lower()

            if self.debug:
                logger.debug(f"CPU detected: {cpu}")

            # Intel
            intel_match = re.search(r'i[3579]-(\d{4,5})', cpu)
            if intel_match:
                generation = int(intel_match.group(1)[:2])
                result = generation >= 8

                if self.debug:
                    logger.debug(f"Intel generation {generation} -> {result}")

                return result

            # AMD Ryzen
            amd_match = re.search(r'ryzen\s*(\d)', cpu)
            if amd_match:
                generation = int(amd_match.group(1))
                result = generation >= 2

                if self.debug:
                    logger.debug(f"AMD Ryzen generation {generation} -> {result}")

                return result

            return False

        except Exception:
            logger.error("\n%s" % (traceback.format_exc()))
            return False

    def check_graphics(self):
        """Verifie la compatibilite du GPU avec DirectX 12 et WDDM 2.0.

        Si l'information manque ou n'est pas exploitable, la verification est consideree comme OK.
        """
        try:
            dxdiag = self._get_dxdiag_info()
            devices = dxdiag.get("display_devices", [])
            directx_version = (dxdiag.get("system", {}).get("DirectXVersion") or "").lower()

            if not devices:
                if self.debug:
                    logger.debug("Graphics check: OK par defaut (aucun resultat)")
                return True

            for device in devices:
                feature_levels = [
                    item.strip()
                    for item in str(device.get("FeatureLevels") or "").split(",")
                    if item.strip()
                ]
                ddi_version = self._extract_numeric_version(device.get("DDIVersion"))
                wddm_version = self._extract_numeric_version(device.get("DriverModel"))

                directx_ok = any(level.startswith("12") for level in feature_levels)
                if not directx_ok and ddi_version is not None:
                    directx_ok = ddi_version >= 12.0
                if not directx_ok and directx_version:
                    directx_ok = "directx 12" in directx_version

                wddm_ok = wddm_version is None or wddm_version >= 2.0

                if directx_ok and wddm_ok:
                    if self.debug:
                        logger.debug("Graphics check: True")
                    return True

            if self.debug:
                logger.debug("Graphics check: False")
            return False

        except Exception:
            if self.debug:
                logger.debug("Graphics check error, OK par defaut")
            return True

    def check_display(self):
        """Verifie la compatibilite de l'affichage pour Windows 11.

        Si l'information manque ou n'est pas exploitable, la verification est consideree comme OK.
        """
        try:
            screens = self._run_powershell_json(
                "Add-Type -AssemblyName System.Windows.Forms; "
                "[System.Windows.Forms.Screen]::AllScreens | ForEach-Object { "
                "[pscustomobject]@{ Width = $_.Bounds.Width; Height = $_.Bounds.Height; BitsPerPixel = $_.BitsPerPixel } } | "
                "ConvertTo-Json -Depth 4 -Compress",
                default=[],
                check=False,
            )
            basic_params = self._run_powershell_json(
                "Get-CimInstance -Namespace root\\wmi -Class WmiMonitorBasicDisplayParams | "
                "Select-Object MaxHorizontalImageSize, MaxVerticalImageSize | ConvertTo-Json -Depth 4 -Compress",
                default=[],
                check=False,
            )

            if not isinstance(screens, list):
                screens = [] if screens is None else [screens]
            if not isinstance(basic_params, list):
                basic_params = [] if basic_params is None else [basic_params]

            if not screens:
                if self.debug:
                    logger.debug("Display check: OK par defaut (aucun resultat)")
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
                        logger.debug("Display check: True")
                    return True

            if self.debug:
                logger.debug("Display check: False")
            return False

        except Exception:
            if self.debug:
                logger.debug("Display check error, OK par defaut")
            return True

    def is_compatible(self):
        try:

            checks = [
                self.check_ram(),
                self.check_disk(),
                self.check_uefi(),
                self.check_tpm(),
                self.check_cpu(),
                self.check_graphics(),
                self.check_display(),
            ]

            result = all(checks)

            if self.debug:
                logger.debug(f"Windows 11 compatibility result: {result}")

            return result

        except Exception:
            logger.error("\n%s" % (traceback.format_exc()))
            return False
# "0409": "EnglishInternational",
# Tableau de correspondance entre les codes Windows et les langues
# "0409": "EnglishInternational",
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
    "0C0C": "French_Canadian",
    "040C": "French",
    "040D": "Hebrew",
    "0439": "Hindi",
    "041A": "Croatian",
    "040E": "Hungarian",
    "0410": "Italian",
    "0411": "Japanese",
    "0412": "Korean",
    "0427": "Lithuanian",
    "0426": "Latvian",
    "0414": "Norwegian",
    "0413": "Dutch",
    "0415": "Polish",
    "0816": "Portuguese_Portugal",
    "0416": "Portuguese_Brazil",
    "0419": "Russian",
    "041D": "Swedish",
    "041E": "Thai",
    "041F": "Turkish",
    "0422": "Ukrainian",
    "7C04": "Chinese_Traditional",
    "0804": "Chinese_Simplified",
    "041B": "Slovak",
    "0424": "Slovenian",
    "0403": "Catalan",
    "0429": "Farsi"
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
    "0816": "pt-PT",
    "0416": "pt-BR",
    "0419": "ru-RU",
    "041D": "sv-SE",
    "041E": "th-TH",
    "041F": "tr-TR",
    "0422": "uk-UA",
    "7C04": "zh-CHT",
    "0804": "zh-CN",
    "041B": "sk-SK",
    "0424": "sl-SI",
    "0403": "ca-ES",
    "0429": "fa-IR"
}

@utils.set_logging_level
def action(xmppobject, action, sessionid, data, message, dataerreur):
    logger.debug("PL-MEDULLAINFO ###################################################")
    logger.debug("PL-MEDULLAINFO call %s from %s" % (plugin, message["from"]))
    logger.debug("PL-MEDULLAINFO ###################################################")

    if sys.platform.startswith("win"):
        try:
            execute_medulla_info_update()
        except Exception:
            logger.error("\n%s" % (traceback.format_exc()))


def execute_medulla_info_update():
    compat = Windows11Compatibility(debug=False)
    compatible=compat.is_compatible()
    # compatibleWin11 = int(compatible) #  1 ou 0
    update = ""
    iso_name = ""

    key_path = r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Medulla Update Info"
    delete_subkey(key_path)
    current_date = datetime.now().strftime("%Y%m%d")
    ProductName = get_os_product_name()


    server_annee=None
    match = re.search(r'\d{4}', ProductName)
    if match:
        server_annee = match.group()


    try:
        DisplayVersion = read_reg_value(r"SOFTWARE\Microsoft\Windows NT\CurrentVersion", "DisplayVersion", winreg.REG_SZ)
    except Exception:
        DisplayVersion = read_reg_value(r"SOFTWARE\Microsoft\Windows NT\CurrentVersion", "ReleaseId", winreg.REG_SZ)

    major_name = None
    if "Windows Server" in ProductName:
        major_name = "MSO"+ server_annee[-2:]
    elif "Windows 10" in ProductName:
        major_name = 10
    elif "Windows 11" in ProductName:
        major_name = 11
    elif "Windows 12" in ProductName:
        major_name = 12
    elif "Windows 13" in ProductName:
        major_name = 13
    else:
        major_name = None
    architecture = read_reg_value(r"System\CurrentControlSet\Control\Session Manager\Environment", "PROCESSOR_ARCHITECTURE", winreg.REG_SZ)
    if architecture == "AMD64":
        archi = "x64"
    else:
        # ARM64, x86 : pas d'ISO de mise a jour majeure disponible dans la base
        logger.warning(f"PL-MEDULLAINFO Architecture non supportee pour mise a jour majeure : {architecture}")
        archi = None
    install_language = read_reg_value(r"SYSTEM\CurrentControlSet\Control\Nls\Language", "InstallLanguage", winreg.REG_SZ)
    if not install_language:
        install_language = read_reg_value(r"SYSTEM\CurrentControlSet\Control\Nls\Language", "Default", winreg.REG_SZ)
    default_lang = read_reg_value(r"SYSTEM\CurrentControlSet\Control\Nls\Language", "Default", winreg.REG_SZ)
    logger.debug(f"PL-MEDULLAINFO Install Language: {install_language} :default lang {default_lang} : language : {correspondence_text.get(install_language, 'Unknown')}")
    create_reg_key(r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Medulla Update Info")
    value_data = r'"C:\Program Files\Python3\python.exe" "C:\Program Files\Medulla\bin\uninstall_pulse2_update_notification.py"'
    write_reg_value(r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Medulla Update Info", "DisplayVersion", "1.0.0", winreg.REG_SZ)
    write_reg_value(r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Medulla Update Info", "Language", int(install_language, 16), winreg.REG_DWORD)
    write_reg_value(r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Medulla Update Info", "Publisher", "Medulla", winreg.REG_SZ)
    write_reg_value(r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Medulla Update Info", "UninstallString", value_data, winreg.REG_SZ)
    write_reg_value(r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Medulla Update Info", "DisplayIcon", r"C:\Program Files\Medulla\bin\install.ico", winreg.REG_SZ)
    write_reg_value(r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Medulla Update Info", "InstallLocation", r"C:\Program Files\Medulla\bin", winreg.REG_SZ)
    write_reg_value(r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Medulla Update Info", "URLInfoAbout", "https://medulla-tech.io", winreg.REG_SZ)
    write_reg_value(r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Medulla Update Info", "NoModify", 1, winreg.REG_DWORD)
    write_reg_value(r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Medulla Update Info", "MajorVersion", "1", winreg.REG_SZ)
    write_reg_value(r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Medulla Update Info", "MinorVersion", "1", winreg.REG_SZ)
    write_reg_value(r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Medulla Update Info", "InstallDate", current_date, winreg.REG_SZ)
    write_reg_value(r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Medulla Update Info", "Readme", "", winreg.REG_SZ)
    # SERVER
    if isinstance(major_name, str) and major_name.startswith("MSO"):
        update = f"{correspondence_text.get(install_language, 'English')}-MSO25"
        iso_name = f"SW_DVD9_Win_Server_STD_CORE_{LATEST_SERVER_ISO}_64Bit_{language_codes.get(install_language, 'English')}"
        # iso_name = "SW_DVD9_Win_Server_STD_CORE_2025_24H2_64Bit_English_DC_STD_MLF_X23-81891"

        if major_name[3:] in ['12', '16', '19', '22', '25']: # les serveur suivant sont mis a jour avec l iso 2025
            update = f"{correspondence_text.get(install_language, 'English')}-MSO25"
            iso_name = f"SW_DVD9_Win_Server_STD_CORE_2025_24H2_64Bit_{language_codes.get(install_language, 'English')}_DC_STD_MLF_X23-81893.ISO"

            iso_name = iso_name.removesuffix('.iso').removesuffix('.ISO')
        if DisplayVersion == "":
            DisplayVersion = major_name
        comments_value = f"{major_name}@{DisplayVersion}@{correspondence_text.get(install_language, 'English')}@{install_language}@{iso_name}@{compatible}@{update}"

    # WINDOWS 10
    elif major_name == 10:
        if DisplayVersion.upper() != LATEST_WIN10:
            # Version marketing	ReleaseId
            # 1507	1507
            # 1511	1511
            # 1607	1607
            # 1703	1703
            # 1709	1709
            # 1803	1803
            # 1809	1809
            # 1903	1903
            # 1909	1909
            # 2004	2004
            # puis adoption
            # Les builds sont 19041, 19042, 19043, 19044, 19045.
            # 21H2	19044
            # 22H2	19045
            if DisplayVersion == "":
                DisplayVersion = "1909"
            if archi:
                iso_name = f"Win10_{LATEST_WIN10}_{language_codes.get(install_language, 'English')}_{archi}"
                update = f"{correspondence_text.get(install_language, 'English')}-10"
        else:
            # Win10 déjà à jour (22H2) → proposer migration vers Win11
            if archi:
                iso_name = f"Win11_{LATEST_WIN11}_{language_codes.get(install_language, 'English')}_{archi}"
                update = f"{correspondence_text.get(install_language, 'English')}-11"

        comments_value = f"{major_name}@{DisplayVersion}@{correspondence_text.get(install_language, 'English')}@{install_language}@{iso_name}@{compatible}@{update}"
    # WINDOWS 11
    elif major_name == 11:
        if archi:
            if DisplayVersion.upper() != LATEST_WIN11:
                update = f"{correspondence_text.get(install_language, 'English')}-11"
                iso_name = f"Win{major_name}_{LATEST_WIN11}_{language_codes.get(install_language, 'English')}_{archi}"
            else:
                iso_name = f"Win11_{LATEST_WIN11}_{language_codes.get(install_language, 'English')}_{archi}"
                update = f"{correspondence_text.get(install_language, 'English')}-11"
        comments_value = f"{major_name}@{DisplayVersion}@{correspondence_text.get(install_language, 'English')}@{install_language}@{iso_name}@{compatible}@{update}"
    else:
        update = ""
        comments_value = f"{major_name}@{DisplayVersion}@{correspondence_text.get(install_language, 'English')}@{install_language}@{iso_name}@{compatible}@{update}"

    medule_info = f"Medulla_{comments_value}"
    write_reg_value(r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Medulla Update Info", "DisplayName", medule_info, winreg.REG_SZ)
    write_reg_value(r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Medulla Update Info", "Comments", f"{comments_value}+{install_language}", winreg.REG_SZ)
    logger.debug("PL-MEDULLAINFO Mise a jour du registre terminee.")

def get_os_product_name():
    """
    Recupere le nom du systeme d'exploitation (ex: "Microsoft Windows 11 Pro")
    en utilisant PowerShell et Get-CimInstance.
    Retourne une chaine de caracteres ou None en cas d'erreur.
    """
    try:
        # Commande PowerShell pour récupérer le nom du système d'exploitation
        command = [
            "powershell",
            "-Command",
            "Get-CimInstance -ClassName Win32_OperatingSystem | Select-Object -ExpandProperty Caption"
        ]

        # Exécute la commande et capture la sortie
        result = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=True
        )

        # Retourne la sortie (en supprimant les espaces et sauts de ligne inutiles)
        return result.stdout.strip()

    except subprocess.CalledProcessError as e:
        print(f"Erreur lors de l'execution de la commande PowerShell : {e.stderr}")
        return None
    except Exception as e:
        print(f"Erreur inattendue : {e}")
        return None


def update_medulla_info_update_notification(xmppobject):
    if sys.platform.startswith("win"):
        # file for download
        listfilename = ["uninstall_medulla_info_update_notification.py", "medulla_info_update.py"]
        script_dir = r"C:\Program Files\Medulla\bin"
        for filename in listfilename:
            pathfilename = os.path.join(script_dir, filename)
            if not os.path.exists(pathfilename):
                txtmsg = ""
                try:
                    dl_url = "%s/downloads/win/%s" % (xmppobject.config.update_server, filename)
                    logger.debug("PL-MEDULLAINFO install %s from %s" % (filename, dl_url))
                    result, txtmsg = utils.downloadfile(dl_url, pathfilename).downloadurl()
                    if result:
                        logger.debug("PL-MEDULLAINFO %s" % txtmsg)
                except Exception as e:
                    # logger.error("\n%s" % (traceback.format_exc()))
                    logger.error(f"{e}")
                    if txtmsg:
                        logger.error("PL-MEDULLAINFO %s" % txtmsg)
            else:
                logger.debug(f"PL-MEDULLAINFO {filename} already exists. Skipping download.")


def delete_subkey(key_path):
    try:
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall", 0, winreg.KEY_ALL_ACCESS)
        winreg.DeleteKey(key, "Medulla Update Info")
        logger.info(f"PL-MEDULLAINFO La sous-cle '{key_path}' a ete supprimee avec succes.")
        return 0
    except FileNotFoundError:
        logger.warning(f"La sous-cle '{key_path}' n existe pas.")
        return 0
    except PermissionError:
        logger.error(f"PL-MEDULLAINFO Vous n avez pas les permissions necessaires pour supprimer la sous-cle '{key_path}'.")
        return -1
    except Exception as e:
        logger.error(f"PL-MEDULLAINFO Une erreur s est produite : {e}")
        return -1

def read_reg_value(key_path, value_name, value_type, defaut_valeur=""):
    try:
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path)
        value, regtype = winreg.QueryValueEx(key, value_name)
        winreg.CloseKey(key)
        if regtype == value_type:
            return value
        else:
            logger.error(f"PL-MEDULLAINFO Erreur : key {key_path} Le type de la valeur {value_name} ne correspond pas a {value_type}.")
            return defaut_valeur
    except Exception as e:
        logger.error(f"PL-MEDULLAINFO Erreur lors de la lecture de la valeur {value_name}: {e}")
        return defaut_valeur

def generate_random_ascii_string(length):
    return ''.join(random.choices(string.printable, k=length))

def write_reg_value(key_path, value_name, value_data, value_type):
    try:
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path, 0, winreg.KEY_SET_VALUE)
        winreg.SetValueEx(key, value_name, 0, value_type, value_data)
        winreg.CloseKey(key)
    except Exception as e:
        logger.error(f"PL-MEDULLAINFO Erreur lors de l ecriture de la valeur {value_name}: {e}")

def create_reg_key(key_path):
    try:
        key = winreg.CreateKey(winreg.HKEY_LOCAL_MACHINE, key_path)
        winreg.CloseKey(key)
    except Exception as e:
        logger.error(f"PL-MEDULLAINFO Erreur lors de la creation de la cle {key_path}: {e}")
