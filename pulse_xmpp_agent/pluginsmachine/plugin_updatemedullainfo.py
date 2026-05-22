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
import time

import traceback
from lib.agentconffile import medullaPath
from lib.medulla_windows11_compatibility import (
    Windows11Compatibility as LibWindows11Compatibility,
)
# Importer winreg uniquement si le système d'exploitation est Windows
if sys.platform.startswith("win"):
    import winreg

logger = logging.getLogger()



plugin = {"VERSION": "1.22", "NAME": "updatemedullainfo", "TYPE": "machine"}  # fmt: skip

LATEST_WIN10 = "22H2"
LATEST_WIN11 = "25H2"
LATEST_SERVER_ISO = "2025_24H2"

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


def _generate_windows11_compatibility_report(json_output_file):
    """Genere le rapport JSON de compatibilite via la lib centralisee."""
    os.makedirs(os.path.dirname(json_output_file), exist_ok=True)
    compat = LibWindows11Compatibility(
        output_format="json",
        output_file=json_output_file,
    )
    compat.run()


def _load_or_generate_windows11_compatibility_flag():
    """Retourne compatible (True/False) depuis le cache JSON de compatibilite."""
    json_output_file = os.path.join(
        medullaPath(), "var", "log", "windows11_compatibility_report.json"
    )

    cache_ttl_seconds = 24 * 60 * 60

    if not os.path.exists(json_output_file):
        _generate_windows11_compatibility_report(json_output_file)
    else:
        age_seconds = time.time() - os.path.getmtime(json_output_file)
        if age_seconds > cache_ttl_seconds:
            logger.debug(
                "PL-MEDULLAINFO Rapport JSON de compatibilite expire (age=%ss), regeneration: %s",
                int(age_seconds),
                json_output_file,
            )
            _generate_windows11_compatibility_report(json_output_file)

    try:
        with open(json_output_file, "r", encoding="utf-8") as handle:
            report = json.load(handle)
    except Exception:
        logger.warning(
            "PL-MEDULLAINFO Rapport JSON de compatibilite illisible, regeneration: %s",
            json_output_file,
        )
        _generate_windows11_compatibility_report(json_output_file)
        with open(json_output_file, "r", encoding="utf-8") as handle:
            report = json.load(handle)

    # compatble_win11 peut etre force a True dans la lib pour un mode failsafe.
    # On privilegie raw_compatible pour refleter la compatibilite reelle.
    compatible_value = report.get("raw_compatible", report.get("compatble_win11", False))
    if isinstance(compatible_value, bool):
        return compatible_value
    if isinstance(compatible_value, (int, float)):
        return bool(compatible_value)
    if isinstance(compatible_value, str):
        return compatible_value.strip().lower() in {"1", "true", "yes", "on"}
    return False


def execute_medulla_info_update():
    compatible = _load_or_generate_windows11_compatibility_flag()
    # compatibleWin11 = bool(compatible) # True ou False
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
            try:
                iso_name = f"Win10_{LATEST_WIN10}_{language_codes.get(install_language, 'English')}_{archi}"
                update = f"{correspondence_text.get(install_language, 'English')}-10"
            except Exception:
                logger.warning("PL-MEDULLAINFO Win10 : impossible de construire iso_name (archi=%s)" % archi)
        else:
            try:
                iso_name = f"Win11_{LATEST_WIN11}_{language_codes.get(install_language, 'English')}_{archi}"
                update = f"{correspondence_text.get(install_language, 'English')}-11"
            except Exception:
                logger.warning("PL-MEDULLAINFO Win10->Win11 : impossible de construire iso_name (archi=%s)" % archi)

        comments_value = f"{major_name}@{DisplayVersion}@{correspondence_text.get(install_language, 'English')}@{install_language}@{iso_name}@{compatible}@{update}"
    # WINDOWS 11
    elif major_name == 11:
        try:
            if DisplayVersion.upper() != LATEST_WIN11:
                update = f"{correspondence_text.get(install_language, 'English')}-11"
                iso_name = f"Win{major_name}_{LATEST_WIN11}_{language_codes.get(install_language, 'English')}_{archi}"
            else:
                iso_name = f"Win11_{LATEST_WIN11}_{language_codes.get(install_language, 'English')}_{archi}"
                update = f"{correspondence_text.get(install_language, 'English')}-11"
        except Exception:
            logger.warning("PL-MEDULLAINFO Win11 : impossible de construire iso_name (archi=%s)" % archi)
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
                try:
                    dl_url = "%s/downloads/win/%s" % (xmppobject.config.update_server, filename)
                    logger.debug("PL-MEDULLAINFO install %s from %s" % (filename, dl_url))
                    result, txtmsg = utils.downloadfile(dl_url, pathfilename).downloadurl()
                    if result:
                        logger.debug("PL-MEDULLAINFO %s" % txtmsg)
                except Exception as e:
                    # logger.error("\n%s" % (traceback.format_exc()))
                    logger.error(f"{e}")
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
