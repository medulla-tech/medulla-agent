# SPDX-FileCopyrightText: 2020-2024 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-3.0-or-later

import sys
import os
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

import traceback
# Importer winreg uniquement si le système d'exploitation est Windows
if sys.platform.startswith("win"):
    import winreg

logger = logging.getLogger()


plugin = {"VERSION": "1.9", "NAME": "updatemedullainfo", "TYPE": "machine"}  # fmt: skip


class Compatibilite:
    def __init__(self, debug=False):
        """
        Initialize the Compatibilite class with an optional debug parameter.

        Parameters:
            debug (bool): If True, print debug information. Default is False.
        """
        self.debug = debug

    def is_uefi(self):
        """
        Check if the system is using UEFI.

        Returns:
            bool: True if UEFI is detected, False otherwise.
        """
        try:
            result = os.path.exists(r"C:\Windows\System32\efi")
            if self.debug:
                print(f"UEFI Check: {result}")
            return result
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
        pattern = '|'.join(map(re.escape, [",", ";", ":", "|", " "]))
        try:
            result = subprocess.run(
                ['powershell', 'Get-WmiObject -Namespace "root\\cimv2\\security\\microsofttpm" -Class Win32_Tpm | Select-Object SpecVersion'],
                capture_output=True,
                text=True,
                check=True
            )
            result=[x for x in result.stdout.splitlines() if x !=""]

            tpm_2_detected = False
            for line in result:
                # Extract the version number from the line
                version = re.split(pattern, line)
                if version:
                    # version = line.split()[-1].strip()
                    try:
                        if float(version[0]) >= 2.0:
                            tpm_2_detected = True
                            break
                    except ValueError:
                        # Handle cases where conversion to float fails
                        continue
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

    def system_meets_requirements(self):
        """
        Check if the system meets all the specified requirements.

        Returns:
            bool: True if all requirements are met, False otherwise.
        """
        result = (
            self.is_disk_c_ge_80gb() and
            self.has_more_than_4gb_ram() and
            self.has_tpm_2() and
            self.is_uefi()
        )
        if self.debug:
            print(f"System Meets Requirements: {result}")
        return result
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
    "0809": "English",
    "0409": "English",
    "040A": "Spanish",
    "080A": "Spanish_Mexico",
    "0425": "Estonian",
    "040E": "Finnish",
    "0C0C": "FrenchCanadian",
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
    "0416": "Portuguese",
    "0419": "Russian",
    "041D": "Swedish",
    "041E": "Thai",
    "041F": "Turkish",
    "0422": "Ukrainian",
    "7C04": "Chinese_Traditional",
    "0804": "Chinese_Simplified"
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
    "040E": "fi-FI",
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
    "0416": "pt-PT",
    "0419": "ru-RU",
    "041D": "sv-SE",
    "041E": "th-TH",
    "041F": "tr-TR",
    "0422": "uk-UA",
    "7C04": "zh-CHT",
    "0804": "zh-CN"
}

@utils.set_logging_level
def action(xmppobject, action, sessionid, data, message, dataerreur):
    logger.debug("PL-MEDULLAINFO ###################################################")
    logger.debug("PL-MEDULLAINFO call %s from %s" % (plugin, message["from"]))
    logger.debug("PL-MEDULLAINFO ###################################################")
    try:
        if sys.platform.startswith("win"):
            update_medulla_info_update_notification(xmppobject)
            execute_medulla_info_update()
    except Exception:
        logger.error("\n%s" % (traceback.format_exc()))


def execute_medulla_info_update():
    compatibilite = Compatibilite(debug=False)
    compatiblew11=compatibilite.system_meets_requirements()
    compatibleWin11=1

    key_path = r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Medulla Update Info"
    delete_subkey(key_path)
    current_date = datetime.now().strftime("%Y%m%d")
    ProductName = read_reg_value(r"SOFTWARE\Microsoft\Windows NT\CurrentVersion", "ProductName", winreg.REG_SZ)


    server_annee=None
    match = re.search(r'\d{4}', ProductName)
    if match:
        server_annee = match.group()


    try:
        DisplayVersion = read_reg_value(r"SOFTWARE\Microsoft\Windows NT\CurrentVersion", "DisplayVersion", winreg.REG_SZ)
    except Exception:
        DisplayVersion = read_reg_value(r"SOFTWARE\Microsoft\Windows NT\CurrentVersion", "ReleaseId", winreg.REG_SZ)

    if "Windows Server" in ProductName:
        major_name = "MSO"+ server_annee[-2:]
    elif "Windows 10" in ProductName:
        major_name = 10
        compatibleWin11 = compatiblew11
    elif "Windows 11" in ProductName:
        major_name = 11
    elif "Windows 12" in ProductName:
        major_name = 12
    elif "Windows 12" in ProductName:
        major_name = 13
    architecture = read_reg_value(r"System\CurrentControlSet\Control\Session Manager\Environment", "PROCESSOR_ARCHITECTURE", winreg.REG_SZ)
    if architecture == "AMD64":
        archi = "x64"
    install_language = read_reg_value(r"SYSTEM\CurrentControlSet\Control\Nls\Language", "InstallLanguage", winreg.REG_SZ)
    install_language_fallback = read_reg_value(r"SYSTEM\CurrentControlSet\Control\Nls\Language", "InstallLanguage", winreg.REG_SZ)
    default_lang = read_reg_value(r"SYSTEM\CurrentControlSet\Control\Nls\Language", "Default", winreg.REG_SZ)
    logger.debug(f"PL-MEDULLAINFO Install Language: {install_language} :default lang {default_lang} : language : {correspondence_text.get(install_language, 'Unknown')}")
    create_reg_key(r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Medulla Update Info")
    value_data = r'"C:\Program Files\Python3\python.exe" "C:\Program Files\Medulla\bin\uninstall_pulse2_update_notification.py"'
    write_reg_value(r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Medulla Update Info", "DisplayVersion", "1.0.0", winreg.REG_SZ)
    write_reg_value(r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Medulla Update Info", "Language", int(install_language, 16), winreg.REG_DWORD)
    write_reg_value(r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Medulla Update Info", "Publisher", "SIVEO", winreg.REG_SZ)
    write_reg_value(r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Medulla Update Info", "UninstallString", value_data, winreg.REG_SZ)
    write_reg_value(r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Medulla Update Info", "DisplayIcon", r"C:\Program Files\Medulla\bin\install.ico", winreg.REG_SZ)
    write_reg_value(r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Medulla Update Info", "InstallLocation", r"C:\Program Files\Medulla\bin", winreg.REG_SZ)
    write_reg_value(r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Medulla Update Info", "URLInfoAbout", "http://www.siveo.net", winreg.REG_SZ)
    write_reg_value(r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Medulla Update Info", "NoModify", 1, winreg.REG_DWORD)
    write_reg_value(r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Medulla Update Info", "MajorVersion", "1", winreg.REG_SZ)
    write_reg_value(r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Medulla Update Info", "MinorVersion", "1", winreg.REG_SZ)
    write_reg_value(r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Medulla Update Info", "InstallDate", current_date, winreg.REG_SZ)
    write_reg_value(r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Medulla Update Info", "Readme", "", winreg.REG_SZ)

    if isinstance(major_name, str) and major_name.startswith("MSO"):
        update = f"{correspondence_text.get(install_language, 'Unknown')}-10"
        iso_name = f"{major_name}_24H2_{language_codes.get(install_language, 'Unknown')}_{archi}"
        comments_value = f"{major_name}@{DisplayVersion}@{correspondence_text.get(install_language, 'Unknown')}@{install_language}@{iso_name}@{compatibleWin11}@{update}"
    elif major_name == 10 and DisplayVersion.upper() != "22H2":
        if DisplayVersion == "":
            DisplayVersion = "1906"
        update = f"{correspondence_text.get(install_language, 'Unknown')}-10"
        iso_name = f"Win{major_name}_22H2_{language_codes.get(install_language, 'Unknown')}_{archi}"
        comments_value = f"{major_name}@{DisplayVersion}@{correspondence_text.get(install_language, 'Unknown')}@{install_language}@{iso_name}@{compatibleWin11}@{update}"
    elif major_name == 10 and DisplayVersion.upper() == "22H2":
        update = f"{correspondence_text.get(install_language, 'Unknown')}-11"
        iso_name = f"Win{major_name+1}_24H2_{language_codes.get(install_language, 'Unknown')}_{archi}"
        comments_value = f"{major_name}@{DisplayVersion}@{correspondence_text.get(install_language, 'Unknown')}@{install_language}@{iso_name}@{compatibleWin11}@{update}"
    elif major_name == 11 and DisplayVersion.upper() != "24H2":
        update = f"{correspondence_text.get(install_language, 'Unknown')}-11"
        iso_name = f"Win{major_name}_24H2_{language_codes.get(install_language, 'Unknown')}_{archi}"
        comments_value = f"{major_name}@{DisplayVersion}@{correspondence_text.get(install_language, 'Unknown')}@{install_language}@{iso_name}@{compatibleWin11}@{update}"
    else:
        update = ""
        comments_value = f"{major_name}@{DisplayVersion}@{correspondence_text.get(install_language, 'Unknown')}@{install_language}@{iso_name}@{compatibleWin11}@{update}"

    medule_info = f"Medulla_{comments_value}"
    write_reg_value(r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Medulla Update Info", "DisplayName", medule_info, winreg.REG_SZ)
    write_reg_value(r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Medulla Update Info", "Comments", f"{comments_value}+{install_language_fallback}", winreg.REG_SZ)
    logger.debug("PL-MEDULLAINFO Mise a jour du registre terminee.")

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
        logger.debug(f"PL-MEDULLAINFO Erreur : regtype {regtype} value_type {value_type} ")
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

