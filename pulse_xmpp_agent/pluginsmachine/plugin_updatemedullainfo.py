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


plugin = {"VERSION": "1.12", "NAME": "updatemedullainfo", "TYPE": "machine"}  # fmt: skip
LATEST_WIN10 = "22H2"
LATEST_WIN11 = "25H2"
LATEST_SERVER_ISO = "2025_24H2"

class Windows11Compatibility:

    def __init__(self, debug=False):
        self.debug = debug

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
            cmd = [
                "powershell",
                "-Command",
                "(Get-CimInstance -ClassName Win32_ComputerSystem).BootupState"
            ]

            result = subprocess.run(cmd, capture_output=True, text=True)
            output = result.stdout.lower()

            is_uefi = "efi" in output

            if self.debug:
                logger.debug(f"UEFI check: {output.strip()} -> {is_uefi}")

            return is_uefi

        except Exception:
            logger.error("\n%s" % (traceback.format_exc()))
            return False

    def check_tpm(self):
        try:
            cmd = [
                "powershell",
                "-Command",
                "Get-Tpm | ConvertTo-Json"
            ]

            result = subprocess.run(cmd, capture_output=True, text=True)

            if not result.stdout:
                return False

            tpm = json.loads(result.stdout)

            present = tpm.get("TpmPresent", False)
            spec = tpm.get("SpecVersion", "")

            tpm_ok = present and "2.0" in spec

            if self.debug:
                logger.debug(f"TPM check: present={present} spec={spec} -> {tpm_ok}")

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

    def is_compatible(self):
        try:

            checks = [
                self.check_ram(),
                self.check_disk(),
                self.check_uefi(),
                self.check_tpm(),
                self.check_cpu()
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
            migrate_registry_publisher(("SIVEO", "NATSU"), "Medulla")
        except Exception:
            logger.error("migrate_registry_publisher error:\n%s" % (traceback.format_exc()))

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
    ProductName = read_reg_value(r"SOFTWARE\Microsoft\Windows NT\CurrentVersion", "ProductName", winreg.REG_SZ)


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
        comments_value = f"{major_name}@{DisplayVersion}@{correspondence_text.get(install_language, 'English')}@{install_language}@{iso_name}@{compatibleWin11}@{update}"

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
                iso_name = f"Win10_{LATEST_WIN10}_{language_codes.get(install_language, 'English')}_{archi}"
                update = f"{correspondence_text.get(install_language, 'English')}-10"
        else:
            iso_name = f"Win11_{LATEST_WIN11}_{language_codes.get(install_language, 'English')}_{archi}"
            update = f"{correspondence_text.get(install_language, 'English')}-11"

        comments_value = f"{major_name}@{DisplayVersion}@{correspondence_text.get(install_language, 'English')}@{install_language}@{iso_name}@{compatibleWin11}@{update}"
    # WINDOWS 11
    elif major_name == 11:
        if DisplayVersion.upper() != LATEST_WIN11:
            update = f"{correspondence_text.get(install_language, 'English')}-11"
            iso_name = f"Win{major_name}_24H2_{language_codes.get(install_language, 'English')}_{archi}"
        else:
            iso_name = f"Win11_{LATEST_WIN11}_{language_codes.get(install_language, 'English')}_{archi}"
            update = f"{correspondence_text.get(install_language, 'English')}-11"
        comments_value = f"{major_name}@{DisplayVersion}@{correspondence_text.get(install_language, 'English')}@{install_language}@{iso_name}@{compatibleWin11}@{update}"
     and DisplayVersion.upper() != LATEST_WIN11:
        update = f"{correspondence_text.get(install_language, 'English')}-11"
        iso_name = f"Win{major_name}_24H2_{language_codes.get(install_language, 'English')}_{archi}"
        comments_value = f"{major_name}@{DisplayVersion}@{correspondence_text.get(install_language, 'English')}@{install_language}@{iso_name}@{compatibleWin11}@{update}"
    else:
        update = ""
        comments_value = f"{major_name}@{DisplayVersion}@{correspondence_text.get(install_language, 'English')}@{install_language}@{iso_name}@{compatibleWin11}@{update}"

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


def migrate_registry_publisher(old_publishers, new_publisher):
    """
    Migrate the Publisher registry value from any of old_publishers to new_publisher
    in all Uninstall keys.
    old_publishers can be a string or a tuple/list of strings.
    """
    if isinstance(old_publishers, str):
        old_publishers = (old_publishers,)

    uninstall_path = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
    try:
        uninstall_key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, uninstall_path)
    except OSError:
        return

    i = 0
    subkeys = []
    while True:
        try:
            subkeys.append(winreg.EnumKey(uninstall_key, i))
            i += 1
        except OSError:
            break
    winreg.CloseKey(uninstall_key)

    for subkey_name in subkeys:
        key_path = f"{uninstall_path}\\{subkey_name}"
        try:
            key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE, key_path, 0,
                winreg.KEY_READ | winreg.KEY_WRITE
            )
            try:
                publisher, reg_type = winreg.QueryValueEx(key, "Publisher")
                if publisher in old_publishers:
                    winreg.SetValueEx(key, "Publisher", 0, reg_type, new_publisher)
                    logger.info(
                        "PL-MEDULLAINFO Migrated Publisher '%s' -> '%s' in %s"
                        % (publisher, new_publisher, subkey_name)
                    )
            except OSError:
                pass
            finally:
                winreg.CloseKey(key)
        except OSError:
            pass

