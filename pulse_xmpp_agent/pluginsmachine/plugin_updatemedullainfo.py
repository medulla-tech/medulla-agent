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
import traceback
# Importer winreg uniquement si le système d'exploitation est Windows
if sys.platform.startswith("win"):
    import winreg

logger = logging.getLogger()

plugin = {"VERSION": "1.2", "NAME": "updatemedulainfo", "TYPE": "machine"}  # fmt: skip


# Tableau de correspondance entre les codes Windows et les langues
language_codes = {
    "0401": "Arabic",
    "0402": "Bulgarian",
    "0405": "Czech",
    "0406": "Danish",
    "0407": "German",
    "0408": "Greek",
    "0809": "English",
    "0409": "EnglishInternational",
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
        update_medulla_info_update_notification(xmppobject)
        execute_medulla_info_update()
    except Exception:
        logger.error("\n%s" % (traceback.format_exc()))


def execute_medulla_info_update():
    key_path = r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Medulla Update Info"
    delete_subkey(key_path)
    current_date = datetime.now().strftime("%Y%m%d")
    ProductName = read_reg_value(r"SOFTWARE\Microsoft\Windows NT\CurrentVersion", "ProductName", winreg.REG_SZ)
    DisplayVersion = read_reg_value(r"SOFTWARE\Microsoft\Windows NT\CurrentVersion", "DisplayVersion", winreg.REG_SZ)
    if "Windows 10" in ProductName:
        major_name = 10
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

    if major_name == 10 and DisplayVersion.upper() != "22H2":
        update = f"{correspondence_text.get(install_language, 'Unknown')}-10"
        iso_name = f"Win{major_name}_22H2_{language_codes.get(install_language, 'Unknown')}_{archi}"
        comments_value = f"{major_name}@{DisplayVersion}@{correspondence_text.get(install_language, 'Unknown')}@{install_language}@{iso_name}@{update}"
    elif major_name == 10 and DisplayVersion.upper() == "22H2":
        update = f"{correspondence_text.get(install_language, 'Unknown')}-11"
        iso_name = f"Win{major_name+1}_24H2_{language_codes.get(install_language, 'Unknown')}_{archi}"
        comments_value = f"{major_name}@{DisplayVersion}@{correspondence_text.get(install_language, 'Unknown')}@{install_language}@{iso_name}@{update}"
    elif major_name == 11 and DisplayVersion.upper() != "24H2":
        update = f"{correspondence_text.get(install_language, 'Unknown')}-11"
        iso_name = f"Win{major_name}_24H2_{language_codes.get(install_language, 'Unknown')}_{archi}"
        comments_value = f"{major_name}@{DisplayVersion}@{correspondence_text.get(install_language, 'Unknown')}@{install_language}@{iso_name}@{update}"
    else:
        update = ""
        comments_value = f"{major_name}@{DisplayVersion}@{correspondence_text.get(install_language, 'Unknown')}@{install_language}@{iso_name}@{update}"

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
                    dl_url = "http://%s/downloads/%s" % (xmppobject.config.Server, filename)
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

def read_reg_value(key_path, value_name, value_type):
    try:
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path)
        value, regtype = winreg.QueryValueEx(key, value_name)
        logger.debug(f"PL-MEDULLAINFO Erreur : regtype {regtype} value_type {value_type} ")
        winreg.CloseKey(key)
        if regtype == value_type:
            return value
        else:
            logger.error(f"PL-MEDULLAINFO Erreur : key {key_path} Le type de la valeur {value_name} ne correspond pas a {value_type}.")
            return None
    except Exception as e:
        logger.error(f"PL-MEDULLAINFO Erreur lors de la lecture de la valeur {value_name}: {e}")
        return None

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

