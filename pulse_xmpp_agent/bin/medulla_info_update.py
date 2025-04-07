#!/usr/bin/python3
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
import platform
import winreg
import random
import string
from datetime import datetime
import logging
import logging.handlers

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

def read_reg_value(key_path, value_name, value_type):
    try:
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path)
        value, regtype = winreg.QueryValueEx(key, value_name)
        winreg.CloseKey(key)
        if regtype == value_type:
            return value
        else:
            logger.error(f"Erreur: Le type de la valeur {value_name} ne correspond pas à {value_type}.")
            return None
    except Exception as e:
        logger.error(f"Erreur lors de la lecture de la valeur {value_name}: {e}")
        return None

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
    install_language_fallback = install_language
    default_lang = read_reg_value(r"SYSTEM\CurrentControlSet\Control\Nls\Language", "Default", winreg.REG_SZ)
    logger.info(f"InstallLanguage: {install_language}")
    logger.info(f"InstallLanguageFallback: {install_language_fallback}")
    logger.info(f"Default Language: {default_lang}")
    logger.info(f"Correspondence Text: {correspondence_text.get(install_language, 'Unknown')}")
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
    logger.info("Mise à jour du registre terminée.")

if __name__ == "__main__":
    if platform.system() == "Windows":
        main()
