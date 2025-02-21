#!/usr/bin/python3
# -*- coding: utf-8; -*-
# SPDX-FileCopyrightText: 2016-2023 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-3.0-or-later

# Ce programme installe un programme pour permettre une remontée d'informations dans GLPI.
# Il ajoute dans les commentaires de Medulla Update les informations nécessaires manquantes dans GLPI.

import platform
import winreg
import random
import string
from datetime import datetime

# Référence pour les informations utilisées
# https://learn.microsoft.com/fr-fr/windows/win32/msi/msiarpsettingsidentifier

# Tableau de correspondance entre les codes Windows et les langues
language_codes = {
    "0409": "English",
    "040C": "French",
    "040A": "Spanish",
    "0407": "German",
    "0410": "Italian",
    "0413": "Dutch",
    "0416": "Portuguese",
    "0419": "Russian",
    "0804": "Chinese_Simplified",
    "0404": "Chinese_Traditional",
    "0411": "Japanese",
    "0412": "Korean",
    "0401": "Arabic",
    "040D": "Hebrew",
    "0439": "Hindi",
    "0415": "Polish",
    "041F": "Turkish",
    "041D": "Swedish",
    "0406": "Danish",
    "040E": "Finnish",
    "0414": "Norwegian",
    "0405": "Czech",
    "040E": "Hungarian",
    "0408": "Greek",
    "041E": "Thai"
}

# Tableau de correspondance entre les codes Windows et les textes de correspondance
correspondence_text = {
    "0409": "en-US",
    "040C": "fr-FR",
    "040A": "es-ES",
    "0407": "de-DE",
    "0410": "it-IT",
    "0413": "nl-NL",
    "0416": "pt-PT",
    "0419": "ru-RU",
    "0804": "zh-CN",
    "0404": "zh-TW",
    "0411": "ja-JP",
    "0412": "ko-KR",
    "0401": "ar-SA",
    "040D": "he-IL",
    "0439": "hi-IN",
    "0415": "pl-PL",
    "041F": "tr-TR",
    "041D": "sv-SE",
    "0406": "da-DK",
    "040E": "fi-FI",
    "0414": "nb-NO",
    "0405": "cs-CZ",
    "040E": "hu-HU",
    "0408": "el-GR",
    "041E": "th-TH"
}

def delete_subkey(key_path):
    """
    Supprime une sous-clé spécifiée dans le registre Windows.

    Args:
        key_path (str): Le chemin de la sous-clé à supprimer.

    Returns:
        int: 0 si la suppression est réussie ou si la clé n'existe pas, -1 en cas d'erreur.
    """
    try:
        # Ouvrir la clé de registre principale
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall", 0, winreg.KEY_ALL_ACCESS)

        # Supprimer la sous-clé spécifiée
        winreg.DeleteKey(key, "Medulla Update Info")
        return 0
    except FileNotFoundError:
        # La sous-clé n'existe pas
        return 0
    except PermissionError:
        print(f"Vous n'avez pas les permissions nécessaires pour supprimer la sous-clé '{key_path}'.")
        return -1
    except Exception as e:
        print(f"Une erreur s'est produite : {e}")
        return -1

def read_reg_value(key_path, value_name, value_type):
    """
    Lit une valeur dans le registre Windows.

    Args:
        key_path (str): Le chemin de la clé.
        value_name (str): Le nom de la valeur à lire.
        value_type (int): Le type attendu de la valeur.

    Returns:
        any: La valeur lue ou None en cas d'erreur.
    """
    try:
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path)
        value, regtype = winreg.QueryValueEx(key, value_name)
        winreg.CloseKey(key)
        if regtype == value_type:
            return value
        else:
            print(f"Erreur: Le type de la valeur {value_name} ne correspond pas à {value_type}.")
            return None
    except Exception as e:
        print(f"Erreur lors de la lecture de la valeur {value_name}: {e}")
        return None

def generate_random_ascii_string(length):
    """
    Génère une chaîne de caractères ASCII aléatoires.

    Args:
        length (int): La longueur de la chaîne à générer.

    Returns:
        str: La chaîne générée.
    """
    return ''.join(random.choices(string.printable, k=length))

def write_reg_value(key_path, value_name, value_data, value_type):
    """
    Écrit une valeur dans le registre Windows.

    Args:
        key_path (str): Le chemin de la clé.
        value_name (str): Le nom de la valeur à écrire.
        value_data (any): Les données à écrire.
        value_type (int): Le type de la valeur.
    """
    try:
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path, 0, winreg.KEY_SET_VALUE)
        winreg.SetValueEx(key, value_name, 0, value_type, value_data)
        winreg.CloseKey(key)
    except Exception as e:
        print(f"Erreur lors de l'écriture de la valeur {value_name}: {e}")

def create_reg_key(key_path):
    """
    Crée une clé dans le registre Windows si elle n'existe pas.

    Args:
        key_path (str): Le chemin de la clé à créer.
    """
    try:
        key = winreg.CreateKey(winreg.HKEY_LOCAL_MACHINE, key_path)
        winreg.CloseKey(key)
    except Exception as e:
        print(f"Erreur lors de la création de la clé {key_path}: {e}")

def main():
    """
    Fonction principale pour installer le programme et mettre à jour les informations dans le registre.
    """
    # Désinstalle le programme pour le réinstaller
    key_path = r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Medulla Update Info"
    delete_subkey(key_path)

    # Obtenir la date actuelle au format YYYYMMDD
    current_date = datetime.now().strftime("%Y%m%d")

    # Lire les valeurs du registre
    ProductName = read_reg_value(r"SOFTWARE\Microsoft\Windows NT\CurrentVersion", "ProductName", winreg.REG_SZ)
    DisplayVersion = read_reg_value(r"SOFTWARE\Microsoft\Windows NT\CurrentVersion", "DisplayVersion", winreg.REG_SZ)

    # Déterminer la version majeure de Windows
    if "Windows 10" in ProductName:
        major_name = 10
    elif "Windows 11" in ProductName:
        major_name = 11
    elif "Windows 12" in ProductName:
        major_name = 12
    elif "Windows 13" in ProductName:
        major_name = 13

    # Déterminer l'architecture du système
    architecture = read_reg_value(r"System\CurrentControlSet\Control\Session Manager\Environment", "PROCESSOR_ARCHITECTURE", winreg.REG_SZ)
    archi = "x64" if architecture == "AMD64" else "x86"

    # Récupérer les informations de langue
    install_language = read_reg_value(r"SYSTEM\CurrentControlSet\Control\Nls\Language", "InstallLanguage", winreg.REG_SZ)
    install_language_fallback = read_reg_value(r"SYSTEM\CurrentControlSet\Control\Nls\Language", "InstallLanguageFallback", winreg.REG_MULTI_SZ)
    default_lang = read_reg_value(r"SYSTEM\CurrentControlSet\Control\Nls\Language", "Default", winreg.REG_SZ)

    # Déterminer le nom de l'ISO
    iso_name = f"Win{major_name}_24H2_{language_codes.get(install_language, 'Unknown')}_{archi}"

    # Créer la clé "Medulla Update Info" si elle n'existe pas
    create_reg_key(r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Medulla Update Info")

    # Mettre à jour les valeurs dans le registre
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

    # Concaténer les valeurs pour la clé "Comments"
    comments_value = f"{major_name}@{DisplayVersion}@{correspondence_text.get(install_language, 'Unknown')}@{install_language}@{iso_name}"
    medule_info = f"Medulla_{comments_value}"

    # Écrire les valeurs finales dans le registre
    write_reg_value(r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Medulla Update Info", "DisplayName", medule_info, winreg.REG_SZ)
    write_reg_value(r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Medulla Update Info", "Comments", f"{comments_value}+{install_language_fallback[0]}", winreg.REG_SZ)

if __name__ == "__main__":
    if platform.system() == "Windows":
        main()
