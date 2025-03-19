#!/usr/bin/python3
# -*- coding: utf-8; -*-
# SPDX-FileCopyrightText: 2016-2023 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-3.0-or-later

import winreg


def delete_subkey(key_path):
    """
    Supprime une sous-clé spécifiée dans le registre Windows.

    Args:
        key_path (str): Le chemin de la sous-clé à supprimer.

    Raises:
        FileNotFoundError: Si la sous-clé n'existe pas.
        PermissionError: Si les permissions nécessaires ne sont pas disponibles.
        Exception: Pour toute autre erreur inattendue.
    """
    try:
        # Ouvrir la clé de registre principale
        key = winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall",
            0,
            winreg.KEY_ALL_ACCESS,
        )

        # Supprimer la sous-clé spécifiée
        winreg.DeleteKey(key, "Medulla Update Info")
        print(f"La sous-clé '{key_path}' a été supprimée avec succès.")

    except FileNotFoundError:
        # Gérer le cas où la sous-clé n'existe pas
        print(f"La sous-clé '{key_path}' n'existe pas.")
    except PermissionError:
        # Gérer le cas où les permissions sont insuffisantes
        print(
            f"Vous n'avez pas les permissions nécessaires pour supprimer la sous-clé '{key_path}'."
        )
    except Exception as e:
        # Gérer toute autre erreur inattendue
        print(f"Une erreur s'est produite : {e}")


if __name__ == "__main__":
    # Définir le chemin de la sous-clé à supprimer
    key_path = r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Medulla Update Info"
    # Appeler la fonction pour supprimer la sous-clé
    delete_subkey(key_path)
