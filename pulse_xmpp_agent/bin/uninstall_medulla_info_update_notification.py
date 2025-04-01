import winreg

def delete_subkey(key_path):
    try:
        # Ouvrir la clé de registre principale
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall", 0, winreg.KEY_ALL_ACCESS)

        # Supprimer la sous-clé spécifiée
        winreg.DeleteKey(key, "Medulla Update Info")
        print(f"La sous-clé '{key_path}' a été supprimée avec succès.")

    except FileNotFoundError:
        print(f"La sous-clé '{key_path}' n'existe pas.")
    except PermissionError:
        print(f"Vous n'avez pas les permissions nécessaires pour supprimer la sous-clé '{key_path}'.")
    except Exception as e:
        print(f"Une erreur s'est produite : {e}")

if __name__ == "__main__":
    key_path = r"HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Medulla Update Info"
    delete_subkey(key_path)
