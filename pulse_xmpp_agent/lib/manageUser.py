# -*- coding: utf-8; -*-
# SPDX-FileCopyrightText: 2016-2023 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-3.0-or-later

import subprocess
import shlex
import re
import platform
import os
import sys



class ManageUser:
    def __init__(self):
        self.os_type = platform.system().lower()
        self._controle_durete_mot_de_passe = True
        self._original_windows_password_policy = None

    @property
    def controle_durete_mot_de_passe(self):
        """Propriété pour obtenir l'état du contrôle de dureté du mot de passe."""
        return self._controle_durete_mot_de_passe

    @controle_durete_mot_de_passe.setter
    def controle_durete_mot_de_passe(self, valeur):
        """Propriété pour activer ou désactiver le contrôle de dureté du mot de passe."""
        self._controle_durete_mot_de_passe = bool(valeur)

    def _run_cmd(self, command):
        """Exécute une commande shell et retourne le code de retour, stdout et stderr."""
        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        stdout, stderr = process.communicate()
        return process.returncode, stdout, stderr

    def _run_cmd_shell(self, command):
        """Exécute une commande shell avec bash."""
        return self._run_cmd(["bash", "-c", command])

    def is_password_strong(self, password):
        """Vérifie si un mot de passe respecte les critères de complexité."""
        errors = []
        if len(password) < 8:
            errors.append("Le mot de passe doit contenir au moins 8 caractères.")
        if not re.search(r'[A-Z]', password):
            errors.append("Le mot de passe doit contenir au moins une majuscule.")
        if not re.search(r'[a-z]', password):
            errors.append("Le mot de passe doit contenir au moins une minuscule.")
        if not re.search(r'[0-9]', password):
            errors.append("Le mot de passe doit contenir au moins un chiffre.")
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            errors.append("Le mot de passe doit contenir au moins un caractère spécial.")
        if ' ' in password:
            errors.append("Le mot de passe ne doit pas contenir d'espaces.")
        return (True, "Le mot de passe est robuste.") if not errors else (False, "\n".join(errors))

    def _get_windows_password_policy(self):
        """Récupère la politique actuelle de mot de passe sous Windows."""
        try:
            result = subprocess.run(
                ["net", "accounts"],
                capture_output=True,
                text=True,
                check=True
            )
            output = result.stdout
            policy = {
                "minpwlen": "0",
                "minpwage": "0",
                "maxpwage": "unlimited",
                "uniquepw": "0"
            }
            for line in output.splitlines():
                if "Longueur minimale du mot de passe" in line:
                    policy["minpwlen"] = line.split(":")[-1].strip()
                elif "Durée minimale du mot de passe" in line:
                    policy["minpwage"] = line.split(":")[-1].strip()
                elif "Durée maximale du mot de passe" in line:
                    policy["maxpwage"] = line.split(":")[-1].strip()
                elif "Mots de passe uniques à conserver" in line:
                    policy["uniquepw"] = line.split(":")[-1].strip()
            return policy
        except subprocess.CalledProcessError as e:
            return {"error": f"Erreur lors de la récupération de la politique : {e.stderr}"}

    def _set_windows_password_policy(self, minpwlen, minpwage, maxpwage, uniquepw):
        """Définit la politique de mot de passe sous Windows."""
        try:
            subprocess.run(
                ["net", "accounts", f"/minpwlen:{minpwlen}", f"/minpwage:{minpwage}", f"/maxpwage:{maxpwage}", f"/uniquepw:{uniquepw}"],
                check=True,
                capture_output=True,
                text=True
            )
            return True, "Politique de mot de passe modifiée avec succès."
        except subprocess.CalledProcessError as e:
            return False, f"Erreur lors de la modification de la politique : {e.stderr}"

    def set_windows_password_policy(self, enable):
        """
        Active ou désactive la politique de complexité des mots de passe sous Windows.
        """
        if enable:
            return self._set_windows_password_policy("8", "1", "42", "5")
        else:
            return self._set_windows_password_policy("0", "0", "unlimited", "0")

    def create_user(self, username, password, set_windows_policy=True):
        """
        Crée un utilisateur sur le système.
        Retourne un dictionnaire avec les clés "success", "stdout", "stderr".
        """
        if self.controle_durete_mot_de_passe:
            is_strong, message = self.is_password_strong(password)
            if not is_strong:
                return {"success": False, "stdout": "", "stderr": message}

        if self.os_type == "windows" and set_windows_policy:
            # Sauvegarder la politique actuelle
            original_policy = self._get_windows_password_policy()
            if "error" in original_policy:
                return {"success": False, "stdout": "", "stderr": original_policy["error"]}

            # Appliquer la politique souhaitée pour la création
            success, message = self.set_windows_password_policy(True)
            if not success:
                return {"success": False, "stdout": "", "stderr": message}

            # Créer l'utilisateur
            result = self._manage_windows_user("create_user", username, password)

            # Restaurer la politique originale
            self._set_windows_password_policy(
                original_policy["minpwlen"],
                original_policy["minpwage"],
                original_policy["maxpwage"],
                original_policy["uniquepw"]
            )

            return result

        if self.os_type == "windows":
            return self._manage_windows_user("create_user", username, password)
        elif self.os_type == "linux":
            return self._manage_linux_user("create_account", username, password)
        elif self.os_type == "darwin":
            return self._manage_macos_user("create_account", username, password)
        else:
            return {"success": False, "stdout": "", "stderr": "Système non supporté."}

    def _manage_windows_user(self, action, username, password=None):
        """
        Gère un utilisateur Windows : création, suppression, création/suppression de profil.
        Args:
            action (str): L'action à effectuer. Doit être l'une des suivantes :
                - "create_user" : Crée un utilisateur.
                - "delete_user" : Supprime un utilisateur.
                - "create_profile" : Crée un profil utilisateur.
                - "delete_profile" : Supprime un profil utilisateur.
            username (str): Nom de l'utilisateur.
            password (str, optionnel) : Mot de passe de l'utilisateur. Requis pour "create_user" et "create_profile".
        Returns:
            dict: Un dictionnaire avec les clés "success", "stdout", "stderr".
        """
        ps_commands = {
            "create_user": f'net user "{username}" "{password}" /add',
            "delete_user": f'net user "{username}" /delete',
            "create_profile": (
                f'powershell -Command "$cred = New-Object System.Management.Automation.PSCredential(\'{username}\', (ConvertTo-SecureString \'{password}\' -AsPlainText -Force)); '
                f'Start-Process cmd.exe -Credential $cred -NoNewWindow -ArgumentList \'/c echo Profil utilisateur créé avec succès\' -Wait"'
            ),
            "delete_profile": (
                f'powershell -NoProfile -ExecutionPolicy Bypass -Command '
                f'"Get-CimInstance -ClassName Win32_UserProfile '
                f'| Where-Object {{ $_.LocalPath -like \'*\\\\{username}\' }} '
                f'| Remove-CimInstance"'
)
        }

        # Vérifie que l'action est valide
        if action not in ps_commands:
            return {"success": False, "stdout": "", "stderr": f"Action inconnue ou non supportée : {action}"}

        # Vérifie que le mot de passe est fourni si nécessaire
        if action in ["create_user", "create_profile"] and not password:
            return {"success": False, "stdout": "", "stderr": f"Le mot de passe est requis pour l'action : {action}"}

        command = ps_commands[action]
        print(command)
        try:
            process = subprocess.run(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                shell=True,
                encoding='utf-8',
                errors='replace'
            )
            return {
                "success": process.returncode == 0,
                "stdout": process.stdout.strip(),
                "stderr": process.stderr.strip()
            }
        except Exception as e:
            return {
                "success": False,
                "stdout": "",
                "stderr": f"Erreur lors de l'exécution de la commande : {str(e)}"
            }


    def _manage_linux_user(self, action, username, password=None):
        """Gère un utilisateur Linux."""
        if action == "create_account":
            cmd = ["sudo", "useradd", "-m", "-s", "/bin/bash", username]
            ret, out, err = self._run_cmd(cmd)
            if ret == 0 and password:
                pass_cmd = f"echo '{username}:{password}' | sudo chpasswd"
                ret2, out2, err2 = self._run_cmd_shell(pass_cmd)
                err += err2
                out += out2
            return {"success": ret == 0, "stdout": out, "stderr": err}
        elif action == "delete_account":
            cmd = ["sudo", "userdel", "-r", username]
            ret, out, err = self._run_cmd(cmd)
            return {"success": ret == 0, "stdout": out, "stderr": err}
        elif action == "delete_profile":
            cmd = ["sudo", "rm", "-rf", f"/home/{username}"]
            ret, out, err = self._run_cmd(cmd)
            return {"success": ret == 0, "stdout": out, "stderr": err}
        return {"success": False, "stdout": "", "stderr": "Action inconnue."}

    def _manage_macos_user(self, action, username, password=None):
        """Gère un utilisateur macOS."""
        home = f"/Users/{username}"
        if action == "create_account":
            cmds = [
                ["sudo", "dscl", ".", "-create", f"/Users/{username}"],
                ["sudo", "dscl", ".", "-create", f"/Users/{username}", "UserShell", "/bin/bash"],
                ["sudo", "dscl", ".", "-create", f"/Users/{username}", "RealName", username],
                ["sudo", "dscl", ".", "-create", f"/Users/{username}", "UniqueID", "510"],
                ["sudo", "dscl", ".", "-create", f"/Users/{username}", "PrimaryGroupID", "20"],
                ["sudo", "dscl", ".", "-create", f"/Users/{username}", "NFSHomeDirectory", home]
            ]
            out_all, err_all = "", ""
            for cmd in cmds:
                ret, out, err = self._run_cmd(cmd)
                out_all += out
                err_all += err
                if ret != 0:
                    return {"success": False, "stdout": out_all, "stderr": err_all}
            if password:
                ret, out, err = self._run_cmd(["sudo", "dscl", ".", "-passwd", f"/Users/{username}", password])
                out_all += out
                err_all += err
            return {"success": True, "stdout": out_all, "stderr": err_all}
        elif action == "delete_account":
            cmd = ["sudo", "dscl", ".", "-delete", f"/Users/{username}"]
            ret, out, err = self._run_cmd(cmd)
            return {"success": ret == 0, "stdout": out, "stderr": err}
        elif action == "create_profile":
            cmd = ["sudo", "mkdir", "-p", home]
            ret, out, err = self._run_cmd(cmd)
            return {"success": ret == 0, "stdout": out, "stderr": err}
        elif action == "delete_profile":
            cmd = ["sudo", "rm", "-rf", home]
            ret, out, err = self._run_cmd(cmd)
            return {"success": ret == 0, "stdout": out, "stderr": err}
        return {"success": False, "stdout": "", "stderr": "Action inconnue."}

    def create_profile(self, username, password=None):
        """
        Crée le profil utilisateur.
        Retourne un dictionnaire avec les clés "success", "stdout", "stderr".
        """
        if self.os_type == "windows":
            return self._manage_windows_user("create_profile", username, password)
        elif self.os_type == "linux":
            return {"success": False, "stdout": "", "stderr": "Linux crée automatiquement le profil à la création du compte."}
        elif self.os_type == "darwin":
            return self._manage_macos_user("create_profile", username)
        else:
            return {"success": False, "stdout": "", "stderr": "Système non supporté."}

    def delete_profile(self, username):
        """
        Supprime le profil utilisateur.
        Retourne un dictionnaire avec les clés "success", "stdout", "stderr".
        """
        if self.os_type == "windows":
            return self._manage_windows_user("delete_profile", username)
        elif self.os_type == "linux":
            return self._manage_linux_user("delete_profile", username)
        elif self.os_type == "darwin":
            return self._manage_macos_user("delete_profile", username)
        else:
            return {"success": False, "stdout": "", "stderr": "Système non supporté."}

    def delete_user(self, username):
        """
        Supprime l'utilisateur et son profil.
        Retourne un dictionnaire avec les clés "success", "stdout", "stderr".
        """
        if self.os_type == "windows":
            return self._manage_windows_user("delete_user", username)
        elif self.os_type == "linux":
            return self._manage_linux_user("delete_account", username)
        elif self.os_type == "darwin":
            return self._manage_macos_user("delete_account", username)
        else:
            return {"success": False, "stdout": "", "stderr": "Système non supporté."}

