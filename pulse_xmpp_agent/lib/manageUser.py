# -*- coding: utf-8; -*-
# SPDX-FileCopyrightText: 2016-2023 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-3.0-or-later

import subprocess
import shlex
import re
import platform
import os
import sys
import json
import logging
logger = logging.getLogger("ManageUser")
class ManageUser:
    def __init__(self):
        self.os_type = platform.system().lower()
        self._controle_durete_mot_de_passe = True
        self._original_windows_password_policy = None
        self.user_info_cache = {}

        # --- Logger configuration ---
        self.logger = logger


        # # Console handler (si tu veux un fichier -> FileHandler possible)
        # handler = logging.StreamHandler(sys.stdout)
        # handler.setLevel(logging.DEBUG)

        # formatter = logging.Formatter(
            # '[%(asctime)s] [%(levelname)s] %(message)s', datefmt='%Y-%m-%d %H:%M:%S'
        # )
        # handler.setFormatter(formatter)

        # # Empêche d’ajouter plusieurs handlers si plusieurs instances sont creees
        # if not self.logger.handlers:
            # self.logger.addHandler(handler)

    @property
    def controle_durete_mot_de_passe(self):
        """Propriete pour obtenir l'etat du contrôle de durete du mot de passe."""
        return self._controle_durete_mot_de_passe

    @controle_durete_mot_de_passe.setter
    def controle_durete_mot_de_passe(self, valeur):
        """Propriete pour activer ou desactiver le contrôle de durete du mot de passe."""
        self._controle_durete_mot_de_passe = bool(valeur)

    def _run_cmd(self, command):
        """Execute une commande shell et retourne le code de retour, stdout et stderr."""
        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        stdout, stderr = process.communicate()
        return process.returncode, stdout, stderr

    def _run_cmd_shell(self, command):
        """Execute une commande shell avec bash."""
        return self._run_cmd(["bash", "-c", command])

    def is_password_strong(self, password):
        """Verifie si un mot de passe respecte les criteres de complexite."""
        errors = []
        if len(password) < 8:
            errors.append("Le mot de passe doit contenir au moins 8 caracteres.")
        if not re.search(r'[A-Z]', password):
            errors.append("Le mot de passe doit contenir au moins une majuscule.")
        if not re.search(r'[a-z]', password):
            errors.append("Le mot de passe doit contenir au moins une minuscule.")
        if not re.search(r'[0-9]', password):
            errors.append("Le mot de passe doit contenir au moins un chiffre.")
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            errors.append("Le mot de passe doit contenir au moins un caractere special.")
        if ' ' in password:
            errors.append("Le mot de passe ne doit pas contenir d espaces.")
        return (True, "Le mot de passe est robuste.") if not errors else (False, "\n".join(errors))

    def _get_windows_password_policy(self):
        """Recupere la politique actuelle de mot de passe sous Windows."""
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
                elif "Duree minimale du mot de passe" in line:
                    policy["minpwage"] = line.split(":")[-1].strip()
                elif "Duree maximale du mot de passe" in line:
                    policy["maxpwage"] = line.split(":")[-1].strip()
                elif "Mots de passe uniques à conserver" in line:
                    policy["uniquepw"] = line.split(":")[-1].strip()
            return policy
        except subprocess.CalledProcessError as e:
            return {"error": f"Erreur lors de la recuperation de la politique : {e.stderr}"}

    def _set_windows_password_policy(self, minpwlen, minpwage, maxpwage, uniquepw):
        """Definit la politique de mot de passe sous Windows."""
        try:
            subprocess.run(
                ["net", "accounts", f"/minpwlen:{minpwlen}", f"/minpwage:{minpwage}", f"/maxpwage:{maxpwage}", f"/uniquepw:{uniquepw}"],
                check=True,
                capture_output=True,
                text=True
            )
            return True, "Politique de mot de passe modifiee avec succes."
        except subprocess.CalledProcessError as e:
            return False, f"Erreur lors de la modification de la politique : {e.stderr}"

    def set_windows_password_policy(self, enable):
        """
        Active ou desactive la politique de complexite des mots de passe sous Windows.
        """
        if enable:
            return self._set_windows_password_policy("8", "1", "42", "5")
        else:
            return self._set_windows_password_policy("0", "0", "unlimited", "0")

    def create_user(self, username, password, set_windows_policy=True):
        """
        Cree un utilisateur sur le systeme.
        Retourne un dictionnaire avec les cles "success", "stdout", "stderr".
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

            # Appliquer la politique souhaitee pour la creation
            success, message = self.set_windows_password_policy(True)
            if not success:
                return {"success": False, "stdout": "", "stderr": message}

            # Creer l'utilisateur
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
            return {"success": False, "stdout": "", "stderr": "Systeme non supporte."}

    def _delete_windows_profile_dirs(self, username):
        """
        Supprime tous les dossiers de profil Windows correspondant à l'utilisateur.
        Gere les profils multiples (pulseuser, pulseuser.000, pulseuser.001, etc.).

        Args:
            username (str): Nom de l'utilisateur dont les profils doivent être supprimes.

        Returns:
            dict: {'success': bool, 'stdout': str, 'stderr': str}
        """
        if self.os_type != "windows":
            return {"success": False, "stdout": "", "stderr": "Non-Windows OS"}

        ps = rf'''
    $ErrorActionPreference = "SilentlyContinue"

    # Recherche tous les dossiers de profil sous C:\Users
    $usersDir = "C:\Users"
    $dirs = Get-ChildItem $usersDir -Directory | Where-Object {{
        $_.Name -ieq "{username}" -or $_.Name -match "^{username}(\.\d+)?$"
    }}

    foreach ($d in $dirs) {{
        Remove-Item $d.FullName -Recurse -Force
        Write-Output "Deleted folder: $($d.FullName)"
    }}
    '''

        result = subprocess.run(
            ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", ps],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace"
        )

        if result.returncode == 0:
            logging.getLogger().info(f"Tous les dossiers de profil pour {username} ont ete supprimes.")
        else:
            logging.getLogger().error(f"Erreur suppression dossiers de profil pour {username}: {result.stderr}")

        return {
            "success": result.returncode == 0,
            "stdout": result.stdout.strip(),
            "stderr": result.stderr.strip()
        }

    def _delete_profile_windows(self, username):
        """
        Supprime completement le profil Windows de l'utilisateur :
        - Supprime la cle registre ProfileList\<SID> et <SID>.bak
        - Supprime tous les dossiers de profil
        - Supprime les objets Win32_UserProfile
        """
        if self.os_type != "windows":
            return {"success": False, "stdout": "", "stderr": "Non-Windows OS"}

        # 1️⃣ Supprimer tous les dossiers de profil
        self._delete_windows_profile_dirs(username)

        # 2️⃣ Supprimer les cles de registre et Win32_UserProfile
        ps = rf'''
    $ErrorActionPreference = "SilentlyContinue"
    $u = Get-LocalUser -Name "{username}"
    if (-not $u) {{ Write-Output "NOUSER"; exit }}

    $sid = $u.SID.Value
    $regBase = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList"

    foreach ($key in @("$regBase\$sid", "$regBase\$sid.bak")) {{
        if (Test-Path $key) {{ Remove-Item $key -Recurse -Force }}
    }}

    Get-CimInstance Win32_UserProfile | Where-Object {{ $_.SID -eq $sid }} | Remove-CimInstance
    Write-Output "OK"
    '''

        result = subprocess.run(
            ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", ps],
            capture_output=True, text=True, encoding="utf-8", errors="replace"
        )

        return {
            "success": result.returncode == 0,
            "stdout": result.stdout.strip(),
            "stderr": result.stderr.strip()
        }


    def _manage_windows_user(self, action, username, password=None):
        """
        Gere un utilisateur Windows : creation, suppression, creation/suppression de profil.
        Args:
            action (str): L'action à effectuer. Doit être l'une des suivantes :
                - "create_user" : Cree un utilisateur.
                - "delete_user" : Supprime un utilisateur.
                - "create_profile" : Cree un profil utilisateur.
                - "delete_profile" : Supprime un profil utilisateur.
            username (str): Nom de l'utilisateur.
            password (str, optionnel) : Mot de passe de l utilisateur. Requis pour "create_user" et "create_profile".
        Returns:
            dict: Un dictionnaire avec les cles "success", "stdout", "stderr".
        """
        if action == "delete_profile":
            return self._delete_profile_windows(username)

        ps_commands = {
            "create_user": f'net user "{username}" "{password}" /add',
            "delete_user": f'net user "{username}" /delete',
            "create_profile": (
                f'powershell -Command '
                f'"$cred = New-Object System.Management.Automation.PSCredential(\'{username}\', (ConvertTo-SecureString \'{password}\' -AsPlainText -Force)); '
                f'Start-Process cmd.exe -Credential $cred -NoNewWindow -ArgumentList \'/c echo Profil utilisateur cree avec succes\' -Wait"'
            )
        }

        if action not in ps_commands:
            return {"success": False, "stdout": "", "stderr": f"Action inconnue : {action}"}

        if action in ["create_user", "create_profile"] and not password:
            return {"success": False, "stdout": "", "stderr": "Mot de passe requis"}

        command = ps_commands[action]
        # logger.debug(f"command {action}:{command}")
        try:
            result = subprocess.run(
                command,
                shell=True,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace"
            )
            resulcommand= {
                "success": result.returncode == 0,
                "stdout": result.stdout.strip(),
                "stderr": result.stderr.strip()
            }
            # logger.debug(f"result command {action} : {resulcommand}")
            return resulcommand

        except Exception as e:
            # Renvoie une erreur proprement formatee
            resulterreur= {
                "success": False,
                "stdout": "",
                "stderr": f"Exception subprocess : {type(e).__name__} : {e}"
            }
            # logger.error(f"erreur command {action}{resulterreur}")
            return resulterreur

    def _manage_linux_user(self, action, username, password=None):
        """Gere un utilisateur Linux."""
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
        """Gere un utilisateur macOS."""
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
        Cree le profil utilisateur.
        Retourne un dictionnaire avec les cles "success", "stdout", "stderr".
        """
        if self.os_type == "windows":
            return self._manage_windows_user("create_profile", username, password)
        elif self.os_type == "linux":
            return {"success": False, "stdout": "", "stderr": "Linux cree automatiquement le profil à la creation du compte."}
        elif self.os_type == "darwin":
            return self._manage_macos_user("create_profile", username)
        else:
            return {"success": False, "stdout": "", "stderr": "Systeme non supporte."}

    def delete_profile(self, username):
        """
        Supprime le profil utilisateur.
        Retourne un dictionnaire avec les cles "success", "stdout", "stderr".
        """
        if self.os_type == "windows":
            return self._manage_windows_user("delete_profile", username)
        elif self.os_type == "linux":
            return self._manage_linux_user("delete_profile", username)
        elif self.os_type == "darwin":
            return self._manage_macos_user("delete_profile", username)
        else:
            return {"success": False, "stdout": "", "stderr": "Systeme non supporte."}

    def delete_user(self, username):
        """
        Supprime l'utilisateur et son profil.
        Retourne un dictionnaire avec les cles "success", "stdout", "stderr".
        """
        if self.os_type == "windows":
            return self._manage_windows_user("delete_user", username)
        elif self.os_type == "linux":
            return self._manage_linux_user("delete_account", username)
        elif self.os_type == "darwin":
            return self._manage_macos_user("delete_account", username)
        else:
            return {"success": False, "stdout": "", "stderr": "Systeme non supporte."}

    # def user_exists(self, username):
        # """
        # Verifie si un utilisateur Windows existe via Get-CimInstance.
        # Retourne True si trouve, sinon False.
        # """
        # if self.os_type != "windows":
            # self.logger.debug(f"Systeme non-Windows detecte. Impossible de verifier l'utilisateur {username}.")
            # return False

        # command = (
            # f'powershell -NoProfile -Command '
            # f'"$u = Get-CimInstance -ClassName Win32_UserAccount '
            # f'-Filter \\"Name=\'{username}\' AND LocalAccount=True\\"; '
            # f'if ($u) {{ exit 0 }} else {{ exit 1 }}"'
        # )

        # result = subprocess.run(command, shell=True)
        # return result.returncode == 0
    def user_exists(self, username):
        """
        Verifie si un utilisateur local existe.
        Retourne True si l utilisateur existe, False sinon.
        """
        if self.os_type != "windows":
            self.logger.debug(f"Systeme non-Windows detecte. Impossible de verifier l utilisateur {username}.")
            return False

        ps_cmd = f"""
        $u = Get-LocalUser -Name "{username}" -ErrorAction SilentlyContinue
        Write-Output ($u -ne $null)
        """

        self.logger.debug(f"Execution de la commande PowerShell pour verifier l existence de {username}.")
        result = subprocess.run(
            ["powershell", "-NoProfile", "-Command", ps_cmd],
            capture_output=True, text=True, encoding="utf-8", errors="replace"
        )

        exists = result.stdout.strip().lower() == "true"
        self.logger.debug(f"L utilisateur {username} existe : {exists}.")
        return exists

    def get_user_info(self, username):
        if not self.user_exists(username):
            self.logger.warning(f"L utilisateur {username} n existe pas.")
            return {}

        sid = self.get_SID_user(username)
        if not sid:
            self.logger.warning(f"Impossible de recuperer le SID pour {username}.")
            return {}

        if sid in self.user_info_cache:
            self.logger.debug(f"Informations recuperees depuis le cache pour le SID {sid}.")
            return self.user_info_cache[sid]

        info = self.get_user_info_sid(sid)
        if info:
            self.user_info_cache[sid] = info
            self.logger.debug(f"Informations mises en cache pour le SID {sid}.")
        else:
            self.logger.warning(f"Aucune information trouvee pour le SID {sid}.")

        return info

    def get_SID_user(self, username):
        """
        Recupere le SID d un utilisateur local.
        Retourne le SID si l utilisateur existe, None sinon.
        """
        if not self.user_exists(username):
            self.logger.warning(f"L utilisateur {username} n existe pas. Impossible de recuperer le SID.")
            return None

        ps_cmd = f"""
        $u = Get-LocalUser -Name "{username}" -ErrorAction SilentlyContinue
        Write-Output $u.SID.Value
        """

        self.logger.debug(f"Recuperation du SID pour l utilisateur {username}.")
        result = subprocess.run(
            ["powershell", "-NoProfile", "-Command", ps_cmd],
            capture_output=True, text=True, encoding="utf-8", errors="replace"
        )

        sid = result.stdout.strip()
        if sid:
            self.logger.debug(f"SID recupere pour {username} : {sid}.")
        else:
            self.logger.warning(f"Impossible de recuperer le SID pour {username}.")

        return sid

    def get_user_info_sid(self, sid):
        """
        Recupere les informations d un utilisateur à partir de son SID.
        Retourne un dictionnaire avec les informations du profil utilisateur.
        """
        if self.os_type != "windows":
            self.logger.debug("Systeme non-Windows detecte. Impossible de recuperer les informations du profil.")
            return {}

        ps_cmd = f"""
        $profile = Get-CimInstance -ClassName Win32_UserProfile | Where-Object {{ $_.SID -eq "{sid}" }}
        if (-not $profile) {{
            Write-Output "{{}}"
            exit
        }}
        $result = @{{
            SID         = $profile.SID
            ProfilePath = $profile.LocalPath
            LastUseTime = $profile.LastUseTime
        }}
        $result | ConvertTo-Json -Compress
        """

        self.logger.debug(f"Recuperation des informations pour le SID {sid}.")
        result = subprocess.run(
            ["powershell", "-NoProfile", "-Command", ps_cmd],
            capture_output=True, text=True, encoding="utf-8", errors="replace"
        )

        if not result.stdout.strip() or result.stdout.strip() == "{}":
            self.logger.warning(f"Aucun profil trouve pour le SID {sid}.")
            return {}

        try:
            info = json.loads(result.stdout.strip())
            self.logger.debug(f"Informations recuperees pour le SID {sid} : {json.dumps(info, indent=4)}.")
            return info
        except Exception as e:
            self.logger.error(f"Erreur lors de la conversion JSON pour le SID {sid} : {e}.")
            return {}

    def get_dir(self, dir, absolu_path=False):
        """
        Recupere les repertoires presents dans le chemin specifie.

        Args:
            dir (str): Chemin du repertoire à lister.
            absolu_path (bool): Si True, retourne les chemins absolus.
                               Si False, retourne uniquement les noms des repertoires.

        Returns:
            list: Liste des repertoires.
        """
        try:
            # Verifie si le chemin existe
            if not os.path.exists(dir):
                logger.error(f"Le chemin {dir} n existe pas.")
                return []

            # Liste les entrees dans le repertoire
            entries = os.listdir(dir)

            # Filtre uniquement les repertoires
            directories = [
                os.path.join(dir, entry) if absolu_path else entry
                for entry in entries
                if os.path.isdir(os.path.join(dir, entry))
            ]

            logger.debug(f"Repertoires trouves dans {dir} : {directories}")
            return directories

        except Exception as e:
            logger.error(f"Erreur lors de la lecture du repertoire {dir} : {e}")
            return []

    def display_dir(self, listdir):
        """
        Affiche les repertoires de la liste avec leur index.

        Args:
            listdir (list): Liste des repertoires à afficher.
        """
        if not listdir:
            logger.info("Aucun repertoire a afficher.")
            return

        for index, directory in enumerate(listdir, start=1):
            logger.info(f"{index}: {directory}")

    def cleanup_corrupted_profiles(self, username, directory_search, base_path="C:\\Users" ):
        """
        Supprime le profil utilisateur courant et tous les profils corrompus suffixes par un nombre sur 3 digits.
        Supprime egalement les repertoires associes.

        Args:
            username (str): Nom du profil utilisateur courant (ex: 'pulseuser').
            directory_search (list): Liste des noms des profils trouves dans le repertoire.
        """
        try:
            # Expression reguliere pour identifier les profils suffixes par .XXX (où X est un chiffre)
            pattern = re.compile(rf"^{re.escape(username)}\.\d{{3}}$")

            # Liste des profils à supprimer (profil courant + profils suffixes)
            # profiles_to_delete = [username]
            profiles_to_delete = []
            profiles_to_delete.extend([profile for profile in directory_search if pattern.match(profile)])

            if not profiles_to_delete:
                logger.debug(f"0 deleting profil {username}.")
                return

            logger.debug(f"Profils deleting: {profiles_to_delete}")
            profiles_to_delete.append(username)
            self.delete_profile(username)
            # Supprimer les repertoires des profils
            for profile in profiles_to_delete:
                profile_path = os.path.join(base_path, profile)
                if os.path.exists(profile_path):
                    try:
                        shutil.rmtree(profile_path)
                        logger.debug(f"directory {profile_path} deleted.")
                    except Exception as e:
                        logger.error(f"Erreur lors de la suppression de {profile_path} : {e}")

            logger.debug(f"Nettoyage termine pour {username} et ses profils corrompus.")

        except Exception as e:
            logger.error(f"Erreur lors du nettoyage des profils corrompus : {e}")
