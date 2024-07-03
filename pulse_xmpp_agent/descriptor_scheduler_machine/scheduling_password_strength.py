## -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2021-2023 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-3.0-or-later

"""
    This plugin is created to check if all users have a strong password
"""

from lib.agentconffile import directoryconffile
import configparser
import json
import os
import random
import re
import logging
import subprocess
import sys
import ctypes



logger = logging.getLogger()
plugin = {"VERSION": "1.0", "NAME": "scheduling_password_check", "TYPE": "all", "SCHEDULED": True}

SCHEDULE = {"schedule": "*/1 * * * *", "nb": -1}

# parse the config file
configfilename = os.path.join(directoryconffile(), "agentconf.ini")
config = configparser.ConfigParser()
if os.path.isfile(configfilename):
    Config = configparser.ConfigParser()
    Config.read(configfilename)

# get depl sub
mto_address = config.get('substitute', 'deployment')


def name_random(nb, pref=""):
    a = "abcdefghijklnmopqrstuvwxyz0123456789"
    d = pref
    for t in range(nb):
        d = d + a[random.randint(0, 35)]
    return d

sessionid = name_random(0, "update_")

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def run_as_admin():
    if is_admin():
        return True

    ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
    return False

def UserDir():
    user_profile_path = os.environ.get('USERPROFILE')

    if user_profile_path:
      # Split the path to get the 'C:\Users' part
        users_directory, username = os.path.split(user_profile_path)
        drive, users_dir = os.path.split(users_directory)
    
    c_users_path = os.path.join(drive, users_dir)
    return c_users_path

def export_security_cfg(user):
    try:
        user_dir = UserDir()
        output_path = os.path.join(user_dir, user, 'security.cfg')

         # Ensure the user directory exists
        if not os.path.exists(user_dir):
            logger.error(f"User directory {user_dir} does not exist.")
            return
        
        # Run the secedit command to export the security policy
        result = subprocess.run(['secedit', '/export', f'/cfg', output_path],
                                capture_output=True, text=True, shell=True)      
        if result.returncode == 0:
          return
        else:
         logger.error(f"Error exporting security policy: {result.stderr}")
    except Exception as e:
      logger.error(f"An error occurred: {e}")

def add_userprofile_path(user):
    try:     
      userDir = UserDir()
      user_directory_path = f'{userDir}\\{user}\\security.cfg'
      if not os.path.exists(user_directory_path):
        export_security_cfg(user)     
    except Exception as e:
      logger.error(f"An error occurred: {e}") 

def check_password_complexity(user):
    try:
        password_complexity_limit = 8
        userDir = UserDir()
        path_already_exist = os.path.exists(userDir)
        path_added = add_userprofile_path(user)
        #user_directory_path = f'{userDir}\\{user}\\security.cfg'
        user_directory_path = f'C:\\Users\\{user}\\security.cfg'
        if  path_already_exist or path_added:
            password_complexity_result = subprocess.run(['powershell', '-Command',  f'Get-Content {user_directory_path} | Select-String -Pattern PasswordComplexity'],
                                capture_output=True, text=True)        
            if password_complexity_result.returncode == 0:  
                password_complexity_value = re.search(r'\d+', password_complexity_result.stdout.strip())
                if password_complexity_value:
                    password_complexity_value = int(password_complexity_value.group())
                    if password_complexity_value >= password_complexity_limit:
                         logger.info(password_complexity_result.stdout.strip())
                         return "Strong"
                    else:
                        logger.info(password_complexity_result.stdout.strip())
                        return "Weak"
                else:
                    logger.error(f"Invalid password complexity value for {user}: {password_complexity_result.stdout.strip()}")
                    return f"Invalid password complexity value for {user}"
            else:    
                logger.error(f"Error checking password complexity for {user}: {password_complexity_result.stderr}")
                return f"Error checking password complexity for {user}: {password_complexity_result.stderr}"        
        else:
            logger.error(f"Invalid userprofile path for {user}")            
            return f"Invalid userprofile path for {user}"
    except Exception as e:
        logger.error(f"Error checking password complexity for {user}: {e}")
        return f"Error checking password complexity for {user}"


def check_password_history(user):
    try:
        password_history_size_limit = 10
        userDir = UserDir()
        path_already_exist = os.path.exists(userDir)
        path_added = add_userprofile_path(user)
        #user_directory_path = f'{userDir}\\{user}\\security.cfg'
        user_directory_path = f'C:\\Users\\{user}\\security.cfg'
        if path_already_exist or path_added:
            password_history_size_result = subprocess.run(['powershell', '-Command', f'Get-Content {user_directory_path} | Select-String -Pattern PasswordHistorySize'],
                                capture_output=True, text=True)           
            if password_history_size_result.returncode == 0:
                password_history_size_value = re.search(r'\d+', password_history_size_result.stdout.strip())
                if password_history_size_value:
                  password_history_size_value = int(password_history_size_value.group())
                  if password_history_size_value >= password_history_size_limit:
                    logger.info(password_history_size_result.stdout.strip())
                    return "Strong"
                  else:    
                    logger.info(password_history_size_result.stdout.strip())
                    return "Weak"
                else:
                   logger.error(f"Invalid password complexity value for {user}: {password_history_size_result.stdout.strip()}")
                   return f"Invalid password complexity value for {user}"
            else:
               logger.error(f"Error checking password history size for {user}: {password_history_size_result.stderr.strip()}")
               return f"Error checking password history size for {user}"
        else:
            logger.error(f"Invalid userprofile path for {user}")            
           

    except Exception as e:
        logger.error(f"Error checking password history size for {user}: {e}")
        return f"Error checking password history size for {user}"
    
def check_local_admin_password_strength():
    try:
        if sys.platform != "win32":
            return "This script is intended for Windows platform only."

        if not is_admin():
            return "Please run this script as an administrator."

        users_with_passwords = []
        users_without_passwords =[]

        result = subprocess.run(['powershell', '-Command', 'Get-LocalUser | ForEach-Object {if ($_.Enabled -eq $true) { $_.Name }}'],
                                capture_output=True, text=True)
        if result.returncode == 0:
            output_lines = result.stdout.strip().split('\n')
            all_users = [line.strip() for line in output_lines if line.strip()]
            check_users_password_results = []

            for user in all_users:
                password_required_result = subprocess.run(['powershell', '-Command', f'Get-LocalUser -Name "{user}" | Select-Object -ExpandProperty PasswordRequired'], capture_output=True, text=True)
                
                if password_required_result.returncode == 0: 
                    if password_required_result.stdout.strip() == 'True':
                       users_with_passwords.append(user)
                       password_complexity_result = check_password_complexity(user)
                       password_history_result = check_password_history(user)

                       check_users_password_results.append({
                        "user_name": user,
                        "password_required": True,
                        "password_complexity": password_complexity_result,
                        "password_history": password_history_result,
                       })   
                
                    elif password_required_result.stdout.strip() == 'False': 
                       users_without_passwords.append(user)
                       check_users_password_results.append({
                         "user_name": user,
                         "password_required": False,
                         "password_complexity": "None",
                         "password_history": "None",
                       })    

                else: 
                  logger.error(f"Error checking password required for {user}: {password_required_result.stderr}")
                  check_users_password_results.append({
                    "user_name": user,
                    "password_required": "Error",
                    "error": password_required_result.stderr.strip(),
                })
            return  check_users_password_results                              
        else:
            logger.error(f"Error retrieving users: {result.stderr.strip()}")
            return f"Error: {result.stderr.strip()}"
    except Exception as e:
        return f"Error checking password: {e}"


def schedule_main(objectxmpp):
    check_user_password_results = check_local_admin_password_strength()

    # data to send to server
    datasend = {
            "action": "checkpassword",
            "sessionid": sessionid,
            "data":  check_user_password_results, 
            "ret": 0,
            "base64": False,
        }
    
    # Convert the data to JSON format
    json_datasend = json.dumps(datasend)

    # send message to master deploy
    objectxmpp.send_message(
            mto="master_depl@pulse",
            mbody=json_datasend,
            mtype="chat",
        )
    
if __name__ == "__main__":
    check_users_password_results = check_local_admin_password_strength()
    if check_users_password_results:
        logger.info(check_users_password_results)    