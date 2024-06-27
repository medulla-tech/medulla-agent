# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2017-2024 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-3.0-or-later


from lib.utils import simplecommand, name_random
import json
import logging
import subprocess

plugin = {"VERSION": "1.0", "NAME": "scheduling_integrity", "TYPE": "all", "SCHEDULED": True}  # fmt: skip

# nb -1 infinie
SCHEDULE = {"schedule": "* */12 * * *", "nb": -1}
logger = logging.getLogger()

logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

sessionid = name_random(8, "update_")


def check_system_integrity():

    run_antivirus_scan()

    run_system_update()

    run_system_integrity_check()


def run_antivirus_scan():

    command = "Start-MpScan -ScanType QuickScan"
    try:
        simplecommand(command)
        logger.debug("Virus scan completed.")
    except Exception:
        logger.debug("An error occured during virus scan")


def run_system_update():
    logger.debug("Checking for system updates...")
    command = (
        'powershell -Command "'
        "$updateSession = New-Object -ComObject Microsoft.Update.Session; "
        "$updateSearcher = $updateSession.CreateUpdateSearcher(); "
        '$searchResult = $updateSearcher.Search(\\"IsInstalled=0\\"); '
        'Write-Output \\"Updates found: $($searchResult.Updates.Count)\\"; '
        "foreach ($update in $searchResult.Updates) { "
        'Write-Output \\"Title: $($update.Title)\\"; '
        '}"'
    )
    try:
        result = subprocess.run(
            command,
            shell=True,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        logger.debug("Result of checking for updates:")
        logger.debug(result.stdout)
        logger.debug("Checking for system updates completed")
    except subprocess.CalledProcessError as e:
        logger.debug(
            f"Error checking for system updates: {e.stderr}"
        )


# def run_system_integrity_check():

#     logger.debug("Vérification de l'intégrité du système...")
#     command = "sfc /scannow"
#     try:
#         simplecommand(command)
#         # La commande sfc /scannow analyse tous les fichiers système protégés et remplace les fichiers endommagés par une copie mise en cache dans un dossier compressé sous %WinDir%\System32\dllcache.
#         logger.debug("Vérification de l'intégrité du système terminée.")
#     except Exception:
#         logger.debug(f"Erreur lors de la vérification de l'intégrité du système")


def notify_admin(message):
    logger.debug(f"Notification to administrator: {message}")
    send_notif_to_admin(subject="System Integrity Alert", body=message)
    pass


def run_system_integrity_check():
    logger.debug("Checking the integrity of the system...")
    command = "sfc /scannow"
    try:
        result = simplecommand(command)
        output = "\n".join(result["result"])

        logger.debug(output)

        # Analyser la sortie pour détecter les réparations
        if (
            "Windows Resource Protection found corrupt files and successfully repaired them"
            in output
        ):
            logger.debug("Corrupted system files have been repaired.")
            notify_admin("Corrupted system files have been repaired.")
        elif (
            "Windows Resource Protection found corrupt files but was unable to fix some of them"
            in output
        ):
            logger.debug(
                "Corrupt system files were found, but some could not be repaired."
            )
            notify_admin(
                "Corrupt system files were found, but some could not be repaired."
            )
        else:
            logger.debug("No system file corruption detected.")

        logger.debug("System integrity check completed.")
    except Exception as e:
        logger.debug(f"Error checking system integrity: {e}")


def schedule_main(objectxmpp):
    """
    Main function for the scheduling inventory plugin.

    Args:
        objectxmpp: An object representing the XMPP connection.

    Notes:
        This function is called at specific intervals based on the crontab descriptor.
        If the inventory_interval in the configuration is not 0, the function does nothing.
        Otherwise, it sends an inventory request and logs the action.

    """

    check_system_integrity()

    datasend = {
        "action": "",
        "sessionid": sessionid,
        "data": "Scan ok",
        "ret": 0,
        "base64": False,
    }

    objectxmpp.send_message(
        mto="master_depl@pulse",
        mbody=json.dumps(datasend),
        mtype="chat",
    )
