# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2016-2023 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-3.0-or-later

"""plugin_regenerateagent - Regeneration par archive pilotee par l'ARS.

Le meme plugin est installe sur l'ARS et les machines. L'ARS fabrique une
archive du socle commun et l'envoie aux machines; la machine la valide, remplace
atomiquement img_agent, puis execute le replicator de cette image.
"""

import base64
import hashlib
import io
import json
import logging
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
import traceback

from lib import utils

logger = logging.getLogger()
plugin = {"VERSION": "1.4", "NAME": "regenerateagent", "TYPE": "all"}  # fmt: skip

ARCHIVE_EXCLUSIONS = {
    ".stfolder",
    "bin",
    "descriptor_scheduler_machine",
    "descriptor_scheduler_relay",
    "pluginsmachine",
    "pluginsrelay",
    "inventoryslot.py",
    "package_watching.py",
    "pulse-xmpp-agent-log.py",
    "lib/ressources",
}


@utils.set_logging_level
def action(objectxmpp, action, sessionid, data, message, dataerreur):
    """Execute le role ARS ou machine selon le type de l'agent receveur."""
    if not isinstance(data, dict):
        logger.error("[REGENERATEAGENT] Demande rejetee: payload invalide")
        return
    if objectxmpp.config.agenttype in ["machine"]:
        _machine_regenerate(objectxmpp, sessionid, data, message)
    else:
        _relay_regenerate(objectxmpp, sessionid, data, message)


def _relay_regenerate(objectxmpp, sessionid, data, message):
    """Envoie l'archive commune aux machines du lot ARS."""
    jidmachines = data.get("jidmachines", [])
    if not isinstance(jidmachines, list) or not jidmachines:
        logger.error("[REGENERATEAGENT-ARS] Demande rejetee: jidmachines absent")
        return
    try:
        archive = _get_archive_payload(objectxmpp)
        for jidmachine in jidmachines:
            jidmachine = str(jidmachine).strip()
            if not jidmachine:
                continue
            machine_sessionid = _send_archive(
                objectxmpp, jidmachine, sessionid, archive
            )
            _send_finalize(objectxmpp, jidmachine, machine_sessionid)
        logger.info(
            "[REGENERATEAGENT-ARS] Lot de %d machine(s) envoye depuis %s",
            len(jidmachines),
            message["from"],
        )
    except Exception:
        logger.error("[REGENERATEAGENT-ARS] Echec de preparation ou envoi archive")
        logger.error(traceback.format_exc())


def _get_archive_payload(objectxmpp):
    """Construit une archive locale pour le lot ARS en cours."""
    archive_buffer = io.BytesIO()

    def archive_filter(member):
        relative_path = member.name.split("/", 1)[-1].rstrip("/")
        if relative_path in ARCHIVE_EXCLUSIONS:
            return None
        if any(relative_path.startswith(path + "/") for path in ARCHIVE_EXCLUSIONS):
            return None
        return member

    with tarfile.open(fileobj=archive_buffer, mode="w:gz") as archive_file:
        archive_file.add(
            objectxmpp.config.diragentbase,
            arcname="xmpp_baseremoteagent",
            filter=archive_filter,
        )
    archive_content = archive_buffer.getvalue()
    payload = {
        "content": base64.b64encode(archive_content).decode("ascii"),
        "md5": hashlib.md5(archive_content).hexdigest(),
        "archive_format": "tar.gz",
        "source": "xmpp_baseremoteagent",
    }
    return payload


def _send_archive(objectxmpp, jidmachine, sessionid, archive):
    """Envoie l'archive avec un identifiant de session propre a la machine."""
    machine_sessionid = "%s-%s" % (sessionid, utils.getRandomName(3, "archive"))
    request = {
        "action": "regenerateagent",
        "sessionid": machine_sessionid,
        "data": {"subaction": "install_archive", **archive},
        "ret": 0,
        "base64": False,
    }
    objectxmpp.send_message(mto=jidmachine, mbody=json.dumps(request), mtype="chat")
    return machine_sessionid


def _send_finalize(objectxmpp, jidmachine, sessionid):
    """Ordonne l'installation de l'image apres reception de l'archive."""
    request = {
        "action": "regenerateagent",
        "sessionid": sessionid,
        "data": {"subaction": "finalize"},
        "ret": 0,
        "base64": False,
    }
    objectxmpp.send_message(mto=jidmachine, mbody=json.dumps(request), mtype="chat")


def _machine_regenerate(objectxmpp, sessionid, data, message):
    """Recoit l'archive ou l'ordre final en provenance de l'ARS."""
    try:
        if data.get("subaction") == "install_archive":
            _install_archive(objectxmpp, sessionid, data, message)
        elif data.get("subaction") == "finalize":
            if sessionid not in getattr(
                objectxmpp, "regenerate_agent_ready_sessions", set()
            ):
                if not hasattr(objectxmpp, "regenerate_agent_finalize_sessions"):
                    objectxmpp.regenerate_agent_finalize_sessions = set()
                objectxmpp.regenerate_agent_finalize_sessions.add(sessionid)
                logger.info(
                    "[REGENERATEAGENT] Finalisation differee: archive en cours d'installation"
                )
                return
            objectxmpp.regenerate_agent_ready_sessions.discard(sessionid)
            _run_image_replicator(objectxmpp)
        else:
            logger.error("[REGENERATEAGENT] Sous-action inconnue: %s", data.get("subaction"))
    except Exception:
        logger.error("[REGENERATEAGENT] Echec de regeneration")
        logger.error(traceback.format_exc())


def _install_archive(objectxmpp, sessionid, data, message):
    """Valide, extrait et bascule atomiquement l'archive dans img_agent."""
    archive_content = base64.b64decode(data["content"], validate=True)
    if hashlib.md5(archive_content).hexdigest() != data.get("md5"):
        logger.error("[REGENERATEAGENT] Archive rejetee: MD5 invalide")
        return
    temporary_directory = tempfile.mkdtemp(
        prefix="regenerate-agent-", dir=objectxmpp.pathagent
    )
    try:
        archive_path = os.path.join(temporary_directory, "xmpp_baseremoteagent.tar.gz")
        with open(archive_path, "wb") as archive_file:
            archive_file.write(archive_content)
        with tarfile.open(archive_path, "r:gz") as archive_file:
            _safe_extract(archive_file, temporary_directory)
        new_image = os.path.join(temporary_directory, "xmpp_baseremoteagent")
        if not os.path.isfile(os.path.join(new_image, "replicator.py")):
            logger.error("[REGENERATEAGENT] Archive rejetee: replicator absent")
            return
        _replace_image_atomically(objectxmpp.img_agent, new_image)
        if not hasattr(objectxmpp, "regenerate_agent_ready_sessions"):
            objectxmpp.regenerate_agent_ready_sessions = set()
        objectxmpp.regenerate_agent_ready_sessions.add(sessionid)
        logger.info("[REGENERATEAGENT] Image remplacee depuis l'ARS %s", message["from"])
        if sessionid in getattr(objectxmpp, "regenerate_agent_finalize_sessions", set()):
            objectxmpp.regenerate_agent_finalize_sessions.discard(sessionid)
            objectxmpp.regenerate_agent_ready_sessions.discard(sessionid)
            logger.info("[REGENERATEAGENT] Finalisation differee reprise apres installation")
            _run_image_replicator(objectxmpp)
    finally:
        shutil.rmtree(temporary_directory, ignore_errors=True)


def _safe_extract(archive_file, destination):
    """Refuse les chemins et liens dangereux avant extraction de l'archive."""
    for member in archive_file.getmembers():
        normalized_name = os.path.normpath(member.name)
        if normalized_name.startswith("..") or os.path.isabs(normalized_name):
            raise ValueError("Archive contains an unsafe path")
        if member.issym() or member.islnk() or member.isdev():
            raise ValueError("Archive contains an unsupported entry")
    archive_file.extractall(destination)


def _replace_image_atomically(current_image, new_image):
    """Bascule une image complete, avec restauration et retry sous Windows."""
    previous_image = current_image + ".previous"
    last_error = None
    for attempt in range(3):
        shutil.rmtree(previous_image, ignore_errors=True)
        moved_current_image = False
        try:
            if os.path.isdir(current_image):
                os.replace(current_image, previous_image)
                moved_current_image = True
            os.replace(new_image, current_image)
            shutil.rmtree(previous_image, ignore_errors=True)
            return
        except PermissionError as error:
            last_error = error
            if moved_current_image and not os.path.exists(current_image):
                os.replace(previous_image, current_image)
            if attempt < 2:
                logger.warning(
                    "[REGENERATEAGENT] img_agent verrouille, nouvelle tentative %d/3",
                    attempt + 2,
                )
                time.sleep(1)
        except Exception:
            if moved_current_image and not os.path.exists(current_image):
                os.replace(previous_image, current_image)
            raise
    raise last_error


def _run_image_replicator(objectxmpp):
    """Execute le replicator de l'image regeneree apres ordre explicite ARS."""
    replicator = os.path.join(objectxmpp.img_agent, "replicator.py")
    if not os.path.isfile(replicator):
        logger.error("[REGENERATEAGENT] Finalisation rejetee: replicator image absent")
        return
    result = subprocess.run(
        [sys.executable, replicator, "--verbose"],
        cwd=objectxmpp.img_agent,
        capture_output=True,
        text=True,
        check=False,
    )
    for line in (result.stdout + result.stderr).splitlines():
        logger.info("[REGENERATEAGENT] replicator: %s", line)
    logger.info("[REGENERATEAGENT] replicator termine avec code %s", result.returncode)
