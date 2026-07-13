# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2016-2023 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-3.0-or-later

import os
import sys
import logging
import json
import zlib
import base64
import traceback
from lib import utils, update_remote_agent

plugin = {"VERSION": "2.3", "VERSIONAGENT": "2.1", "NAME": "updateagent", "TYPE": "all", "waittingmax": 35, "waittingmin": 5}  # fmt: skip

logger = logging.getLogger()
DEBUGPULSEPLUGIN = 25


@utils.set_logging_level
def action(objectxmpp, action, sessionid, data, message, dataerreur):
    """
    Perform the specified action based on the incoming data.

    Parameters:
    - objectxmpp: The XMPP object representing the current agent.
    - action: The action to be performed.
    - sessionid: The session ID associated with the action.
    - data: The data containing information about the action.
    - message: The XMPP message containing the action request.
    - dataerreur: Data related to any errors during the action.

    Returns:
    None
    """
    logger.debug("###################################################")
    logger.debug("call %s from %s" % (plugin, message["from"]))
    logger.debug("###################################################")
    logger.debug("%s" % json.dumps(data, indent=4))

    if "subaction" in data:
        if data["subaction"] == "descriptor":
            difference = {}
            supprimefileimage = []
            utils.file_put_contents(
                os.path.join(objectxmpp.pathagent, "BOOL_UPDATE_AGENT"),
                "use file boolean update. enable verify update.",
            )
            if "version" in data["descriptoragent"]:
                # copy version agent master to image
                vers = (
                    (data["descriptoragent"]["version"])
                    .replace("\n", "")
                    .replace("\r", "")
                    .strip()
                )
                utils.file_put_contents(
                    os.path.join(objectxmpp.img_agent, "agentversion"), vers
                )
                utils.file_put_contents(
                    os.path.join(objectxmpp.pathagent, "agentversion"), vers
                )
            # on genere descriptor actuel de l image
            objdescriptorimage = update_remote_agent.Update_Remote_Agent(
                objectxmpp.img_agent
            )
            descriptorimage = objdescriptorimage.get_md5_descriptor_agent()
            # on recoit le nouveau descripteur depuis base de l'agent.
            objectxmpp.descriptor_master = data["descriptoragent"]

            # il faut supprimer les fichier dans l'image qui ont ete supprimer dans la base.
            # on recherche les differences entre base de l'agent et l'image de
            # la base.

            for directory_agent in objectxmpp.descriptor_master:
                if directory_agent in ["fingerprint", "version", "version_agent"]:
                    continue

                diff, supp = search_action_on_agent_cp_and_del(
                    objectxmpp.descriptor_master[directory_agent],
                    descriptorimage[directory_agent],
                )
                if directory_agent == "program_agent":
                    dirname = ""
                elif directory_agent == "lib_agent":
                    dirname = "lib"
                elif directory_agent == "script_agent":
                    dirname = "script"
                supp2 = [os.path.join(objectxmpp.img_agent, dirname, x) for x in supp]
                difference[directory_agent] = diff
                supprimefileimage.extend(supp2)
                for delfile in supp2:
                    try:
                        os.remove(delfile)
                    except BaseException:
                        pass
            logger.debug(
                "delete unnecessary files in image %s"
                % json.dumps(supprimefileimage, indent=4)
            )

            if len(supprimefileimage) != 0:
                # on genere le descripteur de l'image, on a supprimer les
                # fichiers qui sont dans l'image et pas dans la l'agent base
                objdescriptorimage = update_remote_agent.Update_Remote_Agent(
                    objectxmpp.img_agent
                )
                descriptorimage = objdescriptorimage.get_md5_descriptor_agent()

                objectxmpp.Update_Remote_Agentlist = (
                    update_remote_agent.Update_Remote_Agent(objectxmpp.pathagent)
                )
                descriptoragent = (
                    objectxmpp.Update_Remote_Agentlist.get_md5_descriptor_agent()
                )

                # on regarde si il y a des diff entre img, base, et agent
                if (
                    objectxmpp.descriptor_master["fingerprint"]
                    == descriptorimage["fingerprint"]
                ) and (
                    objectxmpp.descriptor_master["fingerprint"]
                    != descriptoragent["fingerprint"]
                ):
                    # on peut mettre a jour l'agent suite a une suppression de
                    # fichier inutile
                    objectxmpp.reinstall_agent()

            logger.debug("to updating files %s" % json.dumps(difference, indent=4))
            try:
                # on demande les fichiers differents pour la mise a jour de
                # l'image
                total_files_to_update = (
                    len(difference.get("program_agent", [])) +
                    len(difference.get("lib_agent", [])) +
                    len(difference.get("script_agent", []))
                )
                logger.info("[UPDATE] Files to update: %d total" % total_files_to_update)
                logger.info("[UPDATE]   - program_agent: %d" % len(difference.get("program_agent", [])))
                logger.info("[UPDATE]   - lib_agent: %d" % len(difference.get("lib_agent", [])))
                logger.info("[UPDATE]   - script_agent: %d" % len(difference.get("script_agent", [])))
                
                if (
                    len(difference.get("program_agent", [])) != 0
                    or len(difference.get("lib_agent", [])) != 0
                    or len(difference.get("script_agent", [])) != 0
                ):
                    # demande de mise à jour.
                    # todo send message only files for updating.
                    # call resultupdateagent
                    msgupdate_me = {
                        "action": "result%s" % action,
                        "sessionid": sessionid,
                        "data": {
                            "subaction": "update_me",
                            "descriptoragent": difference,
                        },
                        "ret": 0,
                        "base64": False,
                    }
                    # renvoi descriptor pour demander la mise a jour
                    try:
                        agent_installor = objectxmpp.sub_registration
                    except AttributeError:
                        agent_installor = "master@pulse/MASTER"
                    if "ars_update" in data and data["ars_update"] != "":
                        agent_installor = data["ars_update"]
                        msgupdate_me["action"] = "relayupdateagent"
                    logger.info("[UPDATE] Requesting file transfer from %s" % agent_installor)
                    objectxmpp.send_message(
                        mto=agent_installor,
                        mbody=json.dumps(msgupdate_me),
                        mtype="chat",
                    )
                    return
                else:
                    objdescriptorimage = update_remote_agent.Update_Remote_Agent(
                        objectxmpp.img_agent
                    )
                    descriptorimage = objdescriptorimage.get_md5_descriptor_agent()

                    objectxmpp.Update_Remote_Agentlist = (
                        update_remote_agent.Update_Remote_Agent(objectxmpp.pathagent)
                    )
                    descriptoragent = (
                        objectxmpp.Update_Remote_Agentlist.get_md5_descriptor_agent()
                    )

                    # on regarde si il y a des diff entre img, base, et agent
                    logger.debug("[UPDATE] Checking fingerprints after file downloads:")
                    logger.debug("[UPDATE]   - master: %s" % objectxmpp.descriptor_master.get("fingerprint", "UNKNOWN")[:16])
                    logger.debug("[UPDATE]   - image:  %s" % descriptorimage.get("fingerprint", "UNKNOWN")[:16])
                    logger.debug("[UPDATE]   - agent:  %s" % descriptoragent.get("fingerprint", "UNKNOWN")[:16])
                    
                    if (
                        objectxmpp.descriptor_master.get("fingerprint") == descriptorimage.get("fingerprint")
                    ) and (
                        objectxmpp.descriptor_master.get("fingerprint") != descriptoragent.get("fingerprint")
                    ):
                        # on peut mettre a jour l'agent suite a une suppression
                        # de fichier inutile
                        logger.info("[UPDATE] All files downloaded and fingerprints match - calling reinstall_agent()")
                        objectxmpp.reinstall_agent()
                    else:
                        logger.warning("[UPDATE] Fingerprint mismatch detected:")
                        logger.warning("[UPDATE]   - master==image: %s" % (
                            objectxmpp.descriptor_master.get("fingerprint") == descriptorimage.get("fingerprint")
                        ))
                        logger.warning("[UPDATE]   - master!=agent: %s" % (
                            objectxmpp.descriptor_master.get("fingerprint") != descriptoragent.get("fingerprint")
                        ))
                    return
            except Exception as e:
                logger.error(str(e))
                logger.error("\n%s" % (traceback.format_exc()))
        elif data["subaction"] == "install_lib_agent":
            if not ("namescript" in data and data["namescript"] != ""):
                logger.error("[UPDATE] install_lib_agent: missing namescript parameter")
                return
            else:
                logger.info("[UPDATE] install_lib_agent: received %s" % data["namescript"])
                try:
                    content = zlib.decompress(base64.b64decode(data["content"]))
                    logger.debug("[UPDATE] install_lib_agent: decompressed %d bytes" % len(content))
                    dump_file_in_img(objectxmpp, data["namescript"], content, "lib_agent")
                except Exception as e:
                    logger.error("[UPDATE] install_lib_agent: decompression failed: %s" % str(e))
        elif data["subaction"] == "install_program_agent":
            if not ("namescript" in data and data["namescript"] != ""):
                logger.error("[UPDATE] install_program_agent: missing namescript parameter")
                return
            else:
                logger.info("[UPDATE] install_program_agent: received %s" % data["namescript"])
                try:
                    content = zlib.decompress(base64.b64decode(data["content"]))
                    logger.debug("[UPDATE] install_program_agent: decompressed %d bytes" % len(content))
                    dump_file_in_img(
                        objectxmpp, data["namescript"], content, "program_agent"
                    )
                except Exception as e:
                    logger.error("[UPDATE] install_program_agent: decompression failed: %s" % str(e))
        elif data["subaction"] == "install_script_agent":
            if not ("namescript" in data and data["namescript"] != ""):
                logger.error("[UPDATE] install_script_agent: missing namescript parameter")
                return
            else:
                logger.info("[UPDATE] install_script_agent: received %s" % data["namescript"])
                try:
                    content = zlib.decompress(base64.b64decode(data["content"]))
                    logger.debug("[UPDATE] install_script_agent: decompressed %d bytes" % len(content))
                    dump_file_in_img(
                        objectxmpp, data["namescript"], content, "script_agent"
                    )
                except Exception as e:
                    logger.error("[UPDATE] install_script_agent: decompression failed: %s" % str(e))
        elif data["subaction"] == "ars_update":
            # verify agent type relayserver.
            logger.debug(
                "recu update agent from %s"
                " for update agent %s "
                "[ descriptor %s ]"
                % (message["from"], data["jidagent"], data["descriptoragent"])
            )
            senddescriptormd5(objectxmpp, data)


def search_action_on_agent_cp_and_del(fromimg, frommachine):
    """
    Compare files between an image (fromimg) and a machine (frommachine).

    Returns two lists:
    - List of files to copy from the image to the machine.
    - List of files to be deleted in the machine.

    Parameters:
    - fromimg (dict): Dictionary representing files in the image with their checksums.
    - frommachine (dict): Dictionary representing files in the machine with their checksums.

    Returns:
    Tuple containing two lists:
    - List of files to copy from the image to the machine.
    - List of files to be deleted in the machine.
    """
    replace_file_mach_by_file_img = []
    file_missing_in_mach = []
    file_supp_in_mach = []
    # il y aura 1 ou plusieurs fichier a supprimer dans l'agent.
    # search fiichier devenu inutile
    for namefichier in frommachine:
        if namefichier in fromimg:
            # fichier dans les 2 cotes
            # on verifie si on doit remplacer:
            if frommachine[namefichier] != fromimg[namefichier]:
                # on doit le remplacer
                replace_file_mach_by_file_img.append(namefichier)
        else:
            file_supp_in_mach.append(namefichier)
    for namefichier in fromimg:
        if namefichier not in frommachine:
            file_missing_in_mach.append(namefichier)
    # The missing files in the machines need to be added too.
    fichier_to_copie = list(replace_file_mach_by_file_img)
    fichier_to_copie.extend(file_missing_in_mach)
    return fichier_to_copie, file_supp_in_mach


def dump_file_in_img(objectxmpp, namescript, content, typescript):
    """
    Dumps the given script content into the appropriate directory based on its type.

    Parameters:
    objectxmpp (object): The XMPP object containing information about the agent and its image directory.
    namescript (str): The name of the script file to be dumped.
    content (bytes): The binary content of the script file to be written.
    typescript (str): The type of the script, which determines the subdirectory where the file will be saved.
                      Valid types are "program_agent", "script_agent", and "lib_agent".

    Behavior:
    - Determines the correct directory based on the `typescript`.
    - Writes the `content` to the file named `namescript` in the determined directory.
    - Logs the operation details.
    - Updates the remote agent if the fingerprint matches the descriptor master fingerprint.
    - Logs an error if the `typescript` is invalid or if there is a failure in writing the file.

    Raises:
    - Logs an error if the file cannot be written due to any exception.
    """

    valid_types = {
        "program_agent": objectxmpp.img_agent,
        "script_agent": os.path.join(objectxmpp.img_agent, "script"),
        "lib_agent": os.path.join(objectxmpp.img_agent, "lib"),
    }

    if typescript in valid_types:
        directory = valid_types[typescript]
        file_name = os.path.join(directory, namescript)
        
        # DEBUG: Tracer l'opération
        logger.info("[UPDATE] Writing %s file: %s (size=%d bytes)" % (typescript, namescript, len(content)))
        logger.debug("[UPDATE-DEBUG] Full path: %s" % file_name)
        logger.debug("[UPDATE-DEBUG] Directory exists: %s, writable: %s" % (
            os.path.exists(directory),
            os.access(directory, os.W_OK) if os.path.exists(directory) else "N/A"
        ))

        try:
            # Créer le répertoire s'il n'existe pas
            if not os.path.exists(directory):
                logger.info("[UPDATE] Creating directory: %s" % directory)
                os.makedirs(directory, exist_ok=True)
            
            # Écrire le fichier
            with open(file_name, "wb") as filescript:
                filescript.write(content)
            
            # Vérifier que le fichier a bien été écrit
            file_exists = os.path.exists(file_name)
            file_size = os.path.getsize(file_name) if file_exists else 0
            logger.info("[UPDATE] File written successfully: %s (verified size=%d bytes)" % (namescript, file_size))
            
            if not file_exists or file_size != len(content):
                logger.error("[UPDATE] WARNING: File size mismatch! Expected %d, got %d" % (len(content), file_size))
                return

            # Mettre à jour le descripteur de l'image
            logger.debug("[UPDATE] Computing new image fingerprint...")
            newobjdescriptorimage = update_remote_agent.Update_Remote_Agent(
                objectxmpp.img_agent
            )
            new_fingerprint = newobjdescriptorimage.get_fingerprint_agent_base()
            master_fingerprint = objectxmpp.descriptor_master.get("fingerprint", "UNKNOWN")
            
            logger.info("[UPDATE] Fingerprint comparison: image=%s vs master=%s" % (
                new_fingerprint[:16] + "..." if len(new_fingerprint) > 16 else new_fingerprint,
                master_fingerprint[:16] + "..." if len(master_fingerprint) > 16 else master_fingerprint
            ))
            
            if new_fingerprint == master_fingerprint:
                logger.info("[UPDATE] Fingerprint MATCHED! Calling reinstall_agent()...")
                try:
                    objectxmpp.reinstall_agent()
                    logger.info("[UPDATE] Agent reinstall completed successfully")
                except Exception as reinstall_err:
                    logger.error("[UPDATE] Error during reinstall_agent(): %s" % str(reinstall_err))
                    logger.error("[UPDATE] Traceback: %s" % traceback.format_exc())
            else:
                logger.warning("[UPDATE] Fingerprint MISMATCH - agent will not be updated yet")
                logger.debug("[UPDATE] Waiting for remaining files...")
        except Exception as e:
            logger.error("[UPDATE] CRITICAL: Failed to write file %s: %s" % (file_name, str(e)))
            logger.error("[UPDATE] Exception traceback:\n%s" % traceback.format_exc())
    else:
        logger.error("[UPDATE] Invalid file type: %s (valid: program_agent, script_agent, lib_agent)" % typescript)


def senddescriptormd5(objectxmpp, data):
    """
    Send the MD5 descriptor of the agent's base to the specified machine for an update.

    Parameters:
    - objectxmpp: The XMPP object representing the current agent.
    - data (dict): Data containing information about the update request, including the target machine's JID.

    Returns:
    None
    """
    objectxmpp.Update_Remote_Agentbase = update_remote_agent.Update_Remote_Agent(
        objectxmpp.config.diragentbase
    )
    descriptoragentbase = objectxmpp.Update_Remote_Agentbase.get_md5_descriptor_agent()
    datasend = {
        "action": "updateagent",
        "data": {
            "subaction": "descriptor",
            "descriptoragent": descriptoragentbase,
            "ars_update": data["ars_update"],
        },
        "ret": 0,
        "sessionid": utils.getRandomName(5, "updateagent"),
    }
    # Send catalog of files.
    logger.debug("Send descriptor to agent [%s] for update" % data["jidagent"])
    objectxmpp.send_message(data["jidagent"], mbody=json.dumps(datasend), mtype="chat")
