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

plugin = {"VERSION": "2.3", "VERSIONAGENT": "2.0", "NAME": "updateagent", "TYPE": "all", "waittingmax": 35, "waittingmin": 5}  # fmt: skip

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
                if (
                    len(difference["program_agent"]) != 0
                    or len(difference["lib_agent"]) != 0
                    or len(difference["script_agent"]) != 0
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
                    if (
                        objectxmpp.descriptor_master["fingerprint"]
                        == descriptorimage["fingerprint"]
                    ) and (
                        objectxmpp.descriptor_master["fingerprint"]
                        != descriptoragent["fingerprint"]
                    ):
                        # on peut mettre a jour l'agent suite a une suppression
                        # de fichier inutile
                        objectxmpp.reinstall_agent()
                    return
            except Exception as e:
                logger.error(str(e))
                logger.error("\n%s" % (traceback.format_exc()))
        elif data["subaction"] == "install_lib_agent":
            if not ("namescript" in data and data["namescript"] != ""):
                logger.error("update agent install lib name missing")
                return
            else:
                content = zlib.decompress(base64.b64decode(data["content"]))
                dump_file_in_img(objectxmpp, data["namescript"], content, "lib_agent")
        elif data["subaction"] == "install_program_agent":
            if not ("namescript" in data and data["namescript"] != ""):
                logger.error("update agent install program name missing")
                return
            else:
                content = zlib.decompress(base64.b64decode(data["content"]))
                dump_file_in_img(
                    objectxmpp, data["namescript"], content, "program_agent"
                )
        elif data["subaction"] == "install_script_agent":
            if not ("namescript" in data and data["namescript"] != ""):
                logger.error("updateagent install script name missing")
                return
            else:
                content = zlib.decompress(base64.b64decode(data["content"]))
                dump_file_in_img(
                    objectxmpp, data["namescript"], content, "script_agent"
                )
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
        "lib_agent": os.path.join(objectxmpp.img_agent, "lib")
    }

    if typescript in valid_types:
        file_name = os.path.join(valid_types[typescript], namescript)
        logger.debug("dump file %s to %s" % (namescript, file_name))

        # Write the content to the file
        try:
            with open(file_name, "wb") as filescript:
                filescript.write(content)
            
            # Update the remote agent
            newobjdescriptorimage = update_remote_agent.Update_Remote_Agent(
                objectxmpp.img_agent
            )
            if (
                newobjdescriptorimage.get_fingerprint_agent_base()
                == objectxmpp.descriptor_master["fingerprint"]
            ):
                objectxmpp.reinstall_agent()
        except Exception as e:
            logger.error("Failed to write file %s: %s" % (file_name, str(e)))
    else:
        logger.error("Invalid file type: %s" % typescript)


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
