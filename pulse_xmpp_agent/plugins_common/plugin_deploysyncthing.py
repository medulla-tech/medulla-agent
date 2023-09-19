# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2016-2023 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-3.0-or-later

import sys
import os
import logging
import json
import traceback
from lib import utils, managepackage
from slixmpp import jid

plugin = {"VERSION": "2.02", "VERSIONAGENT": "2.1", "NAME": "deploysyncthing", "TYPE": "all"}  # fmt: skip

logger = logging.getLogger()
DEBUGPULSEPLUGIN = 25


@set_logging_level
def action(objectxmpp, action, sessionid, data, message, dataerreur):
    logger.debug("###################################################")
    logger.debug("call %s from %s" % (plugin, message["from"]))
    logger.debug("sessionid : %s" % sessionid)
    logger.debug("###################################################")
    data["sessionid"] = sessionid
    datastring = json.dumps(data, indent=4)
    logger.debug("data in : %s" % datastring)
    if objectxmpp.config.agenttype in ["machine"]:
        try:
            objectxmpp.config.syncthing_on
        except NameError:
            objectxmpp.config.syncthing_on = False
        if not objectxmpp.config.syncthing_on:
            logger.warning(
                "configuration syncthing off"
                " on %s: sessionid : %s" % (sessionid, objectxmpp.boundjid.bare)
            )
        logger.debug("#################AGENT MACHINE#####################")
        if "subaction" in data:
            logger.debug("subaction : %s" % data["subaction"])
            if data["subaction"] == "notify_machine_deploy_syncthing":
                if not objectxmpp.config.syncthing_on:
                    objectxmpp.xmpplog(
                        "<span class='log_err'>"
                        "Syncthing is disabled"
                        "We cannot deploy using this method</span>",
                        type="deploy",
                        sessionname=sessionid,
                        priority=-1,
                        action="xmpplog",
                        who="",
                        how="",
                        why=objectxmpp.boundjid.bare,
                        module="Deployment | Syncthing",
                        date=None,
                        fromuser="",
                        touser="",
                    )
                    objectxmpp.xmpplog(
                        "DEPLOYMENT TERMINATE",
                        type="deploy",
                        sessionname=sessionid,
                        priority=-1,
                        action="xmpplog",
                        who=objectxmpp.boundjid.bare,
                        how="",
                        why="",
                        module="Deployment | Terminate" " | Notify | Syncthing",
                        date=None,
                        fromuser="",
                        touser="",
                    )
                    data["jidrelay"] = "%s" % message["from"]
                    signalendsessionforARS(data, objectxmpp, sessionid, error=True)
                    return

                objectxmpp.syncthing.get_db_completion(
                    data["id_deploy"], objectxmpp.syncthing.device_id
                )
                # savedata fichier sessionid.ars
                namesessionidars = os.path.join(
                    objectxmpp.dirsyncthing, "%s.ars" % sessionid
                )
                utils.file_put_contents(namesessionidars, datastring)
                logger.debug("Creating file %s" % namesessionidars)
                objectxmpp.xmpplog(
                    "Creating ars file %s" % namesessionidars,
                    type="deploy",
                    sessionname=sessionid,
                    priority=-1,
                    action="xmpplog",
                    who="",
                    how="",
                    why=objectxmpp.boundjid.bare,
                    module="Deployment | Syncthing",
                    date=None,
                    fromuser="",
                    touser="",
                )
            elif data["subaction"] == "cleandeploy":
                if not objectxmpp.config.syncthing_on:
                    return
                # TODO: this action will be implemented
                # call suppression partage syncthing
                if "iddeploy" in data:
                    logger.debug("Delete share %s if exist" % data["iddeploy"])
                    objectxmpp.syncthing.delete_folder_pulse_deploy(data["iddeploy"])
                    # call function nettoyage old partage files.
            elif data["subaction"] == "create_partage":
                dataobjpartage = data["objpartage"]
                data["ARS"] = str(message["from"])
                sharedFolder = os.path.join(
                    objectxmpp.getsyncthingroot(), dataobjpartage["repertoiredeploy"]
                )
                if not os.path.exists(sharedFolder):
                    os.makedirs(sharedFolder)
                    utils.file_put_contents(os.path.join(sharedFolder, ".stfolder"), "")
                    if sys.platform.startswith("linux") or sys.platform.startswith(
                        "darwin"
                    ):
                        cmd = "chown -R pulseuser:pulseuser %s" % sharedFolder
                        utils.simplecommand(cmd)
                newfolder = objectxmpp.syncthing.create_template_struct_folder(
                    dataobjpartage["repertoiredeploy"],
                    sharedFolder,
                    id=dataobjpartage["repertoiredeploy"],
                    typefolder="slave",
                )
                msg = "Folder partage  %s " "package %s machine %s" % (
                    sharedFolder,
                    dataobjpartage["packagedeploy"],
                    objectxmpp.boundjid.bare,
                )
                logger.info(msg)
                objectxmpp.xmpplog(
                    msg,
                    type="deploy",
                    sessionname=sessionid,
                    priority=-1,
                    action="xmpplog",
                    why=objectxmpp.boundjid.bare,
                    module="Deployment | Syncthing",
                    date=None,
                    fromuser="",
                    touser="",
                )
                objectxmpp.syncthing.add_folder_dict_if_not_exist_id(newfolder)
                # create device ars et add this device as folder
                devicenamelist = []
                logger.debug("******** CREATION DEVICES SHARE ARS *********")
                for ars in dataobjpartage["cluster"]["arslist"]:
                    if ars != '""' or ars != "":
                        if str(jid.JID(ars).domain) == "pulse":
                            name = "pulse"
                        else:
                            name = str(jid.JID(ars).user)
                        devicenamelist.append(name)
                        msglog = "ADD DEVICE ARS %s device id : %s" % (
                            name,
                            dataobjpartage["cluster"]["arslist"][ars],
                        )
                        logger.debug(msglog)
                        try:
                            objectxmpp.syncthing.add_device_syncthing(
                                dataobjpartage["cluster"]["arslist"][ars],
                                name,
                                address=dataobjpartage["cluster"]["arsip"][ars],
                            )
                        except Exception:
                            logger.error("error %s" % (traceback.format_exc()))

                        msg = "ADD DEVICE ARS %s in folder %s" % (
                            dataobjpartage["cluster"]["arslist"][ars],
                            dataobjpartage["repertoiredeploy"],
                        )

                        objectxmpp.syncthing.add_device_in_folder_if_not_exist(
                            dataobjpartage["repertoiredeploy"],
                            dataobjpartage["cluster"]["arslist"][ars],
                            introducedBy="",
                        )
                        logger.debug(msg)

                # create device machine partage and add this device in folder
                logger.debug("******** CREATION DEVICES SHARE MACHINE *********")
                for machine in dataobjpartage["machines"]:
                    if str(jid.JID(machine["mach"]).bare) == str(
                        objectxmpp.boundjid.bare
                    ):
                        # TODO: See if we need to add the machines' device in
                        # the share
                        continue
                    try:
                        namemachine = str(jid.JID(machine["mach"]).user)[:-4]
                        if namemachine != "":
                            msglog = "CREATE DEVICE MACHINE %s deviceid %s" % (
                                namemachine,
                                machine["devi"],
                            )
                            logger.debug(msglog)
                            devicenamelist.append(namemachine)
                            objectxmpp.syncthing.add_device_syncthing(
                                machine["devi"], namemachine
                            )
                            msglog = (
                                "***ADD THIS DEVICE MACHINE IN FOLDER %s ***"
                                % dataobjpartage["repertoiredeploy"]
                            )
                            logger.debug(msglog)
                            objectxmpp.syncthing.add_device_in_folder_if_not_exist(
                                dataobjpartage["repertoiredeploy"],
                                machine["devi"],
                                introducedBy="",
                            )
                        else:
                            objectxmpp.xmpplog(
                                "<span class='log_err'>"
                                "Syncthing id device "
                                "missing for machine %s</span>" % namemachine,
                                type="deploy",
                                sessionname=sessionid,
                                priority=-1,
                                action="xmpplog",
                                why=objectxmpp.boundjid.bare,
                                module="Deployment | Syncthing",
                                date=None,
                            )
                            objectxmpp.xmpplog(
                                "DEPLOYMENT TERMINATE",
                                type="deploy",
                                sessionname=sessionid,
                                priority=-1,
                                action="xmpplog",
                                who=objectxmpp.boundjid.bare,
                                module="Deployment | Terminate" " | Notify | Syncthing",
                                date=None,
                            )
                    except Exception:
                        messageerror = "remote error%s" % (traceback.format_exc())
                        logger.error(messageerror)
                        objectxmpp.xmpplog(
                            "<span class='log_err'>"
                            "Create Syncthing Share"
                            "%s\n%s </span>" % (namemachine, messageerror),
                            type="deploy",
                            sessionname=machine["ses"],
                            priority=-1,
                            action="xmpplog",
                            why=objectxmpp.boundjid.bare,
                            module="Deployment | Syncthing",
                            date=None,
                        )
                        objectxmpp.xmpplog(
                            "DEPLOYMENT TERMINATE",
                            type="deploy",
                            sessionname=machine["ses"],
                            priority=-1,
                            action="xmpplog",
                            who=objectxmpp.boundjid.bare,
                            module="Deployment | Terminate" " | Notify | Syncthing",
                            date=None,
                        )
                msgpartage = "sharing folder  %s " "package %s between (%s)" % (
                    sharedFolder,
                    dataobjpartage["packagedeploy"],
                    ", ".join(devicenamelist),
                )
                objectxmpp.xmpplog(
                    msgpartage,
                    type="deploy",
                    sessionname=sessionid,
                    priority=-1,
                    action="xmpplog",
                    why=objectxmpp.boundjid.bare,
                    module="Deployment | Syncthing",
                    date=None,
                )

                objectxmpp.syncthing.validate_chang_config()
                namesessionidars = os.path.join(
                    objectxmpp.dirsyncthing, "%s.ars" % sessionid
                )
                utils.file_put_contents(namesessionidars, datastring)
                logger.debug("Creating file %s" % namesessionidars)
                objectxmpp.xmpplog(
                    "Creating ars file %s" % namesessionidars,
                    type="deploy",
                    sessionname=sessionid,
                    priority=-1,
                    action="xmpplog",
                    why=objectxmpp.boundjid.bare,
                    module="Deployment | Syncthing",
                    date=None,
                )
        else:
            if not objectxmpp.config.syncthing_on:
                objectxmpp.xmpplog(
                    "<span class='log_err'>"
                    "Syncthing is disabled"
                    "We cannot deploy using this method</span>",
                    type="deploy",
                    sessionname=sessionid,
                    priority=-1,
                    action="xmpplog",
                    why=objectxmpp.boundjid.bare,
                    module="Deployment | Syncthing",
                    date=None,
                )
                objectxmpp.xmpplog(
                    "DEPLOYMENT TERMINATE",
                    type="deploy",
                    sessionname=sessionid,
                    priority=-1,
                    action="xmpplog",
                    who=objectxmpp.boundjid.bare,
                    module="Deployment | Terminate" " | Notify | Syncthing",
                    date=None,
                )
                data["jidrelay"] = "%s" % message["from"]
                signalendsessionforARS(data, objectxmpp, sessionid, error=True)
                return

            namesessioniddescriptor = os.path.join(
                objectxmpp.dirsyncthing, "%s.descriptor" % sessionid
            )
            utils.file_put_contents(namesessioniddescriptor, json.dumps(data, indent=4))
            logger.debug("creation file %s" % namesessioniddescriptor)
            objectxmpp.xmpplog(
                "Creating descriptor file %s" % namesessioniddescriptor,
                type="deploy",
                sessionname=sessionid,
                priority=-1,
                action="xmpplog",
                who="",
                how="",
                why=objectxmpp.boundjid.bare,
                module="Deployment | Syncthing",
                date=None,
                fromuser="",
                touser="",
            )
    else:
        try:
            logger.debug("##############AGENT RELAY SERVER###################")
            """ les devices des autre ARS sont connue, on initialise uniquement le folder."""
            basesyncthing = objectxmpp.getsyncthingroot()
            if not os.path.exists(basesyncthing):
                os.makedirs(basesyncthing)
            if "subaction" in data:
                logger.debug("subaction : %s" % data["subaction"])
                if data["subaction"] == "syncthingdeploycluster":
                    data1 = data["objpartage"]
                    packagedir = managepackage.managepackage.packagedir()
                    # Creation of the syncthing share files
                    sharedFolder = os.path.join(
                        basesyncthing, data1["repertoiredeploy"]
                    )
                    if not os.path.exists(sharedFolder):
                        os.makedirs(sharedFolder)
                    datasend = {
                        "action": "deploysyncthing",
                        "ret": 0,
                        "base64": False,
                        "data": {"subaction": "create_partage", "objpartage": data1},
                    }
                    folderreppart = os.path.join(sharedFolder, ".stfolder")
                    cmd = "touch %s" % (folderreppart)
                    logger.debug("cmd : %s" % cmd)
                    obj = utils.simplecommand(cmd)
                    if int(obj["code"]) != 0:
                        logger.warning(obj["result"])
                    list_of_deployment_packages = (
                        managepackage.search_list_of_deployment_packages(
                            data1["packagedeploy"]
                        ).search()
                    )
                    logger.warning("copy to sharedFolder")
                    # We copy the packages in the shared folder
                    for z in list_of_deployment_packages:
                        repsrc = os.path.join(packagedir, str(z))
                        cmd = "rsync -r %s %s/" % (repsrc, sharedFolder)
                        logger.debug("cmd : %s" % cmd)
                        obj = utils.simplecommand(cmd)
                        if int(obj["code"]) != 0:
                            logger.warning(obj["result"])
                        else:
                            objectxmpp.xmpplog(
                                "ARS %s share folder %s"
                                % (objectxmpp.boundjid.bare, sharedFolder),
                                type="deploy",
                                sessionname=sessionid,
                                priority=-1,
                                action="xmpplog",
                                who="",
                                how="",
                                why=objectxmpp.boundjid.bare,
                                module="Deployment | Syncthing",
                                date=None,
                                fromuser="",
                                touser="",
                            )
                    cmd = "chown syncthing-depl:syncthing-depl -R %s" % sharedFolder
                    logger.debug("cmd : %s" % cmd)
                    obj = utils.simplecommand(cmd)
                    if int(obj["code"]) != 0:
                        logger.warning(obj["result"])
                    # creation fichier .stfolder

                    # addition des devices. add device ARS si non exist.
                    # creation du partage pour cet
                    # typefolder="slave"
                    # if data1['cluster']['elected'] == objectxmpp.boundjid.bare:
                    # typefolder="all"
                    # else:
                    # typefolder="slave"
                    typefolder = "all"
                    # creation du folder
                    logger.info(
                        "******** CREATION FOLDER share %s for package %s*********"
                        % (sharedFolder, data1["packagedeploy"])
                    )
                    newfolder = objectxmpp.syncthing.create_template_struct_folder(
                        data1["repertoiredeploy"],
                        sharedFolder,
                        id=data1["repertoiredeploy"],
                        typefolder=typefolder,
                    )

                    objectxmpp.syncthing.add_folder_dict_if_not_exist_id(newfolder)

                    # add device cluster ars in new partage folder
                    # ajoute des tas de fois cette device dans le folder.
                    for keyclustersyncthing in data1["cluster"]["arslist"]:
                        if str(jid.JID(keyclustersyncthing).bare) == str(
                            objectxmpp.boundjid.bare
                        ):
                            continue
                        if keyclustersyncthing != '""' or keyclustersyncthing != "":
                            if str(jid.JID(keyclustersyncthing).domain) == "pulse":
                                name = "pulse"
                            else:
                                name = str(jid.JID(keyclustersyncthing).user)

                            msglog = "ADD DEVICE ARS %s device id : %s (%s)" % (
                                name,
                                data1["cluster"]["arslist"][keyclustersyncthing],
                                data1["cluster"]["arsip"][keyclustersyncthing],
                            )
                            logger.debug(msglog)
                            objectxmpp.xmpplog(
                                msglog,
                                type="deploy",
                                sessionname=sessionid,
                                priority=-1,
                                action="xmpplog",
                                why=objectxmpp.boundjid.bare,
                                module="Deployment | Syncthing",
                                date=None,
                            )
                            introducer = False
                            if data1["cluster"]["elected"] == objectxmpp.boundjid.bare:
                                introducer = True

                            objectxmpp.syncthing.add_device_syncthing(
                                data1["cluster"]["arslist"][keyclustersyncthing],
                                name,
                                introducer=introducer,
                                address=data1["cluster"]["arsip"][keyclustersyncthing],
                            )

                            logger.info("******** DEVICE ARS APPENNED*************")

                            msg = "ADD THIS DEVICE ARS %s in folder %s" % (
                                data1["cluster"]["arslist"][keyclustersyncthing],
                                data1["repertoiredeploy"],
                            )

                            objectxmpp.syncthing.add_device_in_folder_if_not_exist(
                                data1["repertoiredeploy"],
                                data1["cluster"]["arslist"][keyclustersyncthing],
                                introducedBy="",
                            )
                            logger.info(msg)
                            objectxmpp.xmpplog(
                                msglog,
                                type="deploy",
                                sessionname=sessionid,
                                priority=-1,
                                action="xmpplog",
                                why=objectxmpp.boundjid.bare,
                                module="Deployment | Syncthing",
                                date=None,
                            )

                            logger.info(
                                "******** ADD DEVICE ARS IN FOLDER %s *********"
                                % data1["repertoiredeploy"]
                            )
                            logger.info(
                                "ADD DEVICE ARS %s in folder %s"
                                % (
                                    data1["cluster"]["arslist"][keyclustersyncthing],
                                    data1["repertoiredeploy"],
                                )
                            )

                            objectxmpp.syncthing.add_device_in_folder_if_not_exist(
                                data1["repertoiredeploy"],
                                data1["cluster"]["arslist"][keyclustersyncthing],
                                introducedBy="",
                            )

                            logger.info(
                                "ADD DEVICE ARS %s in folder %s"
                                % (
                                    data1["cluster"]["arslist"][keyclustersyncthing],
                                    data1["repertoiredeploy"],
                                )
                            )

                            objectxmpp.syncthing.add_device_in_folder_if_not_exist(
                                data1["repertoiredeploy"],
                                data1["cluster"]["arslist"][keyclustersyncthing],
                                introducedBy="",
                            )

                    # add devices of the machines
                    logger.info("******** CREATION DEVICES SHARE MACHINE *********")
                    for machine in data1["machines"]:
                        try:
                            namemachine = str(jid.JID(machine["mach"]).user)[:-4]
                            if machine["devi"] != '""' or machine["devi"] != "":
                                msglog = "DEVICE MACHINE %s deviceid %s" % (
                                    namemachine,
                                    machine["devi"],
                                )
                                logger.debug(msglog)
                                objectxmpp.xmpplog(
                                    msglog,
                                    type="deploy",
                                    sessionname=machine["ses"],
                                    priority=-1,
                                    action="xmpplog",
                                    why=objectxmpp.boundjid.bare,
                                    module="Deployment | Syncthing",
                                    date=None,
                                )
                                objectxmpp.syncthing.add_device_syncthing(
                                    machine["devi"], namemachine
                                )
                                msglog = (
                                    "******** ADD THIS DEVICE MACHINE IN FOLDER %s *********"
                                    % data1["repertoiredeploy"]
                                )
                                logger.info(msglog)
                                objectxmpp.xmpplog(
                                    msglog,
                                    type="deploy",
                                    sessionname=machine["ses"],
                                    priority=-1,
                                    action="xmpplog",
                                    why=objectxmpp.boundjid.bare,
                                    module="Deployment | Syncthing",
                                    date=None,
                                )
                                objectxmpp.syncthing.add_device_in_folder_if_not_exist(
                                    data1["repertoiredeploy"],
                                    machine["devi"],
                                    introducedBy="",
                                )
                            else:
                                objectxmpp.xmpplog(
                                    "<span class='log_err'>"
                                    "Syncthing id device "
                                    "missing for machine %s</span>" % namemachine,
                                    type="deploy",
                                    sessionname=machine["ses"],
                                    priority=-1,
                                    action="xmpplog",
                                    why=objectxmpp.boundjid.bare,
                                    module="Deployment | Syncthing",
                                    date=None,
                                )
                                objectxmpp.xmpplog(
                                    "DEPLOYMENT TERMINATE",
                                    type="deploy",
                                    sessionname=machine["ses"],
                                    priority=-1,
                                    action="xmpplog",
                                    who=objectxmpp.boundjid.bare,
                                    module="Deployment | Terminate"
                                    " | Notify | Syncthing",
                                    date=None,
                                )
                            # Create message for machine Ici
                            datasend["sessionid"] = machine["ses"]
                            if data1["cluster"]["elected"] == objectxmpp.boundjid.bare:
                                logger.debug(
                                    "SEND ARS FILE SYNCTHING TO MACHINE %s"
                                    % machine["mach"]
                                )
                                objectxmpp.send_message(
                                    mto=machine["mach"],
                                    mbody=json.dumps(datasend),
                                    mtype="chat",
                                )

                        except Exception:
                            messageerror = "remote error%s" % (traceback.format_exc())
                            logger.error(messageerror)
                            objectxmpp.xmpplog(
                                "<span class='log_err'>"
                                "Create Syncthing Share"
                                "%s\n%s </span>" % (namemachine, messageerror),
                                type="deploy",
                                sessionname=machine["ses"],
                                priority=-1,
                                action="xmpplog",
                                why=objectxmpp.boundjid.bare,
                                module="Deployment | Syncthing",
                                date=None,
                            )
                            objectxmpp.xmpplog(
                                "DEPLOYMENT TERMINATE",
                                type="deploy",
                                sessionname=machine["ses"],
                                priority=-1,
                                action="xmpplog",
                                who=objectxmpp.boundjid.bare,
                                module="Deployment | Terminate" " | Notify | Syncthing",
                                date=None,
                            )
                    objectxmpp.syncthing.maxSendKbps(kb=0)
                    objectxmpp.syncthing.validate_chang_config()
                elif data["subaction"] == "cleandeploy":
                    objectxmpp.syncthing.maxSendKbps(kb=0)
                    # TODO: this action will be implemented
                    # call suppression partage syncthing
                    if "iddeploy" in data:
                        logger.debug("Delete partage %s if exist" % data["iddeploy"])
                        objectxmpp.syncthing.delete_folder_pulse_deploy(
                            data["iddeploy"]
                        )
                    messgagesend = {
                        "sessionid": sessionid,
                        "action": action,
                        "data": {
                            "subaction": "cleandeploy",
                            "iddeploy": data["iddeploy"],
                        },
                    }
                    machineslist = data["jidmachines"].split(",")
                    relayslist = data["jidrelays"].split(",")
                    nbrelaylist = len(relayslist)
                    for index_relay_mach in range(nbrelaylist):
                        if relayslist[index_relay_mach] == objectxmpp.boundjid.full:
                            # send message machine
                            logger.debug(
                                "send Delete partage %s on mach %s"
                                % (data["iddeploy"], machineslist[index_relay_mach])
                            )
                            logger.debug(
                                "send delete floder to machine %s"
                                % machineslist[index_relay_mach]
                            )
                            objectxmpp.send_message(
                                mto=machineslist[index_relay_mach],
                                mbody=json.dumps(messgagesend),
                                mtype="chat",
                            )
                elif data["subaction"] == "pausefolder":
                    if "folder" in data:
                        objectxmpp.syncthing.maxSendKbps(kb=1)
        except BaseException:
            logger.error("\n%s" % (traceback.format_exc()))
            raise


# syncthing function


def is_exist_folder_id(idfolder, config):
    for folder in config["folders"]:
        if folder["id"] == idfolder:
            return True
    return False


def add_folder_dict_if_not_exist_id(dictaddfolder, config):
    if not is_exist_folder_id(dictaddfolder["id"], config):
        config["folders"].append(dictaddfolder)
        return True
    return False


def add_device_in_folder_if_not_exist(folderid, keydevice, config, introducedBy=""):
    result = False
    for folder in config["folders"]:
        if folderid == folder["id"]:
            # Folder trouve
            for device in folder["devices"]:
                if device["deviceID"] == keydevice:
                    # Device existe
                    result = False
            new_device = {"deviceID": keydevice, "introducedBy": introducedBy}
            folder["devices"].append(new_device)
            result = True
    return result


def add_device_syncthing(
    objctsycthing,
    keydevicesyncthing,
    namerelay,
    config,
    introducer=False,
    autoAcceptFolders=False,
    address=["dynamic"],
):
    for device in config["devices"]:
        if device["deviceID"] == keydevicesyncthing:
            result = False
    logger.debug("add device syncthing %s" % keydevicesyncthing)
    dsyncthing_tmp = objctsycthing.create_template_struct_device(
        namerelay,
        str(keydevicesyncthing),
        introducer=introducer,
        autoAcceptFolders=autoAcceptFolders,
        address=address,
    )

    logger.debug(
        "add device [%s]syncthing to ars %s\n%s"
        % (keydevicesyncthing, namerelay, json.dumps(dsyncthing_tmp, indent=4))
    )

    config["devices"].append(dsyncthing_tmp)
    return dsyncthing_tmp


def signalendsessionforARS(datasend, objectxmpp, sessionid, error=False):
    # Termine sessionid sur ARS pour permettre autre deploiement
    try:
        msgsessionend = {
            "action": "resultapplicationdeploymentjson",
            "sessionid": sessionid,
            "data": datasend,
            "ret": 255,
            "base64": False,
        }
        if error is False:
            msgsessionend["ret"] = 0
        datasend["endsession"] = True
        objectxmpp.send_message(
            mto=datasend["jidrelay"], mbody=json.dumps(msgsessionend), mtype="chat"
        )
    except Exception as e:
        logger.debug(str(e))
        traceback.print_exc(file=sys.stdout)
