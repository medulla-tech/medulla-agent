# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2016-2024 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-3.0-or-later


import datetime
import time
import json
import traceback
import sys
import logging
import os
import re
import types
from lib.plugins.xmpp import XmppMasterDatabase
from lib.plugins.kiosk import KioskDatabase
from lib.plugins.msc import MscDatabase
from lib.plugins.glpi import Glpi
from lib.managepackage import managepackage
from lib.utils import (
    name_random,
    file_get_contents,
    file_put_contents,
    getRandomName,
    call_plugin,
    name_randomplus,
)
import base64

import ast

import random
from slixmpp import jid
import threading
from lib.managesession import session, clean_session
from distutils.version import LooseVersion, StrictVersion

if sys.version_info >= (3, 0, 0):
    basestring = (str, bytes)

logger = logging.getLogger()

plugin = {"VERSION": "1.0", "NAME": "resultkiosk", "TYPE": "substitute"}  # fmt: skip
PREFIX_COMMAND = "commandkiosk"


def action(xmppobject, action, sessionid, data, message, ret, dataobj):
    logger.debug("#################################################")
    logger.debug(plugin)
    logger.debug(json.dumps(data, indent=4))
    logger.debug("#################################################")
    compteurcallplugin = getattr(xmppobject, "num_call%s" % action)
    if compteurcallplugin == 0:
        read_conf_resultkiosk(xmppobject)

    if "subaction" in data:
        if data["subaction"] == "initialization":
            # kiosk ==(tcp/ip)==> agent machine
            # {
            #     "action":"kioskinterface",
            #     "subaction":"initialization"
            # }

            # == agent machine ==(xmpp)==> substitute master (plugin_resultkiosk) ==
            # {
            #     'subaction': 'initialization',
            #     'userlist': ['vagrant'],
            #     'ous': {
            #         'vagrant': {
            #             'ou_user': '',
            #             'ou_machine': '',
            #             'ou_groups': ''
            #         }
            #     }
            # }
            initialisekiosk(data, message, xmppobject)
        elif data["subaction"] == "launch":
            # kiosk ==(tcp/ip)==> agent machine
            # {
            #     "action":"kioskinterfaceLaunch",
            #     "uuid": "5c83c5e6-tcp_beab0z5bhgfqxesl3mlcc8h"
            # }

            # == agent machine ==(xmpp)==> substitute master (plugin_resultkiosk) ==
            #  {
            #     "uuid": "5c83c5e6-tcp_beab0z5bhgfqxesl3mlcc8h",
            #     "subaction": "launch"
            # }

            deploypackage(data, message, xmppobject, sessionid)
        elif data["subaction"] == "delete":
            # kiosk ==(tcp/ip)==> agent machine
            # {
            #     "action":"kioskinterfaceDelete",
            #     "uuid": "8622d48c-VLC_q4sz0uppu5f850rnkkifykn",
            #     "utcdatetime":"(2024, 02, 26, 15, 53)" # optionnal
            # }

            # == agent machine ==(xmpp)==> substitute master (plugin_resultkiosk) ==
            # {
            #     "uuid": "8622d48c-VLC_q4sz0uppu5f850rnkkifykn",
            #     "utcdatetime":"(2024, 02, 26, 15, 53)", # optionnal
            #     "subaction": "delete"
            # }
            deploypackage(data, message, xmppobject, sessionid)
        elif data["subaction"] == "install":
            # kiosk ==(tcp/ip)==> agent machine
            # {
            #     "action":"kioskinterfaceInstall",
            #     "utcdatetime":"(2024, 02, 26, 15, 53)",
            #     "uuid": "5c83c5e6-tcp_beab0z5bhgfqxesl3mlcc8h"
            # }

            # == agent machine ==(xmpp)==> substitute master (plugin_resultkiosk) ==
            # {
            #     "subaction":"install",
            #     "utcdatetime":"(2024, 02, 26, 15, 53)",
            #     "uuid": "5c83c5e6-tcp_beab0z5bhgfqxesl3mlcc8h"
            # }
            deploypackage(data, message, xmppobject, sessionid)
        elif data["subaction"] == "update":
            # kiosk ==(tcp/ip)==> agent machine
            # {
            #     "action":"kioskinterfaceUpdate",
            #     "utcdatetime":"(2024, 02, 26, 15, 53)", # optionnal
            #     "uuid": "5c83c5e6-tcp_beab0z5bhgfqxesl3mlcc8h"
            # }

            # == agent machine ==(xmpp)==> substitute master (plugin_resultkiosk) ==
            # {
            #     "subaction":"update",
            #     "utcdatetime":"(2024, 02, 26, 15, 53)", # optionnal
            #     "uuid": "5c83c5e6-tcp_beab0z5bhgfqxesl3mlcc8h"
            # }

            deploypackage(data, message, xmppobject, sessionid)
        elif data["subaction"] == "presence":
            machine = XmppMasterDatabase().getMachinefromjid(message["from"])
            if "id" in machine:
                result = XmppMasterDatabase().updatemachine_kiosk_presence(
                    machine["id"], data["value"]
                )
        elif data["subaction"] == "ask":
            machine = XmppMasterDatabase().getMachinefromjid(message["from"])
            profiles = []
            if machine is not None:
                OUmachine = [
                    machine["ad_ou_machine"]
                    .replace("\n", "")
                    .replace("\r", "")
                    .replace("@@", "/")
                ]
                OUuser = [
                    machine["ad_ou_user"]
                    .replace("\n", "")
                    .replace("\r", "")
                    .replace("@@", "/")
                ]
                OU = [elem for elem in set(OUmachine + OUuser) if elem != ""]
                profiles = KioskDatabase().add_askacknowledge(
                    OU, data["uuid"], data["askuser"]
                )
        else:
            logger.warning("Subaction %s not recognize" % data["subaction"])
    else:
        logger.warning("No subaction found in agent machine query")


def initialisekiosk(data, message, xmppobject):
    try:
        machine = XmppMasterDatabase().getMachinefromjid(message["from"])
        # Update ous for the userlist in data["userlist"]
        if "userlist" in data:
            for user in data["userlist"]:
                if "ous" in data:
                    ou_user = data["ous"][user]["ou_user"]
                    ou_machine = data["ous"][user]["ou_machine"]
                    ou_group = data["ous"][user]["ou_groups"]
                    logger.debug("call updatemachineAD from plugin_resultkiosk")
                    XmppMasterDatabase().updatemachineAD(
                        machine["id"], user, ou_machine, ou_user
                    )

        initializationdatakiosk = handlerkioskpresence(
            xmppobject,
            message["from"],
            machine["id"],
            machine["platform"],
            machine["hostname"],
            machine["uuid_inventorymachine"],
            machine["agenttype"],
            classutil=machine["classutil"],
            fromplugin=True,
        )
    except Exception as e:
        logger.error(e)


def data_struct_message(action, data={}, ret=0, base64=False, sessionid=None):
    if sessionid is None or sessionid == "" or not isinstance(sessionid, basestring):
        sessionid = action.strip().replace(" ", "")
    return {
        "action": action,
        "data": data,
        "ret": 0,
        "base64": False,
        "sessionid": getRandomName(4, sessionid),
    }


def handlerkioskpresence(
    xmppobject,
    jid,
    id,
    os,
    hostname,
    uuid_inventorymachine,
    agenttype,
    classutil,
    fromplugin=False,
    showinfobool=True,
):
    """
    This function launch the kiosk actions when a prensence machine is active
    """
    if showinfobool:
        logger.info("kiosk handled")
    # print jid, id, os, hostname, uuid_inventorymachine, agenttype, classutil
    # get the profiles from the table machine.
    try:
        machine = XmppMasterDatabase().getMachinefromjid(jid)
    except:
        logger.error("Impossible to find the machine")

    try:
        structuredatakiosk = get_packages_for_machine(machine, showinfobool=showinfobool)
    except:
        logger.error("impossible to find packages for the machine %s"%jid)

    datas = {"subaction": "initialisation_kiosk", "data": structuredatakiosk}
    message_to_machine = data_struct_message(
        "kiosk",
        data=datas,
        ret=0,
        base64=False,
        sessionid=getRandomName(6, "initialisation_kiosk"),
    )
    xmppobject.send_message(mto=jid, mbody=json.dumps(message_to_machine), mtype="chat")
    return datas


def get_packages_for_machine(machine, showinfobool=True):
    """Get a list of the packages for the concerned machine.
    Param:
        machine : dict of the machine datas.
        Data structure:
        { "ad_ou_machine":"somethine", "ad_ou_user": "something", "hostname":"machine-name", "uuid_inventorymachine":"UUID1"}
    Returns:
        list of the packages"""

    try:
        machine_entity = XmppMasterDatabase().getmachineentityfromjid(machine["jid"])

        machine_entity = (
            machine_entity.complete_name.replace(" > ", "/")
            if machine_entity is not None
            else None
        )
    except Exception as e:
        logging.getLogger().error(e)
    OUmachine = (
        machine["ad_ou_machine"].replace("\n", "").replace("\r", "").replace("@@", "/")
    )
    OUuser = (
        machine["ad_ou_user"].replace("\n", "").replace("\r", "").replace("@@", "/")
    )
    group = XmppMasterDatabase().get_ad_group_for_lastuser(machine["lastuser"])

    if OUmachine == "":
        OUmachine = None
    if OUuser == "":
        OUuser == None

    ldap = get_ou_for_user(machine["lastuser"])
    ldap = None if ldap is False else ldap

    _sources = {
        "ou_machine": OUmachine,
        "ou_user": OUuser,
        "ldap": ldap,
        "group": group,
        "entity": machine_entity,
    }

    # remove empty values and delete the temp _sources variable
    sources = {key: _sources[key] for key in _sources if _sources[key] != None}

    # we find all profiles with the specified sources
    profiles = KioskDatabase().get_profiles_by_sources(sources)

    # search packages for the applied profiles
    list_profile_packages = KioskDatabase().get_profile_list_for_profiles_list(profiles)
    if list_profile_packages is None:
        return []

    granted_packages = []
    for element in list_profile_packages:
        granted_packages += KioskDatabase().get_acknowledges_for_package_profile(
            element[9], element[6], machine["lastuser"]
        )
    list_software_glpi = []
    softwareonmachine = Glpi().getLastMachineInventoryPart(
        machine["uuid_inventorymachine"],
        "Softwares",
        0,
        -1,
        "",
        {"hide_win_updates": True, "history_delta": ""},
    )
    for x in softwareonmachine:
        list_software_glpi.append([x[0][1], x[1][1], x[2][1]])

    structuredatakiosk = []

    # Create structuredatakiosk for initialization
    for packageprofile in list_profile_packages:
        toappend = __search_software_in_glpi(
                list_software_glpi, granted_packages, packageprofile
            )
        structuredatakiosk.append(toappend)
    logger.debug(
        "initialisation kiosk %s on machine %s"
        % (structuredatakiosk, machine["hostname"])
    )

    return structuredatakiosk


def __search_software_in_glpi(list_software_glpi, list_granted_packages, packageprofile):
    structuredatakioskelement = {
        "name": packageprofile[0],
        "action": [],
        "uuid": packageprofile[6],
        "description": packageprofile[2],
        "version": packageprofile[3],
        "profile": packageprofile[1],
    }
    patternname = re.compile(
        "(?i)"
        + packageprofile[4]
        .replace("+", "\+")
        .replace("*", "\*")
        .replace("(", "\(")
        .replace(")", "\)")
        .replace(".", "\.")
    )
    for soft_glpi in list_software_glpi:
        if (
            patternname.match(str(soft_glpi[0]))
            or patternname.match(str(soft_glpi[1]))
            or (soft_glpi[1] == packageprofile[4] and soft_glpi[2] == packageprofile[5])
        ):
            # Process with this package which is installed on the machine
            # The package could be deleted
            structuredatakioskelement["icon"] = "kiosk.png"
            structuredatakioskelement["action"].append("Delete")
            structuredatakioskelement["action"].append("Launch")
            # verification if update
            # compare the version
            # TODO
            # For now we use the package version. Later the software version will be needed into the pulse package
            if LooseVersion(soft_glpi[2]) < LooseVersion(packageprofile[3]):
                structuredatakioskelement["action"].append("Update")
                logger.debug(
                    "the software version is superior "
                    "to that installed on the machine %s : %s < %s"
                    % (packageprofile[0], soft_glpi[2], LooseVersion(packageprofile[3]))
                )
            break
    if len(structuredatakioskelement["action"]) == 0:
        # The package defined for this profile is absent from the machine:
        if packageprofile[8] == "allowed":
            structuredatakioskelement["action"].append("Install")
        else:
            trigger = False
            for ack in list_granted_packages:
                if ack["package_uuid"] == structuredatakioskelement["uuid"]:
                    if ack["id_package_has_profil"] != packageprofile[9]:
                        continue
                    else:
                        if ack["status"] == "allowed":
                            structuredatakioskelement["action"].append("Install")
                        elif ack["status"] == "waiting":
                            trigger = True
                        elif ack["status"] == "rejected":
                            trigger = True
                else:
                    continue

            if len(structuredatakioskelement["action"]) == 0 and trigger is False:
                structuredatakioskelement["action"].append("Ask")
    return structuredatakioskelement


#### ancine plugin master resultkiosk
def parsexmppjsonfile(path):
    datastr = file_get_contents(path)

    datastr = re.sub(r"(?i) *: *false", " : false", datastr)
    datastr = re.sub(r"(?i) *: *true", " : true", datastr)

    file_put_contents(path, datastr)


def str_to_date_str(date_str):
    # Analyser la chaîne en tant que tuple
    date_tuple = ast.literal_eval(date_str)
    # Convertir le tuple en objet datetime
    date_obj = datetime.datetime(*date_tuple)
    # Formater la date en tant que chaîne de caractères
    date_str = date_obj.strftime("%Y-%m-%d %H:%M:%S")
    return date_str


def str_to_datetime(date_str):
    # Utiliser strptime pour convertir la chaîne en objet datetime
    date_obj = datetime.datetime.strptime(date_str, "%Y-%m-%d %H:%M:%S")
    return date_obj


def deploypackage(data, message, xmppobject, sessionid):
    try:
        machine = XmppMasterDatabase().getMachinefromjid(message["from"])
        logging.getLogger().error(json.dumps(machine, indent=4))

        # Get the actual timestamp in utc format
        current_date = datetime.datetime.now()
        # current_date = current_date.replace(tzinfo=pytz.UTC)
        section = ""

        if "utcdatetime" in data:
            install_date = str_to_datetime(str_to_date_str(data["utcdatetime"]))
            # date_str = data["utcdatetime"].replace("(", "")
            # date_str = date_str.replace(")", "")
            # date_list_tmp = date_str.split(",")
            # date_list = []
            # for element in date_list_tmp:
            # date_list.append(int(element))

            # sent_datetime = datetime.datetime(
            # date_list[0],
            # date_list[1],
            # date_list[2],
            # date_list[3],
            # date_list[4],
            # 0,
            # 0,
            # pytz.UTC,
            # )
            # install_date = utc2local(sent_datetime)

        else:
            install_date = current_date

        # nameuser = "(kiosk):%s/%s" % (machine["lastuser"], machine["hostname"])
        nameuser = machine["lastuser"]
        if data["subaction"] == "install":
            section = '"section":"install"'
        elif data["subaction"] == "delete":
            section = '"section":"uninstall"'
        elif data["subaction"] == "update":
            section = '"section":"update"'
        else:
            section = '"section":"install"'

        package = managepackage.getdescriptorpackageuuid(data["uuid"])
        path = managepackage.getpathpackagebyuuid(data["uuid"])
        if package is None:
            logger.error(
                "deploy %s on %s  error : xmppdeploy.json missing"
                % (data["uuid"], machine["hostname"])
            )
            return None
        name = package['info']['name']

        _section = section.split(":")[1]

        command = MscDatabase().createcommanddirectxmpp(
            data["uuid"],
            "",
            section,
            "malistetodolistfiles",
            "enable",
            "enable",
            install_date,
            install_date + datetime.timedelta(hours=1),
            nameuser,
            nameuser,
            package["info"]["name"] + "-@kiosk@-" + " : " + _section,
            60,
            4,
            0,
            "",
            None,
            None,
            None,
            "none",
            "active",
            "1",
            cmd_type=0,
        )
        commandid = command.id
        commandstart = command.start_date
        commandstop = command.end_date
        jidrelay = machine["groupdeploy"]
        uuidmachine = machine["uuid_inventorymachine"]
        jidmachine = machine["jid"]
        try:
            target = MscDatabase().xmpp_create_Target(uuidmachine, machine["hostname"])

        except Exception as e:
            traceback.print_exc(file=sys.stdout)

        idtarget = target["id"]

        MscDatabase().xmpp_create_CommandsOnHost(
            commandid, idtarget, machine["hostname"], commandstop, commandstart
        )

        # Write advanced parameter for the deployment
        XmppMasterDatabase().addlogincommand(
            nameuser, commandid, "", "", "", "", section, 0, 0, 0, 0, {}
        )

        sessionid = name_random(5, "deploykiosk_")

        descript = package
        objdeployadvanced = XmppMasterDatabase().datacmddeploy(commandid)
        if not objdeployadvanced:
            logger.error(
                "The line has_login_command for the idcommand %s is missing" % commandid
            )
            logger.error("To solve this, please remove the group, and recreate it")
        datasend = {
            "name": name,
            "login": nameuser,
            "idcmd": commandid,
            "advanced": objdeployadvanced,
            "methodetransfert": "pushrsync",
            "path": path,
            "packagefile": os.listdir(path),
            "jidrelay": jidrelay,
            "jidmachine": jidmachine,
            "jidmaster": xmppobject.boundjid.bare,
            "iprelay": XmppMasterDatabase().ipserverARS(jidrelay)[0],
            "ippackageserver": XmppMasterDatabase().ippackageserver(jidrelay)[0],
            "portpackageserver": XmppMasterDatabase().portpackageserver(jidrelay)[0],
            "ipmachine": XmppMasterDatabase().ipfromjid(jidmachine)[0],
            "ipmaster": xmppobject.config.Server,
            "Dtypequery": "TQ",
            "Devent": "DEPLOYMENT START",
            "uuid": uuidmachine,
            "descriptor": descript,
            "transfert": True,
        }
        # run deploy

        sessionid = xmppobject.send_session_commandkiosk(
            jidrelay,
            "applicationdeploymentjsonkiosk",
            datasend,
            datasession=None,
            encodebase64=False,
            prefix="commandkiosk",
        )
        # add deploy in table.
        XmppMasterDatabase().adddeploy(
            commandid,
            machine["jid"],  # jidmachine
            machine["groupdeploy"],  # jidrelay,
            machine["hostname"],  # host,
            machine["uuid_inventorymachine"],  # inventoryuuid,
            data["uuid"],  # uuidpackage,
            "DEPLOYMENT START",  # state,
            sessionid,  # id session,
            nameuser,  # user
            nameuser,  # login
            name
            + "-@kiosk@-"
            + " "
            + commandstart.strftime("%Y/%m/%d/ %H:%M:%S"),  # title,
            "",  # group_uuid
            commandstart,  # startcmd
            commandstop,  # endcmd
            machine["macaddress"],
        )

        # Convert install_date to timestamp and send it to logs
        timestamp_install_date = int(time.mktime(install_date.timetuple()))
        xmppobject.xmpplog(
            "Start deploy on machine %s" % jidmachine,
            type="deploy",
            sessionname=sessionid,
            priority=-1,
            action="",
            who=nameuser,
            how="",
            why=xmppobject.boundjid.bare,
            module="Deployment | Start | Creation",
            date=timestamp_install_date,
            fromuser=nameuser,
            touser="",
        )
    except Exception as e:
        logging.getLogger().error("\n%s" % (traceback.format_exc()))


def exist_objet(obj, attribut):
    return hasattr(obj, attribut)


def read_conf_resultkiosk(xmppobject):
    try:
        logger.debug("#################################################")
        logger.debug(
            "#######################read_conf_resultkiosk##########################"
        )
        logger.debug("#################################################")
        logger.debug(hasattr(xmppobject, "send_session_commandkiosk"))
        logger.debug(hasattr(xmppobject, "directcallpluginkiosk"))
        # -------------------------- add object dynamique --------------------------
        if not exist_objet(xmppobject, "sessiondeploysubstitute"):
            xmppobject.sessiondeploysubstitute = session("sessiondeploysubstitute")
        if not exist_objet(xmppobject, "machineDeploy"):
            xmppobject.machineDeploy = {}
        if not exist_objet(xmppobject, "hastable"):
            xmppobject.hastable = {}

        # -------------------------- add code dynamique --------------------------
        if not hasattr(xmppobject, "send_session_commandkiosk"):
            xmppobject.send_session_commandkiosk = types.MethodType(
                send_session_commandkiosk, xmppobject
            )

        if not hasattr(xmppobject, "directcallpluginkiosk"):
            xmppobject.directcallpluginkiosk = types.MethodType(
                directcallpluginkiosk, xmppobject
            )

        if not hasattr(xmppobject, "callpluginsubstitutekiosk"):
            xmppobject.callpluginsubstitutekiosk = types.MethodType(
                callpluginsubstitutekiosk, xmppobject
            )

        if not hasattr(
            xmppobject, "applicationdeployjsonUuidMachineAndUuidPackagekiosk"
        ):
            xmppobject.applicationdeployjsonUuidMachineAndUuidPackagekiosk = (
                types.MethodType(
                    applicationdeployjsonUuidMachineAndUuidPackagekiosk, xmppobject
                )
            )

        if not hasattr(xmppobject, "applicationdeployjsonuuidkiosk"):
            xmppobject.applicationdeployjsonuuidkiosk = types.MethodType(
                applicationdeployjsonuuidkiosk, xmppobject
            )

        if not hasattr(xmppobject, "applicationdeploymentjsonkiosk"):
            xmppobject.applicationdeploymentjsonkiosk = types.MethodType(
                applicationdeploymentjsonkiosk, xmppobject
            )

        if not hasattr(xmppobject, "totimestampkiosk"):
            xmppobject.totimestampkiosk = types.MethodType(totimestampkiosk, xmppobject)

    except Exception as e:
        logger.error("%s" % (traceback.format_exc()))


def totimestampkiosk(self, dt, epoch=None):
    if epoch is None:
        epoch = datetime.datetime(1970, 1, 1)
    td = dt - epoch
    return (td.microseconds + (td.seconds + td.days * 86400) * 10**6) / 10**6


def str_to_timestamp(date_str):
    # Use strptime to convert the string to datetime object
    date_obj = datetime.strptime(date_str, "%Y-%m-%d %H:%M:%S")
    # Use timestamp() method to get Unix timestamp
    timestamp = date_obj.timestamp()
    return int(timestamp)  # convert to int if needed


def applicationdeploymentjsonkiosk(
    self,
    jidrelay,
    jidmachine,
    idcommand,
    login,
    name,
    time,
    encodebase64=False,
    uuidmachine="",
    start_date=None,
    end_date=None,
    title=None,
    macadress=None,
    GUID=None,
    keysyncthing="",
    nbdeploy=-1,
    wol=0,
    msg=[],
):
    """For a deployment
    1st action: synchronizes the previous package name
    The package is already on the machine and also in relay server.
    """

    logger.debug("PARAMETER jidrelay (%s)" % (jidrelay))
    logger.debug("PARAMETER jidmachine (%s)" % (jidmachine))
    logger.debug("PARAMETER idcommand (%s)" % (idcommand))
    logger.debug("PARAMETER login (%s)" % (login))
    logger.debug("PARAMETER name (%s)" % (name))
    logger.debug("PARAMETER time (%s)" % (time))
    logger.debug("PARAMETER encodebase64 (%s)" % (encodebase64))
    logger.debug("PARAMETER uuidmachine (%s)" % (uuidmachine))
    logger.debug("PARAMETER start_date (%s)" % (start_date))
    logger.debug("PARAMETER end_date (%s)" % (end_date))
    logger.debug("PARAMETER title (%s)" % (title))
    logger.debug("PARAMETER macadress (%s)" % (macadress))
    logger.debug("PARAMETER GUID (%s)" % (GUID))
    logger.debug("PARAMETER keysyncthing (%s)" % (keysyncthing))
    logger.debug("PARAMETER nbdeploy (%s)" % (nbdeploy))
    logger.debug("PARAMETER wol (%s)" % (wol))
    logger.debug("PARAMETER msg (%s)" % (msg))

    deploymenttype = "deploy"
    if "-@upd@-" in title:
        sessiondeployementless = name_random(5, "arsdeployupdate")
        deploymenttype = "update"
        prefixcommanddeploy = "update"
    else:
        prefixcommanddeploy = "command"
        if PREFIX_COMMAND in globals():
            prefixcommanddeploy = PREFIX_COMMAND
        sessiondeployementless = name_random(5, prefixcommanddeploy)

    if managepackage.getversionpackageuuid(name) is None:
        logger.error("Deployment error package name or version missing for %s" % (name))
        msg.append(
            "<span class='log_err'>Package name or version missing for %s</span>"
            % (name)
        )
        msg.append("Action : check the package %s" % name)
        XmppMasterDatabase().adddeploy(
            idcommand,
            jidmachine,
            jidrelay,
            name,
            uuidmachine,
            title,
            "ABORT PACKAGE VERSION MISSING",
            sessiondeployementless,
            user=login,
            login=login,
            title=title,
            group_uuid=GUID,
            startcmd=start_date,
            endcmd=end_date,
            macadress=macadress,
            result="",
            syncthing=0,
        )
        for logmsg in msg:
            self.xmpplog(
                logmsg,
                type=deploymenttype,
                sessionname=sessiondeployementless,
                priority=-1,
                action="xmpplog",
                why=self.boundjid.bare,
                module="Deployment | Start | Creation",
                fromuser=login,
            )
        return False
    # Name the event
    path = managepackage.getpathpackagebyuuid(name)
    if path is None:
        msg.append(
            "<span class='log_err'>Package name missing in package %s</span>" % (name)
        )
        msg.append("Action : check the package %s" % (name))
        XmppMasterDatabase().adddeploy(
            idcommand,
            jidmachine,
            jidrelay,
            name,
            uuidmachine,
            title,
            "ABORT PACKAGE NAME MISSING",
            sessiondeployementless,
            user=login,
            login=login,
            title=title,
            group_uuid=GUID,
            startcmd=start_date,
            endcmd=end_date,
            macadress=macadress,
            result="",
            syncthing=0,
        )
        for logmsg in msg:
            self.xmpplog(
                logmsg,
                type=deploymenttype,
                sessionname=sessiondeployementless,
                priority=-1,
                action="xmpplog",
                why=self.boundjid.bare,
                module="Deployment | Start | Creation",
                fromuser=login,
            )
        logger.error("package Name missing (%s)" % (name))
        return False
    descript = managepackage.loadjsonfile(os.path.join(path, "xmppdeploy.json"))

    if descript is None:
        XmppMasterDatabase().adddeploy(
            idcommand,
            jidmachine,
            jidrelay,
            name,
            uuidmachine,
            title,
            "ABORT DESCRIPTOR MISSING",
            sessiondeployementless,
            user=login,
            login=login,
            title=title,
            group_uuid=GUID,
            startcmd=start_date,
            endcmd=end_date,
            macadress=macadress,
            result="",
            syncthing=0,
        )
        msg.append(
            "<span class='log_err'>Descriptor xmppdeploy.json "
            "missing for %s [%s]</span>" % (name, uuidmachine)
        )
        msg.append("Action : Find out why xmppdeploy.json file is missing.")
        for logmsg in msg:
            self.xmpplog(
                logmsg,
                type=deploymenttype,
                sessionname=sessiondeployementless,
                priority=-1,
                action="xmpplog",
                why=self.boundjid.bare,
                module="Deployment | Start | Creation",
                fromuser=login,
            )
        logger.error(
            "Deployment %s on %s  error : xmppdeploy.json missing" % (name, uuidmachine)
        )
        return False
    objdeployadvanced = XmppMasterDatabase().datacmddeploy(idcommand)

    if not objdeployadvanced:
        logger.error(
            "The line has_login_command for the idcommand %s is missing" % idcommand
        )
        logger.error("To solve this, please remove the group, and recreate it")

    if (
        jidmachine is not None
        and jidmachine != ""
        and jidrelay is not None
        and jidrelay != ""
    ):
        userjid = jid.JID(jidrelay).user
        iprelay = XmppMasterDatabase().ipserverARS(userjid)[0]
        ippackageserver = XmppMasterDatabase().ippackageserver(userjid)[0]
        portpackageserver = XmppMasterDatabase().portpackageserver(userjid)[0]
    else:
        iprelay = ""
        ippackageserver = ""
        portpackageserver = ""
        wol = 3
    data = {
        "name": name,
        "login": login,
        "idcmd": idcommand,
        "advanced": objdeployadvanced,
        "stardate": str_to_timestamp(start_date),
        "enddate": str_to_timestamp(end_date),
        "methodetransfert": "pushrsync",
        "path": path,
        "packagefile": os.listdir(path),
        "jidrelay": jidrelay,
        "jidmachine": jidmachine,
        "jidmaster": self.boundjid.bare,
        "iprelay": iprelay,
        "ippackageserver": ippackageserver,
        "portpackageserver": portpackageserver,
        "ipmachine": XmppMasterDatabase().ipfromjid(jidmachine, None)[0],
        "ipmaster": self.config.Server,
        "Dtypequery": "TQ",
        "Devent": "DEPLOYMENT START",
        "uuid": uuidmachine,
        "descriptor": descript,
        "transfert": True,
        "nbdeploy": nbdeploy,
    }
    # data = {
    # "name": name,
    # "login": login,
    # "idcmd": idcommand,
    # "advanced": objdeployadvanced,
    # "stardate": self.totimestampkiosk(start_date),
    # "enddate": self.totimestampkiosk(end_date),
    # "methodetransfert": "pushrsync",
    # "path": path,
    # "packagefile": os.listdir(path),
    # "jidrelay": jidrelay,
    # "jidmachine": jidmachine,
    # "jidmaster": self.boundjid.bare,
    # "iprelay": iprelay,
    # "ippackageserver": ippackageserver,
    # "portpackageserver": portpackageserver,
    # "ipmachine": XmppMasterDatabase().ipfromjid(jidmachine, None)[0],
    # "ipmaster": self.config.Server,
    # "Dtypequery": "TQ",
    # "Devent": "DEPLOYMENT START",
    # "uuid": uuidmachine,
    # "descriptor": descript,
    # "transfert": True,
    # "nbdeploy": nbdeploy,
    # }
    # TODO on verify dans la table syncthing machine
    # si il n'y a pas un partage syncthing en cour pour cette machine
    # si c'est la cas on ignore cette machine car deja en deploy.
    # res = XmppMasterDatabase().deploy_machine_partage_exist( jidmachine,
    # descript['info']['packageUuid'])
    # if len(res) > 0:
    # print "il existe 1 deployement de ce package [%s]"\
    # sur la machine [%s]"%(descript['info']['packageUuid'],
    # jidmachine)
    # logger.debug("il existe 1 deployement de ce package [%s]"\
    # sur la machine [%s]"%(descript['info']['packageUuid'],
    # jidmachine))
    # return

    # TODO: rattacher 1 deployement d'un package d'une machine si partage syncthing sur cluster existe deja pour d'autre machines.
    # res = XmppMasterDatabase().getnumcluster_for_ars(jidrelay)

    # ici on peut savoir si c'est 1 groupe et si syncthing est demande
    if wol == 3:
        state = "GROUP DEPLOY MISSING"
        data["wol"] = 2
        data["mac"] = macadress  # use macadress for WOL
        sessionid = self.createsessionfordeploydiffered(data, prefixcommanddeploy)
        result = json.dumps(data, indent=4)
        msg.append("Machine %s is ready for deployment" % jidmachine)
    if wol == 2:
        state = "DEPLOY TASK SCHEDULED"
        data["wol"] = 2
        data["mac"] = macadress  # use macadress for WOL
        sessionid = self.createsessionfordeploydiffered(data, prefixcommanddeploy)
        result = json.dumps(data, indent=4)
        msg.append("Machine %s is ready for deployment" % jidmachine)
    elif wol == 1:
        state = "WOL 1"
        data["wol"] = 1
        data["mac"] = macadress  # use macadress for WOL
        sessionid = self.createsessionfordeploydiffered(data, prefixcommanddeploy)
        result = json.dumps(data, indent=4)
        msg.append("First WOL sent to machine %s" % uuidmachine)
        msg.append("Ping machine %s" % jidmachine)
        pingdata = json.dumps(
            {
                "action": "ping",
                "ret": 0,
                "sessionid": name_random(5, "ping"),
                "data": {"ping": True},
            }
        )
        self.send_message(mto=jidmachine, mbody=pingdata, mtype="chat")
    else:
        state = "DEPLOYMENT START"
        data["wol"] = 0
        if (
            data["advanced"]
            and data["advanced"]["grp"] is not None
            and "syncthing" in data["advanced"]
            and data["advanced"]["syncthing"] == 1
            and nbdeploy > 2
        ):
            # deploiement avec syncthing
            # call plugin preparesyncthing on master or assesseur master
            # addition session
            # send deploy descriptor to machine
            sessionid = self.send_session_commandkiosk(
                jidmachine,
                "deploysyncthing",
                data,
                datasession=None,
                encodebase64=False,
                prefix=prefixcommanddeploy,
            )
            result = json.dumps(data, indent=4)
            msg.append("Starting peer deployment on machine %s" % jidmachine)
        else:
            msg.append(
                "Starting deployment on machine %s from ARS %s" % (jidmachine, jidrelay)
            )
            if data["advanced"] and data["advanced"]["syncthing"] == 1:
                msg.append(
                    "<span class='log_warn'>There are not enough machines "
                    "to deploy in peer mode</span>"
                )

            data["advanced"]["syncthing"] = 0
            result = None

            if self.send_hash is True:
                try:
                    self.mutexdeploy.acquire()
                    if data["name"] in self.hastable:
                        if (self.hastable[data["name"]] + 10) > time:
                            del self.hastable[data["name"]]
                    if not data["name"] in self.hastable:
                        if (
                            "localisation_server" in data["descriptor"]["info"]
                            and data["descriptor"]["info"]["localisation_server"] != ""
                        ):
                            localisation_server = data["descriptor"]["info"][
                                "localisation_server"
                            ]
                        elif (
                            "previous_localisation_server" in data["descriptor"]["info"]
                            and data["descriptor"]["info"][
                                "previous_localisation_server"
                            ]
                            != ""
                        ):
                            localisation_server = data["descriptor"]["info"][
                                "previous_localisation_server"
                            ]
                        else:
                            localisation_server = "global"

                        dest_not_hash = (
                            "/var/lib/pulse2/packages/sharing/"
                            + localisation_server
                            + "/"
                            + data["name"]
                        )
                        dest = (
                            "/var/lib/pulse2/packages/hash/"
                            + localisation_server
                            + "/"
                            + data["name"]
                        )

                        if not os.path.exists(dest_not_hash):
                            XmppMasterDatabase().adddeploy(
                                idcommand,
                                jidmachine,
                                jidrelay,
                                name,
                                uuidmachine,
                                title,
                                "ABORT DESCRIPTOR INFO MISSING",
                                sessiondeployementless,
                                user=login,
                                login=login,
                                title=title,
                                group_uuid=GUID,
                                startcmd=start_date,
                                endcmd=end_date,
                                macadress=macadress,
                                result="",
                                syncthing=0,
                            )
                            msg.append(
                                "<span class='log_err'>Destination package not find, localisation server must be missing in descriptor for %s [%s]</span>"
                                % (name, uuidmachine)
                            )
                            logger.error(
                                "Deployment %s on %s error : destination package not find, localisation server must be missing in descriptor "
                                % (name, uuidmachine)
                            )
                            return False

                        need_hash = False
                        counter_no_hash = 0
                        counter_hash = 0

                        for file_not_hashed in os.listdir(dest_not_hash):
                            counter_no_hash += 1

                        if not os.path.exists(dest):
                            need_hash = True
                        else:
                            if len(os.listdir(dest)) == 0:
                                need_hash = True
                            else:
                                filelist = os.listdir(dest)
                                for file_package in filelist:
                                    file_package_no_hash = file_package.replace(
                                        ".hash", ""
                                    )
                                    counter_hash += 1
                                    if counter_hash == counter_no_hash:
                                        if os.path.getmtime(
                                            dest + "/" + file_package
                                        ) < os.path.getmtime(
                                            dest_not_hash + "/" + file_package_no_hash
                                        ):
                                            need_hash = True
                            if counter_hash != counter_no_hash:
                                need_hash = True

                        if need_hash == True:
                            generate_hash(
                                localisation_server,
                                data["name"],
                                self.hashing_algo,
                                data["packagefile"],
                                self.keyAES32,
                            )
                        self.hastable[data["name"]] = time
                except Exception:
                    logger.error("%s" % (traceback.format_exc()))
                finally:
                    self.mutexdeploy.release()
                content = ""
                try:
                    with open(dest + ".hash", "rb") as infile:
                        content += infile.read()
                        data["hash"] = {}
                        data["hash"]["global"] = content
                        data["hash"]["type"] = self.hashing_algo

                except Exception as e:
                    logger.error(
                        "Pulse is configured to check integrity of packages but the hashes have not been generated"
                    )
                    logger.error(str(e))
                    msg.append(
                        "<span class='log_err'>Pulse is configured to check integrity of packages but the hashes have not been generated</span>"
                    )
                    sessiondeployementless = name_random(5, "hashmissing")
                    sessionid = sessiondeployementless
                    state = "ERROR HASH MISSING"

            if state != "ERROR HASH MISSING":
                sessionid = self.send_session_commandkiosk(
                    jidrelay,
                    "applicationdeploymentjsonkiosk",
                    data,
                    datasession=None,
                    encodebase64=False,
                    prefix=prefixcommanddeploy,
                )

    if wol >= 1:
        advancedparameter_syncthing = 0
    else:
        advancedparameter_syncthing = data["advanced"]["syncthing"]
    for msglog in msg:
        self.xmpplog(
            msglog,
            type="deploy",
            sessionname=sessionid,
            priority=-1,
            action="xmpplog",
            why=self.boundjid.bare,
            module="Deployment | Start | Creation",
            date=None,
            fromuser=data["login"],
        )
    XmppMasterDatabase().adddeploy(
        idcommand,
        jidmachine,
        jidrelay,
        jidmachine,
        uuidmachine,
        descript["info"]["name"],
        state,
        sessionid,
        user="",
        login=login,
        title=title,
        group_uuid=GUID,
        startcmd=start_date,
        endcmd=end_date,
        macadress=macadress,
        result=result,
        syncthing=advancedparameter_syncthing,
    )
    if "syncthing" not in data["advanced"] or data["advanced"]["syncthing"] == 0:
        XmppMasterDatabase().addcluster_resources(
            jidmachine,
            jidrelay,
            jidmachine,
            sessionid,
            login=login,
            startcmd=start_date,
            endcmd=end_date,
        )
    return sessionid


def applicationdeployjsonuuidkiosk(
    self,
    uuidmachine,
    name,
    idcommand,
    login,
    time,
    encodebase64=False,
    uuidpackage="",
    start_date=None,
    end_date=None,
    title=None,
    macadress=None,
    GUID=None,
    nbdeploy=-1,
    wol=0,
):
    try:
        deploymenttype = "deploy"
        if "-@upd@-" in title:
            sessiondeployementless = name_random(5, "arsdeployupdate")
            deploymenttype = "update"
            prefixcommanddeploy = "update"
        else:
            prefixcommanddeploy = "command"
            if PREFIX_COMMAND in globals():
                prefixcommanddeploy = PREFIX_COMMAND
            sessiondeployementless = name_random(5, prefixcommanddeploy)
        msg = []
        # search group deploy and jid machine
        objmachine = XmppMasterDatabase().getGuacamoleRelayServerMachineUuid(
            uuidmachine, None
        )
        if "error" in objmachine and objmachine["error"] == "MultipleResultsFound":
            logger.warning(
                "getGuacamoleRelayServerMachineUuid %s" % objmachine["error"]
            )
            dupplicate_machines = (
                XmppMasterDatabase().get_machine_with_dupplicate_uuidinventory(
                    uuidmachine, None
                )
            )
            logger.warning(
                "get_machine_with_dupplicate_uuidinventory %s" % dupplicate_machines
            )
            grparray = []
            jidarray = []
            keysyncthingarray = []

            for machine in dupplicate_machines:
                grparray.append(machine["groupdeploy"])
                jidarray.append(machine["jid"])
                keysyncthingarray.append(machine["keysyncthing"])

            grparray = list(set(grparray))
            jidarray = list(set(jidarray))
            keysyncthingarray = list(set(keysyncthingarray))
            jidrelay = ",".join(grparray)
            jidmachine = ",".join(jidarray)
            keysyncthing = ",".join(keysyncthingarray)
            raise Exception("MultipleResultsFound")

        jidrelay = objmachine["groupdeploy"]
        jidmachine = objmachine["jid"]
        keysyncthing = objmachine["keysyncthing"]
        if (
            jidmachine is not None
            and jidmachine != ""
            and jidrelay is not None
            and jidrelay != ""
        ):
            # There is an ARS for the deploiement.
            # We check if this ARS is online in the machine table.
            ARSsearch = XmppMasterDatabase().getMachinefromjid(jidrelay)
            if ARSsearch["enabled"] == 0:
                msg.append(
                    "<span class='log_err'>ARS %s for deployment is down.</span>"
                    % jidrelay
                )
                msg.append(
                    "Action : Either restart it or rerun the configurator "
                    "on the machine %s to use another ARS" % (name)
                )
                msg.append("Searching alternative ARS for deployment")
                # We need to check if there is an alternative in the cluster.
                # We check 1 available and online ARS in its cluster
                cluster = XmppMasterDatabase().clusterlistars(enabled=None)
                Found = False
                for i in range(1, len(cluster) + 1):
                    nbars = len(cluster[i]["listarscluster"])
                    if jidrelay in cluster[i]["listarscluster"]:
                        if nbars < 2:
                            msg.append(
                                "<span class='log_err'>No alternative ARS found</span>"
                            )
                            msg.append(
                                "Action : Either restart it or rerun the configurator "
                                "on the machine %s to use another ARS" % (name)
                            )
                            XmppMasterDatabase().adddeploy(
                                idcommand,
                                jidmachine,
                                jidrelay,
                                name,
                                uuidmachine,
                                title,
                                "ABORT RELAY DOWN",
                                sessiondeployementless,
                                user=login,
                                login=login,
                                title=title,
                                group_uuid=GUID,
                                startcmd=start_date,
                                endcmd=end_date,
                                macadress=macadress,
                                result="",
                                syncthing=0,
                            )
                            for logmsg in msg:
                                self.xmpplog(
                                    logmsg,
                                    type="deploy",
                                    sessionname=sessiondeployementless,
                                    priority=-1,
                                    action="xmpplog",
                                    why=self.boundjid.bare,
                                    module="Deployment | Start | Creation",
                                    fromuser=login,
                                )
                            logger.error(
                                "Deployment %s encountered an error on machine %s: ARS down"
                                % (name, uuidmachine)
                            )
                            return False
                        else:
                            cluster[i]["listarscluster"].remove(jidrelay)
                            nbars = len(cluster[i]["listarscluster"])
                            nbint = random.randint(0, nbars - 1)
                            arsalternative = cluster[i]["listarscluster"][nbint]

                            msg.append(
                                "<span class='log_err'>ARS %s for deployment is "
                                "down. Use alternative ARS for deployment %s. ARS "
                                " %s must be restarted</span>"
                                % (jidrelay, arsalternative, jidrelay)
                            )
                            jidrelay = arsalternative
                            ARSsearch = XmppMasterDatabase().getMachinefromjid(jidrelay)
                            if ARSsearch["enabled"] == 1:
                                Found = True
                                break

                if not Found:
                    sessiondeployementless = name_random(5, "commandkiosk")
                    XmppMasterDatabase().adddeploy(
                        idcommand,
                        jidmachine,
                        jidrelay,
                        name,
                        uuidmachine,
                        title,
                        "ABORT ALTERNATIVE RELAYS DOWN",
                        sessiondeployementless,
                        user=login,
                        login=login,
                        title=title,
                        group_uuid=GUID,
                        startcmd=start_date,
                        endcmd=end_date,
                        macadress=macadress,
                        result="",
                        syncthing=0,
                    )
                    msg.append("<span class='log_err'>Alternative ARS Down</span>")
                    msg.append("Action : check ARS cluster.")
                    for logmsg in msg:
                        self.xmpplog(
                            logmsg,
                            type="deploy",
                            sessionname=sessiondeployementless,
                            priority=-1,
                            action="xmpplog",
                            why=self.boundjid.bare,
                            module="Deployment | Start | Creation",
                            fromuser=login,
                        )
                    logger.error("Deployment error: ARS cluster unavailable")
                    return False
            else:
                Found = True
            # Run deploiement
            return self.applicationdeploymentjsonkiosk(
                jidrelay,
                jidmachine,
                idcommand,
                login,
                name,
                time,
                encodebase64=False,
                uuidmachine=uuidmachine,
                start_date=start_date,
                end_date=end_date,
                title=title,
                macadress=macadress,
                GUID=GUID,
                keysyncthing=keysyncthing,
                nbdeploy=nbdeploy,
                wol=wol,
                msg=msg,
            )
        else:
            sessiondeployementless = name_random(5, "command")
            XmppMasterDatabase().adddeploy(
                idcommand,
                jidmachine,
                jidrelay,
                name,
                uuidmachine,
                title,
                "ABORT INFO RELAY MISSING",
                sessiondeployementless,
                user=login,
                login=login,
                title=title,
                group_uuid=GUID,
                startcmd=start_date,
                endcmd=end_date,
                macadress=macadress,
                result="",
                syncthing=0,
            )
            msg.append(
                "<span class='log_err'>ARS for deployment is missing for machine %s </span>"
                % uuidmachine
            )
            msg.append("Action : The configurator must be restarted on the machine.")
            for logmsg in msg:
                self.xmpplog(
                    logmsg,
                    type="deploy",
                    sessionname=sessiondeployementless,
                    priority=-1,
                    action="xmpplog",
                    why=self.boundjid.bare,
                    module="Deployment | Start | Creation",
                    fromuser=login,
                )
            logger.error("The deploiement %s failed on %s" % (name, uuidmachine))
            return False
    except Exception as e:
        logger.error("We encountered the error: %s" % (str(e)))
        logger.error("The deploiement %s failed on %s" % (name, uuidmachine))

        if str(e) == "MultipleResultsFound":
            statusmsg = "ABORT DUPLICATE MACHINES"
        else:
            statusmsg = "ERROR UNKNOWN ERROR"

        XmppMasterDatabase().adddeploy(
            idcommand,
            jidmachine,
            jidrelay,
            name,
            uuidmachine,
            title,
            statusmsg,
            sessiondeployementless,
            user=login,
            login=login,
            title=title,
            group_uuid=GUID,
            startcmd=start_date,
            endcmd=end_date,
            macadress=macadress,
            result="",
            syncthing=0,
        )
        msg.append(
            "<span class='log_err'>Error creating deployment on machine[ %s ] "
            "[%s] package[%s]</span>" % (jidmachine, uuidmachine, name)
        )
        if str(e) == "MultipleResultsFound":
            msg.append(
                "<span class='log_err'>The following machines "
                "(%s) have the same GLPI ID: %s</span>" % (jidmachine, uuidmachine)
            )
        for logmsg in msg:
            self.xmpplog(
                logmsg,
                type="deploy",
                sessionname=sessiondeployementless,
                priority=-1,
                action="xmpplog",
                why=self.boundjid.bare,
                module="Deployment | Start | Creation",
                fromuser=login,
            )
        return False


def applicationdeployjsonUuidMachineAndUuidPackagekiosk(
    self,
    uuidmachine,
    uuidpackage,
    idcommand,
    login,
    time,
    encodebase64=False,
    start_date=None,
    end_date=None,
    macadress=None,
    GUID=None,
    title=None,
    nbdeploy=-1,
    wol=0,
):
    deploymenttype = "deploy"
    if "-@upd@-" in title:
        sessiondeployementless = name_random(5, "arsdeployupdate")
        deploymenttype = "update"
        prefixcommanddeploy = "update"
    else:
        sessiondeployementless = name_random(5, "command")
        prefixcommanddeploy = "command"
    msg = []
    name = uuidpackage
    if name is not None:
        return self.applicationdeployjsonuuidkiosk(
            str(uuidmachine),
            str(name),
            idcommand,
            login,
            time,
            start_date=start_date,
            end_date=end_date,
            macadress=macadress,
            GUID=GUID,
            title=title,
            nbdeploy=nbdeploy,
            wol=wol,
        )
    else:
        XmppMasterDatabase().adddeploy(
            idcommand,
            "%s____" % uuidmachine,
            "package %s" % uuidpackage,
            "error_name_package____",
            uuidmachine,
            title,
            "ABORT PACKAGE IDENTIFIER MISSING",
            sessiondeployementless,
            user=login,
            login=login,
            title=title,
            group_uuid=GUID,
            startcmd=start_date,
            endcmd=end_date,
            macadress=macadress,
            result="",
            syncthing=0,
        )
        msg.append(
            "<span class='log_err'>Package identifier misssing for %s</span>"
            % uuidpackage
        )
        msg.append("Action: Check the package %s" % (uuidpackage))
        for logmsg in msg:
            self.xmpplog(
                logmsg,
                type="deploy",
                sessionname=sessiondeployementless,
                priority=-1,
                action="xmpplog",
                why=self.boundjid.bare,
                module="Deployment | Start | Creation",
                date=None,
                fromuser=login,
            )
        logger.warning("%s package name missing" % uuidpackage)
        return False


def send_session_commandkiosk(
    self,
    jid,
    action,
    data={},
    datasession=None,
    encodebase64=False,
    time=20,
    eventthread=None,
    prefix=None,
):
    if prefix is None:
        prefix = "command"
    if datasession is None:
        datasession = {}
    command = {
        "action": action,
        "base64": encodebase64,
        "sessionid": name_randomplus(25, pref=prefix),
        "data": "",
    }
    if encodebase64:
        command["data"] = base64.b64encode(json.dumps(data))
    else:
        command["data"] = data

    datasession["data"] = data
    datasession["callbackcommand"] = "commandend"
    self.sessiondeploysubstitute.createsessiondatainfo(
        command["sessionid"], datasession=data, timevalid=time, eventend=eventthread
    )
    if action is not None:
        logging.debug("Send command and creation session")
        if jid == self.boundjid.bare:
            self.callpluginsubstitutekiosk(action, data, sessionid=command["sessionid"])
        else:
            self.send_message(mto=jid, mbody=json.dumps(command), mtype="chat")
    else:
        logging.debug("creation session")
    return command["sessionid"]


def callpluginsubstitutekiosk(self, plugin, data, sessionid=None):
    if sessionid is None:
        sessionid = getRandomName(5, plugin)
    msg = {}
    msg["from"] = self.boundjid.bare
    msg["body"] = json.dumps(
        {"action": plugin, "ret": 0, "sessionid": sessionid, "data": data}
    )
    self.directcallpluginkiosk(msg)


def directcallpluginkiosk(self, msg):
    try:
        dataobj = json.loads(msg["body"])
        if "action" in dataobj and dataobj["action"] != "" and "data" in dataobj:
            if "base64" in dataobj and (
                (isinstance(dataobj["base64"], bool) and dataobj["base64"] is True)
                or (
                    isinstance(dataobj["base64"], str)
                    and dataobj["base64"].lower() == "true"
                )
            ):
                mydata = json.loads(base64.b64decode(dataobj["data"]))
            else:
                mydata = dataobj["data"]
            if "sessionid" not in dataobj:
                dataobj["sessionid"] = "absent"
            if "ret" not in dataobj:
                dataobj["ret"] = 0
            try:
                logging.debug(
                    "Calling plugin %s from  %s" % (dataobj["action"], msg["from"])
                )
                msg["body"] = dataobj
                del dataobj["data"]
                dataerreur = {
                    "action": "result" + dataobj["action"],
                    "data": {"msg": "error plugin : " + dataobj["action"]},
                    "sessionid": dataobj["sessionid"],
                    "ret": 255,
                    "base64": False,
                }
                module = "%s/plugin_%s.py" % (self.modulepath, dataobj["action"])
                call_plugin(
                    module,
                    self,
                    dataobj["action"],
                    dataobj["sessionid"],
                    mydata,
                    msg,
                    dataerreur,
                )
            except TypeError:
                logging.error(
                    "TypeError: executing plugin %s %s"
                    % (dataobj["action"], sys.exc_info()[0])
                )
                logger.error("%s" % (traceback.format_exc()))

            except Exception as e:
                logging.error(
                    "Executing plugin (%s) %s %s"
                    % (msg["from"], dataobj["action"], str(e))
                )
                logger.error("%s" % (traceback.format_exc()))

    except Exception as e:
        logging.error("Message structure %s   %s " % (msg, str(e)))
        logger.error("%s" % (traceback.format_exc()))


def get_ou_for_user(user):
    """This function find the ou of the specified user.

    Params:
        string user name

    Returns:
        The string of the OU
        or
        returns False for some issues
    """
    return False
