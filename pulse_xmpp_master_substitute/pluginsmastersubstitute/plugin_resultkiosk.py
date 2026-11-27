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
import types
from lib.plugins.xmpp import XmppMasterDatabase
from lib.plugins.kiosk import send_packages
from lib.plugins.msc import MscDatabase
from lib.plugins.glpi import Glpi
from lib.managepackage import managepackage
from lib.utils import (
    name_random,
    getRandomName,
    call_plugin,
    name_randomplus,
)
import base64

import ast

from lib.managesession import session

if sys.version_info >= (3, 0, 0):
    basestring = (str, bytes)

logger = logging.getLogger()

plugin = {"VERSION": "1.9", "NAME": "resultkiosk", "TYPE": "substitute"}  # fmt: skip
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
            update_kiosk_presence(data, message, xmppobject)
        elif data["subaction"] == "inventory":
            last_inventory(data, message, xmppobject)

        else:
            logger.warning("Subaction %s not recognize" % data["subaction"])
    else:
        logger.warning("resultkiosk - No subaction found in agent machine query")


def initialisekiosk(data, message, xmppobject):
    try:
        machine = XmppMasterDatabase().getMachinefromjid(message["from"])
        # Update ous for the userlist in data["userlist"]
        if "userlist" in data:
            for user in data["userlist"]:
                if "ous" in data:
                    ou_user = data["ous"][user]["ou_user"]
                    ou_machine = data["ous"][user]["ou_machine"]
                    logger.debug("call updatemachineAD from plugin_resultkiosk")
                    XmppMasterDatabase().updatemachineAD(
                        machine["id"], user, ou_machine, ou_user
                    )

        send_packages(
            xmppobject,
            XmppMasterDatabase().getMachinefromjid(message["from"]),
            "initialisation_kiosk",
        )
    except Exception as e:
        logger.error(e)


def update_kiosk_presence(data, message, xmppobject):
    presence = data.get("value")
    if presence not in ("True", "False"):
        logger.warning(
            "resultkiosk - presence value %r from %s ignored"
            % (presence, message["from"])
        )
        return
    machine = XmppMasterDatabase().getMachinefromjid(message["from"])
    if not machine or "id" not in machine:
        logger.warning(
            "resultkiosk - presence from unknown machine %s" % message["from"]
        )
        return
    if machine["kiosk_presence"] == presence:
        return
    if XmppMasterDatabase().updatemachine_kiosk_presence(machine["id"], presence) != 1:
        return
    if presence == "True":
        send_packages(xmppobject, machine, "initialisation_kiosk")


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


def last_inventory(data, message, xmppobject):
    """Ask an inventory from the machine. Retrive the last inventory date for the machine. The ask inventory call is async, so it's normal if the inventory date is not updated.

    Args:
        data(dict): Data from the machine. Should contain the subaction "inventory".
        message(dict): The XMPP message from the machine. Should contain the "from" field with the machine JID.
        xmppobject: The XMPP object to send the message to the machine.

    Returns:
        str: The last inventory date for the machine, or None if not found."""

    machine = XmppMasterDatabase().getMachinefromjid(message["from"])
    logger.debug("Inventory date requested by %s" % message["from"])

    # Force inventory update
    callinventory(xmppobject, message["from"])
    # Add a tempo on inventory call to let the server breath.
    time.sleep(5)
    if machine and "uuid_inventorymachine" in machine:
        machine_uuid = machine["uuid_inventorymachine"]
        logger.debug("Machine found, uuid_inventorymachine=%s" % machine_uuid)

        try:
            last_inv = Glpi().getLastMachineInventoryPart(
                machine_uuid,
                "Summary",
                0,
                -1,
                "",
                {"hide_win_updates": True, "history_delta": ""},
            )
        except Exception:
            logger.error(
                "getLastMachineInventoryPart(Summary) raised:\n%s"
                % traceback.format_exc()
            )
            return None
        logger.debug(
            "getLastMachineInventoryPart(Summary) returned: %s" % last_inv
        )

        last_inventory_date = None
        for item in last_inv:
            for subitem in item:
                if subitem[0] == "Last Inventory Date":
                    last_inventory_date = subitem[1]
                    break
            if last_inventory_date:
                break

        if last_inventory_date:
            datas = {"subaction": "inventory", "data": last_inventory_date}

            message_to_machine = data_struct_message(
                "kiosk",
                data=datas,
                ret=0,
                base64=False,
                sessionid=getRandomName(6, "inventory"),
            )

            logger.debug(
                "Sending inventory date '%s' to %s"
                % (last_inventory_date, message["from"])
            )
            xmppobject.send_message(
                mto=message["from"], mbody=json.dumps(message_to_machine), mtype="chat"
            )

            return last_inventory_date
        else:
            logger.debug(
                "No 'Last Inventory Date' in Summary for machine %s "
                "-> nothing sent to the kiosk (stays N/A)" % machine_uuid
            )
            return None
    else:
        logger.debug(
            "Machine or uuid_inventorymachine not found for JID: %s "
            "-> nothing sent to the kiosk (stays N/A)" % message["from"]
        )
        return None


def str_to_date_str(date_str):
    # Analyser la chaine en tant que tuple
    date_tuple = ast.literal_eval(date_str)
    # Convertir le tuple en objet datetime
    date_obj = datetime.datetime(*date_tuple)
    # Formater la date en tant que chaine de caractaeres
    date_str = date_obj.strftime("%Y-%m-%d %H:%M:%S")
    return date_str


def str_to_datetime(date_str):
    # Utiliser strptime pour convertir la chaine en objet datetime
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
        name = package["info"]["name"]

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
            "applicationdeploymentjson",
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

    except Exception as e:
        logger.error("%s" % (traceback.format_exc()))


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


def callinventory(xmppobject, to):
    try:
        body = {
            "action": "inventory",
            "sessionid": getRandomName(5, "inventory"),
            "data": {"forced": "forced"},
        }
        xmppobject.send_message(mto=to, mbody=json.dumps(body), mtype="chat")
    except Exception:
        logger.error("\n%s" % (traceback.format_exc()))
