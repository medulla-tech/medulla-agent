# -*- coding: utf-8 -*-
#
# (c) 2016-2020 siveo, http://www.siveo.net
#
# This file is part of Pulse 2, http://www.siveo.net
#
# Pulse 2 is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# Pulse 2 is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Pulse 2; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
# MA 02110-1301, USA.
#
# plugin register machine dans presence table xmpp.
#
# file pluginsmachine/plugin_load_agent_machine.py
#
"""
    Ce plugin install les plugins de codes necessaire au fonctionnement de l'agent machine dans des boucles événement différente. (Ce plugin doit etre appeler par le plugin start.
    (voir parametre pluginlist section [plugin] configuration agent)
    1) install serveur tcp/ip dans boucle événement asynio
           pugin TCP_IP command in/out
"""
import base64
import traceback
import os
import json
import logging
from slixmpp import jid
from lib import utils

import base64
import re
from distutils.version import LooseVersion
import configparser

# this import will be used later
import types

logger = logging.getLogger()
plugin = {"VERSION": "1.0", "NAME": "load_agent_machine", "VERSIONAGENT": "2.0.0", "TYPE": "all"}  # fmt: skip


def action(xmppobject, action, sessionid, data, msg, dataerreur):
    try:
        logger.debug("###################################################")
        logger.debug("call %s from %s" % (plugin, msg["from"]))
        logger.debug("###################################################")
        strjidagent = str(xmppobject.boundjid.bare)

        logger.debug("========================================================")
        logger.debug("call %s from %s" % (plugin, msg["from"]))
        logger.debug("=======================================================")
        compteurcallplugin = getattr(xmppobject, "num_call%s" % action)
        if compteurcallplugin == 0:
            logger.debug("===================== master_agent =====================")
            logger.debug("========================================================")
            read_conf_load_agent_machine(xmppobject)
            logger.debug("========================================================")
    except Exception as e:
        logger.error("Plugin load_agent_machine, we encountered the error %s" % str(e))
        logger.error("We obtained the backtrace %s" % traceback.format_exc())


def read_conf_load_agent_machine(xmppobject):
    logger.debug("Initializing plugin :% s " % plugin["NAME"])
    conf_filename = plugin["NAME"] + ".ini"

    logger.debug("Install fonction code specialiser agent machine")
    xmppobject.list_function_agent_name = []
    # ---------- install "get_list_function_dyn_agent_machine" --------
    xmppobject.list_function_agent_name.append("get_list_function_dyn_agent_machine")

    xmppobject.get_list_function_dyn_agent_machine = types.MethodType(
        get_list_function_dyn_agent_machine, xmppobject
    )

    # Install reception message
    xmppobject.handle_client_connection = types.MethodType(
        handle_client_connection, xmppobject
    )

    ### Create TCP/IP Server
    module = "%s/plugin_%s.py" % (xmppobject.modulepath, "__server_tcpip")

    logger.debug("module :% s " % module)
    try:
        utils.call_plugin(module, xmppobject, "__server_tcpip")
    except:
        logger.error(
            "We hit a backtrace in the read_conf_load_agent_machine function \n: %s"
            % (traceback.format_exc())
        )

    try:
        conffile_path = os.path.join(xmppobject.config.pathdirconffile, conf_filename)
        if not os.path.isfile(conffile_path):
            logger.warning(
                "The configuration file for the plugin %s is missing. \n It should be located in %s"
                % (plugin["NAME"], conffile_path)
            )
    except Exception as e:
        logger.error("We obtained the backtrace %s" % traceback.format_exc())


def get_list_function_dyn_agent_machine(self):
    logger.debug(
        "return list function install from this plugin : %s"
        % xmppobject.list_function_agent_name
    )
    return xmppobject.list_function_agent_name


def _minifyjsonstringrecv(strjson):
    strjson = "".join(
        [row.split("//")[0] for row in strjson.split("\n") if len(row.strip()) != 0]
    )
    regex = re.compile(r"[\n\r\t]")
    strjson = regex.sub("", strjson)
    # We protect the spaces in strings in the jsons
    reg = re.compile(r"""(\".*?\n?.*?\")|(\'.*?\n?.*?\')""")
    newjson = re.sub(
        reg,
        lambda x: '"%s"' % str(x.group(0)).strip("\"'").strip().replace(" ", "@@ESP@@"),
        strjson,
    )
    newjson = newjson.replace(" ", "")
    # We add the protected spaces
    newjson = newjson.replace("@@ESP@@", " ")
    # We remove errors often seen on the json files
    newjson = newjson.replace(",}", "}")
    newjson = newjson.replace("{,", "{")
    newjson = newjson.replace("[,", "[")
    newjson = newjson.replace(",]", "]")
    return newjson


def _test_type(value):
    if isinstance(value, bool) or isinstance(value, int) or isinstance(value, float):
        return value
    else:
        try:
            return int(value)
        except BaseException:
            try:
                return float(value)
            except BaseException:
                _value = value.lstrip(" ").strip(" ").lower().capitalize()
                if _value == "True":
                    return True
                elif _value == "False":
                    return False
                else:
                    return value


def _runjson(jsonf, level=0):
    if isinstance(jsonf, dict):
        msg = "%sdict" % (level * "  ")
        tmp = {}
        for element in jsonf:
            tmp[element] = _runjson(jsonf[element], level=level + 1)
        return tmp
    elif isinstance(jsonf, list):
        tmp = []
        for element in jsonf:
            tmp.append(_runjson(element, level=level + 1))
        return tmp
    else:
        tmp = _test_type(jsonf)
        return tmp


def handle_client_connection(self, msg):
    """
    traitement du message recu sur la socket
    """
    substitute_recv = ""
    try:
        logger.info("Received {}".format(msg))
        datasend = {
            "action": "resultkiosk",
            "sessionid": utils.getRandomName(6, "kioskGrub"),
            "ret": 0,
            "base64": False,
            "data": {},
        }

        if utils.isBase64(msg):
            msg = base64.b64decode(msg)
        try:
            _result = json.loads(_minifyjsonstringrecv(msg))
            result = _runjson(_result)
            logger.info("__Event network or kiosk %s" % json.dumps(result, indent=4))
        except ValueError as e:
            logger.error("Message socket is not json correct : %s" % (str(e)))
            return False, ""
        try:
            if "interface" in result:
                logger.debug("RECV NETWORK INTERFACE")

                BOOLFILECOMPLETREGISTRATION = os.path.join(
                    os.path.dirname(os.path.realpath(__file__)),
                    "..",
                    "BOOLFILECOMPLETREGISTRATION",
                )
                utils.file_put_contents(
                    BOOLFILECOMPLETREGISTRATION,
                    "Do not erase.\n"
                    "when re-recording, it will be of type 2. full recording.",
                )
                if self.config.alwaysnetreconf:
                    # politique reconfiguration sur chaque changement de
                    # network.
                    logger.warning(
                        "No network interface can replace the previous one. Agent reconfiguration needed to resume the service."
                    )
                    self.networkMonitor()
                    return True, {}

                if self.state.ensure("connected"):
                    # toujours connected.
                    self.md5reseau = ()
                    self.update_plugin()
                    return True, ""
                try:
                    self.config.ipxmpp
                except BaseException:
                    self.config.ipxmpp = getIpXmppInterface(
                        self.config.Server, self.config.Port
                    )
                if self.config.ipxmpp in result["removedinterface"]:
                    logger.info(
                        "The IP address used to contact the XMPP Server is: %s"
                        % self.config.ipxmpp
                    )
                    logger.info(
                        "__DETECT SUPP INTERFACE USED FOR CONNECTION AGENT MACHINE TO EJABBERD__"
                    )
                    logmsg = (
                        "The new network interface can replace the previous one. "
                        "The service will resume after restarting the agent"
                    )
                    if is_connectedServer(self.ipconnection, self.config.Port):
                        # We only do a restart
                        logger.warning(logmsg)
                        self.md5reseau = utils.refreshfingerprint()
                        self.restartBot()
                    else:
                        # We reconfigure all
                        # Activating the new interface can take a while.
                        time.sleep(15)
                        if is_connectedServer(
                            self.ipconnection,
                            self.config.Port,
                        ):
                            # We only do a restart
                            logger.warning(logmsg)
                            self.md5reseau = utils.refreshfingerprint()
                            self.restartBot()
                        else:
                            logger.warning(
                                "No network interface can replace the previous one. "
                                "Agent reconfiguration needed to resume the service."
                            )
                            self.networkMonitor()
                            pass
                else:
                    # detection si 1 seule interface presente or 127.0.0.1
                    if len(result["interface"]) < 2:
                        # il y a seulement l'interface 127.0.0.1
                        # dans ce cas on refait la total.
                        logger.warning(
                            "The new uniq network interface. "
                            "Agent reconfiguration needed to resume the service."
                        )
                        self.networkMonitor()
                    else:
                        logger.warning(
                            "The new network interface is directly usable. Nothing to do"
                        )
                        self.md5reseau = utils.refreshfingerprint()
                        self.update_plugin()
                return True, ""
        except Exception as e:
            logger.error("%s" % str(e))
            return False, ""
        # Manage message from tcp connection
        logger.debug("RECV FROM TCP/IP CLIENT")
        if "uuid" in result:
            datasend["data"]["uuid"] = result["uuid"]
        if "utcdatetime" in result:
            datasend["data"]["utcdatetime"] = result["utcdatetime"]
        if "action" in result:
            if result["action"] == "kioskinterface":
                # start kiosk ask initialization
                datasend["data"]["subaction"] = result["subaction"]
                datasend["data"]["userlist"] = list(
                    {users[0] for users in psutil.users()}
                )
                datasend["data"]["ouuser"] = organizationbyuser(
                    datasend["data"]["userlist"]
                )
                datasend["data"]["oumachine"] = organizationbymachine()
            elif result["action"] == "kioskinterfaceInstall":
                datasend["data"]["subaction"] = "install"
            elif result["action"] == "kioskinterfaceLaunch":
                datasend["data"]["subaction"] = "launch"
            elif result["action"] == "kioskinterfaceDelete":
                datasend["data"]["subaction"] = "delete"
            elif result["action"] == "kioskinterfaceUpdate":
                datasend["data"]["subaction"] = "update"
            elif result["action"] == "kioskLog":
                if "message" in result and result["message"] != "":
                    self.xmpplog(
                        result["message"],
                        type="noset",
                        sessionname="",
                        priority=0,
                        action="xmpplog",
                        who=self.boundjid.bare,
                        how="Planned",
                        why="",
                        module="Kiosk | Notify",
                        fromuser="",
                        touser="",
                    )
                    if "type" in result:
                        if result["type"] == "info":
                            logger.info(result["message"])
                        elif result["type"] == "warning":
                            logger.warning(result["message"])
            elif result["action"] == "notifysyncthing":
                datasend["action"] = "notifysyncthing"
                datasend["sessionid"] = utils.getRandomName(6, "syncthing")
                datasend["data"] = result["data"]
            elif (
                result["action"] == "terminalInformations"
                or result["action"] == "terminalAlert"
            ):
                substitute_recv = self.sub_monitoring
                datasend["action"] = "vectormonitoringagent"
                datasend["sessionid"] = utils.getRandomName(
                    6, "monitoringterminalInformations"
                )
                datasend["data"] = result["data"]
                datasend["data"]["subaction"] = result["action"]
                if "date" in result:
                    result["data"]["date"] = result["date"]
                if "serial" in result:
                    result["data"]["serial"] = result["serial"]
            else:
                # bad action
                logger.warning(
                    "this action is not taken " "into account : %s" % result["action"]
                )
                return False, ""
            if substitute_recv:
                # pour le monitoring l agent est  le substitut monitoring
                logger.warning("send to %s " % substitute_recv)
                self.send_message(
                    mbody=json.dumps(datasend), mto=substitute_recv, mtype="chat"
                )
                return True, ""
            else:
                # Call plugin on master
                logger.warning("send to master")
                self.send_message_to_master(datasend)
                return True, ""
    except Exception as e:
        logger.error("message to kiosk server : %s" % str(e))
        logger.error("\n%s" % (traceback.format_exc()))
        return False, ""
