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
# file : plugin_load_agent_machine.py
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
from lib import utils
from lib.networkinfo import organizationbymachine, organizationbyuser

import psutil
import zlib
import configparser
import re
import time

# this import will be used later
import types

logger = logging.getLogger()
plugin = {"VERSION": "1.0", "NAME": "load_agent_machine", "VERSIONAGENT": "2.0.0", "TYPE": "all"}  # fmt: skip


def action(xmppobject, action, sessionid, data, msg, dataerreur):
    try:
        logger.debug("###################################################")
        logger.debug(f'call {plugin} from {msg["from"]}')
        logger.debug("###################################################")
        strjidagent = str(xmppobject.boundjid.bare)

        logger.debug("========================================================")
        logger.debug(f'call {plugin} from {msg["from"]}')
        logger.debug("=======================================================")
        compteurcallplugin = getattr(xmppobject, f"num_call{action}")
        if compteurcallplugin == 0:
            logger.debug("===================== master_agent =====================")
            logger.debug("========================================================")
            read_conf_load_agent_machine(xmppobject)
            logger.debug("========================================================")
    except Exception as e:
        logger.error(f"Plugin load_agent_machine, we encountered the error {str(e)}")
        logger.error(f"We obtained the backtrace {traceback.format_exc()}")


def read_conf_load_agent_machine(xmppobject):
    logger.debug("Initializing plugin :% s " % plugin["NAME"])
    conf_filename = plugin["NAME"] + ".ini"

    try:
        pathfileconf = os.path.join(xmppobject.config.nameplugindir, conf_filename)
        if not os.path.isfile(pathfileconf):
            logger.warning(
                "Plugin %s\nConfiguration file :"
                "\n\t%s missing" % (plugin["NAME"], pathfileconf)
            )
        else:
            logger.info(f"Read Configuration in File {pathfileconf}")
        Config = configparser.ConfigParser()
        Config.read(pathfileconf)
        if os.path.exists(f"{pathfileconf}.local"):
            Config.read(f"{pathfileconf}.local")
    except Exception as e:
        logger.error(f"We obtained the backtrace {traceback.format_exc()}")

    logger.debug("Install fonction code specialiser agent machine")
    xmppobject.list_function_agent_name = ["get_list_function_dyn_agent_machine"]
    xmppobject.get_list_function_dyn_agent_machine = types.MethodType(
        get_list_function_dyn_agent_machine, xmppobject
    )

    # Install reception message
    xmppobject.handle_client_connection = types.MethodType(
        handle_client_connection, xmppobject
    )

    ### Create TCP/IP Server
    module = f"{xmppobject.modulepath}/plugin___server_tcpip.py"

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
        logger.error(f"We obtained the backtrace {traceback.format_exc()}")


def get_list_function_dyn_agent_machine(xmppobject):
    logger.debug(
        f"return list function install from this plugin : {xmppobject.list_function_agent_name}"
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
    if isinstance(value, (bool, int, float)):
        return value
    try:
        return int(value)
    except BaseException:
        try:
            return float(value)
        except BaseException:
            _value = value.lstrip(" ").strip(" ").lower().capitalize()
            if _value == "False":
                return False
            elif _value == "True":
                return True
            else:
                return value


def _runjson(jsonf, level=0):
    if isinstance(jsonf, dict):
        msg = f'{level * "  "}dict'
        return {
            element: _runjson(jsonf[element], level=level + 1)
            for element in jsonf
        }
    elif isinstance(jsonf, list):
        return [_runjson(element, level=level + 1) for element in jsonf]
    else:
        return _test_type(jsonf)


def handle_client_connection(self, msg):
    """
    traitement du message recu sur la socket
    """
    substitute_recv = ""

    try:
        logger.info(f"Received {msg}")
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
            logger.error(f"Message socket is not json correct : {str(e)}")
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
                    self.config.ipxmpp = utils.getIpXmppInterface(
                        self.config.Server, self.config.Port
                    )
                if self.config.ipxmpp in result["removedinterface"]:
                    logger.info(
                        f"The IP address used to contact the XMPP Server is: {self.config.ipxmpp}"
                    )
                    logger.info(
                        "__DETECT SUPP INTERFACE USED FOR CONNECTION AGENT MACHINE TO EJABBERD__"
                    )
                    logmsg = (
                        "The new network interface can replace the previous one. "
                        "The service will resume after restarting the agent"
                    )
                    if utils.is_connectedServer(self.ipconnection, self.config.Port):
                        # We only do a restart
                        logger.warning(logmsg)
                        self.md5reseau = utils.refreshfingerprint()
                        self.restartBot()
                    else:
                        # We reconfigure all
                        # Activating the new interface can take a while.
                        time.sleep(15)
                        if utils.is_connectedServer(
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
                elif len(result["interface"]) < 2:
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
            logger.error(f"{str(e)}")
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
                datasend["sessionid"] = utils.getRandomName(6, "notifysyncthing")
                datasend["action"] = "notifysyncthing"
                datasend["sessionid"] = utils.getRandomName(6, "syncthing")
                datasend["data"] = result["data"]
            elif result["action"] == "iqsendpulse":
                return iqsendpulse_str(self, result)
            elif result["action"] == "unzip":
                # direct action unzip str64
                return unzip_str(self, result)
            elif result["action"] == "setparameter":
                # direct action setparameter
                return setparameter_str(self, result)
            elif result["action"] == "getparameter":
                # direct action getparameter
                return getparameter_str(self, result)
            elif result["action"] == "get_debug_level":
                logger.warning("action get_debug_level")
                return get_debug_level_str(self, result)
            elif result["action"] == "set_debug_level":
                logger.warning("action set_debug_level")
                return set_debug_level_str(self, result)
            elif result["action"] == "help":
                # direct action help
                return helpcmd(self, result)
            elif result["action"] in ["terminalInformations", "terminalAlert"]:
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
                logger.warning(f'this action is not taken into account : {result["action"]}')
                return False, ""
            if substitute_recv:
                # pour le monitoring l agent est  le substitut monitoring
                logger.warning(f"send to {substitute_recv} ")
                self.send_message(
                    mbody=json.dumps(datasend), mto=substitute_recv, mtype="chat"
                )
            else:
                # Call plugin on master
                logger.warning("send to master")
                self.send_message_to_master(datasend)
            return True, ""
    except Exception as e:
        logger.error(f"message to kiosk server : {str(e)}")
        logger.error("\n%s" % (traceback.format_exc()))
        return False, ""


def helpcmd(xmppobject, result):
    actioncmd = {
        "cmd": {
            "setparameter": {
                "factory command": {
                    "action": "setparameter",
                    "data": {"parameter_name": "parameter_value"},
                },
                "comment": "Define or modify the value of a parameter.",
                "exemple": 'echo -n \'{"action": "setparameter", "data":  {"packageserver": {\n        "public_ip": "192.168.0.69",\n        "port": 9990\n    }}}\' | nc localhost 8765',
            },
            "getparameter": {
                "factory command": {"action": "getparameter"},
                "comment": "show parameter",
                "exemple": 'echo -n \'\n{"action": "getparameter"}\'| nc localhost 8765',
            },
            "help": {
                "factory command": {
                    "action": "help",
                    "data": "command name",
                },
                "comment": "help on command",
                "exemple": 'echo -n \'{"action": "help", "data" : "unzip" }\'| nc localhost 8765',
            },
            "unzip": {
                "factory command": {
                    "action": "unzip",
                    "data": "string compressed in base64",
                },
                "comment": "unzip base64 string",
                "exemple": 'echo -n \'{"action": "unzip", "data":  "eNpzSS3LTE5VQAUh+SWJOWBWaHFqCpjhVpSaCuYqqELVVBYABXzzS/NKuJytYhTQgamBnoGBO5BhZK5nBGEY6VmAGQqmJlBD/ELcghUUgNq5ACckHJk="}\' | nc localhost 8765',
            },
            "iqsendpulse": {
                "factory command": {
                    "action": "iqsendpulse",
                    "data": {
                        "action": "action_function_iq",
                        "data": "suject_iq",
                        "mto": "recipient_complete_jid",
                        "mtimeout": "time in seconds",
                    },
                },
                "comment": "Send a synchrone IQ to the target with complete jid: user@domain/resource",
                "exemple": 'echo -n \'{"action": "iqsendpulse", "data":  {"action": "remotexmppmonitoring", "data": "disk_usage",  "mto": "test-win-1.hpl@pulse/52540014cf93", "mtimeout": 100}}\' | nc localhost 8765',
            },
            "get_debug_level": {
                "factory command": {
                    "action": "get_debug_level",
                    "data": "name_module",
                },
                "comment": 'get level handler omettre key data pour le logger principal. autrement "data": "nom de module"',
                "exemple": 'echo -n \'{"action": "get_debug_level", "data": "slixmpp" }\'| nc localhost 8765}',
            },
            "set_debug_level": {
                "factory command": [
                    {
                        "action": "set_debug_level",
                        "data": "###POUR LOGGER PRINCIPAL### (int levelnumber | str in value 'critical,error,warning,info,debug')",
                        "exemple": 'echo -n \'{"action": "get_debug_level", "data": "debug" }\'| nc localhost 8765}',
                    },
                    {
                        "action": "set_debug_level",
                        "data": '{ ###POUR LOGGER SPECIFIQUE### "loggername" : "nom module ", "level" : (int levelnumber | str in value \'critical,error,warning,info,debug\')}',
                        "exemple": 'echo -n \'{"action": "get_debug_level", "data": { "loggername" : "slixmpp", "level":"debug" }\'| nc localhost 8765}',
                    },
                ],
                "comment": "set level facility logger",
                "exemple": "suivant cas",
            },
        }
    }
    if "data" in result and result["data"]:
        try:
            cmdsearch = result["data"].lower()
            return False, json.dumps(actioncmd["cmd"][cmdsearch], indent=4)
        except Exception:
            pass
    return False, json.dumps(actioncmd["cmd"], indent=4)


def iqsendpulse_str(xmppobject, result):
    boolresult, msg = helpcmd(xmppobject, {"data": result["action"]})
    try:
        tosend = result["data"]["mto"]
        totimeout = result["data"]["mtimeout"]
        del result["data"]["mtimeout"]
        del result["data"]["mto"]
        resultat = xmppobject.iqsendpulse(tosend, result["data"], totimeout)
        return False, resultat
    except Exception as e:
        msgr = "error verify format command %s\n%s" % (msg, traceback.format_exc())
        logger.warning(msgr)
        return False, msgr


def unzip_str(xmppobject, result):
    boolresult, msg = helpcmd(xmppobject, {"data": result["action"]})
    try:
        if "data" not in result or not isinstance(result["data"], str):
            return False, "error verify format command \n" + msg
        resultdata = zlib.decompress(base64.b64decode(result["data"]))
        msg = resultdata.decode("utf-8")
        return False, msg
    except Exception as e:
        msgr = "error verify format command %s\n%s" % (msg, traceback.format_exc())
        logger.warning(msgr)
        return False, msgr


def setparameter_str(xmppobject, result):
    # direct action decompresse str64
    boolresult, msg = helpcmd(xmppobject, {"data": result["action"]})
    try:
        if "data" in result and isinstance(result["data"], dict):
            for parameter in result["data"]:
                setattr(xmppobject.config, parameter, result["data"][parameter])
            cc = json.dumps(
                vars(xmppobject.config), cls=utils.DateTimebytesEncoderjson, indent=4
            )
            return False, "Parameters list\n" + cc + "\n"
        else:
            return False, "error verify format command\n %s" % msg
    except Exception as e:
        msgr = "error verify format command %s\n%s" % (msg, traceback.format_exc())
        logger.warning(msgr)
        return False, msgr


def getparameter_str(xmppobject, result):
    # direct action decompresse str64
    boolresult, msg = helpcmd(xmppobject, {"data": result["action"]})
    try:
        cc = json.dumps(
            vars(xmppobject.config), cls=utils.DateTimebytesEncoderjson, indent=4
        )
        return False, cc + "\n"
    except Exception as e:
        msgr = "error verify format command %s\n%s" % (msg, traceback.format_exc())
        logger.warning(msgr)
        return False, msgr


def value_facility(leveldeb):
    try:
        if isinstance(leveldeb, int):
            return leveldeb
        leveldeb = leveldeb.lower()
        if leveldeb == "critical":
            return 50
        elif leveldeb == "error":
            return 40
        elif leveldeb == "warning":
            return 30
        elif leveldeb == "info":
            return 20
        elif leveldeb == "debug":
            return 10
        elif leveldeb == "notset":
            return 0
        else:
            return None
    except:
        return None


def levellogger(module_name_handler=None):
    if module_name_handler is None:
        r = vars(logging.getLogger())
        return r["name"], r["level"]
    elif isinstance(module_name_handler, str):
        try:
            r = vars(logging.getLogger(module_name_handler))
            return r["name"], r["level"]
        except:
            pass

    return None, None


def set_debug_level_str(xmppobject, result):
    # direct action decompresse str64
    boolresult, msg = helpcmd(xmppobject, {"data": result["action"]})
    msgr = ""
    try:
        if "data" in result and result["data"]:
            if isinstance(result["data"], (str, int)):
                name, level = levellogger()
                if newlevel := value_facility(result["data"]):
                    msgr = "logger name %s( old level %s)\n" % (name, level)
                    logging.getLogger().setLevel(newlevel)
                    name, level = levellogger()
                    msgr += "logger name %s( new level %s)\n" % (name, level)
                    return False, msgr
                msgr = "error verify format command \n %s" % (msg)
                return False, msgr
            elif isinstance(result["data"], dict):
                # on travaille sur 1 handler
                if (
                    "loggername" in result["data"]
                    and result["data"]["loggername"]
                    and "level" in result["data"]
                    and result["data"]["level"]
                ):
                    try:
                        if value_facility(result["data"]["level"]):
                            handler_name_obj = logging.getLogger(
                                result["data"]["loggername"]
                            )
                            name, level = levellogger(
                                module_name_handler=result["data"]["loggername"]
                            )
                            msgr = "logger name %s( old level %s)\n" % (name, level)
                            handler_name_obj.setLevel(
                                value_facility(result["data"]["level"])
                            )
                            name, level = levellogger(
                                module_name_handler=result["data"]["loggername"]
                            )
                            msgr += "logger name %s( new level %s)\n" % (
                                name,
                                level,
                            )
                        else:
                            msgr = "error verify format module existe\n %s %s" % (
                                result["data"]["loggername"],
                                msg,
                            )
                        return False, msgr
                    except Exception as e:
                        logger.error(f"{traceback.format_exc()}")
                        logger.error(f'handler module logger missing {result["data"]["loggername"]}')
                        msgr = "handler module logger missing %s\n%s" % (
                            result["data"]["loggername"],
                            msg,
                        )
                        return False, msgr
    except Exception as e:
        msgr = "error verify format command %s\n%s" % (msg, traceback.format_exc())
        logger.warning(msgr)


def get_debug_level_str(xmppobject, result):
    logger.error(f"get_debug_level_str {result}")
    boolresult, msg = helpcmd(xmppobject, {"data": result["action"]})
    logger.error(f"get_debug_level_str {boolresult} {msg}")
    try:
        if "data" in result and result["data"]:
            handler_name_obj = logging.getLogger(result["data"])
            name, level = levellogger(module_name_handler=result["data"])
        else:
            handler_name_obj = logging.getLogger()
            name, level = levellogger()
        msgr = "logger name %s( level %s)\n" % (name, level)
        return False, msgr
    except Exception:
        msgr = "error verify format command %s\n%s" % (msg, traceback.format_exc())
        logger.warning(msgr)
        return False, msgr
