#!/usr/bin/env python3
# -*- coding: utf-8; -*-
# SPDX-FileCopyrightText: 2016-2023 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-3.0-or-later
# file : pulse_xmpp_agent/lib/grafcetdeploy.py

import sys
import os
import platform
import os.path
import json
import datetime
import getpass
import socket
from lib.utils import (
    getMacAdressList,
    getIPAdressList,
    shellcommandtimeout,
    shutdown_command,
    reboot_command,
    isBase64,
    isBase64tostring,
    downloadfile,
    simplecommand,
    send_data_tcp,
    call_plugin_sequentially,
)
from lib.configuration import setconfigfile
import traceback
import logging
import netifaces
import re
from .managepackage import managepackage
from tempfile import mkstemp
import zipfile
import base64
import time
import copy
import shlex
from .agentconffile import pulseTempDir

if sys.platform.startswith("win"):
    from lib.registerwindows import constantregisterwindows

logger = logging.getLogger()


class grafcet:
    def __init__(self, objectxmpp, datasend):
        # verify exist directory packagedir
        if not os.path.isdir(managepackage.packagedir()):
            os.makedirs(managepackage.packagedir())
        if sys.platform.startswith("win"):
            os.system(
                f'icacls "{managepackage.packagedir()}" /grant "*S-1-5-32-545:(OI)(CI)F" /T /C'
            )
        self.datasend = datasend
        logging.getLogger().debug(json.dumps(self.datasend, indent=4))
        self.parameterdynamic = {}
        self.advanced_param_deploy = {}
        self.descriptorsection = {"action_section_install": -1}
        self.objectxmpp = objectxmpp
        self.userconecter = None
        self.userstatus = None
        self.userid = None
        self.userconectdate = None
        self.data = self.datasend["data"]
        self.sessionid = self.datasend["sessionid"]
        self.__clean_protected()
        self.sequence = self.data["descriptor"]["sequence"]
        self.__initialise_user_connected__()
        self.dynamic_param_deploy = {}

        # Dynamic parameters sent from msc.commands.parameters (master side).
        raw_command_parameters = self.data.get("command_parameters")

        # Compatibility fallbacks for older/alternate payload shapes.
        if raw_command_parameters in (None, "", {}):
            raw_command_parameters = self.datasend.get("command_parameters")
        if raw_command_parameters in (None, "", {}):
            raw_command_parameters = self.data.get("parameters")
        if raw_command_parameters in (None, "", {}):
            raw_command_parameters = self.datasend.get("parameters")

        if isinstance(raw_command_parameters, dict):
            self.dynamic_param_deploy = copy.deepcopy(raw_command_parameters)
        elif isinstance(raw_command_parameters, str) and raw_command_parameters.strip():
            try:
                parsed = json.loads(raw_command_parameters)
                if isinstance(parsed, dict):
                    self.dynamic_param_deploy = parsed
                else:
                    self.dynamic_param_deploy = {"payload": parsed}
            except Exception:
                self.dynamic_param_deploy = {"payload": raw_command_parameters}

        if (
            "advanced" in self.data
            and "paramdeploy" in self.data["advanced"]
            and isinstance(self.data["advanced"]["paramdeploy"], dict)
        ):
            self.advanced_param_deploy = copy.deepcopy(self.data["advanced"]["paramdeploy"])
            # there are  dynamic parameters.
            for k, v in list(self.data["advanced"]["paramdeploy"].items()):
                self.parameterdynamic[k] = v
        if "repriseok" in self.data and self.data["repriseok"] != "":
            self.objectxmpp.xmpplog(
                self.data["repriseok"],
                type="deploy",
                sessionname=self.sessionid,
                priority=self.data["stepcurrent"],
                action="xmpplog",
                who=self.objectxmpp.boundjid.bare,
                how="",
                why="",
                module="Deployment | Error | Terminate | Notify",
                date=None,
                fromuser=self.userconecter,
                touser="",
            )
        if "repriseerror" in self.data:
            self.objectxmpp.xmpplog(
                self.data["repriseerror"],
                type="deploy",
                sessionname=self.sessionid,
                priority=self.data["stepcurrent"],
                action="xmpplog",
                who=self.objectxmpp.boundjid.bare,
                how="",
                why="",
                module="Deployment | Error | Terminate | Notify",
                date=None,
                fromuser=self.userconecter,
                touser="",
            )
            self.__terminate_remote_deploy()
            return
        if "stepcurrent" not in self.data:
            return
        try:
            # search section in sequence
            self.find_step_type()
            # attribute step curent in function section
            if int(self.data["stepcurrent"]) == 0:
                mesg_install = ""
                if "section" not in self.parameterdynamic:
                    self.parameterdynamic["section"] = "install"
                if "section" in self.parameterdynamic:
                    strsection = str(self.parameterdynamic["section"]).lower()
                    if strsection == "install":
                        # attribute section "install" if exists
                        mesg_install = "Starting Install section"
                        if self.descriptorsection["action_section_install"] != -1:
                            # stage status marked as complete
                            self.__action_completed__(
                                self.sequence[
                                    self.descriptorsection["action_section_install"]
                                ]
                            )
                            self.data["stepcurrent"] = (
                                self.descriptorsection["action_section_install"] + 1
                            )
                    elif strsection == "uninstall":
                        # Attribute section "uninstall" if exists
                        mesg_install = "Starting Uninstall section"
                        if "action_section_uninstall" in self.descriptorsection:
                            self.__action_completed__(
                                self.sequence[
                                    self.descriptorsection["action_section_uninstall"]
                                ]
                            )
                            self.data["stepcurrent"] = (
                                self.descriptorsection["action_section_uninstall"] + 1
                            )
                    elif strsection == "update":
                        # attribute section "update" if exists
                        mesg_install = "Starting Update section"
                        if "action_section_update" in self.descriptorsection:
                            self.__action_completed__(
                                self.sequence[
                                    self.descriptorsection["action_section_update"]
                                ]
                            )
                            self.data["stepcurrent"] = (
                                self.descriptorsection["action_section_update"] + 1
                            )
                    self.__affiche_message(
                        f'[{self.data["name"]}]-[{self.data["stepcurrent"]}]: {mesg_install}',
                        module="Deployment | Execution",
                    )
            self.workingstep = self.sequence[self.data["stepcurrent"]]
            self.__execstep__()  # call action workingstep
        except BaseException as e:
            logging.getLogger().error("END DEPLOY ON ERROR INITIALISATION")
            self.datasend["ret"] = 255

            logging.getLogger().debug(
                "object datasend \n%s "
                % json.dumps(self.datasend, indent=4, sort_keys=True)
            )
            if "jidmaster" in self.datasend["data"]:
                # retourne resultat error to master for end session on master.
                self.objectxmpp.send_message(
                    mto=self.datasend["data"]["jidmaster"],
                    mbody=json.dumps(self.datasend),
                    mtype="chat",
                )
            self.objectxmpp.session.clearnoevent(self.sessionid)
            msg_user = [
                '<span class="log_err">Error initializing grafcet</span>',
                f'<span class="log_err">{str(e)}</span>',
            ]
            self.__affiche_message(msg_user, module="Deployment | Error | Execution")
            self.terminate(-1, True, "end error initialisation deploy")

    def __terminate_remote_deploy(self):
        self.sequence = self.data["descriptor"]["sequence"]
        self.workingstep = self.sequence[self.data["stepcurrent"]]
        self.terminate(-1, False, f'end error re {self.workingstep["step"]}')
        self.__affiche_message(
            "[%s] - [%s]: Error relaunch"
            " of deployment after shutdown "
            % (self.data["name"], self.workingstep["step"]),
            module="Deployment | Execution | Error",
        )

    def __affiche_message(self, msg, module="Deployment | Execution | Notification"):
        if type(msg) != list:
            msg = [msg]
        if msg:
            try:
                self.workingstep["step"]
                wkset = self.workingstep["step"]
            except:
                wkset = -1
            for messagetxtlog in msg:
                self.objectxmpp.xmpplog(
                    messagetxtlog,
                    type="deploy",
                    sessionname=self.sessionid,
                    priority=wkset,
                    action="xmpplog",
                    who=self.objectxmpp.boundjid.bare,
                    how="",
                    why=self.data["name"],
                    module="Deployment | notification | Execution",
                    date=None,
                    fromuser=self.data["login"],
                    touser="",
                )

    def __initialise_user_connected__(self):
        """
        cette function search si 1 utilisateur est connected.
        """
        # call function pour avoir connected user
        # implementer en 1er version uniquement pour windows

        if not sys.platform.startswith("win"):
            return
        try:
            self.userstatus = None
            self.userconectdate = None
            self.userconecter = None
            re = simplecommand("query user")
            if len(re["result"]) >= 2:
                userdata = [
                    x.strip("> ") for x in re["result"][1].split(" ") if x != ""
                ]
                self.userconecter = userdata[0]
                self.userid = userdata[2]
                self.userstatus = userdata[3]
                self.userconectdate = f"{userdata[5]} {userdata[6]}"
                msg_user = f'[{self.data["name"]}]-[{self.data["stepcurrent"]}]: Currently connected user {self.userconecter} status [{self.userstatus}] from {self.userconectdate}'
            else:
                msg_user = f'[{self.data["name"]}]-[{self.data["stepcurrent"]}]: No user connected'
            self.__affiche_message(msg_user, module="Deployment | Execution")
        except:
            logger.error("\n%s" % (traceback.format_exc()))
            self.userconecter = None
            self.userstatus = None
            self.userid = None
            self.userconectdate = None

    def find_step_type(self):
        for stepseq in self.sequence:
            if "action" in stepseq:
                if stepseq["action"] == "action_section_install":
                    self.descriptorsection["action_section_install"] = stepseq["step"]
                elif stepseq["action"] == "action_section_uninstall":
                    self.descriptorsection["action_section_uninstall"] = stepseq["step"]
                elif stepseq["action"] == "action_section_update":
                    self.descriptorsection["action_section_update"] = stepseq["step"]
                elif stepseq["action"] == "action_section_launch":
                    self.descriptorsection["action_section_launch"] = stepseq["step"]
                elif stepseq["action"] == "actionsuccescompletedend":
                    self.descriptorsection["actionsuccescompletedend"] = stepseq["step"]

    def __execstep__(self):
        # call function self.workingstep['action']
        # execute step current
        method = getattr(self, self.workingstep["action"])
        method()

    def __Next_Step__(self):
        # next Step for xmpp message
        if "stepcurrent" not in self.data:
            return
        self.data["stepcurrent"] = self.data["stepcurrent"] + 1
        self.sendnextstep()

    def sendnextstep(self):  # self.objectxmpp.boundjid.bare
        self.objectxmpp.send_message(
            mto=self.objectxmpp.boundjid.bare,
            mbody=json.dumps(self.datasend),
            mtype="chat",
        )

    def __Etape_Next_in__(self):
        if "stepcurrent" not in self.data:
            return
        self.data["stepcurrent"] = self.data["stepcurrent"] + 1
        self.workingstep = self.sequence[self.data["stepcurrent"]]
        self.__execstep__()

    def __set_backtoworksession__(self):
        # tag les signaux "restart" and "reload" dans le descripteur de session
        self.datasend["data"]["restart"] = True
        self.datasend["data"]["sessionreload"] = True

    def __unset_backtoworksession(self):
        # Removes the "restart" and "reload" signals in the session descriptor
        # next running if session existe then session clearing
        self.datasend["data"]["sessionreload"] = False
        self.datasend["data"]["restart"] = False

    def __next_current_step__(self):
        # pointer to the next step
        self.data["stepcurrent"] = self.data["stepcurrent"] + 1

    def __action_completed__(self, datajson):
        """
        update compteur step used
        """
        try:
            if "completed" in datajson:
                datajson["completed"] = datajson["completed"] + 1
            else:
                datajson["completed"] = 1
        except Exception as e:
            logging.getLogger().error(str(e))
            logger.error("\n%s" % (traceback.format_exc()))

    def replaceTEMPLATE(self, cmd):
        # print "__________________________________"
        # print  "replaceTEMPLATE in %s"% cmd
        # print "__________________________________"

        dynamic_param_deploy_json = self.__dynamic_param_deploy_json()
        advanced_param_deploy_json = self.__advanced_param_deploy_json()
        merged_deploy_params_json = self.__merged_deploy_params_json()

        if "@@@ADVANCED_PARAM_DEPLOY_JSON@@@" in cmd:
            cmd = cmd.replace("@@@ADVANCED_PARAM_DEPLOY_JSON@@@", advanced_param_deploy_json)

        if "@@@ADVANCED_PARAM_DEPLOY_B64@@@" in cmd:
            cmd = cmd.replace(
                "@@@ADVANCED_PARAM_DEPLOY_B64@@@",
                self.__json_to_b64(advanced_param_deploy_json),
            )

        if "@@@ADVANCED_PARAM_DEPLOY_SHELL@@@" in cmd:
            cmd = cmd.replace(
                "@@@ADVANCED_PARAM_DEPLOY_SHELL@@@",
                self.__json_to_shell(advanced_param_deploy_json),
            )

        if "@@@MERGED_DEPLOY_PARAMS_JSON@@@" in cmd:
            cmd = cmd.replace("@@@MERGED_DEPLOY_PARAMS_JSON@@@", merged_deploy_params_json)

        if "@@@MERGED_DEPLOY_PARAMS_B64@@@" in cmd:
            cmd = cmd.replace(
                "@@@MERGED_DEPLOY_PARAMS_B64@@@",
                self.__json_to_b64(merged_deploy_params_json),
            )

        if "@@@MERGED_DEPLOY_PARAMS_SHELL@@@" in cmd:
            cmd = cmd.replace(
                "@@@MERGED_DEPLOY_PARAMS_SHELL@@@",
                self.__json_to_shell(merged_deploy_params_json),
            )

        if "@@@DYNAMIC_PARAM_DEPLOY_JSON@@@" in cmd:
            cmd = cmd.replace("@@@DYNAMIC_PARAM_DEPLOY_JSON@@@", dynamic_param_deploy_json)

        if "@@@DYNAMIC_PARAM_DEPLOY_B64@@@" in cmd:
            cmd = cmd.replace(
                "@@@DYNAMIC_PARAM_DEPLOY_B64@@@",
                self.__json_to_b64(dynamic_param_deploy_json),
            )

        if "@@@DYNAMIC_PARAM_DEPLOY_SHELL@@@" in cmd:
            cmd = cmd.replace(
                "@@@DYNAMIC_PARAM_DEPLOY_SHELL@@@", self.__json_to_shell(dynamic_param_deploy_json)
            )

        if "@@@DYNAMIC_PARAM_DEPLOY@@@" in cmd:
            # Replace by raw JSON text so script/command keeps explicit descriptor intent.
            cmd = cmd.replace(
                "@@@DYNAMIC_PARAM_DEPLOY@@@",
                dynamic_param_deploy_json,
            )

        now_epoch = str(int(time.time()))
        now_utc = datetime.datetime.now(datetime.timezone.utc)
        now_iso8601 = now_utc.replace(microsecond=0).isoformat().replace("+00:00", "Z")
        cmd = cmd.replace("@@@NOW_EPOCH@@@", now_epoch)
        cmd = cmd.replace("@@@NOW_ISO8601@@@", now_iso8601)
        cmd = cmd.replace("@@@DATE_YYYYMMDD@@@", now_utc.strftime("%Y%m%d"))
        cmd = cmd.replace("@@@TIME_HHMMSS@@@", now_utc.strftime("%H%M%S"))
        cmd = cmd.replace("@@@TIMEZONE@@@", str(datetime.datetime.now().astimezone().tzinfo))

        cmd = cmd.replace("@@@EXEC_USER@@@", getpass.getuser())
        cmd = cmd.replace("@@@HOME_DIR@@@", os.path.expanduser("~"))
        cmd = cmd.replace("@@@WORKING_DIR@@@", os.getcwd())

        cmd = cmd.replace("@@@FQDN@@@", socket.getfqdn())
        cmd = cmd.replace("@@@OS_VERSION@@@", platform.version())
        cmd = cmd.replace("@@@KERNEL_VERSION@@@", platform.release())

        cmd = cmd.replace("@@@PATH_SEP@@@", os.sep)
        cmd = cmd.replace("@@@LINE_SEP@@@", os.linesep)
        cmd = cmd.replace("@@@NULL_DEVICE@@@", os.devnull)

        # Preferred placeholder for Linux updates.
        if "@@@UPDATE_LINUX@@@" in cmd:
            cmd = cmd.replace(
                "@@@UPDATE_LINUX@@@", "@@@DEPLOY_ACTION_UPDATE_LINUX_COMMAND@@@"
            )

        # Backward-compatibility alias.
        if "@@@DEPLOY@@@" in cmd:
            cmd = cmd.replace(
                "@@@DEPLOY@@@", "@@@DEPLOY_ACTION_UPDATE_LINUX_COMMAND@@@"
            )

        # Generic plugin call: @@@PLUGIN_CALL_<name>@@@ or @@@PLUGIN_CALL_"<name>"@@@
        # Case-insensitive. The plugin name is normalized to lowercase.
        # Example: @@@PLUGIN_CALL_update_linux_command@@@
        #          @@@PLUGIN_CALL_"My_Plugin"@@@
        for _m in re.finditer(r'@@@PLUGIN_CALL_"?([^@"]+?)"?@@@', cmd, re.IGNORECASE):
            _raw_name = _m.group(1).strip().strip('"').strip().lower()
            cmd = cmd.replace(_m.group(0), f"@@@DEPLOY_ACTION_PLUGIN_CALL_{_raw_name}@@@")

        # remplace all dynamic parameters by values.
        # eg :  @@@DYNAMIC_PARAM@@@section@@@ is dynamique parameter "section"
        # Si le parameter dynamic section exist, it is replace by value.
        # for def a paramater dynamic. "Dynamic parameters Packages" Single advanced launch.
        # eg  In Single advanced launch:     "section" : "install", "otherparameter" : "data"
        #
        if "@@@DYNAMIC_PARAM@@@" in cmd:
            listname = re.findall(r"@@@DYNAMIC_PARAM@@@(.*?)@@@", cmd)
            for nameparameter in listname:
                if nameparameter in self.parameterdynamic:
                    cmd = cmd.replace(
                        f"@@@DYNAMIC_PARAM@@@{nameparameter}@@@",
                        self.parameterdynamic[nameparameter],
                    )
        if "oldresult" in self.datasend["data"]:
            cmd = cmd.replace("@@@PREC_RESULT@@@", self.datasend["data"]["oldresult"])
        if "oldreturncode" in self.datasend["data"]:
            cmd = cmd.replace(
                "@@@PREC_RETURNCODE@@@", self.datasend["data"]["oldreturncode"]
            )
        cmd = cmd.replace("@@@JID_MASTER@@@", self.datasend["data"]["jidmaster"])
        cmd = cmd.replace("@@@JID_RELAYSERVER@@@", self.datasend["data"]["jidrelay"])
        cmd = cmd.replace("@@@JID_MACHINE@@@", self.datasend["data"]["jidmachine"])
        cmd = cmd.replace("@@@IP_MACHINE@@@", self.datasend["data"]["ipmachine"])
        cmd = cmd.replace("@@@IP_RELAYSERVER@@@", self.datasend["data"]["iprelay"])
        cmd = cmd.replace("@@@IP_MASTER@@@", self.datasend["data"]["ipmaster"])
        cmd = cmd.replace("@@@PACKAGE_NAME@@@", self.datasend["data"]["name"])
        cmd = cmd.replace("@@@SESSION_ID@@@", self.datasend["sessionid"])
        cmd = cmd.replace("@@@HOSTNAME@@@", platform.node().split(".")[0])

        cmd = cmd.replace(
            "@@@PYTHON_IMPLEMENTATION@@@", platform.python_implementation()
        )
        cmd = cmd.replace("@@@PYTHON_PATH@@@", sys.executable)

        cmd = cmd.replace("@@@ARCHI_MACHINE@@@", platform.machine())
        cmd = cmd.replace("@@@OS_FAMILY@@@", platform.system())

        cmd = cmd.replace("@@@OS_COMPLET_NAME@@@", platform.platform())

        cmd = cmd.replace(
            "@@@UUID_PACKAGE@@@",
            os.path.basename(self.datasend["data"]["pathpackageonmachine"]),
        )

        cmd = cmd.replace(
            "@@@PACKAGE_DIRECTORY_ABS_MACHINE@@@",
            self.datasend["data"]["pathpackageonmachine"],
        )

        cmd = cmd.replace("@@@LIST_INTERFACE_NET@@@", " ".join(netifaces.interfaces()))

        # Replace windows registry value in template (only for windows)
        # @@@VRW@@@HKEY@@K@@Subkey@@K@@value@@@VRW@@@
        for t in re.findall("@@@VRW@@@.*?@@@VRW@@@", cmd):
            if not sys.platform.startswith("win"):
                cmd = cmd.replace(t, "")
                logging.warning(
                    "bad descriptor : Registry update only works on Windows"
                )
            else:
                import winreg

                keywindows = t.replace("@@@VRW@@@", "").split("@@K@@")
                key = winreg.OpenKey(
                    constantregisterwindows.getkey(keywindows[0]),
                    keywindows[1],
                    0,
                    winreg.KEY_READ,
                )
                (valeur, typevaleur) = winreg.QueryValueEx(key, keywindows[1])
                winreg.CloseKey(key)
                cmd = cmd.replace(t, str(valeur))

        # Replace windows registry value type in template (only for windows)
        # @@@TRW@@@HKEY@@K@@Subkey@@K@@value@@@TRW@@@
        for t in re.findall("@@@TRW@@@.*?@@@TRW@@@", cmd):
            if not sys.platform.startswith("win"):
                cmd = cmd.replace(t, " ")
                logging.warning(
                    "bad descriptor : Registry update only works on Windows"
                )
            else:
                import winreg

                keywindows = t.replace("@@@TRW@@@", "").split("@@K@@")
                key = winreg.OpenKey(
                    constantregisterwindows.getkey(keywindows[0]),
                    keywindows[1],
                    0,
                    winreg.KEY_READ,
                )
                (valeur, typevaleur) = winreg.QueryValueEx(key, keywindows[1])
                winreg.CloseKey(key)
                cmd = cmd.replace(t, typevaleur)

        cmd = cmd.replace(
            "@@@LIST_INTERFACE_NET_NO_LOOP@@@",
            " ".join([x for x in netifaces.interfaces() if x != "lo" and x != ""]),
        )

        cmd = cmd.replace("@@@LIST_MAC_ADRESS@@@", " ".join(getMacAdressList()))

        cmd = cmd.replace("@@@LIST_IP_ADRESS@@@", " ".join(getIPAdressList()))

        cmd = cmd.replace("@@@IP_MACHINE_XMPP@@@", self.data["ipmachine"])

        # Quick fix for blacklisted mac addresses
        # TODO: A proper fix to blacklisted mac addresses will allow uncommenting
        # the below block
        # cmd = cmd.replace(
        #     '@@@MAC_ADRESS_MACHINE_XMPP@@@',
        #     MacAdressToIp(
        #         self.data['ipmachine']))

        cmd = cmd.replace("@@@TMP_DIR@@@", pulseTempDir())
        # recherche variable environnement
        for t in re.findall("@_@.*?@_@", cmd):
            z = t.replace("@_@", "")
            cmd = cmd.replace(t, os.environ[z])
        # print "__________________________________"
        # print "replace TEMPLATE ou %s"% cmd
        # print "__________________________________"
        return cmd

    def __dynamic_param_deploy_json(self):
        return json.dumps(
            self.dynamic_param_deploy if self.dynamic_param_deploy else {},
            separators=(",", ":"),
        )

    def __json_to_b64(self, raw_json):
        return base64.b64encode(raw_json.encode("utf-8")).decode("ascii")

    def __json_to_shell(self, raw_json):
        return shlex.quote(raw_json)

    def __advanced_param_deploy_json(self):
        return json.dumps(
            self.advanced_param_deploy if self.advanced_param_deploy else {},
            separators=(",", ":"),
        )

    def __merged_deploy_params_json(self):
        merged = {}
        if isinstance(self.dynamic_param_deploy, dict):
            merged.update(self.dynamic_param_deploy)
        if isinstance(self.advanced_param_deploy, dict):
            # User launch-time choice has final priority over MSC defaults.
            merged.update(self.advanced_param_deploy)
        return json.dumps(merged, separators=(",", ":"))

    def __extract_marker_payload(self, text):
        """Extract JSON payload from @@@DEPLOY_ACTION_UPDATE_LINUX_COMMAND@@@ marker.
        
        Returns dict extracted from JSON after marker, or empty dict if not found/invalid.
        """
        marker = "@@@DEPLOY_ACTION_UPDATE_LINUX_COMMAND@@@"
        if marker not in text:
            return {}
        
        try:
            # Find marker position and extract content after it
            idx = text.find(marker)
            content = text[idx + len(marker):].strip()
            
            # Try to parse as JSON
            if content.startswith("{"):
                # Extract JSON object (handle potential trailing text)
                brace_count = 0
                json_end = 0
                for i, char in enumerate(content):
                    if char == "{":
                        brace_count += 1
                    elif char == "}":
                        brace_count -= 1
                        if brace_count == 0:
                            json_end = i + 1
                            break
                
                if json_end > 0:
                    json_str = content[:json_end]
                    return json.loads(json_str)
        except Exception as exc:
            logger.warning("Failed to extract marker payload: %s", str(exc))
        
        return {}

    def __dispatch_update_linux_command(self, marker_payload=None):
        """Dispatch Linux update execution through dedicated machine plugin.
        
        Args:
            marker_payload: dict extracted from marker JSON (has highest priority)
        """
        if marker_payload is None:
            marker_payload = {}
        
        msg = {
            "from": self.objectxmpp.boundjid.bare,
            "to": self.objectxmpp.boundjid.bare,
            "type": "chat",
        }
        
        # Merge payloads with priority: marker > advanced > dynamic
        merged_dict = {}
        merged_dict.update(self.dynamic_param_deploy or {})
        merged_dict.update(self.advanced_param_deploy or {})
        merged_dict.update(marker_payload or {})
        
        dynamic_param_deploy_json = self.__dynamic_param_deploy_json()
        advanced_param_deploy_json = self.__advanced_param_deploy_json()
        merged_deploy_params_json = json.dumps(merged_dict) if merged_dict else "{}"
        
        payload_data = {
            "command_parameters": copy.deepcopy(self.dynamic_param_deploy),
            "dynamic_param_deploy": copy.deepcopy(self.dynamic_param_deploy),
            "advanced_param_deploy": copy.deepcopy(self.advanced_param_deploy),
            "marker_payload": copy.deepcopy(marker_payload),
            "payload": merged_deploy_params_json,
            "deploy_step": self.workingstep.get("step", 0),
            "source": "grafcetdeploy",
        }
        logger.info("DEBUG grafcetdeploy: payload_data being sent to plugin: %s", 
                    json.dumps(payload_data, indent=4))
        dataerror = {
            "action": "resultupdate_linux_command",
            "sessionid": self.sessionid,
            "ret": 255,
            "base64": False,
            "data": {"msg": "ERROR : update_linux_command"},
        }
        call_plugin_sequentially(
            "update_linux_command",
            self.objectxmpp,
            "update_linux_command",
            self.sessionid,
            payload_data,
            msg,
            dataerror,
        )

    def __handle_update_linux_marker(self):
        """Handle Linux update marker by dispatching dedicated plugin and finalizing the step."""
        # Extract payload from marker in command/script
        marker_payload = self.__extract_marker_payload(
            self.workingstep.get("command", "") or self.workingstep.get("script", "")
        )
        
        # Dispatch with extracted marker payload (highest priority)
        self.__dispatch_update_linux_command(marker_payload=marker_payload)
        self.__action_completed__(self.workingstep)
        self.workingstep["codereturn"] = 0
        
        # Log the payload used
        logged_payload = marker_payload or (self.dynamic_param_deploy if self.dynamic_param_deploy else {})
        self.__resultinfo__(
            self.workingstep,
            [
                "update_linux_command plugin executed",
                json.dumps(logged_payload),
            ],
        )
        self.steplog()
        if self.__Go_to_by_jump_succes_and_error__(0):
            return True
        self.__Etape_Next_in__()
        return True

    def __handle_plugin_call_marker(self, plugin_name):
        """Dispatch any plugin by name via @@@PLUGIN_CALL_<name>@@@ grafcet marker.

        The plugin receives the same payload structure as update_linux_command:
        marker_payload, command_parameters, dynamic_param_deploy, advanced_param_deploy.

        Args:
            plugin_name (str): Normalized (lowercase) plugin name to call.

        Returns:
            True after dispatching and finalizing the step.
        """
        marker_payload = self.__extract_marker_payload(
            self.workingstep.get("command", "") or self.workingstep.get("script", "")
        )

        msg = {
            "from": self.objectxmpp.boundjid.bare,
            "to": self.objectxmpp.boundjid.bare,
            "type": "chat",
        }

        payload_data = {
            "command_parameters": copy.deepcopy(self.dynamic_param_deploy),
            "dynamic_param_deploy": copy.deepcopy(self.dynamic_param_deploy),
            "advanced_param_deploy": copy.deepcopy(self.advanced_param_deploy),
            "marker_payload": copy.deepcopy(marker_payload),
            "payload": self.__merged_deploy_params_json(),
            "deploy_step": self.workingstep.get("step", 0),
            "source": "grafcetdeploy",
        }

        logger.info("PLUGIN_CALL dispatch: plugin=%s payload=%s", plugin_name,
                    json.dumps(payload_data, sort_keys=True))

        dataerror = {
            "action": f"result{plugin_name}",
            "sessionid": self.sessionid,
            "ret": 255,
            "base64": False,
            "data": {"msg": f"ERROR: {plugin_name}"},
        }

        call_plugin_sequentially(
            plugin_name,
            self.objectxmpp,
            plugin_name,
            self.sessionid,
            payload_data,
            msg,
            dataerror,
        )

        self.__action_completed__(self.workingstep)
        self.workingstep["codereturn"] = 0
        self.__resultinfo__(
            self.workingstep,
            [f"PLUGIN_CALL {plugin_name} executed", json.dumps(marker_payload)],
        )
        self.steplog()
        if self.__Go_to_by_jump_succes_and_error__(0):
            return True
        self.__Etape_Next_in__()
        return True
        logged_payload = marker_payload or (self.dynamic_param_deploy if self.dynamic_param_deploy else {})
        self.__resultinfo__(
            self.workingstep,
            [
                "update_linux_command plugin executed",
                json.dumps(logged_payload),
            ],
        )
        self.steplog()
        if self.__Go_to_by_jump_succes_and_error__(0):
            return True
        self.__Etape_Next_in__()
        return True

    def __search_Next_step_int__(self, val):
        """
        goto to val
        search step next for step number value
        workingstep is the new step current
        """
        valstep = 0
        if isinstance(val, int):
            for step_in_sequence in self.sequence:
                if int(step_in_sequence["step"]) == val:
                    self.data["stepcurrent"] = val
                    self.workingstep = self.sequence[self.data["stepcurrent"]]
                    return 0
                valstep = valstep + 1
            logging.getLogger().error("inconsistency in descriptor")
            self.terminate(
                -1,
                False,
                f"end error inconsistency in descriptor verify the step number [step {val} not exist]",
            )
            self.__affiche_message(
                f'[{val}] : Descriptor error: Verify the step number [step {self.data["name"]} not exist]',
                module="Deployment | Error | Execution",
            )
            return 5
        elif isinstance(val, str):
            if val == "next":
                self.data["stepcurrent"] = self.data["stepcurrent"] + 1
                self.workingstep = self.sequence[self.data["stepcurrent"]]
                return 0
            elif val == "end":
                for step_in_sequence in self.sequence:
                    if self.sequence["action"] == "actiondeploymentcomplete":
                        self.data["stepcurrent"] = int(step_in_sequence["step"])
                        self.workingstep = self.sequence[self.data["stepcurrent"]]
                        return 0
                    valstep = valstep + 1
                    logging.getLogger().error("inconsistency in descriptor")
                return 5
            elif val == "error":
                for step_in_sequence in self.sequence:
                    if self.sequence["action"] == "actionerrordeployment":
                        self.data["stepcurrent"] = int(step_in_sequence["step"])
                        self.workingstep = self.sequence[self.data["stepcurrent"]]
                        return 0
                    valstep = valstep + 1
                    logging.getLogger().error("inconsistency in descriptor")
                return 5
            else:
                for step_in_sequence in self.sequence:
                    if step_in_sequence["actionlabel"] == val:
                        self.data["stepcurrent"] = int(step_in_sequence["step"])
                        logging.getLogger().debug(
                            f'goto step {self.data["stepcurrent"]}'
                        )
                        self.workingstep = self.sequence[self.data["stepcurrent"]]
                        return 0
                valstep = valstep + 1
                logging.getLogger().error("inconsistency in descriptor")
                return 5
        else:
            logging.getLogger().error("label error")
            self.data["stepcurrent"] = self.data["stepcurrent"] + 1
            return 5

    def terminate(self, ret, clear=True, msgstate=""):
        """
        use for terminate deploy
        send msg to log sequence
        Clean client disk packages (ie clear)
        """
        login = self.data["login"]
        self.__clean_protected()
        restarmachine = False
        shutdownmachine = False
        # print "TERMINATE %s"%json.dumps(self.datasend, indent = 4)
        if (
            "advanced" in self.datasend["data"]
            and "shutdownrequired" in self.datasend["data"]["advanced"]
            and self.datasend["data"]["advanced"]["shutdownrequired"] is True
        ):
            shutdownmachine = True
            self.__affiche_message(
                f'Shutdown required for machine after deployment on {self.datasend["data"]["name"]}',
                module="Deployment|Terminate|Execution|Restart|Notify",
            )
        if (
            not shutdownmachine
            and "advanced" in self.datasend["data"]
            and "rebootrequired" in self.datasend["data"]["advanced"]
            and self.datasend["data"]["advanced"]["rebootrequired"] is True
        ):
            restarmachine = True
            self.__affiche_message(
                f'Reboot required for machine after deploy on {self.datasend["data"]["name"]}',
                module="Deployment|Terminate|Execution|Restart|Notify",
            )
        datas = {}
        datas = self.datasend
        try:
            self.__action_completed__(self.workingstep)
        except AttributeError:
            # grafcet instance has no attribute 'workingstep'
            self.datasend["data"]["status"] = "ABORT PACKAGE WORKFLOW ERROR"
            self.objectxmpp.xmpplog(
                '<span class="log_err">Workflow error. Please check your package<span>',
                type="deploy",
                sessionname=self.sessionid,
                priority=-2,
                action="xmpplog",
                who=self.objectxmpp.boundjid.bare,
                how="",
                why="",
                module="Deployment | Error | Terminate | Notify",
                date=None,
                fromuser=login,
                touser="",
            )
        try:
            self.objectxmpp.session.clearnoevent(self.sessionid)
            logging.getLogger().debug(
                f'terminate install package {self.datasend["data"]["descriptor"]["info"]["name"]}'
            )
            self.datasend["action"] = "result" + self.datasend["action"]
            if "quitonerror" not in self.datasend["data"]["descriptor"]["info"]:
                quiterror = True
            else:
                quiterror = self.datasend["data"]["descriptor"]["info"]["quitonerror"]
            try:
                del self.datasend["data"]["result"]
            except KeyError:
                pass
            try:
                del self.datasend["data"]["methodetransfert"]
            except KeyError:
                pass
            try:
                del self.datasend["data"]["path"]
            except KeyError:
                pass
            try:
                del self.datasend["data"]["restart"]
            except KeyError:
                pass
            try:
                del self.datasend["data"]["sessionreload"]
            except KeyError:
                pass
            try:
                del self.datasend["data"]["stepcurrent"]
            except KeyError:
                pass
            try:
                del self.datasend["data"]["Devent"]
            except KeyError:
                pass
            try:
                del self.datasend["data"]["Dtypequery"]
            except KeyError:
                pass
            try:
                self.datasend["data"]["environ"] = str(os.environ)
            except KeyError:
                pass
            self.datasend["ret"] = ret
            os.chdir(managepackage.packagedir())
            if clear:
                if sys.platform.startswith("win"):
                    os.system(
                        f'rmdir /s /q "{self.datasend["data"]["pathpackageonmachine"]}"'
                    )
                else:
                    os.system(f'rm -Rf {self.datasend["data"]["pathpackageonmachine"]}')
            datas = self.datasend

            if msgstate != "":
                self.datasend["data"]["msgstate"] = msgstate
            self.datasend["data"]["uname"] = list(platform.uname())
            logstruct = copy.deepcopy(self.datasend)
            logstruct["data"]["action"] = logstruct["action"]
            logstruct["action"] = "xmpplog"
            logstruct["data"]["ret"] = ret
            logstruct["data"]["sessionid"] = self.sessionid
            # self.objectxmpp.send_message(
            # mto=self.objectxmpp.sub_logger,
            # mbody=json.dumps(logstruct),
            # mtype="chat",
            # )
            self.objectxmpp.sendbigdatatoagent(
                self.objectxmpp.sub_logger, json.dumps(logstruct), segment_size=65535
            )
        except Exception as e:
            logging.getLogger().error(str(e))
            err = str(traceback.format_exc())
            logger.error("\n%s" % (err))
            logstruct = copy.deepcopy(self.datasend)
            logstruct["data"]["action"] = logstruct["action"]
            logstruct["action"] = "xmpplog"
            logstruct["data"]["ret"] = ret
            logstruct["data"]["sessionid"] = self.sessionid
            logstruct["data"]["tracebackmachine"] = err
            logstruct["ret"] = 255
            self.objectxmpp.send_message(
                mto=self.objectxmpp.sub_logger,
                mbody=json.dumps(logstruct),
                mtype="chat",
            )

        try:
            del datas["data"]["descriptor"]["sequence"]
        except KeyError:
            pass
        try:
            del datas["data"]["environ"]
        except KeyError:
            pass
        try:
            del datas["data"]["packagefile"]
        except KeyError:
            pass
        try:
            del datas["data"]["transfert"]
        except KeyError:
            pass
        try:
            self.objectxmpp.send_message(
                mto=self.datasend["data"]["jidmaster"],
                mbody=json.dumps(datas),
                mtype="chat",
            )
        except Exception as e:
            logging.getLogger().error(str(e))
            err = str(traceback.format_exc())
            logger.error("\n%s" % (err))
        try:
            datapackage = self.datasend
            mach = self.datasend["data"]["jidmachine"]
            datapackage["data"] = {}
            if msgstate != "":
                datapackage["msgstate"] = {"msg": msgstate, "quitonerror": quiterror}
            datapackage["action"] = "applicationdeploymentjson"

            # print "signal grafcet terminate%s" % datapackage

            if shutdownmachine:
                self.__affiche_message(
                    "DEPLOYMENT TERMINATE and shutdown machine",
                    module="Deployment | Terminate | Notify",
                )
            else:
                self.objectxmpp.send_message(
                    mto=mach,
                    mbody=json.dumps(datapackage),
                    mtype="chat",
                )

        except Exception as e:
            logging.getLogger().error(str(e))
            err = str(traceback.format_exc())
            logger.error("\n%s" % (err))
        try:
            if shutdownmachine:
                shutdown_command()
        except Exception as e:
            logging.getLogger().error(str(e))
            err = str(traceback.format_exc())
            logger.error("\n%s" % (err))
        try:
            if restarmachine:
                reboot_command()
        except Exception as e:
            logging.getLogger().error(str(e))
            err = str(traceback.format_exc())
            logger.error("\n%s" % (err))

    def steplog(self):
        """inscrit log"""
        logging.getLogger().debug(
            "deploy %s on machine %s [%s] STEP %s\n %s "
            % (
                self.data["descriptor"]["info"]["name"],
                self.objectxmpp.boundjid.bare,
                self.sessionid,
                self.workingstep["step"],
                json.dumps(self.workingstep, indent=4, sort_keys=True),
            )
        )

    def __terminateifcompleted__(self, workingstep):
        """test if step taged completed"""
        if "completed" in self.workingstep:
            if self.workingstep["completed"] >= 1:
                return True
        return False

    def __resultinfo__(self, workingstepinfo, listresult):
        for t in workingstepinfo:
            if t == "@resultcommand":
                workingstepinfo[t] = os.linesep.join(listresult)
            elif t.endswith("lastlines"):
                nb = t.split("@")
                nb1 = -int(nb[0])
                logging.getLogger().debug(
                    f"=======lastlines============{nb1}============================="
                )
                tab = listresult[nb1:]
                workingstepinfo[t] = os.linesep.join(tab)
            elif t.endswith("firstlines"):
                nb = t.split("@")
                nb1 = int(nb[0])
                logging.getLogger().debug(
                    f"=======firstlines============{nb1}============================="
                )
                tab = listresult[:nb1]
                workingstepinfo[t] = os.linesep.join(tab)

    def __jump_to_label__(self, label: str) -> bool:
        """
        Jump to a step having actionlabel == label.
        Returns True if a jump occurred, otherwise False.
        """
        logger = logging.getLogger()

        for step in self.sequence:
            if step.get("actionlabel") == label:
                self.__log_and_notify__("debug",f"Branching to {label} at step {step['step']}")
                self.__search_Next_step_int__(step["step"])
                self.__execstep__()
                return True

        self.__log_and_notify__("warning",f"Label '{label}' not found in sequence.")
        return False

    def __jump_on_returncode_success__(self, returncode: int) -> bool:
        """
        If returncode == 0 → END_SUCCESS
        Else → END_ERROR (optional if you want)
        """
        if returncode == 0:
            return self.__jump_to_label__("END_SUCCESS")
        else:
            return self.__jump_to_label__("END_ERROR")

    def __jump_to_next_step__(self) -> bool:
        """
        Jump to next step in sequence.
        If next step contains special action sections,
        jump to END_SUCCESS instead.
        """
        logger = logging.getLogger()

        current_step_number = self.workingstep["step"]

        # Trouver prochaine étape
        next_steps = [
            step for step in self.sequence
            if step.get("step") > current_step_number
        ]

        if not next_steps:
            self.__log_and_notify__("debug","No next step found.")
            return False

        # Prendre la plus proche
        next_step = sorted(next_steps, key=lambda x: x["step"])[0]

        self.__log_and_notify__("debug",f"Next step detected: {next_step['step']}")

        # Vérification des sections spéciales
        special_sections = {
            "action_section_install",
            "action_section_uninstall",
            "action_section_update",
        }

        if any(section in next_step for section in special_sections):
            self.__log_and_notify__("debug",
                "Next step contains install/uninstall/update section. "
                "Redirecting to END_SUCCESS."
            )
            return self.__jump_to_label__("END_SUCCESS")

        # Sinon saut normal
        self.__log_and_notify__("debug", f"Branching to next step {next_step['step']}")
        self.__search_Next_step_int__(next_step["step"])
        self.__execstep__()
        return True


    def __log_and_notify__(self, level: str, message: str):
        """
        Central logging + notification handler.

        Parameters:
            level   : "debug", "info", "warning", "error"
            message : message body (without prefix formatting)

        Behavior:
            - Always logs via Python logger
            - Sends notification via __affiche_message
            - DEBUG notifications are sent only if logger level allows DEBUG
        """

        logger = logging.getLogger()

        formatted_message = (
            f'[{self.data["name"]}]-[{self.workingstep["step"]}]: {message}'
        )

        level = level.lower()

        # -----------------------------
        # DEBUG
        # -----------------------------
        if level == "debug":
            logger.debug(formatted_message)

            if logger.isEnabledFor(logging.DEBUG):
                self.__affiche_message(
                    formatted_message,
                    module="Deployment | Execution | Debug",
                )

        # -----------------------------
        # INFO
        # -----------------------------
        elif level == "info":
            logger.info(formatted_message)
            self.__affiche_message(
                formatted_message,
                module="Deployment | Execution | Info",
            )

        # -----------------------------
        # WARNING
        # -----------------------------
        elif level == "warning":
            logger.warning(formatted_message)
            self.__affiche_message(
                formatted_message,
                module="Deployment | Execution | Warning",
            )

        # -----------------------------
        # ERROR
        # -----------------------------
        elif level == "error":
            logger.error(formatted_message)
            self.__affiche_message(
                formatted_message,
                module="Deployment | Execution | Error",
            )

        else:
            logger.error(
                f"Invalid log level '{level}' used in __log_and_notify__"
            )

    def __Go_to_by_jump_succes_and_error__(self, returncode):
        """
        Evaluate branching rules based on a return code.

        Logic overview:
        ----------------
        1. Normalize the return code to an integer.
        If invalid → default to 0 and log WARNING.

        2. Evaluate all keys in self.workingstep starting with:
            "gotoreturncode@<condition>"

        Supported condition syntaxes:

        Simple comparisons:
            n               → equivalent to == n
            ==n, =n         → equal to n
            !=n, !n         → different from n
            <n, <=n
            >n, >=n

        Interval comparisons (comma separator required):
            INn1,n2         → n1 <= returncode <= n2
            OUTn1,n2        → returncode < n1 OR returncode > n2

        Notes:
        - Interval separator MUST be a comma.
        - Negative numbers are supported.
        - Conditions are evaluated in declaration order.
        - First matching condition triggers a jump.
        - Invalid conditions are ignored but logged as WARNING
            and notified to Deployment manager.

        3. If no condition matches:
            - If returncode == 0 → jump to END_SUCCESS
            - Otherwise → jump to next step in sequence

        Returns:
            True  → a jump was executed
            False → no jump possible
        """

        logger = logging.getLogger()
        self.__log_and_notify__("debug",f"[GoTo] Received return code: {returncode}")

        # ==========================================================
        # Package presence check (notification level only)
        # ==========================================================
        # package_uuid = self.workingstep.get("packageuuid")
        #
        # if not package_uuid:
        #     logger.warning("[GoTo] Missing package UUID in working step.")
        #
        #     self.__affiche_message(
        #         f'[{self.data["name"]}]-[{self.workingstep["step"]}]: '
        #         f'WARNING - Missing package UUID in working step.',
        #         module="Deployment | Execution | Warning",
        #     )

        # ==========================================================
        # 1️⃣ Normalize return code
        # ==========================================================
        try:
            returncode = int(returncode)
        except (TypeError, ValueError):
            logger.warning(
                f"[GoTo] Invalid return code '{returncode}'. "
                "Return code must be convertible to integer. Defaulting to 0."
            )

            self.__affiche_message(
                f'[{self.data["name"]}]-[{self.workingstep["step"]}]: '
                f'WARNING - Invalid return code "{returncode}" received. '
                f'Defaulting to 0.',
                module="Deployment | Execution | Warning",
            )

            returncode = 0
        self.__log_and_notify__("debug", f"[GoTo] Normalized return code: {returncode}")

        self.workingstep["completed"] = True
        self.workingstep["successed"] = True

        # ==========================================================
        # 2️⃣ Comparison operators
        # ==========================================================
        operators = {
            "=": lambda a, b: a == b,
            "==": lambda a, b: a == b,
            "!=": lambda a, b: a != b,
            "!": lambda a, b: a != b,
            ">": lambda a, b: a > b,
            "<": lambda a, b: a < b,
            ">=": lambda a, b: a >= b,
            "<=": lambda a, b: a <= b,
        }

        # ==========================================================
        # 3️⃣ Evaluate gotoreturncode@ conditions
        # ==========================================================
        for key in self.workingstep:

            if not key.startswith("gotoreturncode@"):
                continue

            condition_part = key.split("@", 1)[1].strip()
            logger.debug(f"[GoTo] Evaluating condition: '{condition_part}'")

            # ======================================================
            # 3.1️⃣ Interval handling
            # ======================================================
            if condition_part.upper().startswith(("IN", "OUT")):

                interval_match = re.match(
                    r'^(IN|OUT)\s*(-?\d+)\s*,\s*(-?\d+)$',
                    condition_part,
                    re.IGNORECASE,
                )

                if not interval_match:
                    logger.warning(
                        f"[GoTo] Invalid interval format '{condition_part}'."
                    )

                    self.__affiche_message(
                        f'[{self.data["name"]}]-[{self.workingstep["step"]}]: '
                        f'WARNING - Invalid interval format "{condition_part}". '
                        f'Expected INn1,n2 or OUTn1,n2.',
                        module="Deployment | Execution | Warning",
                    )
                    continue

                op_symbol = interval_match.group(1).upper()
                start = int(interval_match.group(2))
                end = int(interval_match.group(3))

                self.__log_and_notify__("debug", f"[GoTo] Interval detected: {op_symbol} {start},{end}")
                if start > end:
                    logger.warning(
                        f"[GoTo] Invalid interval '{condition_part}' "
                        f"(start greater than end)."
                    )

                    self.__affiche_message(
                        f'[{self.data["name"]}]-[{self.workingstep["step"]}]: '
                        f'WARNING - Invalid interval "{condition_part}" '
                        f'(start greater than end).',
                        module="Deployment | Execution | Warning",
                    )
                    continue

                matched = (
                    start <= returncode <= end
                    if op_symbol == "IN"
                    else returncode < start or returncode > end
                )

                if matched:
                    self.__log_and_notify__("debug",
                                             f"[GoTo] Interval MATCHED → Jumping to '{self.workingstep[key]}'"
                    )
                    return self.__jump_to_label__(self.workingstep[key])

                self.__log_and_notify__("debug","[GoTo] Interval NOT matched")
                continue

            # ======================================================
            # 3.2️⃣ Simple comparison
            # ======================================================
            if condition_part.lstrip("-").isdigit():
                op_symbol = "=="
                value = int(condition_part)
                self.__log_and_notify__("debug",f"[GoTo] Default equality comparison: == {value}")
            else:
                match = re.match(
                    r'(==|!=|>=|<=|>|<|=|!)?\s*(-?\d+)$',
                    condition_part,
                )

                if not match:
                    logger.warning(
                        f"[GoTo] Invalid condition format '{condition_part}'."
                    )

                    self.__affiche_message(
                        f'[{self.data["name"]}]-[{self.workingstep["step"]}]: '
                        f'WARNING - Invalid condition format "{condition_part}".',
                        module="Deployment | Execution | Warning",
                    )
                    continue

                op_symbol = match.group(1) or "=="
                value = int(match.group(2))

                if op_symbol not in operators:
                    logger.warning(
                        f"[GoTo] Unsupported operator '{op_symbol}'."
                    )

                    self.__affiche_message(
                        f'[{self.data["name"]}]-[{self.workingstep["step"]}]: '
                        f'WARNING - Unsupported operator "{op_symbol}" '
                        f'in condition "{condition_part}".',
                        module="Deployment | Execution | Warning",
                    )
                    continue

                self.__log_and_notify__("debug",f"[GoTo] Operator detected: {op_symbol} {value}")

            # ======================================================
            # 3.3️⃣ Evaluate operator
            # ======================================================
            if operators[op_symbol](returncode, value):
                self.__log_and_notify__("debug",
                    f"[GoTo] Condition MATCHED → Jumping to '{self.workingstep[key]}'"
                )
                return self.__jump_to_label__(self.workingstep[key])

            self.__log_and_notify__("debug","[GoTo] Condition NOT matched")

        # ==========================================================
        # 4️⃣ No condition matched
        # ==========================================================
        # politique decider
        # self.__log_and_notify__("debug","[GoTo] No explicit condition matched.")
        #
        # if self.__jump_on_returncode_success__(returncode):
        #     self.__log_and_notify__("debug","[GoTo] Jump executed via __jump_on_returncode_success__.")
        #     return True

        self.__log_and_notify__("debug","[GoTo] Attempting jump to next step.")
        result = self.__jump_to_next_step__()

        if not result:
            logger.error("[GoTo] No jump destination found.")
            self.__affiche_message(
                f'[{self.data["name"]}]-[{self.workingstep["step"]}]: '
                f'ERROR - No valid jump destination found.',
                module="Deployment | Execution | Error",
            )

        return result


    def __Go_to_by_jump__(self, result):
        if "goto" in self.workingstep:
            self.__search_Next_step_int__(self.workingstep["goto"])
            self.__execstep__()
            return True
        elif "gotoyes" in self.workingstep and result == "yes":
            # goto Faire directement reboot
            self.__search_Next_step_int__(self.workingstep["gotoyes"])
            self.__execstep__()
            return True
        elif "gotono" in self.workingstep and result == "no":
            # goto attendre pour Faire reboot
            self.__search_Next_step_int__(self.workingstep["gotono"])
            self.__execstep__()
            return True
        elif "gotoopen" in self.workingstep and result == "open":
            # goto attendre pour Faire reboot
            self.__search_Next_step_int__(self.workingstep["gotoopen"])
            self.__execstep__()
            return True
        elif "gotosave" in self.workingstep and result == "save":
            # goto attendre pour Faire reboot
            self.__search_Next_step_int__(self.workingstep["gotosave"])
            self.__execstep__()
            return True
        elif "gotocancel" in self.workingstep and result == "cancel":
            # goto attendre pour Faire reboot
            self.__search_Next_step_int__(self.workingstep["gotocancel"])
            self.__execstep__()
            return True
        elif "gotoclose" in self.workingstep and result == "close":
            # goto attendre pour Faire reboot
            self.__search_Next_step_int__(self.workingstep["gotoclose"])
            self.__execstep__()
            return True
        elif "gotodiscard" in self.workingstep and result == "discard":
            # goto attendre pour Faire reboot
            self.__search_Next_step_int__(self.workingstep["gotodiscard"])
            self.__execstep__()
            return True
        elif "gotoapply" in self.workingstep and result == "apply":
            # goto attendre pour Faire reboot
            self.__search_Next_step_int__(self.workingstep["gotoapply"])
            self.__execstep__()
            return True
        elif "gotoreset" in self.workingstep and result == "reset":
            # goto attendre pour Faire reboot
            self.__search_Next_step_int__(self.workingstep["gotoreset"])
            self.__execstep__()
            return True
        elif "gotorestoreDefaults" in self.workingstep and result == "restoreDefaults":
            # goto attendre pour Faire reboot
            self.__search_Next_step_int__(self.workingstep["gotorestoreDefaults"])
            self.__execstep__()
            return True
        elif "gotoabort" in self.workingstep and result == "abort":
            # goto attendre pour Faire reboot
            self.__search_Next_step_int__(self.workingstep["gotoabort"])
            self.__execstep__()
            return True
        elif "gotoretry" in self.workingstep and result == "retry":
            # goto attendre pour Faire reboot
            self.__search_Next_step_int__(self.workingstep["gotoretry"])
            self.__execstep__()
            return True
        elif "gotoignore" in self.workingstep and result == "ignore":
            # goto attendre pour Faire reboot
            self.__search_Next_step_int__(self.workingstep["gotoignore"])
            self.__execstep__()
            return True
        else:
            return False

    def __alternatefolder(self):
        if "packageuuid" in self.workingstep:
            self.workingstep["packageuuid"] = self.replaceTEMPLATE(
                self.workingstep["packageuuid"]
            )
            directoryworking = os.path.join(
                managepackage.packagedir(), self.workingstep["packageuuid"]
            )
            if os.path.isdir(directoryworking):
                os.chdir(directoryworking)
                self.workingstep["pwd"] = os.getcwd()
                self.__affiche_message(
                    f'[{self.data["name"]}]-[{self.workingstep["step"]}]: Using package folder {self.workingstep["packageuuid"]}',
                    module="Deployment | Execution | Warning",
                )
            else:
                self.__affiche_message(
                    "[%s]-[%s]: Warning : Requested package "
                    "directory missing!!!:  %s"
                    % (
                        self.data["name"],
                        self.workingstep["step"],
                        self.workingstep["packageuuid"],
                    ),
                    module="Deployment | Execution | Warning",
                )
        self.workingstep["pwd"] = os.getcwd()
        self.__affiche_message(
            f'[{self.data["name"]}]-[{self.workingstep["step"]}]: Current directory {self.workingstep["pwd"]}',
            module="Deployment | Execution | Notification",
        )

    # --------------------------------------------------#
    # DEFINITIONS OF EXISTING ACTIONS FOR A DESCRIPTOR###
    # --------------------------------------------------#

    def action_pwd_package(self):
        """
        {
                "action": "action_pwd_package",
                "step": 0,
                "packageuuid" : ""  obtionnel
        }
        """
        try:
            if self.__terminateifcompleted__(self.workingstep):
                return
            self.__protected()
            self.__action_completed__(self.workingstep)
            self.__alternatefolder()
            self.steplog()
            self.__Etape_Next_in__()
        except Exception as e:
            logger.error("\n%s" % (traceback.format_exc()))
            self.terminate(
                -1,
                False,
                f'end error in action_pwd_package step {self.workingstep["step"]}',
            )
            self.__affiche_message(
                f'[{self.data["name"]}] - [{self.workingstep["step"]}]: Error action_pwd_package : {str(e)}',
                module="Deployment | Execution | Error",
            )

    def action_section_install(self):
        """
        {
                "action": "action_section_install",
                "step": 1
        }
        """
        try:
            if self.__terminateifcompleted__(self.workingstep):
                return
            if "section" in self.parameterdynamic:
                strsection = str(self.parameterdynamic["section"]).upper()
                self.__affiche_message(
                    f'[{self.data["name"]}]-[{self.workingstep["step"]}]: End of section {strsection}',
                    module="Deployment | Execution",
                )
            # goto succes
            self.__search_Next_step_int__(
                self.descriptorsection["actionsuccescompletedend"]
            )
            self.__execstep__()
            return
        except Exception as e:
            logger.error("\n%s" % (traceback.format_exc()))
            self.terminate(
                -1,
                False,
                f'end error in action_section_install step {self.workingstep["step"]}',
            )
            self.__affiche_message(
                f'[{self.data["name"]}] - [{self.workingstep["step"]}]: Error action_section_install : {str(e)}',
                module="Deployment | Execution | Error",
            )

    def action_section_uninstall(self):
        """
        {
                "action": "action_section_uninstall",
                "step": 1
        }
        """
        try:
            if self.__terminateifcompleted__(self.workingstep):
                return
            if "section" in self.parameterdynamic:
                strsection = str(self.parameterdynamic["section"]).upper()
                self.__affiche_message(
                    f'[{self.data["name"]}]-[{self.workingstep["step"]}]: End of section {strsection}',
                    module="Deployment | Execution",
                )
            # goto succes
            self.__search_Next_step_int__(
                self.descriptorsection["actionsuccescompletedend"]
            )
            self.__execstep__()
            return
        except Exception as e:
            logger.error("\n%s" % (traceback.format_exc()))
            self.terminate(
                -1,
                False,
                f'end error in action_section_uninstall step {self.workingstep["step"]}',
            )
            self.__affiche_message(
                f'[{self.data["name"]}] - [{self.workingstep["step"]}]: Error action_section_uninstall : {str(e)}',
                module="Deployment | Execution | Error",
            )

    def action_section_update(self):
        """
        {
                "action": "action_section_update",
                "step": 1
        }
        """
        try:
            if self.__terminateifcompleted__(self.workingstep):
                return
            if "section" in self.parameterdynamic:
                strsection = str(self.parameterdynamic["section"]).upper()
                self.__affiche_message(
                    f'[{self.data["name"]}]-[{self.workingstep["step"]}]: End of section {strsection}',
                    module="Deployment | Execution",
                )
            # goto succes
            self.__search_Next_step_int__(
                self.descriptorsection["actionsuccescompletedend"]
            )
            self.__execstep__()
            return
        except Exception as e:
            logger.error("\n%s" % (traceback.format_exc()))
            self.terminate(
                -1,
                False,
                f'end error in action_section_update step {self.workingstep["step"]}',
            )
            self.__affiche_message(
                f'[{self.data["name"]}] - [{self.workingstep["step"]}]: Error action_section_update : {str(e)}',
                module="Deployment | Execution | Error",
            )

    def action_section_launch(self):
        """
        {
                "action": "action_section_launch",
                "step": 1
        }
        """
        try:
            if self.__terminateifcompleted__(self.workingstep):
                return
            if "section" in self.parameterdynamic:
                strsection = str(self.parameterdynamic["section"]).upper()
                self.__affiche_message(
                    f'[{self.data["name"]}]-[{self.workingstep["step"]}]: End of section {strsection}',
                    module="Deployment | Execution",
                )
            # goto succes
            self.__search_Next_step_int__(
                self.descriptorsection["actionsuccescompletedend"]
            )
            self.__execstep__()
            return
        except Exception as e:
            logger.error("\n%s" % (traceback.format_exc()))
            self.terminate(
                -1,
                False,
                f'end error in action_section_launch step {self.workingstep["step"]}',
            )
            self.__affiche_message(
                f'[{self.data["name"]}] - [{self.workingstep["step"]}]: Error action_section_launch : {str(e)}',
                module="Deployment | Execution | Error",
            )

    def action_comment(self):
        """
        {
                "action": "action_comment",
                "step": n,
                "comment" : "salut la compagnie"
        }
        """
        try:
            if self.__terminateifcompleted__(self.workingstep):
                return
            self.__protected()
            self.__action_completed__(self.workingstep)
            print(self.workingstep)
            if "comment" in self.workingstep:
                self.workingstep["comment"] = self.replaceTEMPLATE(
                    self.workingstep["comment"]
                )
            else:
                self.workingstep["comment"] = "no comment user"
            self.__affiche_message(
                f'[{self.data["name"]}]-[{self.workingstep["step"]}]: User comment : {self.workingstep["comment"]}',
                module="Deployment | Execution",
            )

            self.steplog()
            self.__Etape_Next_in__()
        except Exception as e:
            logger.error("\n%s" % (traceback.format_exc()))
            self.terminate(
                -1,
                False,
                f'end error in action_comment step {self.workingstep["step"]}',
            )
            self.__affiche_message(
                f'[{self.data["name"]}] - [{self.workingstep["step"]}]: Error action_comment : {str(e)}',
                module="Deployment | Execution | Error",
            )

    def action_set_environ(self):
        """
        {
                "action": "action_set_environ",
                "step": 0,
                "environ" : {"PLIP22" : "plop"  }
        }
        """
        try:
            if self.__terminateifcompleted__(self.workingstep):
                return
            self.__action_completed__(self.workingstep)
            if "environ" in self.workingstep:
                if isinstance(self.workingstep["environ"], dict):
                    for z in self.workingstep["environ"]:
                        a = self.replaceTEMPLATE(z)
                        b = self.replaceTEMPLATE(self.workingstep["environ"][a])
                        os.environ[a] = b
                        self.__affiche_message(
                            f'[{self.data["name"]}]-[{self.workingstep["step"]}] : Set environment parameter {a} = {b}',
                            module="Deployment | Error | Execution",
                        )
            self.steplog()
            self.__Etape_Next_in__()
        except Exception as e:
            logging.getLogger().error(str(e))
            logger.error("\n%s" % (traceback.format_exc()))
            self.terminate(
                -1,
                False,
                f'end error in action_set_environ step {self.workingstep["step"]}',
            )
            self.__affiche_message(
                f'[{self.data["name"]}]-[{self.workingstep["step"]}]: Error action_set_environ ',
                module="Deployment | Error | Execution",
            )

    def action_set_config_file(self):
        """
        {
                "action": "action_set_config_file",
                "step": 0,
                "set" : "add@__@agentconf@__@global@__@log_level@__@DEBUG" or "del@__@agentconf@__@global@__@log_level"
        }
        """
        try:
            if self.__terminateifcompleted__(self.workingstep):
                return
            self.__action_completed__(self.workingstep)
            if "set" in self.workingstep:
                self.workingstep["set"] = base64.b64decode(self.workingstep["set"])
                # now b64encode and b64decode use bytes instead of str
                self.workingstep["set"] = self.workingstep["set"].decode("utf-8")
                if isinstance(self.workingstep["set"], str):
                    self.workingstep["set"] = str(self.workingstep["set"])
                    if self.workingstep["set"] != "":
                        dataconfiguration = self.workingstep["set"].split("@__@")
                        if len(dataconfiguration) > 0 and dataconfiguration[
                            0
                        ].lower() in ["add", "del"]:
                            # traitement configuration.
                            if not setconfigfile(dataconfiguration):
                                self.__affiche_message(
                                    f'[{self.data["name"]}]-[{self.workingstep["step"]}] : Error setting configuration option {self.workingstep["set"]}',
                                    module="Deployment | Error | Configuration",
                                )
                            else:
                                self.__affiche_message(
                                    f'[{self.data["name"]}]-[{self.workingstep["step"]}] : Set configuration option {self.workingstep["set"]}',
                                    module="Deployment | Notify | Configuration",
                                )
            self.steplog()
            self.__Etape_Next_in__()
        except Exception as e:
            logging.getLogger().error(str(e))
            logger.error("\n%s" % (traceback.format_exc()))
            self.terminate(
                -1,
                False,
                f'end error in action_set_config_file step {self.workingstep["step"]}',
            )
            self.__affiche_message(
                f'[{self.data["name"]}]-[{self.workingstep["step"]}]: Error action_set_config_file ',
                module="Deployment | Error | Execution",
            )

    def action_no_operation(self):
        """
        {
                "action": "action_no_operation",
                "step": n,
                "environ" : {"PLIP22" : "plop" ,"kk" }
        }
        """
        try:
            if self.__terminateifcompleted__(self.workingstep):
                return
            self.__action_completed__(self.workingstep)
            self.steplog()
            self.__Etape_Next_in__()
        except Exception as e:
            logging.getLogger().error(str(e))
            logger.error("\n%s" % (traceback.format_exc()))
            self.terminate(
                -1,
                False,
                f'end error in action_no_operation step {self.workingstep["step"]}',
            )
            self.__affiche_message(
                f'[{self.data["name"]}]-[{self.workingstep["step"]}]: Error action_no_operation',
                module="Deployment | Error | Execution",
            )

    def action_unzip_file(self):
        """
        unzip file from python
        descriptor type
        {
            "step" : intnb,
            "action" : "action_unzip_file",
            "filename" : "namefile",
            "pathdirectorytounzip" : "pathdirextract",
            "@resultcommand": "",
            "packageuuid" : ""

        }
        filename if current directory or pathfilename
        optionnel
            @resultcommand list files
            10@lastlines 10 last lines
            10@firstlines 10 first lines
            succes
            error
            goto
        """
        try:
            if self.__terminateifcompleted__(self.workingstep):
                return
            self.__action_completed__(self.workingstep)
            self.workingstep["filename"] = self.replaceTEMPLATE(
                self.workingstep["filename"]
            )
            self.workingstep["pwd"] = ""
            if os.path.isdir(self.datasend["data"]["pathpackageonmachine"]):
                os.chdir(self.datasend["data"]["pathpackageonmachine"])
                self.workingstep["pwd"] = os.getcwd()
            self.__protected()
            self.__alternatefolder()
            zip_ref = zipfile.ZipFile(self.workingstep["filename"], "r")
            if "pathdirectorytounzip" not in self.workingstep:
                self.workingstep["pathdirectorytounzip"] = self.replaceTEMPLATE(".")
                zip_ref.extractall(self.datasend["data"]["pathpackageonmachine"])
            else:
                self.workingstep["pathdirectorytounzip"] = self.replaceTEMPLATE(
                    self.workingstep["pathdirectorytounzip"]
                )
                zip_ref.extractall(self.workingstep["pathdirectorytounzip"])
            listname = zip_ref.namelist()
            self.__resultinfo__(self.workingstep, listname)
            zip_ref.close()
            self.__affiche_message(
                f'[{self.data["name"]}]-[{self.workingstep["step"]}]: Extracting {self.workingstep["filename"]} to directory {self.workingstep["pathdirectorytounzip"]}',
                module="Deployment | Error | Execution",
            )
            if "goto" in self.workingstep:
                self.__search_Next_step_int__(self.workingstep["goto"])
                self.__execstep__()
                return

            if "succes" in self.workingstep:
                # goto succes
                self.__search_Next_step_int__(self.workingstep["succes"])
                self.__execstep__()
            else:
                self.__Etape_Next_in__()
                self.steplog()
        except Exception as e:
            self.workingstep["@resultcommand"] = traceback.format_exc()
            logging.getLogger().error(str(e))
            self.__affiche_message(
                f'[{self.data["name"]}]-[{self.workingstep["step"]}]: Error extracting {self.workingstep["filename"]} to directory {self.workingstep["pathdirectorytounzip"]}',
                module="Deployment | Error | Execution",
            )
            if "error" in self.workingstep:
                self.__search_Next_step_int__(self.workingstep["error"])
                self.__execstep__()
            else:
                self.__Etape_Next_in__()
                self.steplog()

    def actionprocessscript(self):
        """
        Executes a command, retrieves its return code and output, and directs the flow to the appropriate next step.

        - Executes the command specified in `workingstep` with a defined timeout.
        - Processes the command output and return code, storing results as specified in the package descriptor.
        - Directs to the next step based on the return code, using predefined rules in the descriptor or default success/error paths.
        """
        try:
            if self.__terminateifcompleted__(self.workingstep):
                return
            self.workingstep["command"] = isBase64tostring(self.workingstep["command"])
            self.workingstep["command"] = self.replaceTEMPLATE(
                self.workingstep["command"]
            )

            if "@@@DEPLOY_ACTION_UPDATE_LINUX_COMMAND@@@" in self.workingstep["command"]:
                if self.__handle_update_linux_marker():
                    return

            # Generic PLUGIN_CALL dispatch
            _pc_match = re.search(r"@@@DEPLOY_ACTION_PLUGIN_CALL_([^@]+)@@@",
                                  self.workingstep["command"])
            if _pc_match:
                if self.__handle_plugin_call_marker(_pc_match.group(1).strip().lower()):
                    return

            if "timeout" not in self.workingstep:
                try:
                    self.workingstep["timeout"] = int(
                        self.objectxmpp.config.default_timeout
                    )
                except BaseException:
                    self.workingstep["timeout"] = 800
                logging.getLogger().warning(
                    f'timeout missing : default value {self.workingstep["timeout"]}s'
                )
            else:
                try:
                    self.workingstep["timeout"] = int(self.workingstep["timeout"])
                except BaseException:
                    self.workingstep["timeout"] = 800
                    logging.getLogger().warning(
                        f'timeout integer error : default value {self.workingstep["timeout"]}s'
                    )
            # working Step recup from process et session
            self.__protected(self.workingstep["timeout"])
            self.workingstep["pwd"] = ""
            if os.path.isdir(self.datasend["data"]["pathpackageonmachine"]):
                os.chdir(self.datasend["data"]["pathpackageonmachine"])
                self.workingstep["pwd"] = os.getcwd()

            self.__alternatefolder()
            # Execute the order and recover the return code and the output
            code_return, output_lines = (
                self.objectxmpp.process_on_end_send_message_xmpp.add_processcommand(
                    self.workingstep["command"],
                    self.datasend,
                    self.objectxmpp.boundjid.bare,
                    self.objectxmpp.boundjid.bare,
                    self.workingstep["timeout"],
                    self.workingstep["step"],
                )
            )

            # Indicate the return code and process the results
            self.workingstep["codereturn"] = code_return
            # Apply __Reultinfo__ to treat the results of the order
            self.__resultinfo__(self.workingstep, output_lines)

            if code_return == 0:
                self.__Go_to_by_jump_succes_and_error__(code_return)
            else:
                if f"gotoreturncode@{code_return}" in self.workingstep:
                    self.__Go_to_by_jump_succes_and_error__(code_return)
                else:
                    self.__Go_to_by_jump_succes_and_error__(code_return)

            self.steplog()

        except Exception as e:
            self.steplog()
            logging.getLogger().error(str(e))
            logger.error("\n%s" % (traceback.format_exc()))
            self.terminate(
                -1,
                False,
                f'end error in actionprocessscript step {self.workingstep["step"]}',
            )
            self.__affiche_message(
                f'[{self.data["name"]}]-[{self.workingstep["step"]}]: Error in actionprocessscript step',
                module="Deployment | Error | Execution",
            )

    def action_command_natif_shell(self):
        """information
        "@resultcommand or nb@lastlines or nb@firstlines": "",
        "action": "action_command_natif_shell",
        "codereturn": "",
        "command": "ls",
        "error": "END",
        "step": "1",
        "succes": 3
        timeout
        """
        try:
            if self.__terminateifcompleted__(self.workingstep):
                return
            self.workingstep["command"] = self.replaceTEMPLATE(
                self.workingstep["command"]
            )

            if "@@@DEPLOY_ACTION_UPDATE_LINUX_COMMAND@@@" in self.workingstep["command"]:
                self.__dispatch_update_linux_command()
                self.__action_completed__(self.workingstep)
                self.workingstep["codereturn"] = 0
                self.__resultinfo__(
                    self.workingstep,
                    [
                        "update_linux_command plugin executed",
                        json.dumps(
                            self.dynamic_param_deploy if self.dynamic_param_deploy else {}
                        ),
                    ],
                )
                self.steplog()
                if self.__Go_to_by_jump_succes_and_error__(0):
                    return
                self.__Etape_Next_in__()
                return

            # Generic PLUGIN_CALL dispatch
            _pc_match2 = re.search(r"@@@DEPLOY_ACTION_PLUGIN_CALL_([^@]+)@@@",
                                   self.workingstep["command"])
            if _pc_match2:
                if self.__handle_plugin_call_marker(_pc_match2.group(1).strip().lower()):
                    return

            # self.objectxmpp.logtopulse("action_command_natif_shell")
            # todo si action deja faite return
            if "timeout" not in self.workingstep:
                self.workingstep["timeout"] = 15
                logging.getLogger().warn("timeout missing : default value 15s")
            self.__protected(self.workingstep["timeout"])
            re = shellcommandtimeout(
                self.workingstep["command"], self.workingstep["timeout"]
            ).run()
            self.__action_completed__(self.workingstep)
            self.workingstep["codereturn"] = re["codereturn"]
            result = [x.strip("\n") for x in re["result"] if x != ""]
            self.__resultinfo__(self.workingstep, result)
            self.__affiche_message(
                f'[{self.data["name"]}] - [{self.workingstep["step"]}]: Error code {self.workingstep["codereturn"]} for command : {self.workingstep["command"]} ',
                module="Deployment | Error | Execution",
            )
            self.steplog()
            if self.__Go_to_by_jump_succes_and_error__(re["codereturn"]):
                return
            self.__Etape_Next_in__()
            return
        except Exception as e:
            logging.getLogger().error(str(e))
            logger.error("\n%s" % (traceback.format_exc()))
            if re["codereturn"] != 0 and "error" in self.workingstep:
                self.__search_Next_step_int__(self.workingstep["succes"])
                self.__execstep__()
                return
            self.terminate(
                -1,
                False,
                f'end error in action_command_natif_shell step {self.workingstep["step"]}',
            )
            self.objectxmpp.xmpplog(
                "[%s]-[%s]: Error action_command_natif_shell"
                % (self.data["name"], self.workingstep["step"]),
                type="deploy",
                sessionname=self.sessionid,
                priority=self.workingstep["step"],
                action="xmpplog",
                who=self.objectxmpp.boundjid.bare,
                how="",
                why=self.data["name"],
                module="Deployment | Error | Execution",
                date=None,
                fromuser=self.data["login"],
                touser="",
            )

    def action_command_natif(self):
        """Backward-compatible alias for action_command_natif_shell."""
        return self.action_command_natif_shell()

    def __clean_protected(self):
        dir_reprise_session = os.path.join(
            os.path.dirname(os.path.realpath(__file__)), "INFOSTMP", "REPRISE"
        )
        filelistprotected = [
            os.path.join(dir_reprise_session, x)
            for x in os.listdir(dir_reprise_session)
            if os.path.isfile(os.path.join(dir_reprise_session, x))
            and x.endswith(self.sessionid)
            and x.startswith("medulla_protected")
        ]
        for t in filelistprotected:
            if os.path.isfile(t):
                os.remove(t)

    def __protected(self, timeout=3600):
        self.__clean_protected()
        if int(timeout) < 3600:
            timeout = 3600
        if "reprise" not in self.workingstep:
            self.workingstep["reprise"] = 0
            self.workingstep["protected"] = int(time.time()) + int(timeout)
            namefile = f'medulla_protected@_@{self.workingstep["protected"]}@_@{timeout}@_@{self.workingstep["step"]}@_@{self.sessionid}'
            self.__sauvedatasessionrepriseinterface(namefile, self.datasend)

    def actionprocessscriptfile(self):
        """
        {
                "step": intnb,
                "action": "actionprocessscriptfile",
                "typescript": "",
                "script" :  "",
                "suffix" : "",
                "bang" : "",
                "codereturn": "",
                "timeout": 900,
                "error": 5,
                "success": 3,
                "@resultcommand": "",
                "packageuuid" : ""
        }
        bang et suffix sont prioritaire sur ceux trouver depuis le typescript
        title action is Execute script
        script is copy in file in temp.
        execution of temp file

        typescript list python, tcl,

        """

        suffix = None
        shebang = None
        commandtype = ""

        if sys.platform.startswith("win"):
            # exec for power shell " powershell -executionpolicy bypass -File
            # <ton_script_ps1>"
            extensionscriptfile = {
                "python": {"suffix": "py", "bang": "#!/usr/bin/python"},
                "visualbasicscript": {"suffix": "vbs", "bang": ""},
                "Batch": {"suffix": "bat", "bang": ""},
                "powershell": {
                    "suffix": "ps1",
                    "bang": "",
                    "commandtype": "powershell -executionpolicy bypass -File ",
                },
            }
        elif sys.platform.startswith("linux"):
            extensionscriptfile = {
                "python": {
                    "suffix": "py",
                    "bang": "#!/usr/bin/python",
                    "commandtype": "python",
                },
                "Batch": {
                    "suffix": "sh",
                    "bang": "#!/bin/bash",
                    "commandtype": "/bin/bash ",
                },
                "unixKornshell": {
                    "suffix": "ksh",
                    "bang": "#!/bin/ksh",
                    "commandtype": "/bin/ksh",
                },
                "unixCshell": {
                    "suffix": "csh",
                    "bang": "#!/bin/csh",
                    "commandtype": "/bin/csh ",
                },
            }
        elif sys.platform.startswith("darwin"):
            extensionscriptfile = {
                "python": {
                    "suffix": "py",
                    "bang": "#!/usr/bin/python",
                    "commandtype": "python",
                },
                "Batch": {
                    "suffix": "sh",
                    "bang": "#!/bin/bash",
                    "commandtype": "/bin/bash",
                },
                "unixKornshell": {
                    "suffix": "ksh",
                    "bang": "#!/bin/ksh",
                    "commandtype": "/bin/ksh",
                },
                "unixCshell": {
                    "suffix": "csh",
                    "bang": "#!/bin/csh",
                    "commandtype": "/bin/csh",
                },
            }

        try:
            if self.__terminateifcompleted__(self.workingstep):
                return
            self.workingstep["script"] = isBase64tostring(self.workingstep["script"])
            self.workingstep["script"] = self.replaceTEMPLATE(
                self.workingstep["script"]
            )

            if "@@@DEPLOY_ACTION_UPDATE_LINUX_COMMAND@@@" in self.workingstep["script"]:
                if self.__handle_update_linux_marker():
                    return

            # Generic PLUGIN_CALL dispatch
            _pc_match3 = re.search(r"@@@DEPLOY_ACTION_PLUGIN_CALL_([^@]+)@@@",
                                   self.workingstep["script"])
            if _pc_match3:
                if self.__handle_plugin_call_marker(_pc_match3.group(1).strip().lower()):
                    return

            if "timeout" not in self.workingstep:
                self.workingstep["timeout"] = 900
                logging.getLogger().warning("timeout missing : default value 900s")
            else:
                self.workingstep["timeout"] = float(self.workingstep["timeout"])

            self.workingstep["pwd"] = ""
            if os.path.isdir(self.datasend["data"]["pathpackageonmachine"]):
                os.chdir(self.datasend["data"]["pathpackageonmachine"])
                self.workingstep["pwd"] = os.getcwd()
            self.__alternatefolder()
            if self.workingstep["typescript"] in extensionscriptfile:
                suffix = extensionscriptfile[self.workingstep["typescript"]]["suffix"]
                shebang = extensionscriptfile[self.workingstep["typescript"]]["bang"]
                if "commandtype" in extensionscriptfile[self.workingstep["typescript"]]:
                    commandtype = extensionscriptfile[self.workingstep["typescript"]][
                        "commandtype"
                    ]

            if "suffix" in self.workingstep and self.workingstep["suffix"] != "":
                # Search sufix and extension for typescript.
                suffix = self.workingstep["suffix"]

            if "bang" in self.workingstep and self.workingstep["bang"] != "":
                # Search sufix and extension for typescript.
                shebang = self.workingstep["bang"]

            self.workingstep["suffix"] = suffix if suffix is not None else ""
            if shebang is not None:
                self.workingstep["bang"] = shebang
                if shebang != "" and not self.workingstep["script"].startswith(
                    self.workingstep["bang"]
                ):
                    self.workingstep["script"] = (
                        self.workingstep["bang"]
                        + os.linesep
                        + self.workingstep["script"]
                    )
            else:
                self.workingstep["bang"] = ""

            self.workingstep["script"] = self.replaceTEMPLATE(
                self.workingstep["script"]
            )
            fd, temp_path = mkstemp(suffix=f".{suffix}")
            # TODO:  See how we deal with \
            st = self.workingstep["script"]

            if sys.platform.startswith("win"):
                encoding = "cp1252"
            else:  # Linux or Mac
                encoding = "utf-8"

            if suffix in ["bat", "ps1"]:
                os.write(fd, st.encode(encoding))
            else:
                os.write(fd, st.replace("\\", "\\\\").encode(encoding))
            os.close(fd)
            self.workingstep["script"] = f"script in temp file : {temp_path}"
            # Create command
            if commandtype is not None:
                command = commandtype + temp_path
            # working Step recup from process et session
            if command != "":
                code_return, output_lines = (
                    self.objectxmpp.process_on_end_send_message_xmpp.add_processcommand(
                        command,
                        self.datasend,
                        self.objectxmpp.boundjid.bare,
                        self.objectxmpp.boundjid.bare,
                        self.workingstep["timeout"],
                        self.workingstep["step"],
                    )
                )

            # Indicate the return code and process the results
            self.workingstep["codereturn"] = code_return
            # Apply __Reultinfo__ to treat the results of the order
            self.__resultinfo__(self.workingstep, output_lines)

            if code_return == 0:
                self.__Go_to_by_jump_succes_and_error__(code_return)
            else:
                if f"gotoreturncode@{code_return}" in self.workingstep:
                    self.__Go_to_by_jump_succes_and_error__(code_return)
                else:
                    self.__Go_to_by_jump_succes_and_error__(code_return)

            self.steplog()
        except Exception as e:
            self.steplog()
            logging.getLogger().error(str(e))
            logging.getLogger().error("\n%s" % (traceback.format_exc()))
            self.terminate(
                -1,
                False,
                f'end error in actionprocessscriptfile step {self.workingstep["step"]}',
            )
            self.__affiche_message(
                f'[{self.data["name"]}]-[{self.workingstep["step"]}]: Error in actionprocessscriptfile step',
                module="Deployment | Error | Execution",
            )

    def actionsuccescompletedend(self):
        """
        descriptor type
        {
            "step" : 11,
            "action" : "actionsuccescompletedend",
            "clear" : "True"
            "inventory" : "True"
        }
        clear optionnel option
        if clear is not defini then clear = True
        inventory optionnel option
        if inventory is not defini then inventory = True
        """
        inventory = True
        self.__protected()
        if "inventory" in self.workingstep:
            boolstr = str(self.workingstep["inventory"])
            # status inventory "No inventory / Inventory on change / Forced inventory"
            if boolstr.lower() in {
                "true",
                "1",
                "y",
                "yes",
                "ok",
                "forced",
                "forced inventory",
            }:
                inventory = True
                self.workingstep["actioninventory"] = "forced"

            if boolstr.lower() in {
                "false",
                "0",
                "n",
                "no",
                "ko",
                "non",
                "not" "no inventory",
            }:
                inventory = False
                self.workingstep["actioninventory"] = "noforced"

            if boolstr.lower() in {"Inventory on change", "noforced"}:
                inventory = True
                self.workingstep["actioninventory"] = "noforced"

        if "actioninventory" not in self.workingstep:
            logger.warning("inventory option is forced check option inventory")
            self.workingstep["actioninventory"] = "forced"
        inventoryfile = ""
        clear = True
        if "clear" in self.workingstep:
            if isinstance(self.workingstep["clear"], bool):
                clear = self.workingstep["clear"]
            else:
                self.workingstep["clear"] = str(self.workingstep["clear"])
                if self.workingstep["clear"] == "False":
                    clear = False
        self.__affiche_message(
            f'[{self.data["name"]}]-[{self.workingstep["step"]}] :<span class="log_ok">Execution successful<span>',
            module="Deployment | Error | Execution | Notify",
        )
        if self.__terminateifcompleted__(self.workingstep):
            return
        self.terminate(0, clear, "end success")
        if inventory:
            # genere inventaire et envoi inventaire
            # call plugin inventory pour master.
            if sys.platform.startswith("linux"):
                inventoryfile = os.path.join("/", "tmp", "inventory.txt")
            else:
                inventoryfile = os.path.join(pulseTempDir(), "inventory.txt")
            self.__affiche_message(
                "Starting inventory", module="Deployment | Execution | Inventory"
            )
            try:
                self.objectxmpp.handleinventory(
                    forced=self.workingstep["actioninventory"], sessionid=self.sessionid
                )
            except Exception as e:
                print(e)
            # Waiting active generated new inventory
            doinventory = False
            timeinventory = 0
            for indextime in range(48):  # Waiting max 2 minutes
                if os.path.isfile(inventoryfile):
                    doinventory = True
                    timeinventory = (indextime + 1) * 5
                    break
                time.sleep(5)
            if doinventory:
                self.__affiche_message(
                    f"Sending new inventory from {self.objectxmpp.boundjid.bare} : (generated in {timeinventory} s)",
                    module="Deployment | Execution | Inventory",
                )
        self.steplog()

    def actionerrorcompletedend(self):
        """
        descriptor type
        {
            "step" : 11,
            "action" : "actionerrorcompletedend",
            "clear" : true
        }
        clear optionnel option
        if clear is not defini then clear = True
        """
        clear = True
        if "clear" in self.workingstep and isinstance(self.workingstep["clear"], bool):
            clear = self.workingstep["clear"]
        self.__affiche_message(
            f'[{self.data["name"]}]-[{self.workingstep["step"]}] :<span class="log_err"> Deployment aborted <span>',
            module="Deployment | Error | Execution | Notify",
        )
        if self.__terminateifcompleted__(self.workingstep):
            return
        self.terminate(-1, clear, "end error")
        self.steplog()

    def actionconfirm(self):
        """
        descriptor type
        {
            "step" : 7,
            "action": "actionconfirm",
            "title" : "titre de la fenetre",
            "query" : "Question demandé",
            "boutontype" :[yes | no | Open | Save | Cancel | Close | Discard | Apply | Reset|  RestoreDefaults |Abort | Retry | Ignore ]
            "icon" :  ["noIcon" |  question | information | warning | critical }
            "goto" : numStep
            "gotoyes" : numStep
            "gotono" :numStep
            "gotoopen": numStep
            "gotosave" :numStep
            "gotocancel" : numStep
            "gotoclose" :numStep
            "gotodiscard" : numStep
            "gotoapply" :numStep
            "gotoreset" :numStep
            "gotorestoreDefaults" :numStep
            "gotoabort":numStep
            "gotoretry":numStep
            "gotoIgnore": numStep
        gotoxxx assure le branchement a l'etape precisé
        # goto est 1 branchement prioritaire non conditionel quelque soit le choix de la doalog box il y a branchement.
        # gotoxxx suivant le choix des boutons, xxx le bouton choix
        #list des boutons possibles

        # bouton yes -> branchement etape pointer par gotoyes
        # bouton no -> branchement etape pointer par gotono

        """
        # composition command
        if "title" not in self.workingstep:
            self.workingstep["title"] = "Confirmation"
        if "icon" not in self.workingstep:
            self.workingstep["icon"] = "information"
        if "query" not in self.workingstep:
            self.workingstep["query"] = "Yes or No"
        if "boutontype" not in self.workingstep:
            self.workingstep["boutontype"] = ["yes", "no"]

        if sys.platform.startswith("linux"):
            logging.debug("machine linux")
            try:
                os.environ["DISPLAY"]
                logging.debug(f'There is an X server  {os.environ["DISPLAY"]}')
                logging.debug("############################################")
                logging.debug("linux avec serveur X")
                linux_executable_dlg_confirm = "dlg_comfirm_pulse"
                command = (
                    linux_executable_dlg_confirm
                    + " -T "
                    + self.workingstep["title"]
                    + " -I "
                    + self.workingstep["icon"]
                    + " -Q "
                    + self.workingstep["query"]
                    + " -B "
                    + ",".join(self.workingstep["boutontype"])
                )
                logging.debug(
                    f"################LINUX  command ############################ {command}"
                )
            except KeyError:
                logging.debug("There is not X server")
                os.system(
                    'echo "'
                    + self.workingstep["title"]
                    + "\n"
                    + self.workingstep["query"]
                    + '\n" | wall'
                )

                self.__Etape_Next_in__()
                return

        elif sys.platform.startswith("win"):
            logging.debug("command on windows")
            win_executable_dlg_confirm = "dlg_comfirm_pulse"
            command = (
                win_executable_dlg_confirm
                + " -T "
                + self.workingstep["title"]
                + " -I "
                + self.workingstep["icon"]
                + " -Q "
                + self.workingstep["query"]
                + " -B "
                + ",".join(self.workingstep["boutontype"])
            )
        elif sys.platform.startswith("darwin"):
            logging.debug("command on darwin")
            Macos_executable_dlg_confirm = "dlg_comfirm_pulse"
            command = (
                Macos_executable_dlg_confirm
                + " -T "
                + self.workingstep["title"]
                + " -I "
                + self.workingstep["icon"]
                + " -Q "
                + self.workingstep["query"]
                + " -B "
                + ",".join(self.workingstep["boutontype"])
            )
        # TODO: si action deja faite return

        # appelle boite de dialog

        re = shellcommandtimeout(command, 60).run()
        self.steplog()
        result = [x.strip("\n") for x in re["result"] if x != ""]
        logging.getLogger().debug("result action actionconfirm:")
        self.__affiche_message(
            f'[{self.data["name"]}]-[{self.workingstep["step"]}]: Dialog : Response {result[-1]}',
            module="Deployment | Error | Execution",
        )
        if self.__Go_to_by_jump__(result[0]):
            return
        if self.__Go_to_by_jump_succes_and_error__(re["codereturn"]):
            return
        self.__Etape_Next_in__()
        return

    def actionwaitandgoto(self):
        """
        descriptor type
        {
                    "step" : 8,
                    "action": "actionwaitandgoto",
                    "waiting" : 60,
                    "goto" : 7
        }
        """
        try:
            if self.__terminateifcompleted__(self.workingstep):
                return
            # todo si action deja faite return
            if "waiting" not in self.workingstep:
                self.workingstep["waiting"] = "10"
                logging.getLogger().warning("waiting missing : default value 180s")
            logging.getLogger().warn(
                f'timeout  waiting : {self.workingstep["waiting"]}'
            )
            self.__affiche_message(
                f'[{self.data["name"]}]-[{self.workingstep["step"]}]: Waiting {self.workingstep["waiting"]} s before resuming deployment',
                module="Deployment | Error | Execution",
            )
            time.sleep(int(self.workingstep["waiting"]))
            if "goto" in self.workingstep:
                self.__search_Next_step_int__(self.workingstep["goto"])
                self.__execstep__()
                return True
            self.steplog()
            self.__Etape_Next_in__()
        except Exception:
            logger.error("\n%s" % (traceback.format_exc()))
            self.terminate(
                -1,
                False,
                f'end error in actionwaitandgoto step {self.workingstep["step"]}',
            )
            self.__affiche_message(
                f'[{self.data["name"]}]-[{self.workingstep["step"]}]: Error in descriptor for action waitandgoto ',
                module="Deployment | Error | Execution",
            )

    def actionrestart(self):
        """
        descriptor type :
        {
            "step" : 9,
            "action": "actionrestart"
            "targetrestart" : "AM" or "MA"
        }
        """
        try:
            if self.__terminateifcompleted__(self.workingstep):
                return
            # prepare action suivante # pointe maintenant sur l tape suivante
            self.__next_current_step__()
            self.__action_completed__(self.workingstep)
            # tag this session [reload session] and [execute etape] newly
            # currente step.
            self.__set_backtoworksession__()

            if not (
                "targetrestart" in self.workingstep
                and self.workingstep["targetrestart"] == "AM"
            ):
                self.workingstep["targetrestart"] = "MA"

            # rewrite session
            objsession = self.objectxmpp.session.sessionfromsessiondata(self.sessionid)
            objsession.setdatasession(self.datasend)
            # Restart machine based on OS
            self.steplog()

            if self.workingstep["targetrestart"] == "AM":
                # restart Agent Machine
                self.__affiche_message(
                    f'[{self.data["name"]}]-[{self.workingstep["step"]}]: Restart machine agent',
                    module="Deployment | Error | Execution",
                )

                self.objectxmpp.restartBot()
            else:
                # restart Machine
                self.__affiche_message(
                    f'[{self.data["name"]}]-[{self.workingstep["step"]}]: Restart machine',
                    module="Deployment | Error | Execution",
                )
                logging.debug("actionrestartmachine  RESTART MACHINE")
                if sys.platform.startswith("linux"):
                    logging.debug("actionrestartmachine  shutdown machine linux")
                    os.system("shutdown -r now")
                elif sys.platform.startswith("win"):
                    logging.debug("actionrestartmachine  shutdown machine windows")
                    os.system("shutdown /r")
                elif sys.platform.startswith("darwin"):
                    logging.debug("actionrestartmachine  shutdown machine MacOS")
                    os.system("shutdown -r now")
        except Exception as e:
            logging.getLogger().error(str(e))
            logger.error("\n%s" % (traceback.format_exc()))
            self.terminate(
                -1,
                False,
                f'end error in actionrestart {self.workingstep["targetrestart"]} step {self.workingstep["step"]}',
            )
            self.__affiche_message(
                "[%s]-[%s]: Error actionrestart"
                % (self.data["name"], self.workingstep["step"]),
                module="Deployment | Error | Execution",
            )

    def actioncleaning(self):
        self.__affiche_message(
            f'[{self.data["name"]}] Cleaning package',
            module="Deployment | Notification | Execution",
        )
        try:
            if self.__terminateifcompleted__(self.workingstep):
                return
            self.__action_completed__(self.workingstep)
            if (
                managepackage.packagedir()
                in self.datasend["data"]["pathpackageonmachine"]
            ):
                os.chdir(managepackage.packagedir())
                if sys.platform.startswith("win"):
                    os.system(
                        f'rmdir /s /q "{self.datasend["data"]["pathpackageonmachine"]}"'
                    )
                else:
                    os.system(f'rm -Rf {self.datasend["data"]["pathpackageonmachine"]}')
                self.__affiche_message(
                    f'[{self.data["name"]}]-[{self.workingstep["step"]}]: Deleting package file from machine',
                    module="Deployment | Error | Execution",
                )
            self.steplog()
            self.__Etape_Next_in__()
        except Exception as e:
            logging.getLogger().error(str(e))
            logger.error("\n%s" % (traceback.format_exc()))
            self.terminate(
                -1,
                False,
                f'end error in actioncleaning step {self.workingstep["step"]}',
            )
            self.__affiche_message(
                f'[{self.data["name"]}]-[{self.workingstep["step"]}]: Error in actioncleaning step',
                module="Deployment | Error | Execution",
            )

    def getpackagemanager(self):
        """
        This function helps to find the update manager
        depending on the linux distribution.
        """
        if os.path.isfile("/etc/mageia-release"):
            return "urpmi --auto"
        if os.path.isfile("/etc/redhat-release"):
            return "yum"
        elif os.path.isfile("/etc/arch-release"):
            return "pacman"
        elif os.path.isfile("/etc/gentoo-release"):
            return "emerge"
        elif os.path.isfile("/etc/SuSE-release"):
            return "zypp"
        elif os.path.isfile("/etc/debian_version"):
            return "apt-get -q -y install "
        else:
            return ""

    def action_download(self):
        """
        {
            "action": "action_download",
            "actionlabel": "74539906",
            "fullpath": "",
            "step": 0,
            "url": "https://github.com/notepad-plus-plus/notepad-plus-plus/releases/download/v7.8.9/npp.7.8.9.Installer.exe",
            "packageuuid" : ""
        }
        """
        try:
            if self.__terminateifcompleted__(self.workingstep):
                return
            self.__action_completed__(self.workingstep)
            self.workingstep["pwd"] = ""
            if os.path.isdir(self.datasend["data"]["pathpackageonmachine"]):
                os.chdir(self.datasend["data"]["pathpackageonmachine"])
                self.workingstep["pwd"] = os.getcwd()
            self.__alternatefolder()

            msg = f'[{self.data["name"]}]-[{self.workingstep["step"]}]: Downloading file {self.workingstep["url"]}'
            self.objectxmpp.xmpplog(
                msg,
                type="deploy",
                sessionname=self.sessionid,
                priority=self.workingstep["step"],
                action="xmpplog",
                who=self.objectxmpp.boundjid.bare,
                why=self.data["name"],
                module="Deployment | Error | Execution",
                date=None,
                fromuser=self.data["login"],
            )
            result, txtmsg = downloadfile(self.workingstep["url"]).downloadurl()

            if result:
                self.objectxmpp.xmpplog(
                    f'[{self.data["name"]}]-[{self.workingstep["step"]}] : {txtmsg} {self.workingstep["url"]}',
                    type="deploy",
                    sessionname=self.sessionid,
                    priority=self.workingstep["step"],
                    action="xmpplog",
                    who=self.objectxmpp.boundjid.bare,
                    why=self.data["name"],
                    module="Deployment | Execution",
                    date=None,
                    fromuser=self.data["login"],
                )
                if "succes" in self.workingstep:
                    # goto succes
                    self.__search_Next_step_int__(self.workingstep["succes"])
                    self.__execstep__()
                    return
            else:
                self.objectxmpp.xmpplog(
                    f'[{self.data["name"]}]-[{self.workingstep["step"]}] : {txtmsg} {self.workingstep["url"]}',
                    type="deploy",
                    sessionname=self.sessionid,
                    priority=self.workingstep["step"],
                    action="xmpplog",
                    who=self.objectxmpp.boundjid.bare,
                    why=self.data["name"],
                    module="Deployment | Execution",
                    date=None,
                    fromuser=self.data["login"],
                )
                if "error" in self.workingstep:
                    self.__search_Next_step_int__(self.workingstep["error"])
                    self.__execstep__()
                    return
                self.objectxmpp.xmpplog(
                    f'[{self.data["name"]}]-[{self.workingstep["step"]}] : Error downloading file but proceeding to next step {txtmsg}',
                    type="deploy",
                    sessionname=self.sessionid,
                    priority=self.workingstep["step"],
                    action="xmpplog",
                    who=self.objectxmpp.boundjid.bare,
                    why=self.data["name"],
                    module="Deployment | Execution",
                    date=None,
                    fromuser=self.data["login"],
                )
            self.steplog()
            self.__Etape_Next_in__()
        except Exception as e:
            logging.getLogger().error(str(e))
            logger.error("\n%s" % (traceback.format_exc()))
            self.terminate(-1, False, f'Transfer error {self.workingstep["step"]}')
            self.objectxmpp.xmpplog(
                f'[{self.data["name"]}]-[{self.workingstep["step"]}]: Transfer error',
                type="deploy",
                sessionname=self.sessionid,
                priority=self.workingstep["step"],
                action="xmpplog",
                who=self.objectxmpp.boundjid.bare,
                why=self.data["name"],
                module="Deployment | Error | Execution",
                date=None,
                fromuser=self.data["login"],
            )

    def action_kiosknotification(self):
        """
        Step notification msg for kiosk

        nota notif for  kiosk
        {
            "status": "Install",
            "stat": 20,
            "actionlabel": "d72f10ae",
            "step": 0,
            "action": "action_kiosknotification",
            "message": "totoot"
        }
        or
        {
            "status": "Install",
            "stat": 20,
            "actionlabel": "bd6720ca",
            "step": 0,
            "action": "action_kiosknotification",
            "message": ""
        }
        or
        {
            "action": "action_kiosknotification",
            "step": 0,
            "actionlabel": "bd6720ca",
            "message": ""
        }
        """
        try:
            if self.__terminateifcompleted__(self.workingstep):
                return
            self.__action_completed__(self.workingstep)
            self.workingstep["pathpackageonmachine"] = self.datasend["data"][
                "pathpackageonmachine"
            ]
            self.workingstep["name"] = self.datasend["data"]["name"]
            self.workingstep["path"] = self.datasend["data"]["path"]
            msgxmpp = {
                "action": "action_kiosknotification",
                "sessionid": self.sessionid,
                "data": self.workingstep,
                "ret": 0,
                "base64": False,
            }
            send_data_tcp(json.dumps(msgxmpp))
            self.steplog()
            self.__Etape_Next_in__()
        except Exception as e:
            logger.error("\n%s" % (traceback.format_exc()))
            self.terminate(
                -1,
                False,
                f'end error in action_kiosknotification step {self.workingstep["step"]}',
            )
            self.objectxmpp.xmpplog(
                f'[{self.data["name"]}] - [{self.workingstep["step"]}]: Error action_kiosknotification : {str(e)}',
                type="deploy",
                sessionname=self.sessionid,
                priority=self.workingstep["step"],
                action="",
                who=self.objectxmpp.boundjid.bare,
                how="",
                why=self.data["name"],
                module="Deployment | Execution | Error",
                date=None,
                fromuser=self.data["login"],
                touser="",
            )

    def action_notification(self):
        """
        descriptor type
        "actionlabel": "55522cb7",
        "codereturn": "",
                "step": 0,
                "timeout": "200",
                "action": "action_notification",
                "message": "\ufffd\ufffde"
        """
        if "titlemessage" in self.workingstep:
            titlemessage = base64.b64decode(self.workingstep["titlemessage"])
        if "message" in self.workingstep:
            message = base64.b64decode(self.workingstep["message"])
        if "sizeheader" in self.workingstep:
            self.workingstep["sizeheader"] = int(self.workingstep["sizeheader"])
        if "sizemessage" in self.workingstep:
            self.workingstep["sizemessage"] = int(self.workingstep["sizemessage"])
        try:
            msg = []
            command = ""
            msg.append(
                """[%s]-[%s]:user notification message %s"""
                % (self.data["name"], self.workingstep["step"], message)
            )
            if sys.platform.startswith("linux"):
                logging.debug("machine linux")
                msg = []
                msg.append(
                    """[%s]-[%s]: linux notification not implemented yet"""
                    % (self.data["name"], self.workingstep["step"])
                )
            elif sys.platform.startswith("win"):
                # self.objectxmpp.userconnected=None
                # self.objectxmpp.statusconnected=None
                # START query user /MIN /B
                # command = """C:\\progra~1\\Medulla\\bin\\paexec.exe -accepteula -s -i 1 """\

                if isinstance(message, bytes):
                    message = message.decode("utf-8")

                if isinstance(titlemessage, bytes):
                    titlemessage = titlemessage.decode("utf-8")

                command = (
                    """C:\\progra~1\\Medulla\\bin\\paexec.exe -accepteula -s -i %s """
                    """C:\\progra~1\\Python3\\pythonw C:\\progra~1\\Medulla\\bin\\pulse2_update_notification.py"""
                    """ -M "%s"  -B"%s" -t %s -Y "%s" -S%s -s%s -c"""
                    % (
                        self.userid,
                        self.workingstep["message"],
                        self.workingstep["titlemessage"],
                        self.workingstep["timeout"],
                        self.workingstep["textbuttonyes"],
                        int(self.workingstep["sizeheader"]),
                        int(self.workingstep["sizemessage"]),
                    )
                )
                logging.debug("command on windows %s" % command)
            elif sys.platform.startswith("darwin"):
                logging.debug("command on darwin")
                msg = []
                msg.append(
                    """[%s]-[%s]: linux notification not implemented yet"""
                    % (self.data["name"], self.workingstep["step"])
                )

            if self.userconecter is None:
                msg.append(
                    """[%s]-[%s]: user session not active, the notification is not delivered. [notif : %s]"""
                    % (self.data["name"], self.workingstep["step"], message)
                )

            if command:
                re = shellcommandtimeout(command, 600).run()
                self.steplog()
                result = [x.strip("\n") for x in re["result"] if x != ""]
                logging.getLogger().debug("result action notification: %s" % re)
                if re["code"] == 2:
                    msg.append(
                        """[%s]-[%s]:<span class="log_warn">The user notification message """
                        """was not acknowledged within %s seconds.</span>"""
                        % (
                            self.data["name"],
                            self.workingstep["step"],
                            self.workingstep["timeout"],
                        )
                    )
                elif re["code"] == 0:
                    msg.append(
                        """[%s]-[%s]:The user notification message has been acknowledged."""
                        % (self.data["name"], self.workingstep["step"])
                    )
            else:
                msg.append(
                    """[%s]-[%s]:command notification missing."""
                    % (self.data["name"], self.workingstep["step"])
                )
            self.__affiche_message(msg, module="Deployment | Execution | Notification")
            self.__action_completed__(self.workingstep)
            self.__Etape_Next_in__()
        except Exception as e:
            logger.error("\n%s" % (traceback.format_exc()))
            self.terminate(
                -1,
                False,
                "end error in action_comment step %s" % self.workingstep["step"],
            )
            self.__affiche_message(
                "[%s] - [%s]: Error action_comment : %s"
                % (self.data["name"], self.workingstep["step"], str(e)),
                module="Deployment | Error | Notification",
            )

    def action_question(self):
        """
        descriptor type
            "gototimeout": "",
            "actionlabel": "2ddf9ad7",
            "gotono": "",
            "codereturn": "",
            "step": 0,
            "gotonouser": "",
            "gotoyes": "",
            "timeout": "800",
            "action": "action_question",
            "message": "rfrezfzef"
        """
        if "titlemessage" in self.workingstep:
            titlemessage = base64.b64decode(self.workingstep["titlemessage"])
        if "message" in self.workingstep:
            message = base64.b64decode(self.workingstep["message"])
        if "sizeheader" in self.workingstep:
            self.workingstep["sizeheader"] = int(self.workingstep["sizeheader"])
        if "sizemessage" in self.workingstep:
            self.workingstep["sizemessage"] = int(self.workingstep["sizemessage"])
        try:
            msg = []
            command = ""
            msg.append(
                """[%s]-[%s]:user question message %s"""
                % (self.data["name"], self.workingstep["step"], message)
            )
            if self.userconecter is None:
                msg.append(
                    """[%s]-[%s]: user session not active, the question is not delivered. [notif : %s]"""
                    % (self.data["name"], self.workingstep["step"], message)
                )
            if sys.platform.startswith("linux"):
                logging.debug("machine linux")
                msg = []
                msg.append(
                    """[%s]-[%s]: linux notification not implemented yet"""
                    % (self.data["name"], self.workingstep["step"])
                )
            elif sys.platform.startswith("win"):
                if isinstance(message, bytes):
                    message = message.decode("utf-8")

                if isinstance(titlemessage, bytes):
                    titlemessage = titlemessage.decode("utf-8")

                command = (
                    """C:\\progra~1\\Medulla\\bin\\paexec.exe -accepteula -s -i %s """
                    """C:\\progra~1\\Python3\\pythonw C:\\progra~1\\Medulla\\bin\\pulse2_update_notification.py -M "%s" -B"%s" -t%s -Y "%s" -N "%s" -S%s -s%s -c"""
                    % (
                        self.userid,
                        self.workingstep["message"],
                        self.workingstep["titlemessage"],
                        self.workingstep["timeout"],
                        self.workingstep["textbuttonyes"],
                        self.workingstep["textbuttonno"],
                        int(self.workingstep["sizeheader"]),
                        int(self.workingstep["sizemessage"]),
                    )
                )
                logging.debug("command on windows %s" % command)
            elif sys.platform.startswith("darwin"):
                logging.debug("command on darwin")
                msg = []
                msg.append(
                    """[%s]-[%s]: linux notification not implemented yet"""
                    % (self.data["name"], self.workingstep["step"])
                )

            self.steplog()
            if self.userconecter is None:
                msg.append(
                    """[%s]-[%s]: user session not active, the question is not delivered. [notif : %s]"""
                    % (self.data["name"], self.workingstep["step"], message)
                )
                self.__affiche_message(
                    msg, module="Deployment | Execution | Notification"
                )
                if "gotonouser" in self.workingstep:
                    self.__search_Next_step_int__(self.workingstep["gototimeout"])
                    self.__execstep__()
                else:
                    self.__Etape_Next_in__()
                return True
            if command:
                re = shellcommandtimeout(command, 600).run()
                self.steplog()
                result = [x.strip("\n") for x in re["result"] if x != ""]
                logging.getLogger().debug("result action notification: %s" % re)
                if re["code"] == 2:
                    # timeout
                    msg.append(
                        """[%s]-[%s]:<span class="log_warn">The user question message """
                        """was not acknowledged within %s seconds.</span>"""
                        % (
                            self.data["name"],
                            self.workingstep["step"],
                            self.workingstep["timeout"],
                        )
                    )
                    self.__affiche_message(
                        msg, module="Deployment | Execution | Notification"
                    )
                    if "gototimeout" in self.workingstep:
                        self.__search_Next_step_int__(self.workingstep["gototimeout"])
                        self.__execstep__()
                    else:
                        self.__Etape_Next_in__()
                    return True

                elif re["code"] == 0:
                    msg.append(
                        """[%s]-[%s]:The user question message has been acknowledged. Positif resp"""
                        % (self.data["name"], self.workingstep["step"])
                    )
                    self.__affiche_message(
                        msg, module="Deployment | Execution | Notification"
                    )
                    if "gotoyes" in self.workingstep:
                        self.__search_Next_step_int__(self.workingstep["gotoyes"])
                        self.__execstep__()
                    else:
                        self.__Etape_Next_in__()
                    return True
                elif re["code"] == 1:
                    msg.append(
                        """[%s]-[%s]:The user Question message has been acknowledged. Negatif resp"""
                        % (self.data["name"], self.workingstep["step"])
                    )
                    self.__affiche_message(
                        msg, module="Deployment | Execution | Notification"
                    )
                    if "gotono" in self.workingstep:
                        self.__search_Next_step_int__(self.workingstep["gotono"])
                        self.__execstep__()
                    else:
                        self.__Etape_Next_in__()
                    return True
            else:
                msg.append(
                    """[%s]-[%s]:command question missing."""
                    % (self.data["name"], self.workingstep["step"])
                )
                self.__Etape_Next_in__()
                return True
        except Exception as e:
            logger.error("\n%s" % (traceback.format_exc()))
            self.terminate(
                -1,
                False,
                "end error in action_comment step %s" % self.workingstep["step"],
            )
            self.__affiche_message(
                "[%s] - [%s]: Error action_comment : %s"
                % (self.data["name"], self.workingstep["step"], str(e)),
                module="Deployment | Error | Notification",
            )

    def __Setdirectorysessionreprise(self):
        """
        This functions a  directory if no exist
        @returns path directory INFO Temporaly and key RSA
        """
        dir_reprise_session = os.path.join(
            os.path.dirname(os.path.realpath(__file__)), "INFOSTMP", "REPRISE"
        )
        if not os.path.exists(dir_reprise_session):
            os.makedirs(dir_reprise_session, mode=0o007)
        return dir_reprise_session

    def __sauvedatasessionrepriseinterface(self, name, datasession):
        """
        Save the data session for resumption in a file.

        Parameters:
        - name (str): The name of the file to be created, including the path.
        - datasession (dict): The data session to be saved.

        Returns:
        - bool: True if the data session is successfully saved, False otherwise.

        The function attempts to save the provided datasession in a file specified by the given name. If successful,
        it returns True; otherwise, it logs an error message and removes the file if it exists, then returns False.

        Note: This function is intended for internal use and should not be called directly outside the class.
        """
        namesession = os.path.join(self.__Setdirectorysessionreprise(), name)

        try:
            with open(namesession, "w") as f:
                json.dump(datasession, f, indent=4)
            return True
        except Exception as e:
            logging.getLogger().error(
                "We encountered an issue while creating the session %s" % namesession
            )
            logging.getLogger().error("The error is %s" % str(e))
            if os.path.isfile(namesession):
                os.remove(namesession)
            return False
        return True

    def action_loop_question(self):
        """
        Process a loop question action based on the configured parameters.

        This function handles a loop question action, including decoding message and title, displaying notifications,
        and responding based on user input.

        Note: This function is part of a larger system and is designed for specific use cases. It handles notifications,
        user interactions, and session resumption.

        Raises:
        - Exception: Any unexpected error encountered during the execution of the loop question action.

        Returns:
        - bool: True if the action is successfully processed, False otherwise.
        """
        if "loopnumber" in self.workingstep:
            self.workingstep["loopnumber"] = int(self.workingstep["loopnumber"])
        if "timeloop" in self.workingstep:
            self.workingstep["timeloop"] = int(self.workingstep["timeloop"])
        if "timeout" in self.workingstep:
            self.workingstep["timeout"] = int(self.workingstep["timeout"])
        if "titlemessage" in self.workingstep:
            titlemessage = base64.b64decode(self.workingstep["titlemessage"]).decode(
                "utf-8"
            )
        if "message" in self.workingstep:
            message = base64.b64decode(self.workingstep["message"]).decode("utf-8")
        if "sizeheader" in self.workingstep:
            self.workingstep["sizeheader"] = int(self.workingstep["sizeheader"])
        if "sizemessage" in self.workingstep:
            self.workingstep["sizemessage"] = int(self.workingstep["sizemessage"])

        self.__initialise_user_connected__()  # le comportement peut changer si user se deconecte
        try:
            msg = []
            command = ""
            msg.append(
                """[%s]-[%s]:user question message %s"""
                % (self.data["name"], self.workingstep["step"], message)
            )
            if self.userconecter is None:
                msg.append(
                    """[%s]-[%s]: user session not active, the question is not delivered. [notif : %s]"""
                    % (self.data["name"], self.workingstep["step"], message)
                )
            if sys.platform.startswith("linux"):
                logging.debug("machine linux")
                msg = []
                msg.append(
                    """[%s]-[%s]: linux notification not implemented yet"""
                    % (self.data["name"], self.workingstep["step"])
                )
            elif sys.platform.startswith("win"):
                command = (
                    """C:\\progra~1\\Medulla\\bin\\paexec.exe -accepteula -s -i %s """
                    """C:\\progra~1\\Python3\\pythonw C:\\progra~1\\Medulla\\bin\\pulse2_update_notification.py -M "%s" -B"%s" -t %s -Y "%s" -N "%s" -S%s -s%s -c"""
                    % (
                        self.userid,
                        self.workingstep["message"],
                        self.workingstep["titlemessage"],
                        self.workingstep["timeout"],
                        self.workingstep["textbuttonyes"],
                        self.workingstep["textbuttonno"],
                        self.workingstep["sizeheader"],
                        self.workingstep["sizemessage"],
                    )
                )

                logging.debug("command on windows %s" % command)
            elif sys.platform.startswith("darwin"):
                logging.debug("command on darwin")
                msg = []
                msg.append(
                    """[%s]-[%s]: linux notification not implemented yet"""
                    % (self.data["name"], self.workingstep["step"])
                )
            self.steplog()
            if self.userconecter is None:
                msg.append(
                    """[%s]-[%s]: user session not active, the question is not delivered. [notif : %s]"""
                    % (self.data["name"], self.workingstep["step"], message)
                )
                self.__affiche_message(
                    msg, module="Deployment | Execution | Notification"
                )

                if "gotonouser" in self.workingstep:
                    self.__search_Next_step_int__(self.workingstep["gototimeout"])
                    self.__execstep__()
                else:
                    self.__Etape_Next_in__()
                return True
            if command:
                re = shellcommandtimeout(command, 1000).run()
                self.steplog()
                result = [x.strip("\n") for x in re["result"] if x != ""]
                logging.getLogger().debug("result action notification: %s" % re)
                if re["code"] == 2:
                    ## timeout pas de reponse utilisateur
                    msg.append(
                        """[%s]-[%s]:<span class="log_warn">The user question message """
                        """was not acknowledged within %s seconds.</span>"""
                        % (
                            self.data["name"],
                            self.workingstep["step"],
                            self.workingstep["timeout"],
                        )
                    )
                    self.__affiche_message(
                        msg, module="Deployment | Execution | Notification"
                    )
                    if "gototimeout" in self.workingstep:
                        self.__search_Next_step_int__(self.workingstep["gototimeout"])
                        self.__execstep__()
                    else:
                        self.__Etape_Next_in__()
                    return True

                elif re["code"] == 0:
                    # bouton positif
                    msg.append(
                        """[%s]-[%s]:The user question message has been acknowledged. Positif resp"""
                        % (self.data["name"], self.workingstep["step"])
                    )
                    self.__affiche_message(
                        msg, module="Deployment | Execution | Notification"
                    )
                    if "gotoyes" in self.workingstep:
                        self.__search_Next_step_int__(self.workingstep["gotoyes"])
                        self.__execstep__()
                    else:
                        self.__Etape_Next_in__()
                    return True
                elif re["code"] == 1:
                    # bouton negatif
                    # On doit reposer la question a n + timeloop si compteur n'est pas a 0
                    msg.append(
                        """[%s]-[%s]:The user Question message has been acknowledged. Negatif resp"""
                        % (self.data["name"], self.workingstep["step"])
                    )
                    # on verify le compteur -1
                    if "loopnumber" not in self.workingstep:
                        self.workingstep["loopnumber"] = 1
                    else:
                        self.workingstep["loopnumber"] = int(
                            self.workingstep["loopnumber"]
                        )
                    if "timeloop" not in self.workingstep:
                        self.workingstep["timeloop"] = 10
                    self.workingstep["loopnumber"] = (
                        int(self.workingstep["loopnumber"]) - 1
                    )
                    if self.workingstep["loopnumber"] <= 0:
                        # branchement gotolookterminate
                        if "gotolookterminate" in self.workingstep:
                            msg.append(
                                """[%s]-[%s]: Le compteur de demande " \
                            "est termine sans reponse positive"""
                                % (self.data["name"], self.workingstep["step"])
                            )
                            self.__search_Next_step_int__(
                                self.workingstep["gotolookterminate"]
                            )
                            self.__execstep__()
                    else:
                        # on attend n seconde
                        # 2 facons de regler cela
                        #   avec 1 sleep mais voir si le temps peut etre > 15 minutes.
                        # autrement save session et relancer apres n seconde.
                        # on sauve la session avec la convention suivante.   time de reprise en timestamp@@@_@@@sessionnumber
                        # exemple 1668091410@@@_@@@commandd04eb8ae68844bcb99
                        # rewrite session
                        self.__search_Next_step_int__(self.workingstep["actionlabel"])
                        msg.append(
                            """[%s]-[%s]: Remise dans %s seconde de cette demande a l'utilisateur %s"""
                            % (
                                self.data["name"],
                                self.workingstep["step"],
                                self.workingstep["timeloop"],
                                self.userconecter,
                            )
                        )
                        self.__affiche_message(msg)
                        msg = []
                        if float(self.workingstep["timeloop"]) >= 10.0:
                            namefile = "medulla_messagebox@_@%s@_@%s@_@%s@_@%s" % (
                                int(time.time()) + int(self.workingstep["timeloop"]),
                                int(self.workingstep["timeloop"]),
                                self.workingstep["actionlabel"],
                                self.sessionid,
                            )
                            self.__sauvedatasessionrepriseinterface(
                                namefile, self.datasend
                            )
                        else:
                            time.sleep(float(self.workingstep["timeloop"]))
                            self.__execstep__()
                            self.__affiche_message(msg)
                    return True
            else:
                msg.append(
                    """[%s]-[%s]:command question missing."""
                    % (self.data["name"], self.workingstep["step"])
                )
                self.__Etape_Next_in__()
                return True
        except Exception as e:
            logger.error("\n%s" % (traceback.format_exc()))
            self.terminate(
                -1,
                False,
                "end error in action_comment step %s" % self.workingstep["step"],
            )
            self.__affiche_message(
                "[%s] - [%s]: Error action_comment : %s"
                % (self.data["name"], self.workingstep["step"], str(e)),
                module="Deployment | Error | Notification",
            )
