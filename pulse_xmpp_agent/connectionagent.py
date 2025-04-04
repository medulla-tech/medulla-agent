#!/usr/bin/python3
# -*- coding: utf-8; -*-
# SPDX-FileCopyrightText: 2016-2023 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-3.0-or-later

import sys
from pathlib import Path

from slixmpp import ClientXMPP
from slixmpp import jid
from slixmpp.xmlstream import handler, matcher
from slixmpp.exceptions import IqError, IqTimeout
from slixmpp.xmlstream.stanzabase import ET
import slixmpp
import asyncio
import configparser

if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

import shutil
import os
import logging
import platform
import subprocess
import time
import json
import re
import traceback
import base64
import socket

from lib.networkinfo import (
    networkagentinfo,
    organizationbymachine,
    organizationbyuser,
    powershellgetlastuser,
)
from lib.configuration import (
    confParameter,
    changeconnection,
    alternativeclusterconnection,
    nextalternativeclusterconnection,
    substitutelist,
    changeconfigurationsubtitute,
)
from lib.agentconffile import (
    conffilename,
    medullaPath,
    directoryconffile,
    pulseTempDir,
    conffilenametmp,
    rotation_file,
)
from lib.utils import (
    DEBUGPULSE,
    getIpXmppInterface,
    subnetnetwork,
    check_exist_ip_port,
    ipfromdns,
    isWinUserAdmin,
    isMacOsUserAdmin,
    file_put_contents,
    getRandomName,
    AESCipher,
    refreshfingerprintconf,
    geolocalisation_agent,
    serialnumbermachine,
    offline_search_kb,
    base64strencode,
    pulseuser_useraccount_mustexist,
    pulseuser_profile_mustexist,
    add_key_to_authorizedkeys_on_client,
)

from optparse import OptionParser

from threading import Timer
from lib.logcolor import add_coloring_to_emit_ansi, add_coloring_to_emit_windows
from lib.syncthingapirest import syncthing, syncthingprogram, iddevice

# Additionnal path for library and plugins
pathbase = os.path.abspath(os.curdir)
pathplugins = os.path.join(pathbase, "pluginsmachine")
pathplugins_relay = os.path.join(pathbase, "pluginsrelay")
sys.path.append(pathplugins)

sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), "lib"))

if platform.system() == "Windows":
    # Windows does not support ANSI escapes and we are using API calls to
    # set the console color
    logging.StreamHandler.emit = add_coloring_to_emit_windows(
        logging.StreamHandler.emit
    )
else:
    # all non-Windows platforms are supporting ANSI escapes so we use them
    logging.StreamHandler.emit = add_coloring_to_emit_ansi(logging.StreamHandler.emit)

logger = logging.getLogger()


class MUCBot(ClientXMPP):
    """
    MUCBot class inherits from ClientXMPP and handles XMPP connections and messages.
    """

    def __init__(self, conf):
        """
        Initialize the MUCBot with the given configuration.

        Args:
            conf: Configuration object containing necessary parameters.
        """
        self.agent_machine_name = conf.jidagent
        newjidconf = conf.jidagent.split("@")
        resourcejid = newjidconf[1].split("/")
        resourcejid[0] = conf.confdomain
        newjidconf[0] = getRandomName(4, "conf_%s_" % socket.gethostname())
        self.HostNameSystem = platform.node().split(".")[0]
        conf.jidagent = f"{newjidconf[0]}@{resourcejid[0]}/{self.HostNameSystem}"
        self.agentmaster = jid.JID("master@pulse")
        self.session = ""
        logger.info(f"Starting the {conf.agenttype} agent on {socket.gethostname()}")

        # Time allocated for the assessor to provide a configuration
        self.assessor_response_timeout = 120
        self.timedebut = time.time()  # Start time

        ClientXMPP.__init__(self, conf.jidagent, conf.confpassword)
        self.config = conf

        # Create tmp config file
        namefileconfiguration = conffilename(self.config.agenttype)
        namefileconfigurationtmp = conffilenametmp(self.config.agenttype)
        shutil.copyfile(namefileconfiguration, namefileconfigurationtmp)

        # Update level log for slixmpp
        handler_sleekxmpp = logging.getLogger("slixmpp")
        handler_sleekxmpp.setLevel(self.config.log_level_slixmpp)

        if not hasattr(self.config, "geoservers"):
            self.geoservers = "if.siveo.net"

        self.ippublic = None
        self.geodata = None

        if self.config.geolocalisation:
            self.geodata = geolocalisation_agent(
                typeuser="nomade",
                geolocalisation=self.config.geolocalisation,
                ip_public=None,
                strlistgeoserveur=self.config.geoservers,
            )

            self.ippublic = self.geodata.get_ip_public()

        if self.ippublic == "" or self.ippublic is None:
            self.ippublic = None

        if not hasattr(self.config, "sub_assessor"):
            self.sub_assessor = self.agentmaster
        elif (
            isinstance(self.config.sub_assessor, list)
            and len(self.config.sub_assessor) > 0
        ):
            self.sub_assessor = jid.JID(self.config.sub_assessor[0])
        else:
            self.sub_assessor = jid.JID(self.config.sub_assessor)
        if self.sub_assessor.bare == "":
            self.sub_assessor = self.agentmaster
        self.add_event_handler("session_start", self.start)
        self.add_event_handler("message", self.message)
        # _______________________ Gestion connection agent _____________________
        self.add_event_handler("register", self.register)
        self.add_event_handler("connecting", self.handle_connecting)
        self.add_event_handler("connection_failed", self.handle_connection_failed)
        self.add_event_handler("disconnected", self.handle_disconnected)
        self.add_event_handler("connected", self.handle_connected)

        # _______________________ Getion connection agent _____________________

        self.add_event_handler("stream_error", self.stream_error1)
        try:
            self.config.syncthing_on
        except NameError:
            self.config.syncthing_on = False

        # Planification d'un événement pour gérer le dépassement du délai
        self.schedule(
            "assessor_response_timeout_event",  # Nom de l'événement
            self.assessor_response_timeout,  # Délai en secondes
            self.handle_assessor_timeout,  # Fonction appelée en cas de timeout
            repeat=False,  # L'événement ne se répète pas
        )

        if self.config.syncthing_on:
            logger.debug("We will configure syncthing")
            self.deviceid = ""
            if logger.level <= 10:
                console = False
                browser = True

            if sys.platform.startswith("linux"):
                self.fichierconfsyncthing = os.path.join(
                    os.path.expanduser("~pulseuser"),
                    ".config",
                    "syncthing",
                    "config.xml",
                )
            elif sys.platform.startswith("win"):
                self.fichierconfsyncthing = os.path.join(
                    directoryconffile(), "syncthing", "config.xml"
                )

            if sys.platform.startswith("linux") or sys.platform.startswith("darwin"):
                tmpfile = "/tmp/confsyncting.txt"
            else:
                tmpfile = os.path.join(pulseTempDir(), "confsyncting.txt")

            # Before reinitialisation we remove the config.xml file
            try:
                os.remove(self.fichierconfsyncthing)
            except Exception:
                pass
            self.Ctrlsyncthingprogram = syncthingprogram(
                agenttype=self.config.agenttype
            )
            self.Ctrlsyncthingprogram.restart_syncthing()
            time.sleep(4)
            try:
                self.syncthing = syncthing(configfile=self.fichierconfsyncthing)
                if logger.level <= 10:
                    self.syncthing.save_conf_to_file(tmpfile)
                else:
                    try:
                        os.remove(tmpfile)
                    except Exception:
                        pass
                time.sleep(1)
                if os.path.isfile(self.fichierconfsyncthing):
                    try:
                        self.deviceid = iddevice(configfile=self.fichierconfsyncthing)
                    except Exception:
                        pass

                logger.debug(f"device local syncthing : [{self.deviceid}]")

            except KeyError as keyerror:
                logger.error(
                    f"The {keyerror} key is missing in your syncthing config file"
                )
                informationerror = traceback.format_exc()
                logger.error("\n%s" % informationerror)
                confsyncthing = {
                    "action": "resultconfsyncthing",
                    "sessionid": getRandomName(6, "confsyncthing"),
                    "ret": 255,
                    "data": {"errorsyncthingconf": informationerror},
                }
                self.send_message(
                    mto=self.sub_assessor, mbody=json.dumps(confsyncthing), mtype="chat"
                )

            except Exception as e:
                logger.error(
                    f"The initialisation of syncthing failed. We got the error {str(e)}"
                )
                informationerror = traceback.format_exc()
                logger.error("\n%s" % informationerror)
                logger.error("Syncthing is not functionnal. Using the degraded mode")
                confsyncthing = {
                    "action": "resultconfsyncthing",
                    "sessionid": getRandomName(6, "confsyncthing"),
                    "ret": 255,
                    "data": {"errorsyncthingconf": informationerror},
                }
                self.send_message(
                    mto=self.sub_assessor, mbody=json.dumps(confsyncthing), mtype="chat"
                )

    def handle_assessor_timeout(self):
        """
        Handle the timeout event for the assessor response.
        """
        logger.error(
            f"Assessor timeout: No response within {self.assessor_response_timeout} seconds."
        )
        self.disconnect(wait=1)

    def stream_error1(self, mesg):
        """
        Handle stream errors.

        Args:
            mesg: The error message.
        """
        if mesg.get_text() == "User removed":
            logger.debug(
                f"The {self.boundjid.bare} account have been removed by the assessor: {self.sub_assessor}"
            )
            self.disconnect(wait=5)

    async def start(self, event):
        """
        Start the XMPP connection and send presence.

        Args:
            event: The event triggering the start.
        """
        self.send_presence()
        await self.get_roster()
        self.xmpplog(
            f"Starting configurator on machine {self.config.jidagent}. Assessor : {self.sub_assessor}",
            type="conf",
            priority=-1,
            action="xmpplog",
            who=self.HostNameSystem,
            module="Configuration",
            date=None,
            fromuser=self.boundjid.bare,
            touser="",
        )
        self.config.ipxmpp = getIpXmppInterface(self.config)
        self.infos_machine_assessor()

    def xmpplog(
        self,
        text,
        type="noset",
        sessionname="",
        priority=0,
        action="xmpplog",
        who="",
        how="",
        why="",
        module="",
        date=None,
        fromuser="",
        touser="",
    ):
        """
        Log XMPP messages.

        Args:
            text: The log message.
            type: The type of log.
            sessionname: The session name.
            priority: The priority of the log.
            action: The action associated with the log.
            who: The entity performing the action.
            how: How the action was performed.
            why: Why the action was performed.
            module: The module associated with the log.
            date: The date of the log.
            fromuser: The user sending the message.
            touser: The user receiving the message.
        """
        if sessionname == "":
            sessionname = getRandomName(6, "logagent")
        if who == "":
            who = self.boundjid.bare
        if touser == "":
            touser = self.boundjid.bare
        data = {
            "log": "xmpplog",
            "text": text,
            "type": type,
            "sessionid": sessionname,
            "priority": priority,
            "action": action,
            "who": who,
            "how": how,
            "why": why,
            "module": module,
            "date": None,
            "fromuser": fromuser,
            "touser": touser,
        }
        msgbody = {"data": data, "action": "xmpplog", "sessionid": sessionname}
        if not hasattr(self.config, "sub_logger"):
            self.sub_logger = self.agentmaster
        elif (
            isinstance(self.config.sub_logger, list) and len(self.config.sub_logger) > 0
        ):
            self.sub_logger = jid.JID(self.config.sub_logger[0])
        else:
            self.sub_logger = jid.JID(self.config.sub_logger)
        self.send_message(mto=self.sub_logger, mbody=json.dumps(msgbody), mtype="chat")

    def adddevicesyncthing(self, keydevicesyncthing, namerelay, address=["dynamic"]):
        """
        Add a device to Syncthing configuration.

        Args:
            keydevicesyncthing: The key of the Syncthing device.
            namerelay: The name of the relay.
            address: The address of the device.
        """
        resource = jid.JID(namerelay).user[2:]
        if jid.JID(namerelay).bare == "rspulse@pulse":
            resource = "pulse"
        if resource == "":
            resource = namerelay
        if not self.is_exist_device_in_config(keydevicesyncthing):
            logger.debug(
                f"add device syncthing name : {namerelay} key: {keydevicesyncthing}"
            )
            dsyncthing_tmp = self.syncthing.create_template_struct_device(
                resource,
                str(keydevicesyncthing),
                introducer=True,
                autoAcceptFolders=True,
                address=address,
            )
            logger.debug(
                "add device [%s]syncthing to ars %s\n%s"
                % (keydevicesyncthing, namerelay, json.dumps(dsyncthing_tmp, indent=4))
            )
            self.syncthing.config["devices"].append(dsyncthing_tmp)
        else:
            # Change conf for introducer and autoAcceptFolders
            for dev in self.syncthing.config["devices"]:
                if dev["name"] == namerelay or dev["deviceID"] == keydevicesyncthing:
                    dev["introducer"] = True
                    dev["autoAcceptFolders"] = True
                if dev["name"] == jid.JID(namerelay).resource:
                    dev["name"] = "pulse"
                dev["addresses"] = address
                logger.debug(
                    "Device [%s] syncthing to ars %s\n%s"
                    % (dev["deviceID"], dev["name"], json.dumps(dev, indent=4))
                )

    def is_exist_device_in_config(self, keydevicesyncthing):
        """
        Check if a device exists in the Syncthing configuration.

        Args:
            keydevicesyncthing: The key of the Syncthing device.

        Returns:
            bool: True if the device exists, False otherwise.
        """
        return any(
            device["deviceID"] == keydevicesyncthing
            for device in self.syncthing.devices
        )

    def is_format_key_device(self, keydevicesyncthing):
        """
        Check if the Syncthing device key is in the correct format.

        Args:
            keydevicesyncthing: The key of the Syncthing device.

        Returns:
            bool: True if the key is in the correct format, False otherwise.
        """
        if len(str(keydevicesyncthing)) != 63:
            logger.warning("The size of the syncthing key is incorrect.")
        listtest = keydevicesyncthing.split("-")
        if len(listtest) != 8:
            logger.error("group key diff of 8")
            return False
        for z in listtest:
            if len(z) != 7:
                logger.error("size group key diff of 7")
                return False
            index = 1 + 1
        return True

    async def message(self, msg):
        """
        Handle incoming messages.

        Args:
            msg: The incoming message.
        """
        iscorrectmsg, typemessage = self._check_message(msg)
        if iscorrectmsg:
            try:
                data = json.loads(msg["body"])
            except Exception:
                return

            if (
                self.session == data["sessionid"]
                and data["action"] == "resultconnectionconf"
            ):
                if data["ret"] == 0:
                    fromagent = str(msg["from"].bare)
                    if fromagent == self.sub_assessor:
                        logger.debug(
                            "Resultat data: %s"
                            % json.dumps(data, indent=4, sort_keys=True)
                        )
                        if len(data["data"]) == 0:
                            logger.error("Verify table cluster : has_cluster_ars")
                            sys.exit(0)

                        logger.debug(
                            "Start relay server agent configuration\n%s"
                            % json.dumps(data["data"], indent=4, sort_keys=True)
                        )
                        logger.info(
                            f"The choosen relayserver is {data['data'][0][2]} with the IP {data['data'][0][0]}"
                        )

                        if data["ssh_public_key"]:
                            try:
                                # Make sure user account and profile exists
                                username = "pulseuser"
                                result, message = pulseuser_useraccount_mustexist(
                                    username
                                )
                                if result is False:
                                    logger.error(f"{message}")
                                logger.debug(f"{message}")
                                result, message = pulseuser_profile_mustexist(username)
                                if result is False:
                                    logger.error(f"{message}")
                                logger.debug(f"{message}")
                                for jid, public_key in data["ssh_public_key"].items():
                                    logger.debug(f"Add key of {jid} to authorized_keys")
                                    result, message = (
                                        add_key_to_authorizedkeys_on_client(
                                            username, public_key
                                        )
                                    )
                                    if result is False:
                                        logger.error(f"{message}")
                                    logger.debug(f"{message}")
                            except Exception as e:
                                logger.error(f"{e}")

                        if self.config.syncthing_on:
                            try:
                                if "syncthing" in data:
                                    self.syncthing.config["options"][
                                        "globalAnnounceServers"
                                    ] = [data["syncthing"]]
                                    self.syncthing.config["options"][
                                        "relaysEnabled"
                                    ] = False
                                    self.syncthing.config["options"][
                                        "localAnnounceEnabled"
                                    ] = False
                                    self.syncthing.del_folder("default")
                                    if sys.platform.startswith("win"):
                                        defaultFolderPath = os.path.join(
                                            medullaPath(), "var", "syncthing"
                                        )
                                    elif sys.platform.startswith("linux"):
                                        defaultFolderPath = os.path.join(
                                            os.path.expanduser("~pulseuser"),
                                            "syncthing",
                                        )
                                    elif sys.platform.startswith("darwin"):
                                        defaultFolderPath = os.path.join(
                                            "/",
                                            "Library",
                                            "Application Support",
                                            "Pulse",
                                            "var",
                                            "syncthing",
                                        )
                                    if not os.path.exists(defaultFolderPath):
                                        os.mkdir(defaultFolderPath)
                                        os.chmod(defaultFolderPath, 0o777)
                                    self.syncthing.config["options"][
                                        "defaultFolderPath"
                                    ] = defaultFolderPath

                                if self.deviceid != "":
                                    if len(data["data"][0]) >= 7:
                                        for x in data["data"]:
                                            if self.is_format_key_device(str(x[5])):
                                                self.adddevicesyncthing(
                                                    str(x[5]),
                                                    str(x[2]),
                                                    address=[f"tcp4://{x[0]}:{x[6]}"],
                                                )
                                    logger.debug(
                                        f"synchro config {self.syncthing.is_config_sync()}"
                                    )
                                    self.syncthing.validate_chang_config()
                                    time.sleep(2)
                                    filesyncthing = os.path.join(
                                        os.path.dirname(os.path.realpath(__file__)),
                                        "baseconfigsyncthing.xml",
                                    )
                                    logger.debug("copy configuration syncthing")
                                    shutil.copyfile(
                                        self.fichierconfsyncthing, filesyncthing
                                    )
                                    logger.debug(
                                        "%s"
                                        % json.dumps(self.syncthing.config, indent=4)
                                    )
                                    # if logging.getLogger().level == logging.DEBUG:
                                    # dataconf = json.dumps(
                                    # self.syncthing.config, indent=4
                                    # )
                                    # else:
                                    dataconf = "re-setup syncthing ok"

                                    confsyncthing = {
                                        "action": "resultconfsyncthing",
                                        "sessionid": getRandomName(6, "confsyncthing"),
                                        "ret": 0,
                                        "base64": False,
                                        "data": {
                                            "syncthingconf": "re-setup syncthing ok\n%s"
                                            % dataconf
                                        },
                                    }

                                    self.send_message(
                                        mto=msg["from"],
                                        mbody=json.dumps(confsyncthing),
                                        mtype="chat",
                                    )
                            except Exception:
                                confsyncthing = {
                                    "action": "resultconfsyncthing",
                                    "sessionid": getRandomName(6, "confsyncthing"),
                                    "ret": 255,
                                    "data": {
                                        "errorsyncthingconf": f"{traceback.format_exc()}"
                                    },
                                }
                                self.send_message(
                                    mto=msg["from"],
                                    mbody=json.dumps(confsyncthing),
                                    mtype="chat",
                                )
                        try:
                            if "substitute" in data:
                                logger.debug("substitute information")
                                changeconfigurationsubtitute(
                                    conffilenametmp(opts.typemachine),
                                    data["substitute"],
                                )
                        except Exception as e:
                            logger.error("change configuration subtitute ko")
                            logger.error(f"We encounted the error \n {e}")

                    try:
                        changeconnection(
                            conffilenametmp(opts.typemachine),
                            data["data"][0][1],
                            data["data"][0][0],
                            data["data"][0][2],
                            data["data"][0][3],
                        )
                        try:
                            # write alternative configuration
                            alternativeclusterconnection(
                                conffilenametmp("cluster"), data["data"]
                            )
                            alternativeclusterconnection(
                                conffilename("cluster"), data["data"]
                            )
                            # go to next ARS
                            nextalternativeclusterconnection(conffilenametmp("cluster"))

                            namefileconfiguration = conffilename(self.config.agenttype)
                            namefileconfigurationtmp = conffilenametmp(
                                self.config.agenttype
                            )
                            logger.debug("rotate configuration")
                            rotation_file(namefileconfiguration)
                            logger.debug("write new configuration")
                            shutil.move(namefileconfigurationtmp, namefileconfiguration)
                            logger.debug("make finger print conf file")
                            refreshfingerprintconf(opts.typemachine)
                            logger.debug("end Assesor configuration")
                        except Exception as configuration_error:
                            logger.error(
                                "An error occured while modifying the configuration"
                            )
                            logger.error(f"We obtained the error {configuration_error}")
                            logger.error(
                                f"We hit the backtrace {traceback.format_exc()} "
                            )

                    except Exception:
                        # We failed to read the configuration file. Trying with the old version for compatibility.
                        try:
                            logger.debug("old configuration structure")
                            changeconnection(
                                conffilenametmp(opts.typemachine),
                                data["data"][1],
                                data["data"][0],
                                data["data"][2],
                                data["data"][3],
                            )
                        except Exception as configuration_error:
                            logger.error(
                                "An error occured while modifying the configuration in old format."
                            )
                            logger.error(f"We obtained the error {configuration_error}")
                            logger.error(
                                f"The data variable contains the value: {data}"
                            )
                            logger.error(
                                f"We hit the backtrace {traceback.format_exc()} "
                            )
            else:
                logger.error("The configuration failed.")
                logger.error(
                    f"The AES key may be invalid. On this machine, this is configured to use the key {self.config.keyAES32}"
                )
                logger.error(
                    "Please check on the server on the /etc/pulse-xmpp-agent-substitute/assessor_agent.ini.local"
                )

            # Fin du traitement
            timefin = time.time()

            # Calcul du temps écoulé
            temps_ecoule = timefin - self.timedebut
            # Log du temps de traitement
            logger.info(
                f"The configuration is done. It tooks {temps_ecoule:.2f} seconds"
            )
            self.disconnect(wait=1)

    def infosubstitute(self):
        """
        Get substitute information.

        Returns:
            dict: Substitute information.
        """
        return substitutelist().parameterssubtitute()

    def infos_machine_assessor(self):
        """
        Send machine information to the assessor.
        """
        # envoi information
        dataobj = self.searchInfoMachine()
        self.session = getRandomName(10, "session")
        dataobj["sessionid"] = self.session
        dataobj["base64"] = False
        dataobj["action"] = "assessor_agent"
        dataobj["substitute"] = self.infosubstitute()
        msginfo = {
            "action": "assessor_agent",
            "base64": False,
            "sessionid": self.session,
            "data": dataobj,
            "ret": 0,
        }
        self.config.keyAES32 = [
            str(x.strip())
            for x in re.split(r"[;,:@\(\)\[\]\|\s]\s*", self.config.keyAES32)
            if x.strip() != "" and len(x) == 32
        ][0]
        cipher = AESCipher(self.config.keyAES32)
        msginfo["data"]["codechaine"] = cipher.encrypt(str(self.boundjid))
        self.send_message(
            mto=self.sub_assessor, mbody=json.dumps(msginfo), mtype="chat"
        )

    def searchInfoMachine(self):
        """
        Search for machine information.

        Returns:
            dict: Machine information.
        """
        er = networkagentinfo("config", "inforegle")
        er.messagejson["info"] = self.config.information
        for t in er.messagejson["listipinfo"]:
            if t["ipaddress"] == self.config.ipxmpp:
                xmppmask = t["mask"]
                try:
                    xmppbroadcast = t["broadcast"]
                except Exception:
                    xmppbroadcast = ""
                xmppdhcp = t["dhcp"]
                xmppdhcpserver = t["dhcpserver"]
                xmppgateway = t["gateway"]
                xmppmacaddress = t["macaddress"]
                xmppmacnotshortened = t["macnotshortened"]
                break

        subnetreseauxmpp = subnetnetwork(self.config.ipxmpp, xmppmask)
        BOOLFILECOMPLETREGISTRATION = os.path.join(
            os.path.dirname(os.path.realpath(__file__)), "BOOLFILECOMPLETREGISTRATION"
        )
        self.FullRegistration = False
        if os.path.exists(BOOLFILECOMPLETREGISTRATION):
            self.FullRegistration = True
            os.remove(BOOLFILECOMPLETREGISTRATION)
        system_info = offline_search_kb().get()
        if "infobuild" in system_info:
            if "DisplayVersion" in system_info["infobuild"]:
                # er.messagejson["info"]["platform"]=er.messagejson["info"]["platform"]+" ["+system_info['infobuild']['DisplayVersion'] +"]"
                er.messagejson["info"]["DisplayVersion"] = system_info["infobuild"][
                    "DisplayVersion"
                ]
            if "update_major" in system_info["infobuild"]:
                er.messagejson["info"]["update_major"] = system_info["infobuild"][
                    "update_major"
                ]
            if "ProductName" in system_info["infobuild"]:
                er.messagejson["info"]["ProductName"] = system_info["infobuild"][
                    "ProductName"
                ]
            if "code_lang_iso" in system_info["infobuild"]:
                er.messagejson["info"]["code_lang_iso"] = system_info["infobuild"][
                    "code_lang_iso"
                ]
        try:
            dataobj = {
                "action": "connectionconf",
                "from": self.config.jidagent,
                "compress": False,
                "deployment": self.config.jidchatroomcommand,
                "who": f"{self.config.jidchatroomcommand}/{self.config.NickName}",
                "machine": self.config.NickName,
                "platform": platform.platform(),
                "completedatamachine": base64.b64encode(
                    json.dumps(er.messagejson).encode("utf-8")
                ).decode("utf-8"),
                "plugin": {},
                "portxmpp": self.config.Port,
                "serverxmpp": self.config.Server,
                "agenttype": self.config.agenttype,
                "baseurlguacamole": self.config.baseurlguacamole,
                "subnetxmpp": subnetreseauxmpp,
                "xmppip": self.config.ipxmpp,
                "xmppmask": xmppmask,
                "xmppbroadcast": xmppbroadcast,
                "xmppdhcp": xmppdhcp,
                "xmppdhcpserver": xmppdhcpserver,
                "xmppgateway": xmppgateway,
                "xmppmacaddress": xmppmacaddress,
                "xmppmacnotshortened": xmppmacnotshortened,
                "classutil": self.config.classutil,
                "ippublic": self.ippublic,
                "geolocalisation": {},
                "adorgbymachine": base64strencode(organizationbymachine()),
                "adorgbyuser": "",
                "agent_machine_name": self.agent_machine_name,
                "uuid_serial_machine": serialnumbermachine(),
                "regcomplet": self.FullRegistration,
                "system_info": system_info,
            }

        except Exception:
            logger.error(f"dataobj {traceback.format_exc()}")

        if self.geodata is not None:
            dataobj["geolocalisation"] = self.geodata.localisation
        else:
            logger.warning("geolocalisation disabled")
        lastusersession = ""
        try:
            lastusersession = os.environ["USERNAME"]
        except KeyError as e:
            lastusersession = ""

        if not lastusersession:
            dataobj["adorgbyuser"] = base64strencode(
                organizationbyuser(lastusersession)
            )
        if not lastusersession:
            lastusersession = powershellgetlastuser()
        return dataobj

    # -----------------------------------------------------------------------
    # ----------------------- Getion connection agent -----------------------
    # -----------------------------------------------------------------------

    def handle_connecting(self, data):
        """
        Handle the connecting event.

        Args:
            data: The event data.
        """
        # connection reusssi
        time_connection_ok = time.time()
        # Calcul du temps écoulé
        time_connection = time_connection_ok - self.timedebut
        # Log du temps de traitement
        logger.debug(
            f"The connection to the ejabberd server took {time_connection:.2f} seconds"
        )

    def handle_connection_failed(self, data):
        """
        Handle the connection failed event.

        Args:
            data: The event data.
        """
        print("CONNECTION FAILED")
        loop1 = asyncio.get_event_loop()
        loop1.stop()

    def handle_disconnected(self, data):
        """
        Handle the disconnected event.

        Args:
            data: The event data.
        """
        logger.debug("We got disconnected.")
        loop1 = asyncio.get_event_loop()
        loop1.stop()

    def handle_connected(self, data):
        """
        Handle the connected event.

        Args:
            data: The event data.
        """
        logger.debug(
            f"Configurator connected with jid name {self.config.jidagent} on ({self.config.confserver}:{self.config.confport})"
        )

    async def register(self, iq):
        """
        Fill out and submit a registration form.

        Args:
            iq: The IQ stanza.
        """
        resp = self.Iq()
        resp["type"] = "set"
        resp["register"]["username"] = self.boundjid.user
        resp["register"]["password"] = self.password
        try:
            await resp.send()
            logging.info(f"The account {self.boundjid} is created")
        except IqError as e:
            logging.debug("Could not register account: %s" % e.iq["error"]["text"])
        except IqTimeout:
            logging.error("Could not register account No response from server.")
            self.disconnect()

    def _check_message(self, msg):
        """
        Check the conformity of the message.

        Args:
            msg: The message to check.

        Returns:
            tuple: A tuple containing a boolean indicating if the message is correct and the type of the message.
        """
        try:
            # verify message conformity
            msgkey = msg.keys()
            msgfrom = ""
            if "from" not in msgkey:
                logger.error(f"Stanza message bad format {msg}")
                return (
                    False,
                    "bad format",
                )
            msgfrom = str(msg["from"])
            if "type" in msgkey:
                # eg: ref section 2.1
                type = str(msg["type"])
                if type == "chat":
                    pass
                elif type == "error":
                    # An error has occurred related to a previous message sent
                    # by the sender
                    logger.error(f"Stanza message from {msgfrom}")
                    self.errorhandlingstanza(msg, msgfrom, msgkey)
                    return False, "error"
                elif type == "groupchat":
                    # The message is sent in the context of a multi-user chat
                    # environment
                    logger.error(f"Stanza groupchat message no process {msg} ")
                    msg.reply("Thank you, but I do not treat groupchat messages").send()
                    return False, "groupchat"
                elif type == "headline":
                    # The message is probably generated by an automated service
                    # that delivers or broadcasts content
                    logger.error(
                        f"Stanza headline (automated service) message no process {msg} "
                    )
                    return False, "headline"
                elif type == "normal":
                    # The message is a single message that is sent outside the context of a one-to-one conversation
                    # "or groupchat, and to which it is expected that the recipient will reply
                    logger.warning(f"MESSAGE stanza normal {msg}")
                    msg.reply("Thank you, but I do not treat normal messages").send()
                    return False, "normal"
                else:
                    logger.error(f"Stanza message type inconu {type}")
                    return False, "error"
        except Exception as e:
            logger.error(f"Stanza message bad format {msg}")
            logger.error(f"{traceback.format_exc()}")
            return False, f"error {str(e)}"
        if "body" not in msgkey:
            logger.error(f"Stanza message body missing {msg}")
            return False, "error body missing"
        return True, "chat"

    def _errorhandlingstanza(self, msg, msgfrom, msgkey):
        """
        Analyze stanza information.

        Args:
            msg: The message stanza.
            msgfrom: The sender of the message.
            msgkey: The keys of the message.
        """
        logger.error("child elements message")
        messagestanza = ""
        for t in msgkey:
            if t not in ["error", "lang"]:
                e = str(msg[t])
                if e != "":
                    messagestanza += "%s : %s\n" % (t, e)
        if "error" in msgkey:
            messagestanza += "Error information\n"
            msgkeyerror = msg["error"].keys()
            for t in msg["error"].keys():
                if t != "lang":
                    e = str(msg["error"][t])
                    if e != "":
                        messagestanza += "%s : %s\n" % (t, e)
        if messagestanza != "":
            logger.error(messagestanza)

    # -----------------------------------------------------------------------
    # ---------------------- END analyse strophe xmpp -----------------------
    # -----------------------------------------------------------------------


def createDaemon(optstypemachine, optsconsoledebug, optsdeamon, tglevellog, tglogfile):
    """
    Create a service/Daemon that will execute a det. task.

    Args:
        optstypemachine: The type of machine.
        optsconsoledebug: Console debug flag.
        optsdeamon: Daemon flag.
        tglevellog: Log level.
        tglogfile: Log file.
    """
    try:
        if sys.platform.startswith("win"):
            import multiprocessing

            p = multiprocessing.Process(
                name="xmppagent",
                target=doTask,
                args=(
                    optstypemachine,
                    optsconsoledebug,
                    optsdeamon,
                    tglevellog,
                    tglogfile,
                ),
            )
            p.daemon = True
            p.start()
            p.join()
        else:
            # Store the Fork PID
            pid = os.fork()
            if pid > 0:
                print("PID: %d" % pid)
                os._exit(0)
            doTask(optstypemachine, optsconsoledebug, optsdeamon, tglevellog, tglogfile)
    except OSError as error:
        logger.error("Unable to fork. Error: %d (%s)" % (error.errno, error.strerror))
        logger.error("\n%s" % (traceback.format_exc()))
        os._exit(1)


def doTask(optstypemachine, optsconsoledebug, optsdeamon, tglevellog, tglogfile):
    """
    Execute the task.

    Args:
        optstypemachine: The type of machine.
        optsconsoledebug: Console debug flag.
        optsdeamon: Daemon flag.
        tglevellog: Log level.
        tglogfile: Log file.
    """
    file_put_contents(
        os.path.join(
            os.path.dirname(os.path.realpath(__file__)),
            "INFOSTMP",
            "pidconnection",
        ),
        f"{os.getpid()}",
    )
    if sys.platform.startswith("win"):
        try:
            result = subprocess.check_output(
                [
                    "icacls",
                    os.path.join(
                        os.path.dirname(os.path.realpath(__file__)),
                        "INFOSTMP",
                        "pidconnection",
                    ),
                    "/setowner",
                    "pulse",
                    "/t",
                ],
                stderr=subprocess.STDOUT,
            )
        except subprocess.CalledProcessError as e:
            pass

    if optstypemachine.lower() in ["machine"]:
        sys.path.append(
            os.path.join(os.path.dirname(os.path.realpath(__file__)), "pluginsmachine")
        )
    else:
        sys.path.append(
            os.path.join(os.path.dirname(os.path.realpath(__file__)), "pluginsrelay")
        )
    # Setup the command line arguments.
    tg = confParameter(optstypemachine)
    logger.debug(
        "Parameter to connect. (%s : %s) on xmpp server."
        " %s" % (tg.confserver, tg.confport, tg.confserver),
    )

    if optstypemachine.lower() in ["machine"]:
        tg.pathplugins = os.path.join(
            os.path.dirname(os.path.realpath(__file__)), "pluginsmachine"
        )
    else:
        tg.pathplugins = os.path.join(
            os.path.dirname(os.path.realpath(__file__)), "pluginsrelay"
        )

    attempts = 0  # Initialisation du compteur de tentatives

    while attempts < 5:  # Limitation à 5 essais
        if not tg.confserver.strip():
            tg = confParameter(optstypemachine)

        ip_server = ipfromdns(tg.confserver)  # Résolution de l'IP à partir du DNS
        if ip_server and check_exist_ip_port(ip_server, tg.confport):
            break  # Sort de la boucle si connexion réussie

        # Log d'erreur avec tentative et détails
        logger.error(
            f"Attempt {attempts + 1}: Connection failed - IP: {ip_server or 'N/A'}, Port: {tg.confport}"
        )

        attempts += 1  # Incrémente le compteur
        time.sleep(2)  # Pause de 2 secondes entre chaque tentative
    else:
        # Si toutes les tentatives échouent, consigne un log et quitte le programme
        logger.error("Maximum retry limit reached. Unable to establish a connection.")
        sys.exit(1)  # Quitte le programme avec un code d'erreur

    if tg.agenttype != "relayserver":
        logger.debug(f"connect {ip_server} {tg.confport}")
        xmpp = MUCBot(tg)
        xmpp.register_plugin("xep_0030")  # Service Discovery
        xmpp.register_plugin("xep_0045")  # Multi-User Chat
        xmpp.register_plugin("xep_0004")  # Data Forms
        xmpp.register_plugin("xep_0050")  # Adhoc Commands
        xmpp.register_plugin(
            "xep_0199",
            {"keepalive": True, "frequency": 600, "interval": 600, "timeout": 500},
        )
        xmpp.register_plugin("xep_0077")  # In-band Registration
        xmpp["xep_0077"].force_registration = True

        # Connect to the XMPP server and start processing XMPP
        logger.debug(f"Connecting to {ip_server}:{tg.confport}")
        logger.debug(f"The jid for the configuration is : {tg.jidagent}")

        xmpp.IP_or_FQDN_connect = ip_server
        xmpp.Port_connect = tg.confport

        xmpp.address = (ip_server, int(tg.confport))
        logger.debug("-----------------------------------------")
        logger.debug("----- CONNECTION XMPP CONFIGURATEUR -----")
        logger.debug("-----------------------------------------")
        try:
            xmpp.connect(address=xmpp.address, force_starttls=None)
        except Exception as e:
            logging.error("Connection failed: %s. Retrying..." % e)
            logging.error("Connection to: IP %s, Port %s." % (ip_server, tg.confport))
        try:
            xmpp.loop.run_forever()
        except RuntimeError:
            logging.error("RuntimeError during connection")
        finally:
            logger.debug("bye bye connecteur")
            namefilebool = os.path.join(
                os.path.dirname(os.path.realpath(__file__)), "BOOLCONNECTOR"
            )
            fichier = open(namefilebool, "w")
            fichier.close()
            # xmpp.loop.close()

            logger.debug("bye bye connecteur")
            # sys.exit(0)  # Quitte le programme avec un code d'erreur
    else:
        logger.debug(
            "Warning: A relay server holds a Static "
            "configuration. Do not run configurator agent on relay servers.",
        )
        sys.exit(1)  # Quitte le programme avec un code d'erreur


if __name__ == "__main__":
    if sys.platform.startswith("linux") and os.getuid() != 0:
        logging.error("Agent must be running as root")
        sys.exit(0)
    elif sys.platform.startswith("win") and isWinUserAdmin() == 0:
        logging.error("Medulla agent must be running as Administrator")
        sys.exit(0)
    elif sys.platform.startswith("darwin") and not isMacOsUserAdmin():
        logging.error("Medulla agent must be running as root")
        sys.exit(0)

    optp = OptionParser()
    optp.add_option(
        "-d",
        "--deamon",
        action="store_true",
        dest="deamon",
        default=False,
        help="deamonize process",
    )
    optp.add_option(
        "-t",
        "--type",
        dest="typemachine",
        default=False,
        help="Type machine : machine or relayserver",
    )
    optp.add_option(
        "-c",
        "--consoledebug",
        action="store_true",
        dest="consoledebug",
        default=False,
        help="console debug",
    )

    opts, args = optp.parse_args()

    try:
        tg = confParameter(opts.typemachine)
    except configparser.NoSectionError:
        if opts.typemachine.lower() in ["machine"] and os.path.exists(
            conffilename(opts.typemachine.lower())
        ):
            logger.error(
                "The agentconf.ini file does not exist. We add the template file"
            )
            shutil.copy(
                conffilename(opts.typemachine.lower()) + ".tpl",
                conffilename(opts.typemachine.lower()),
            )
    except Exception as e:
        logger.error(str(e))

    mfile = os.path.join(
        os.path.dirname(os.path.realpath(__file__)), "DEBUG_CONNECTION_AGENT"
    )
    if opts.consoledebug or os.path.isfile(mfile) or os.path.isfile(f"{mfile}.txt"):
        tg.levellog = logging.DEBUG
    format = "%(asctime)s - %(levelname)s - (CONF)%(message)s"
    formatter = logging.Formatter(format)
    logging.basicConfig(level=tg.levellog, format=format)

    logger = logging.getLogger()  # either the given logger or the root logger
    logger.setLevel(tg.levellog)
    # If the logger has handlers, we configure the first one. Otherwise we add a handler and configure it
    if logger.handlers:
        console = logger.handlers[
            0
        ]  # we assume the first handler is the one we want to configure
    else:
        console = logging.StreamHandler()
        logger.addHandler(console)
    console.setFormatter(formatter)
    console.setLevel(tg.levellog)

    medullaLogFolder = Path(os.path.join(medullaPath(), "var", "log"))
    medullaLogFolder.mkdir(exist_ok=True)
    file_handler = logging.FileHandler(tg.logfile)
    file_handler.setLevel(tg.levellog)
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)

    if not opts.deamon:
        doTask(
            opts.typemachine, opts.consoledebug, opts.deamon, tg.levellog, tg.logfile
        )
    else:
        createDaemon(
            opts.typemachine, opts.consoledebug, opts.deamon, tg.levellog, tg.logfile
        )
