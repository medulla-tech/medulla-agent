#!/usr/bin/python3
# -*- coding: utf-8; -*-
# SPDX-FileCopyrightText: 2016-2023 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-3.0-or-later

import sys
import re
import os
import logging
import traceback
import platform
import base64
import json
import time
import socket
import select
import threading
from multiprocessing import Queue
import psutil
from .utils import (
    getRandomName,
    isBase64,
    is_connectedServer,
    getIpXmppInterface,
    file_put_contents,
    refreshfingerprint,
)

from .configuration import confParameter
from .logcolor import add_coloring_to_emit_ansi, add_coloring_to_emit_windows

from .networkinfo import organizationbymachine, organizationbyuser

if sys.platform.startswith("win"):
    import win32api
    import win32con
    import win32pipe
    import win32file


class process_serverPipe:
    def __init__(
        self,
        optstypemachine,
        optsconsoledebug,
        optsdeamon,
        tglevellog,
        tglogfile,
        queue_recv_tcp_to_xmpp,
        queueout,
        eventkillpipe,
    ):
        if platform.system() == "Windows":
            # Windows does not support ANSI escapes and we are using API calls
            # to set the console color
            logging.StreamHandler.emit = add_coloring_to_emit_windows(
                logging.StreamHandler.emit
            )
        else:
            # all non-Windows platforms are supporting ANSI escapes so we use
            # them
            logging.StreamHandler.emit = add_coloring_to_emit_ansi(
                logging.StreamHandler.emit
            )
        # format log more informations
        format = "%(asctime)s - %(levelname)s -(SP) %(message)s"
        # more information log
        # format ='[%(name)s : %(funcName)s : %(lineno)d] - %(levelname)s - %(message)s'
        if not optsdeamon and optsconsoledebug:
            logging.basicConfig(level=logging.DEBUG, format=format)
        else:
            logging.basicConfig(
                level=tglevellog, format=format, filename=tglogfile, filemode="a"
            )
        self.logger = logging.getLogger()
        self.logger.debug(" INITIALISATION SERVER PIPE")

        tg = confParameter(optstypemachine)
        self.eventkillpipe = eventkillpipe
        self.queue_recv_tcp_to_xmpp = queue_recv_tcp_to_xmpp
        # just do one connection and terminate.
        # self.quitserverpipe = False
        if platform.system() == "Windows":
            self.logger.debug(
                "Starting the server that watches for network interface changes"
            )
            pid = os.getpid()
            while not self.eventkillpipe.wait(1):
                self.logger.debug("Waiting for interface informations")
                try:
                    self.pipe_handle = win32pipe.CreateNamedPipe(
                        r"\\.\pipe\interfacechang",
                        win32pipe.PIPE_ACCESS_DUPLEX,
                        win32pipe.PIPE_TYPE_MESSAGE | win32pipe.PIPE_WAIT,
                        win32pipe.PIPE_UNLIMITED_INSTANCES,
                        65536,
                        65536,
                        300,
                        None,
                    )
                    win32pipe.ConnectNamedPipe(self.pipe_handle, None)
                    self.logger.debug(f"Waiting event network change pid {pid}")
                    data = win32file.ReadFile(self.pipe_handle, 4096)
                except Exception as e:
                    self.logger.error(f"read input from Pipenammed error {str(e)}")
                    self.logger.warning(f"pid server pipe process is {pid}")
                    continue
                finally:
                    self.pipe_handle.Close()
                if len(data) >= 2:
                    if data[1] == "terminate":
                        self.logger.debug("Terminate event network listen Server")
                    else:
                        try:
                            self.logger.debug(f"_____________{data[1]}")
                            self.queue_recv_tcp_to_xmpp.put(data[1])
                        except Exception as e:
                            self.logger.warning(
                                f"read input from Pipe nammed error {str(e)}"
                            )


class process_tcp_serveur:
    def __init__(
        self,
        port,
        optstypemachine,
        optsconsoledebug,
        optsdeamon,
        tglevellog,
        tglogfile,
        queue_recv_tcp_to_xmpp,
        queueout,
        eventkilltcp,
    ):
        if platform.system() == "Windows":
            # Windows does not support ANSI escapes and we are using API calls
            # to set the console color
            logging.StreamHandler.emit = add_coloring_to_emit_windows(
                logging.StreamHandler.emit
            )
        else:
            # all non-Windows platforms are supporting ANSI escapes so we use
            # them
            logging.StreamHandler.emit = add_coloring_to_emit_ansi(
                logging.StreamHandler.emit
            )
        # format log more informations
        format = "%(asctime)s - %(levelname)s -(SK) %(message)s"
        # more information log
        # format ='[%(name)s : %(funcName)s : %(lineno)d] - %(levelname)s - %(message)s'
        if not optsdeamon and optsconsoledebug:
            logging.basicConfig(level=logging.DEBUG, format=format)
        else:
            logging.basicConfig(
                level=tglevellog, format=format, filename=tglogfile, filemode="a"
            )
        self.logger = logging.getLogger()
        self.logger.debug("Initialisation of the Kiosk server")

        tg = confParameter(optstypemachine)

        # using event eventkill for signal stop thread
        self.eventkill = eventkilltcp
        # multiprocessing.Event
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.queue_recv_tcp_to_xmpp = queue_recv_tcp_to_xmpp
        self.queueout = queueout
        self.port = tg.am_local_port
        self.optstypemachine = optstypemachine
        self.optsconsoledebug = optsconsoledebug
        self.optsdeamon = optsdeamon
        self.tglevellog = tglevellog
        self.tglogfile = tglogfile
        # Bind the socket to the port
        server_address = ("localhost", self.port)
        for _ in range(20):
            try:
                self.logger.debug(f"Binding to kiosk server {server_address}")
                self.sock.bind(server_address)
                break
            except Exception as e:
                self.logger.error(f"bind adress {str(e)}")
                time.sleep(40)
        # Listen for incoming connections
        self.sock.listen(5)
        self.logger.debug("_____________ START SERVER KIOSK ______________")
        pid = os.getpid()
        while not self.eventkill.wait(1):
            self.logger.debug(f"The process of the KIOSK server is {pid}")
            try:
                rr, rw, err = select.select([self.sock], [], [self.sock], 7)
            except Exception as e:
                self.logger.error(f"kiosk server : {str(e)}")
                # self.sock.shutdown(2)    # 0 = done receiving, 1 = done
                # sending, 2 = both
                self.sock.close()
                # connection error event here, maybe reconnect
                self.logger.error("Quit connection kiosk")
                break
            except KeyboardInterrupt:
                self.logger.error("The KIOSK server has been interupted by CTRL+C")
                break
            if self.sock in rr:
                try:
                    clientsocket, client_address = self.sock.accept()
                except Exception as e:
                    break
                if client_address[0] == "127.0.0.1":
                    self.logger.debug("creation thread")
                    client_handler = threading.Thread(
                        target=self.handle_client_connection, args=(clientsocket,)
                    ).start()
                else:
                    self.logger.info(f"Connection refused from : {client_address}")
                    clientsocket.close()
            if self.sock in err:
                self.sock.close()
                self.logger.error("Quit connection kiosk")
                break
        self.logger.info("QUIT process tcp serveur")
        self.sock.close()

    def handle_client_connection(self, client_socket):
        """
        this function handles the message received from kiosk or watching syncting service
        the function must provide a response to an acknowledgment kiosk or a result
        Args:
            client_socket: socket for exchanges between AM and Kiosk

        Returns:
            no return value
        """
        try:
            # request the recv message
            recv_msg_from_kiosk = client_socket.recv(4096)
            if len(recv_msg_from_kiosk) != 0:
                msg = str(recv_msg_from_kiosk.decode("utf-8", "ignore"))
                self.queue_recv_tcp_to_xmpp.put(msg)
        except Exception as e:
            self.logger.error(f"message to kiosk server : {str(e)}")
            self.logger.error("\n%s" % (traceback.format_exc()))
        finally:
            client_socket.close()


def minifyjsonstringrecv(strjson):
    # on supprime les commentaires // et les passages a la ligne
    strjson = "".join(
        [row.split("//")[0] for row in strjson.split("\n") if len(row.strip()) != 0]
    )
    # on vire les tab les passage a la ligne et les fin de ligne
    regex = re.compile(r"[\n\r\t]")
    strjson = regex.sub("", strjson)
    # on protege les espaces des strings json
    reg = re.compile(r"""(\".*?\n?.*?\")|(\'.*?\n?.*?\')""")
    newjson = re.sub(
        reg,
        lambda x: '"%s"' % str(x.group(0)).strip("\"'").strip().replace(" ", "@@ESP@@"),
        strjson,
    )
    # on vire les espaces
    newjson = newjson.replace(" ", "")
    # on remet les espace protégé
    newjson = newjson.replace("@@ESP@@", " ")
    # on supprime deserror retrouver souvent dans les json
    newjson = newjson.replace(",}", "}")
    newjson = newjson.replace("{,", "{")
    newjson = newjson.replace("[,", "[")
    newjson = newjson.replace(",]", "]")
    return newjson


class manage_kiosk_message:
    def __init__(self, queue_in, objectxmpp, key_quit="quit_server_kiosk"):
        self.logger = logging.getLogger()
        self.queue_in = queue_in
        self.objectxmpp = objectxmpp
        self.key_quit = key_quit
        self.threadevent = threading.Thread(
            name="thread_read_queue", target=self.manage_event_kiosk
        )
        self.running = True
        self.threadevent.start()

    def quit(self):
        self.queue_in.put(self.key_quit)
        self.running = False

    def send_message(self, msg):
        self.queue_in.put(msg)

    def manage_event_kiosk(self):
        self.logger.debug("loop event wait start")
        while self.running:
            try:
                event = self.queue_in.get(5)
                self.logger.debug("Loop event wait start")
                if event == self.key_quit:
                    self.logger.debug("Quit server manage event kiosk")
                    break
                self.handle_client_connection(str(event))
            except Queue.Empty:
                self.logger.debug("The loop is empty")
            except KeyboardInterrupt:
                pass
            finally:
                self.logger.debug("loop event wait stop")

    def test_type(self, value):
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

    def runjson(self, jsonf, level=0):
        if isinstance(jsonf, dict):
            msg = f'{level * "  "}dict'
            return {
                element: self.runjson(jsonf[element], level=level + 1)
                for element in jsonf
            }
        elif isinstance(jsonf, list):
            return [self.runjson(element, level=level + 1) for element in jsonf]
        else:
            return self.test_type(jsonf)

    def handle_client_connection(self, recv_msg_from_kiosk):
        substitute_recv = ""
        try:
            self.logger.info(f"Received {recv_msg_from_kiosk}")
            datasend = {
                "action": "resultkiosk",
                "sessionid": getRandomName(6, "kioskGrub"),
                "ret": 0,
                "base64": False,
                "data": {},
            }
            msg = str(recv_msg_from_kiosk.decode("utf-8", "ignore"))
            ##############
            if isBase64(msg):
                msg = base64.b64decode(msg)
            try:
                _result = json.loads(minifyjsonstringrecv(msg))
                result = self.runjson(_result)
                self.logger.info(
                    "__Event network or kiosk %s" % json.dumps(result, indent=4)
                )
            except ValueError as e:
                self.logger.error(f"Message socket is not json correct : {str(e)}")
                return
            try:
                if "interface" in result:
                    self.logger.debug("RECV NETWORK INTERFACE")

                    BOOLFILECOMPLETREGISTRATION = os.path.join(
                        os.path.dirname(os.path.realpath(__file__)),
                        "..",
                        "BOOLFILECOMPLETREGISTRATION",
                    )
                    file_put_contents(
                        BOOLFILECOMPLETREGISTRATION,
                        "Do not erase.\n"
                        "when re-recording, it will be of type 2. full recording.",
                    )
                    if self.objectxmpp.config.alwaysnetreconf:
                        # politique reconfiguration sur chaque changement de
                        # network.
                        self.logger.warning(
                            "No network interface can replace the previous one. Agent reconfiguration needed to resume the service."
                        )
                        self.objectxmpp.networkMonitor()
                        return

                    if self.objectxmpp.state.ensure("connected"):
                        # toujours connected.
                        self.objectxmpp.md5reseau = refreshfingerprint()
                        self.objectxmpp.update_plugin()
                        return
                    try:
                        self.objectxmpp.config.ipxmpp
                    except BaseException:
                        self.objectxmpp.config.ipxmpp = getIpXmppInterface(
                            self.objectxmpp.config.Server, self.objectxmpp.config.Port
                        )
                    if self.objectxmpp.config.ipxmpp in result["removedinterface"]:
                        self.logger.info(
                            f"The IP address used to contact the XMPP Server is: {self.objectxmpp.config.ipxmpp}"
                        )
                        self.logger.info(
                            "__DETECT SUPP INTERFACE USED FOR CONNECTION AGENT MACHINE TO EJABBERD__"
                        )
                        logmsg = (
                            "The new network interface can replace the previous one. "
                            "The service will resume after restarting the agent"
                        )
                        if is_connectedServer(
                            self.objectxmpp.ipconnection, self.objectxmpp.config.Port
                        ):
                            # We only do a restart
                            self.logger.warning(logmsg)
                            self.objectxmpp.md5reseau = refreshfingerprint()
                            self.objectxmpp.restartBot()
                        else:
                            # We reconfigure all
                            # Activating the new interface can take a while.
                            time.sleep(15)
                            if is_connectedServer(
                                self.objectxmpp.ipconnection,
                                self.objectxmpp.config.Port,
                            ):
                                # We only do a restart
                                self.logger.warning(logmsg)
                                self.objectxmpp.md5reseau = refreshfingerprint()
                                self.objectxmpp.restartBot()
                            else:
                                self.logger.warning(
                                    "No network interface can replace the previous one. "
                                    "Agent reconfiguration needed to resume the service."
                                )
                                self.objectxmpp.networkMonitor()
                    elif len(result["interface"]) < 2:
                        # il y a seulement l'interface 127.0.0.1
                        # dans ce cas on refait la total.
                        self.logger.warning(
                            "The new uniq network interface. "
                            "Agent reconfiguration needed to resume the service."
                        )
                        self.objectxmpp.networkMonitor()
                    else:
                        self.logger.warning(
                            "The new network interface is directly usable. Nothing to do"
                        )
                        self.objectxmpp.md5reseau = refreshfingerprint()
                        self.objectxmpp.update_plugin()
                    return
            except Exception as e:
                self.logger.error(f"{str(e)}")
                return
            # Manage message from tcp connection
            self.logger.debug("RECV FROM TCP/IP CLIENT")
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
                elif result["action"] == "kioskinterfaceAsk":
                    datasend["data"]["subaction"] = "ask"
                    datasend["data"]["askuser"] = result["askuser"]
                    datasend["data"]["askdate"] = result["askdate"]
                elif result["action"] == "kioskLog":
                    if "message" in result and result["message"] != "":
                        self.objectxmpp.xmpplog(
                            result["message"],
                            type="noset",
                            sessionname="",
                            priority=0,
                            action="xmpplog",
                            who=self.objectxmpp.boundjid.bare,
                            how="Planned",
                            why="",
                            module="Kiosk | Notify",
                            fromuser="",
                            touser="",
                        )
                        if "type" in result:
                            if result["type"] == "info":
                                self.logger.info(result["message"])
                            elif result["type"] == "warning":
                                self.logger.warning(result["message"])
                elif result["action"] == "notifysyncthing":
                    datasend["action"] = "notifysyncthing"
                    datasend["sessionid"] = getRandomName(6, "syncthing")
                    datasend["data"] = result["data"]
                elif result["action"] in ["terminalInformations", "terminalAlert"]:
                    substitute_recv = self.objectxmpp.sub_monitoring
                    datasend["action"] = "vectormonitoringagent"
                    datasend["sessionid"] = getRandomName(
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
                    logging.getLogger().warning(
                        "this action is not taken "
                        "into account : %s" % result["action"]
                    )
                    return
                if substitute_recv:
                    logging.getLogger().warning(f"send to {substitute_recv} ")
                    self.objectxmpp.send_message(
                        mbody=json.dumps(datasend), mto=substitute_recv, mtype="chat"
                    )
                else:
                    # Call plugin on master
                    self.objectxmpp.send_message_to_master(datasend)
        except Exception as e:
            logging.getLogger().error(f"message to kiosk server : {str(e)}")
            logging.getLogger().error("\n%s" % (traceback.format_exc()))
