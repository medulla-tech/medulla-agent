#!/usr/bin/python3
# -*- coding: utf-8; -*-
#
# (c) 2016 siveo, http://www.siveo.net
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

# file: pulse_xmpp_master_substitute/bin/agent.py

from slixmpp import jid
import sys
import os
from os import listdir
from os.path import isfile, join
import logging
import base64
import json
import time
import slixmpp
from slixmpp.exceptions import IqError, IqTimeout
from slixmpp.xmlstream.stanzabase import ET
import posix_ipc

from lib.configuration import confParameter
from lib.utils import (
    DEBUGPULSE,
    getRandomName,
    call_plugin,
    call_plugin_sequentially,
    ipfromdns,
    base_message_queue_posix,
)
import traceback
import signal
from lib.plugins.xmpp import XmppMasterDatabase
from lib.plugins.glpi import Glpi
from lib.manage_scheduler import manage_scheduler
import asyncio
import random
import imp
from slixmpp.xmlstream.handler import CoroutineCallback
from slixmpp.xmlstream.handler import Callback
from slixmpp.xmlstream.matcher.xpath import MatchXPath
from slixmpp.xmlstream.matcher.stanzapath import StanzaPath
from slixmpp.xmlstream.matcher.xmlmask import MatchXMLMask

logger = logging.getLogger()

raw_input = input


def getComputerByMac(mac):
    ret = Glpi().getMachineByMacAddress("imaging_module", mac)
    if type(ret) == list:
        if len(ret) != 0:
            return ret[0]
        else:
            return None
    return ret


#### faire singeton
class MUCBot(slixmpp.ClientXMPP):
    def __init__(self, conf_file):  # jid, password, room, nick):
        self.fileconf = conf_file
        self.modulepath = os.path.abspath(
            os.path.join(
                os.path.dirname(os.path.realpath(__file__)),
                "..",
                "pluginsmastersubstitute",
            )
        )
        signal.signal(signal.SIGINT, self.signal_handler)
        self.config = confParameter(conf_file)

        ### update level log for slixmpp
        handler_slixmpp = logging.getLogger("slixmpp")
        logging.log(
            DEBUGPULSE, "slixmpp log level is %s" % self.config.log_level_slixmpp
        )
        handler_slixmpp.setLevel(self.config.log_level_slixmpp)

        logging.log(
            DEBUGPULSE, "Starting Master sub (%s)" % (self.config.jidmastersubstitute)
        )
        slixmpp.ClientXMPP.__init__(
            self,
            jid.JID(self.config.jidmastersubstitute),
            self.config.passwordconnection,
        )
        # We define the type of the Agent
        self.config.agenttype = "substitute"
        self.manage_scheduler = manage_scheduler(self)
        self.schedule("schedulerfunction", 10, self.schedulerfunction, repeat=True)

        # Update agent from Master
        # self.pathagent = os.path.join(os.path.dirname(os.path.realpath(__file__)))
        # self.img_agent = os.path.join(os.path.dirname(os.path.realpath(__file__)), "img_agent")
        # self.Update_Remote_Agentlist = Update_Remote_Agent(self.pathagent, True )
        # self.descriptorimage = Update_Remote_Agent(self.img_agent)
        # END Update agent from Master
        self.agentmaster = jid.JID(self.config.jidmaster)
        # self.schedule('queueinfo', 10 , self.queueinfo, repeat=True)
        # _____________ Getion connection agent _______________________
        self.add_event_handler("register", self.register)
        self.add_event_handler("connecting", self.handle_connecting)
        self.add_event_handler("connection_failed", self.handle_connection_failed)
        self.add_event_handler("disconnected", self.handle_disconnected)
        # _____________ Getion connection agent _______________________
        self.add_event_handler("session_start", self.start)
        self.add_event_handler("message", self.message)
        # self.add_event_handler('iqsendpulseasync', self.iqsendpulseasync)
        # self.add_event_handler('iq_function', self.myiq)

        self.schedule("Clean_old_queue", 10, self.Clean_old_queue, [200], repeat=True)
        self.add_event_handler(
            "restartmachineasynchrone", self.restartmachineasynchrone
        )

        self.register_handler(
            CoroutineCallback(
                "CustomXEP_Handle2",
                StanzaPath("/iq@type=result"),
                self._handle_custom_iq,
            )
        )
        self.register_handler(
            CoroutineCallback(
                "CustomXEP_Handle",
                StanzaPath("/iq@type=error"),
                self._handle_custom_iq_error,
            )
        )

        base_message_queue_posix().clean_file_all_message(prefixe=self.boundjid.user)

    def Clean_old_queue(self, nbsecond):
        """
        Remove queue older than a defined seconds.

        Args:
            nbsecond: The number of seconds from which we delete the queue
        """
        queue_files = [
            queue_file
            for queue_file in os.listdir("/dev/mqueue")
            if queue_file != "mysend"
            and os.path.isfile(os.path.join("/dev/mqueue", queue_file))
        ]
        for queue_file in queue_files:
            path_queue = os.path.join("/dev/mqueue", queue_file)
            if time.time() - os.path.getmtime(path_queue) > nbsecond:
                try:
                    posix_ipc.unlink_message_queue("/" + queue_file)
                except:
                    logger.debug(
                        "An error occured while deleting the file %s from the queue"
                        % queue_file
                    )

    def clean_my_mpqueue(self):
        """
        Delete all the files from /dev/mqueue
        """
        mpqueue_files = [
            mpqueue_file
            for mpqueue_file in listdir("/dev/mqueue")
            if isfile(join("/dev/mqueue", mpqueue_file))
        ]
        for mpqueue_file in mpqueue_files:
            if mpqueue_file != "mysend":
                if mpqueue_file.startswith("/" + self.boundjid.user):
                    try:
                        posix_ipc.unlink_message_queue("/" + mpqueue_file)
                    except:
                        logger.error(
                            "An error occured while deleting the file %s" % mpqueue_file
                        )

    # -----------------------------------------------------------------------
    # ----------------------- Getion connection agent -----------------------
    # -----------------------------------------------------------------------

    def Mode_Marche_Arret_loop(self, nb_reconnect=None, forever=False, timeout=None):
        """
        Connect to the XMPP server and start processing XMPP stanzas.
        """
        if nb_reconnect:
            self.startdata = nb_reconnect
        else:
            self.startdata = 1
        while self.startdata > 0:
            self.disconnect(wait=1)
            logger.debug("reconnect Mode_Marche_Arret_loop")
            self.config = confParameter(self.fileconf)
            self.address = (ipfromdns(self.config.Server), int(self.config.Port))
            logger.debug("try connection (%s) %s " % (self.startdata, self.address))
            logger.debug("forever (%s) %s " % (forever, timeout))
            self.Mode_Marche_Arret_connect(forever=forever, timeout=timeout)
            if nb_reconnect:
                self.startdata = self.startdata - 1

    def Mode_Marche_Arret_connect(self, forever=False, timeout=10):
        """
        a savoir apres "CONNECTION FAILED"
        il faut reinitialiser address et port de connection.
        """
        self.connect(address=self.address)
        self.process(forever=forever, timeout=timeout)

    def Mode_Marche_Arret_nb_reconnect(self, nb_reconnect):
        self.startdata = nb_reconnect

    def Mode_Marche_Arret_terminate(self):
        self.startdata = 0
        self.disconnect()

    def Mode_Marche_Arret_stop_agent(self, time_stop=5):
        self.startdata = 0
        self.connect_loop_wait = -1
        self.disconnect(wait=time_stop)

    def handle_connecting(self, data):
        """
        success connecting agent
        """
        pass

    def handle_connection_failed(self, data):
        """
        on connection failed on libere la connection
        a savoir apres "CONNECTION FAILED"
        il faut reinitialiser adress et port de connection.
        """
        # self.Mode_Marche_Arret_init_adress_connect("jfk.siveo.net", 5222)
        print("\nCONNECTION FAILED %s" % self.connect_loop_wait)
        self.connect_loop_wait = 5
        self.Mode_Marche_Arret_stop_agent(time_stop=1)
        # self.disconnect(wait=5)

    def handle_disconnected(self, data):
        print("handle_disconnected %s\n" % self.connect_loop_wait)
        self.connect_loop_wait = 2
        # self.disconnect()

    def register(self, iq):
        logging.info("register user %s" % self.boundjid)
        resp = self.Iq()
        resp["type"] = "set"
        resp["register"]["username"] = self.boundjid.user
        resp["register"]["password"] = self.password
        try:
            resp.send()
            logging.info("Account created for %s!" % self.boundjid)
        except IqError as e:
            logging.error("Could not register account: %s" % e.iq["error"]["text"])
            self.disconnect()

        except IqTimeout as e:
            logging.error("No response from server.")
            self.disconnect()

    # async def register(self, iq):
    # logging.info("register user %s" % self.boundjid)
    # resp = self.Iq()
    # resp['type'] = 'set'
    # resp['register']['username'] = self.boundjid.user
    # resp['register']['password'] = self.password
    # try:
    # task = asyncio.ensure_future(resp.send())
    # await task
    # logging.info("Account created for %s!" % self.boundjid)
    # except IqError as e:
    # logging.info("Account created for")
    # if e.iq["error"]["code"] == "409":
    # logging.warning(
    # "Could not register account %s : User already exists"
    #% resp["register"]["username"])
    # else:
    # logging.error(
    # "Could not register account %s : %s"
    #% (resp["register"]["username"], e.iq["error"]["text"]))
    ##self.disconnect()
    # except IqTimeout as e:
    # logging.error("No response from server.")
    # self.Mode_Marche_Arret_stop_agent(time_stop=1)

    # -----------------------------------------------------------------------
    # --------------------- END Getion connection agent ---------------------
    # -----------------------------------------------------------------------

    # -----------------------------------------------------------------------
    # ------------------------ analyse strophe xmpp -------------------------
    # -----------------------------------------------------------------------

    def _check_message(self, msg):
        try:
            # verify message conformity
            msgkey = msg.keys()
            msgfrom = ""
            if "from" not in msgkey:
                logging.error("Stanza message bad format %s" % msg)
                return (
                    False,
                    "bad format",
                )
            msgfrom = str(msg["from"])
            if "type" in msgkey:
                # eg: ref section 2.1
                type = str(msg["type"])
                if type == "chat":
                    # The message is sent in the context of a one-to-one chat
                    # conversation agent
                    pass
                elif type == "groupchat":
                    # The message is sent in the context of a multi-user chat
                    # environment
                    logger.error("Stanza groupchat message no process %s " % msg)
                    msg.reply("Thank you, but I do not treat groupchat messages").send()
                    return False, "groupchat"
                elif type == "headline":
                    # The message is probably generated by an automated service
                    # that delivers or broadcasts content
                    logger.error(
                        "Stanza headline (automated service) message no process %s "
                        % msg
                    )
                    return False, "headline"
                elif type == "normal":
                    # The message is a single message that is sent outside the context of a one-to-one conversation
                    # "or groupchat, and to which it is expected that the recipient will reply
                    logger.warning("MESSAGE stanza normal %s" % msg)
                    msg.reply("Thank you, but I do not treat normal messages").send()
                    return False, "normal"
                elif type == "error":
                    # An error has occurred related to a previous message sent
                    # by the sender
                    logger.error("Stanza message from %s" % msgfrom)
                    self.errorhandlingstanza(msg, msgfrom, msgkey)
                    return False, "error"
                else:
                    logger.error("Stanza message type inconu %s" % type)
                    return False, "error"
        except Exception as e:
            logging.error("Stanza message bad format %s" % msg)
            logging.error("%s" % (traceback.format_exc()))
            return False, "error %s" % str(e)
        if "body" not in msgkey:
            logging.error("Stanza message body missing %s" % msg)
            return False, "error body missing"
        return True, "chat"

    def _errorhandlingstanza(self, msg, msgfrom, msgkey):
        """
        analyse stanza information
        """
        logging.error("child elements message")
        messagestanza = ""
        for t in msgkey:
            if t != "error" and t != "lang":
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
            logging.error(messagestanza)

    # -----------------------------------------------------------------------
    # ---------------------- END analyse strophe xmpp -----------------------
    # -----------------------------------------------------------------------

    def send_message_to_master(self, msg):
        self.send_message(
            mbody=json.dumps(msg), mto="%s/MASTER" % self.agentmaster, mtype="chat"
        )

    async def start(self, event):
        self.datas_send = []
        mg = base_message_queue_posix()
        mg.load_file(self.boundjid.user)
        mg.clean_file_all_message(prefixe=self.boundjid.user)
        self.shutdown = False
        self.send_presence()
        await self.get_roster()
        logging.log(DEBUGPULSE, "subscribe xmppmaster")
        self.send_presence(pto=self.agentmaster, ptype="subscribe")

        self.xmpplog(
            "Starting substitute agent",
            type="info",
            sessionname="",
            priority=-1,
            action="xmpplog",
            who=self.boundjid.bare,
            how="",
            why="",
            date=None,
            fromuser=self.boundjid.bare,
            touser="",
        )

        # call plugin start
        startparameter = {
            "action": "start",
            "sessionid": getRandomName(6, "start"),
            "ret": 0,
            "base64": False,
            "data": {},
        }
        dataerreur = {
            "action": "result" + startparameter["action"],
            "data": {"msg": "error plugin : " + startparameter["action"]},
            "sessionid": startparameter["sessionid"],
            "ret": 255,
            "base64": False,
        }
        msg = {"from": self.boundjid.bare, "to": self.boundjid.bare, "type": "chat"}
        if "data" not in startparameter:
            startparameter["data"] = {}
        module = "%s/plugin_%s.py" % (self.modulepath, startparameter["action"])
        call_plugin(
            module,
            self,
            startparameter["action"],
            startparameter["sessionid"],
            startparameter["data"],
            msg,
            dataerreur,
        )

    def signal_handler(self, signal, frame):
        logging.log(DEBUGPULSE, "CTRL-C EVENT")
        msgevt = {
            "action": "evtfrommachine",
            "sessionid": getRandomName(6, "eventwin"),
            "ret": 0,
            "base64": False,
            "data": {"machine": self.boundjid.jid, "event": "CTRL_C_EVENT"},
        }
        self.send_message_to_master(msgevt)
        self.shutdown = True
        logging.log(DEBUGPULSE, "shutdown xmpp agent %s!" % self.boundjid.user)
        self.Mode_Marche_Arret_stop_agent(time_stop=1)
        # self.disconnect(wait=10)

    def restartAgent(self, to):
        self.send_message(
            mto=to, mbody=json.dumps({"action": "restartbot", "data": ""}), mtype="chat"
        )

    async def restartmachineasynchrone(self, jid):
        waittingrestart = random.randint(10, 20)
        # TODO : Replace print by log
        # print "Restart Machine jid %s after %s secondes" % (jid, waittingrestart)
        # time.sleep(waittingrestart)
        await asyncio.sleep(waittingrestart)
        # TODO : Replace print by log
        # print "Restart Machine jid %s fait" % jid
        # Check if restartAgent is not called from a plugin or a lib.
        self.restartAgent(jid)

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
        if sessionname == "":
            sessionname = getRandomName(6, "logagent")
        if who == "":
            who = self.boundjid.bare
        if touser == "":
            touser = self.boundjid.bare
        if "xmpp" in self.config.plugins_list:
            XmppMasterDatabase().setlogxmpp(
                text,
                type=type,
                sessionname=sessionname,
                priority=priority,
                who=who,
                how=how,
                why=why,
                module=module,
                action="",
                touser=touser,
                fromuser=fromuser,
            )
        else:
            msgbody = {"action": "xmpplog", "sessionid": sessionname}
            msgbody["data"] = {
                "log": "xmpplog",
                "text": text,
                "type": type,
                "session": sessionname,
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
            self.send_message(
                mto=jid.JID(self.config.sub_logger),
                mbody=json.dumps(msgbody),
                mtype="chat",
            )

    def schedulerfunction(self):
        self.manage_scheduler.process_on_event()

    def __bool_data(self, variable, default=False):
        if isinstance(variable, bool):
            return variable
        elif isinstance(variable, str):
            if variable.lower() == "true":
                return True
        return default

    async def message(self, msg):
        if msg["from"].bare == self.boundjid.bare:
            logging.error("msg from/to self agent : no process.")
            return
        if not msg["type"] == "chat":
            logging.error("Stanza %s message no process." " only chat" % msg["type"])
            return
        is_correct_msg, typemessage = self._check_message(msg)
        if not is_correct_msg:
            logging.error("Stanza message no process : bad form")
            return
        dataerreur = {
            "action": "resultmsginfoerror",
            "sessionid": "",
            "ret": 255,
            "base64": False,
            "data": {"msg": "ERROR : Message structure"},
        }
        try:
            dataobj = json.loads(msg["body"])

        except Exception as e:
            logging.error("bad struct Message %s %s " % (msg, str(e)))
            self.send_message(
                mto=msg["from"], mbody=json.dumps(dataerreur), mtype="chat"
            )
            logger.error("\n%s" % (traceback.format_exc()))
            return
        if "action" in dataobj and dataobj["action"] == "infomachine":
            dd = {
                "data": dataobj,
                "action": dataobj["action"],
                "sessionid": getRandomName(6, "registration"),
                "ret": 0,
            }
            dataobj = dd

        list_action_traiter_directement = []
        if dataobj["action"] in list_action_traiter_directement:
            # call function avec dataobj
            return

        ### Call plugin in action
        try:
            if "action" in dataobj and dataobj["action"] != "" and "data" in dataobj:
                # il y a une action a traite dans le message
                if "base64" in dataobj and self.__bool_data(dataobj["data"]):
                    mydata = json.loads(base64.b64decode(dataobj["data"]))
                else:
                    mydata = dataobj["data"]

                if "sessionid" not in dataobj:
                    dataobj["sessionid"] = getRandomName(6, "misssingid")
                    logging.warning(
                        "sessionid missing in message from %s : attributed sessionid %s "
                        % (msg["from"], dataobj["sessionid"])
                    )

                del dataobj["data"]
                if (
                    dataobj["action"] == "infomachine"
                ):  # infomachine call plugin registeryagent
                    dataobj["action"] = "registeryagent"

                # traite plugin
                try:
                    msg["body"] = dataobj
                    # logging.info("call plugin %s from %s" % (dataobj['action'],msg['from'].user))

                    dataerreur = {
                        "action": "result" + dataobj["action"],
                        "data": {"msg": "error plugin : " + dataobj["action"]},
                        "sessionid": getRandomName(6, "misssingid"),
                        "ret": 255,
                        "base64": False,
                    }
                    module = "%s/plugin_%s.py" % (self.modulepath, dataobj["action"])
                    if "ret" not in dataobj:
                        dataobj["ret"] = 0
                        # call_plugin_sequentially(
                        logging.debug("call plugin %s from %s" % (module, msg))
                        call_plugin(
                            module,
                            self,
                            dataobj["action"],
                            dataobj["sessionid"],
                            mydata,
                            msg,
                            dataobj["ret"],
                            dataerreur,
                        )
                except TypeError:
                    if dataobj["action"] != "resultmsginfoerror":
                        dataerreur["data"]["msg"] = (
                            "ERROR : plugin %s Missing" % dataobj["action"]
                        )
                        dataerreur["action"] = "result%s" % dataobj["action"]
                        self.send_message(
                            mto=msg["from"], mbody=json.dumps(dataerreur), mtype="chat"
                        )
                    logging.error(
                        "TypeError execution plugin %s : [ERROR : plugin Missing] %s"
                        % (dataobj["action"], sys.exc_info()[0])
                    )
                    logger.error("\n%s" % (traceback.format_exc()))

                except Exception as e:
                    logging.error(
                        "execution plugin [%s]  : %s " % (dataobj["action"], str(e))
                    )
                    logger.error("\n%s" % (traceback.format_exc()))
                    if dataobj["action"].startswith("result"):
                        return
                    if dataobj["action"] != "resultmsginfoerror":
                        dataerreur["data"]["msg"] = (
                            "ERROR : plugin execution %s" % dataobj["action"]
                        )
                        dataerreur["action"] = "result%s" % dataobj["action"]
                        self.send_message(
                            mto=msg["from"], mbody=json.dumps(dataerreur), mtype="chat"
                        )
            else:
                # There is no action to proceed on the message
                dataerreur["data"]["msg"] = "ERROR : Action ignored"
                self.send_message(
                    mto=msg["from"], mbody=json.dumps(dataerreur), mtype="chat"
                )
        except Exception as e:
            logging.error("bad struct Message %s %s " % (msg, str(e)))
            dataerreur["data"]["msg"] = "ERROR : Message structure"
            self.send_message(
                mto=msg["from"], mbody=json.dumps(dataerreur), mtype="chat"
            )
            logger.error("\n%s" % (traceback.format_exc()))

    def get_or_create_eventloop(self):
        try:
            return asyncio.get_event_loop()
        except RuntimeError as ex:
            if "There is no current event loop in thread" in str(ex):
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                return asyncio.get_event_loop()

    def iqsendpulse1(self, to, datain, timeout):
        tempo = time.time()
        datafile = {
            "sesssioniq": "",
            "time": tempo + timeout,
            "name_iq_queue": datain["name_iq_queue"],
        }
        if type(datain) == dict or type(datain) == list:
            try:
                data = json.dumps(datain)
            except Exception as e:
                logging.error("iqsendpulse : encode json : %s" % str(e))
                return '{"err" : "%s"}' % str(e).replace('"', "'")
        elif type(datain) == str:
            data = str(datain)
        else:
            data = datain
        try:
            data = base64.b64encode(bytes(data, "utf-8")).decode("utf8")
        except Exception as e:
            logging.error("iqsendpulse : encode base64 : %s" % str(e))
            return '{"err" : "%s"}' % str(e).replace('"', "'")
        try:
            iq = self.make_iq_get(queryxmlns="custom_xep", ito=to)
            datafile["sesssioniq"] = iq["id"]
            logging.debug("iq id=%s" % iq["id"])
            logging.debug("iq datafile=%s" % datafile)
            itemXML = ET.Element("{%s}data" % data)
            for child in iq.xml:
                if child.tag.endswith("query"):
                    child.append(itemXML)
            try:
                self.datas_send.append(datafile)
                result = iq.send(timeout=timeout)
            except IqError as e:
                err_resp = e.iq
                logging.error(
                    "iqsendpulse : Iq error %s" % str(err_resp).replace('"', "'")
                )
                logger.error("\n%s" % (traceback.format_exc()))
                ret = '{"err" : "%s"}' % str(err_resp).replace('"', "'")

            except IqTimeout:
                logging.error("iqsendpulse : Timeout Error")
                ret = '{"err" : "Timeout Error"}'
        except Exception as e:
            logging.error("iqsendpulse : error %s" % str(e).replace('"', "'"))
            logger.error("\n%s" % (traceback.format_exc()))
            ret = '{"err" : "%s"}' % str(e).replace('"', "'")

    def iqsendpulse(self, destinataire, msg, mtimeout):
        def close_posix_queue(name):
            # Keep result and remove datafile['name_iq_queue']
            logger.debug("close queue msg %s" % (name))
            try:
                posix_ipc.unlink_message_queue(name)
            except:
                pass

        if isinstance(msg, (bytes)):
            msg = msg.decode("utf-8")
        if isinstance(msg, (dict, list)):
            msg = json.dumps(msg, cls=DateTimebytesEncoderjson)

        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        tempo = time.time()
        datafile = {"sesssioniq": "", "time": tempo + mtimeout + 1, "name_iq_queue": ""}
        try:
            data = base64.b64encode(bytes(msg, "utf-8")).decode("utf8")
        except Exception as e:
            logging.error("iqsendpulse : encode base64 : %s" % str(e))
            return '{"err" : "%s"}' % str(e).replace('"', "'")
        try:
            iq = self.make_iq_get(queryxmlns="custom_xep", ito=destinataire)
            datafile["sesssioniq"] = iq["id"]
            datafile["name_iq_queue"] = "/" + iq["id"]
            itemXML = ET.Element("{%s}data" % data)
            for child in iq.xml:
                if child.tag.endswith("query"):
                    child.append(itemXML)
            self.datas_send.append(datafile)
            result = iq.send(timeout=mtimeout)
        except IqError as e:
            err_resp = e.iq
            logging.error("iqsendpulse : Iq error %s" % str(err_resp).replace('"', "'"))
            logger.error("\n%s" % (traceback.format_exc()))
            ret = '{"err" : "%s"}' % str(err_resp).replace('"', "'")
            return ret
        # creation ou ouverture queu datafile['name_iq_queue']
        try:
            logger.debug(
                "***  send_iq_message_resquest create queue %s"
                % datafile["name_iq_queue"]
            )
            quposix = posix_ipc.MessageQueue(
                datafile["name_iq_queue"], posix_ipc.O_CREX, max_message_size=2097152
            )
        except posix_ipc.ExistentialError:
            logger.debug("***  open queue %s" % datafile["name_iq_queue"])
            quposix = posix_ipc.MessageQueue(datafile["name_iq_queue"])
        except OSError as e:
            logger.error("ERROR CREATE QUEUE POSIX %s" % e)
            logger.error("eg : admin (/etc/security/limits.conf and  /etc/sysctl.conf")
        except Exception as e:
            logger.error("exception %s" % e)
            logger.error("\n%s" % (traceback.format_exc()))

        # attente sur cette queue le result n mtimeout.
        try:
            logger.debug(
                "***  send_iq_message_resquest attente result %s"
                % datafile["name_iq_queue"]
            )
            msgout, priority = quposix.receive(mtimeout)
            logger.debug("send_iq_message_resquest recu result")
            msgout = bytes.decode(msgout, "utf-8")
            logger.debug("*** recu  %s" % msgout)
            close_posix_queue(datafile["name_iq_queue"])
            return msgout
        except posix_ipc.BusyError:
            logger.debug("*** rien recu dans %s" % datafile["name_iq_queue"])
            close_posix_queue(datafile["name_iq_queue"])
            logger.debug("***  timeout %s" % datafile["name_iq_queue"])
            ret = '{"err" : "timeout %s" % }'
            return ret

    # def iqsendpulseasync(self, to, datain, timeout):
    # iq = self.make_iq_get(queryxmlns='custom_xep', ito=to)
    # logging.debug("iq id=%s" % iq['id'])
    # event_loop = asyncio.get_event_loop()
    # future1 = asyncio.ensure_future( self.myiq(iq,
    # to,
    # datain,
    # timeout),
    # loop=event_loop)
    # return iq['id']

    # ##################################################################
    # async def myiq(self, iq, to, datain, timeout):
    # if type(datain) == dict or type(datain) == list:
    # try:
    # data = json.dumps(datain)
    # except Exception as e:
    # logging.error("iqsendpulse : encode json : %s" % str(e))
    # return '{"err" : "%s"}' % str(e).replace('"', "'")
    # elif type(datain) == str:
    # data = str(datain)
    # else:
    # data = datain
    # try:
    ##data = data.encode("base64")
    # data = base64.b64encode(bytes(data, "utf-8")).decode('utf8')
    # except Exception as e:
    # logging.error("iqsendpulse : encode base64 : %s" % str(e))
    # return '{"err" : "%s"}' % str(e).replace('"', "'")
    # try:
    # iq = self.make_iq_get(queryxmlns='custom_xep', ito=to)
    # logging.debug("iq id=%s" % iq['id'])
    # itemXML = ET.Element('{%s}data' % data)
    # for child in iq.xml:
    # if child.tag.endswith('query'):
    # child.append(itemXML)

    # mq = base_message_queue_posix()
    # mq.create_file_message(iq['id'],
    # prefixe = self.boundjid.user)
    # if result['type'] == 'result':
    # for child in result.xml:
    # if child.tag.endswith('query'):
    # for z in child:
    # if z.tag.endswith('data'):
    ##ret = str(base64.b64decode(bytes(z.tag[1:-5], 'utf-8')), 'utf-8')
    # ret = base64.b64decode(bytes(z.tag[1:-5], 'utf-8'))

    # mq.sendbytes(iq['id'],
    # ret,
    # prefixe = self.boundjid.user,
    # priority= 9)
    # return
    # try:
    ##data=str(base64.b64decode(bytes(z.tag[1:-5],
    ##'utf-8')),'utf-8')
    # ret=base64.b64decode(bytes(z.tag[1:-5],
    #'utf-8'))
    # mq.sendbytes(iq['id'],
    # ret,
    # prefixe = self.boundjid.user,
    # priority= 9)
    # return
    # except Exception as e:
    # logging.error("iqsendpulse : %s" % str(e))
    # logger.error("\n%s"%(traceback.format_exc()))
    # ret =  '{"err" : "%s"}' % str(e).replace('"', "'")
    # mq.sendbytes(iq['id'],
    # ret,
    # prefixe = self.boundjid.user,
    # priority= 9)

    # except IqError as e:
    # err_resp = e.iq
    # logging.error("iqsendpulse : Iq error %s" % str(err_resp).replace('"', "'"))
    # logger.error("\n%s"%(traceback.format_exc()))
    # ret='{"err" : "%s"}' % str(err_resp).replace('"', "'")

    # except IqTimeout:
    # logging.error("iqsendpulse : Timeout Error")
    # ret='{"err" : "Timeout Error"}'
    # except Exception as e:
    # logging.error("iqsendpulse : error %s" % str(e).replace('"', "'"))
    # logger.error("\n%s"%(traceback.format_exc()))
    # ret='{"err" : "%s"}' % str(e).replace('"', "'")
    # mq.sendbytes(iq['id'],
    # ret,
    # prefixe = self.boundjid.user,
    # priority= 9)

    async def _handle_custom_iq_error(self, iq):
        if iq["type"] == "error":
            miqkeys = iq.keys()
            logger.debug("ERROR ERROR TYPE %s" % iq["id"])
            logger.debug("ERROR ERROR TYPE %s" % miqkeys)
            errortext = iq["error"]["text"]
            t = time.time()
            queue = ""
            liststop = []
            delqueue = []

            logger.debug("time ref %s" % t)
            try:
                for ta in self.datas_send:
                    logger.debug("On Traite %s" % ta["name_iq_queue"])
                    logger.debug("time fin %s " % (ta["time"]))
                    logger.debug("time now %s " % (t))
                    logger.debug("sessioniq %s" % ta["sesssioniq"])
                    if ta["time"] < t:
                        logger.debug("timeout queu %s" % ta["name_iq_queue"])
                        delqueue.append(ta["name_iq_queue"])
                        continue
                    if ta["sesssioniq"] == iq["id"]:
                        queue = ta["name_iq_queue"]
                        logger.debug("TRAITEMENT RESULT IN %s" % ta["name_iq_queue"])
                    liststop.append(ta)
                self.datas_send = liststop
                logger.debug("list de queue pendante a supprimer %s" % delqueue)
                # dellete les queues terminees
                # on supprime les ancienne liste.
                for ta in delqueue:
                    try:
                        logger.debug("delete queue %s" % ta["name_iq_queue"])
                        posix_ipc.unlink_message_queue(ta["name_iq_queue"])
                    except:
                        pass
                if not queue:
                    # pas de message recu return
                    logger.debug("pas de queue trouver on quitte")
                    return
                else:
                    logger.debug("QUEUE DEFINIE POUR SORTIE")
                # queue existe pour le resultat
                # creation ou ouverture de queues
                try:
                    logger.debug("essai de creer queue %s" % queue)
                    quposix = posix_ipc.MessageQueue(
                        queue, posix_ipc.O_CREX, max_message_size=2097152
                    )
                    logger.debug("create queue  pour envoi du result %s" % queue)
                except posix_ipc.ExistentialError:
                    logger.debug("essai ouvrir queue %s" % queue)
                    quposix = posix_ipc.MessageQueue(queue)
                    logger.debug("open queue %s" % queue)
                except OSError as e:
                    logger.error("ERROR CREATE QUEUE POSIX %s" % e)
                    logger.error(
                        "eg : admin (/etc/security/limits.conf and  /etc/sysctl.conf"
                    )
                    return
                except Exception as e:
                    logger.error("exception %s" % e)
                    logger.error("\n%s" % (traceback.format_exc()))
                    return
                ret = '{"err" : "%s"}' % errortext
                logger.error("RET ERROR ERROR CREATE QUEUE POSIX %s" % ret)
                quposix.send(ret, 2)
            except AttributeError:
                pass
            except Exception as e:
                logger.error("exception %s" % e)
                logger.error("\n%s" % (traceback.format_exc()))

    async def _handle_custom_iq(self, iq):
        if iq["query"] != "custom_xep":
            return
        if iq["type"] == "get":
            pass
        elif iq["type"] == "set":
            pass
        elif id["type"] == "error":
            logger.debug("ERROR ERROR TYPE %s" % iq["id"])

        elif iq["type"] == "result":
            logger.debug("process IQ result id %s" % iq["id"])
            logger.debug("IQ EXIST %s" % iq["id"])
            t = time.time()
            queue = ""
            liststop = []
            delqueue = []

            logger.debug("time ref %s" % t)
            for ta in self.datas_send:
                logger.debug("On Traite %s" % ta["name_iq_queue"])
                logger.debug("time fin %s " % (ta["time"]))
                logger.debug("time now %s " % (t))
                logger.debug("sessioniq %s" % ta["sesssioniq"])
                if ta["time"] < t:
                    logger.debug("timeout queu %s" % ta["name_iq_queue"])
                    delqueue.append(ta["name_iq_queue"])
                    continue
                if ta["sesssioniq"] == iq["id"]:
                    queue = ta["name_iq_queue"]
                    logger.debug("TRAITEMENT RESULT IN %s" % ta["name_iq_queue"])
                liststop.append(ta)
            self.datas_send = liststop
            logger.debug("list de queue pendante a supprimer %s" % delqueue)
            # dellete les queues terminees
            # on supprime les ancienne liste.
            for ta in delqueue:
                try:
                    logger.debug("delete queue %s" % ta["name_iq_queue"])
                    posix_ipc.unlink_message_queue(ta["name_iq_queue"])
                except:
                    pass
            if not queue:
                # pas de message recu return
                logger.debug("pas de queue trouver on quitte")
                return
            else:
                logger.debug("QUEUE DEFINIE POUR SORTIE")
            # queue existe pour le resultat
            # creation ou ouverture de queues
            try:
                logger.debug("essai de creer queue %s" % queue)
                quposix = posix_ipc.MessageQueue(
                    queue, posix_ipc.O_CREX, max_message_size=2097152
                )
                logger.debug("create queue  pour envoi du result %s" % queue)
            except posix_ipc.ExistentialError:
                logger.debug("essai ouvrir queue %s" % queue)
                quposix = posix_ipc.MessageQueue(queue)
                logger.debug("open queue %s" % queue)
            except OSError as e:
                logger.error("ERROR CREATE QUEUE POSIX %s" % e)
                logger.error(
                    "eg : admin (/etc/security/limits.conf and  /etc/sysctl.conf"
                )
            except Exception as e:
                logger.error("exception %s" % e)
                logger.error("\n%s" % (traceback.format_exc()))
            for child in iq.xml:
                if child.tag.endswith("query"):
                    for z in child:
                        if z.tag.endswith("data"):
                            ret = base64.b64decode(bytes(z.tag[1:-5], "utf-8"))
                            quposix.send(ret, 2)
                            logger.debug("Result inject to %s" % (queue))
                            return ret
                            try:
                                strdatajson = base64.b64decode(
                                    bytes(z.tag[1:-5], "utf-8")
                                )
                                data = json.loads(strdatajson.decode("utf-8"))
                                quposix.send(data["result"], 2)
                                return data["result"]
                            except Exception as e:
                                logging.error("_handle_custom_iq : %s" % str(e))
                                logger.error("\n%s" % (traceback.format_exc()))
                                ret = '{"err" : "%s"}' % str(e).replace('"', "'")
                                quposix.send(ret, 2)
                                return ret
                            ret = "{}"
                            quposix.send(ret, 2)
                            return ret
        else:
            # ... This will capture error responses too
            ret = "{}"
            return ret
            pass

        # self.register_handler(Callback(
        #'CustomXEP Handler3',
        # StanzaPath('iq@type=result/custom_xep'),
        # self._handle_custom_iq_get))


class DateTimebytesEncoderjson(json.JSONEncoder):
    """
    Used to hanld datetime in json files.
    """

    def default(self, obj):
        if isinstance(obj, datetime):
            encoded_object = obj.isoformat()
        elif isinstance(obj, bytes):
            encoded_object = obj.decode("utf-8")
        else:
            encoded_object = json.JSONEncoder.default(self, obj)
        return encoded_object
