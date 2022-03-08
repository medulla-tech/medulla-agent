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

# fish: pulse_xmpp_master_substitute/bin/agent.py

from slixmpp import jid
import sys
import os
import logging
import base64
import json
import time
import slixmpp
from slixmpp.exceptions import IqError, IqTimeout
from slixmpp.xmlstream.stanzabase import ET
from lib.configuration import confParameter
from lib.utils import (
    DEBUGPULSE,
    getRandomName,
    call_plugin,
    call_plugin_sequentially,
    ipfromdns,
)
import traceback
import signal
from lib.plugins.xmpp import XmppMasterDatabase
from lib.plugins.glpi import Glpi
from lib.manage_scheduler import manage_scheduler
import asyncio
import random
import imp

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
        logger.debug("##############################################")

        ####################Update agent from MAster#############################
        # self.pathagent = os.path.join(os.path.dirname(os.path.realpath(__file__)))
        # self.img_agent = os.path.join(os.path.dirname(os.path.realpath(__file__)), "img_agent")
        # self.Update_Remote_Agentlist = Update_Remote_Agent(self.pathagent, True )
        # self.descriptorimage = Update_Remote_Agent(self.img_agent)
        ###################END Update agent from MAster#############################
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
        # self.add_event_handler("signalsessioneventrestart", self.signalsessioneventrestart)
        # self.add_event_handler("loginfotomaster", self.loginfotomaster)
        # self.add_event_handler('changed_status', self.changed_status)
        self.add_event_handler(
            "restartmachineasynchrone", self.restartmachineasynchrone
        )

        # self.register_handler(handler.Callback(
        # 'CustomXEP Handler',
        # matcher.MatchXPath('{%s}iq/{%s}query' % (self.default_ns,"custom_xep")),
        # self._handle_custom_iq))

    # -----------------------------------------------------------------------
    # ----------------------- Getion connection agent -----------------------
    # -----------------------------------------------------------------------

    def Mode_Marche_Arret_loop(self, nb_reconnect=None, forever=False, timeout=None):
        """
        Connect to the XMPP server and start processing XMPP stanzas.
        """
        logger.debug("Mode_Marche_Arret_loop")
        if nb_reconnect:
            self.startdata = nb_reconnect
        else:
            self.startdata = 1
        while self.startdata > 0:
            logger.debug("loop Mode_Marche_Arret_loop")
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

    # def changed_status(self, message):
    # print "%s %s"%(message['from'], message['type'])
    # if message['from'].user == 'master':
    # if message['type'] == 'available':
    # pass

    async def start(self, event):
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

        # self.schedule('updatelistplugin', 20, self.loadPluginList, repeat=True)

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
        time.sleep(waittingrestart)
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
                    call_plugin_sequentially(
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
                # il n'y pas d action a traite dans le message
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

    def iqsendpulse(self, to, datain, timeout):
        # send iq synchronous message
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
            data = data.encode("base64")
        except Exception as e:
            logging.error("iqsendpulse : encode base64 : %s" % str(e))
            return '{"err" : "%s"}' % str(e).replace('"', "'")
        try:
            iq = self.make_iq_get(queryxmlns="custom_xep", ito=to)
            itemXML = ET.Element("{%s}data" % data)
            for child in iq.xml:
                if child.tag.endswith("query"):
                    child.append(itemXML)
            try:
                result = iq.send(timeout=timeout)
                if result["type"] == "result":
                    for child in result.xml:
                        if child.tag.endswith("query"):
                            for z in child:
                                if z.tag.endswith("data"):
                                    # decode result
                                    # TODO : Replace print by log
                                    # print z.tag[1:-5]
                                    return base64.b64decode(z.tag[1:-5])
                                    try:
                                        data = base64.b64decode(z.tag[1:-5])
                                        # TODO : Replace print by log
                                        # print "RECEIVED data"
                                        # print data
                                        return data
                                    except Exception as e:
                                        logging.error("iqsendpulse : %s" % str(e))
                                        logger.error("\n%s" % (traceback.format_exc()))
                                        return '{"err" : "%s"}' % str(e).replace(
                                            '"', "'"
                                        )
                                    return "{}"
            except IqError as e:
                err_resp = e.iq
                logging.error(
                    "iqsendpulse : Iq error %s" % str(err_resp).replace('"', "'")
                )
                logger.error("\n%s" % (traceback.format_exc()))
                return '{"err" : "%s"}' % str(err_resp).replace('"', "'")

            except IqTimeout:
                logging.error("iqsendpulse : Timeout Error")
                return '{"err" : "Timeout Error"}'
        except Exception as e:
            logging.error("iqsendpulse : error %s" % str(e).replace('"', "'"))
            logger.error("\n%s" % (traceback.format_exc()))
            return '{"err" : "%s"}' % str(e).replace('"', "'")
        return "{}"
