#!/usr/bin/env python
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
import sys
import os
import logging
import platform
import base64
import json
import time
import threading
import sleekxmpp
from sleekxmpp.xmlstream import handler, matcher
from sleekxmpp.exceptions import IqError, IqTimeout
from sleekxmpp import jid
import subprocess
from lib.configuration import confParameter
from lib.utils import DEBUGPULSE, getRandomName, call_plugin, ipfromdns
from lib.logcolor import add_coloring_to_emit_ansi, add_coloring_to_emit_windows

import traceback
from optparse import OptionParser
from multiprocessing import Queue
from multiprocessing.managers import SyncManager
import psutil
import signal
from sqlalchemy import create_engine
from sqlalchemy import Column, String, Integer, DateTime, Text
from sqlalchemy.orm import sessionmaker
from sqlalchemy.ext.declarative import declarative_base
import imp
from lib.plugins.xmpp import XmppMasterDatabase
from lib.plugins.glpi import Glpi
from lib.plugins.kiosk import KioskDatabase

logger = logging.getLogger()

if sys.version_info < (3, 0):
    reload(sys)
    sys.setdefaultencoding('utf8')
else:
    raw_input = input



def getComputerByMac( mac):
    ret = Glpi().getMachineByMacAddress('imaging_module', mac)
    if type(ret) == list:
        if len(ret) != 0:
            return ret[0]
        else:
            return None
    return ret

#### faire singeton
class MUCBot(sleekxmpp.ClientXMPP):
    def __init__(self):#jid, password, room, nick):
        self.modulepath = os.path.abspath(os.path.join(os.path.dirname(os.path.realpath(__file__)),'..', "pluginsmastersubtitute"))
        signal.signal(signal.SIGINT, self.signal_handler)
        self.config = confParameter()
        logging.log(DEBUGPULSE, "start Master sub (%s)" %(self.config.jidmastersubstitute))
        sleekxmpp.ClientXMPP.__init__(self, jid.JID(self.config.jidmastersubstitute), self.config.passwordconnection)

        ####################Update agent from MAster#############################
        #self.pathagent = os.path.join(os.path.dirname(os.path.realpath(__file__)))
        #self.img_agent = os.path.join(os.path.dirname(os.path.realpath(__file__)), "img_agent")
        #self.Update_Remote_Agentlist = Update_Remote_Agent(self.pathagent, True )
        #self.descriptorimage = Update_Remote_Agent(self.img_agent)
        ###################END Update agent from MAster#############################
        self.agentmaster = jid.JID(self.config.jidmaster)
        #self.schedule('queueinfo', 10 , self.queueinfo, repeat=True)

        self.add_event_handler("register", self.register, threaded=True)
        self.add_event_handler("session_start", self.start)
        self.add_event_handler('message', self.message, threaded=True)
        #self.add_event_handler("signalsessioneventrestart", self.signalsessioneventrestart)
        #self.add_event_handler("loginfotomaster", self.loginfotomaster)
        self.add_event_handler('changed_status', self.changed_status)

        #self.register_handler(handler.Callback(
                                    #'CustomXEP Handler',
                                    #matcher.MatchXPath('{%s}iq/{%s}query' % (self.default_ns,"custom_xep")),
                                    #self._handle_custom_iq))

    def send_message_to_master(self , msg):
        self.send_message(  mbody = json.dumps(msg),
                            mto = '%s/MASTER'%self.agentmaster,
                            mtype ='chat')

    def changed_status(self, message):
        #print "%s %s"%(message['from'], message['type'])
        if message['from'].user == 'master':
            if message['type'] == 'available':
               pass

    def start(self, event):
        self.shutdown = False
        self.get_roster()
        self.send_presence()
        logging.log(DEBUGPULSE,"subscribe xmppmaster")
        self.send_presence ( pto = self.agentmaster , ptype = 'subscribe' )
        self.xmpplog("Start Agent master inventory",
                    type = 'info',
                    sessionname = "",
                    priority = -1,
                    action = "",
                    who = self.boundjid.bare,
                    how = "",
                    why = "",
                    module = "AM",
                    date = None ,
                    fromuser = "MASTER",
                    touser = "")

        #call plugin start
        startparameter={
            "action": "start",
            "sessionid" : getRandomName(6, "start"),
            "ret" : 0,
            "base64" : False,
            "data" : {}}
        dataerreur={ "action" : "result" + startparameter["action"],
                     "data" : { "msg" : "error plugin : " + startparameter["action"]},
                     'sessionid' : startparameter['sessionid'],
                     'ret' : 255,
                     'base64' : False}
        msg = {'from' : self.boundjid.bare, "to" : self.boundjid.bare, 'type' : 'chat' }
        if not 'data' in startparameter:
            startparameter['data'] = {}
        module = "%s/plugin_%s.py"%(self.modulepath,  startparameter["action"])
        call_plugin( module,
                    self,
                    startparameter["action"],
                    startparameter['sessionid'],
                    startparameter['data'],
                    msg,
                    dataerreur)


    def signal_handler(self, signal, frame):
        logging.log(DEBUGPULSE, "CTRL-C EVENT")
        msgevt={
                    "action": "evtfrommachine",
                    "sessionid" : getRandomName(6, "eventwin"),
                    "ret" : 0,
                    "base64" : False,
                    'data' : { 'machine' : self.boundjid.jid ,
                               'event'   : "CTRL_C_EVENT" }
                    }
        self.send_message_to_master(msgevt)
        self.shutdown = True
        logging.log(DEBUGPULSE,"shutdown xmpp agent %s!" % self.boundjid.user)
        self.disconnect(wait=10)

    def xmpplog(self,
                text,
                type = 'noset',
                sessionname = '',
                priority = 0,
                action = "",
                who = "",
                how = "",
                why = "",
                module = "",
                date = None ,
                fromuser = "",
                touser = ""):
        if who == "":
            who = self.boundjid.bare
        msgbody = { 'log' : 'xmpplog',
                    'text' : text,
                    'type': type,
                    'session' : sessionname,
                    'priority': priority,
                    'action' : action ,
                    'who': who,
                    'how' : how,
                    'why' : why,
                    'module': module,
                    'date' : None ,
                    'fromuser' : fromuser,
                    'touser' : touser
                    }
        self.send_message(  mto = jid.JID(self.config.jidlog),
                            mbody=json.dumps(msgbody),
                            mtype='chat')

    def register(self, iq):
        """ This function is called for automatic registation """
        resp = self.Iq()
        resp['type'] = 'set'
        resp['register']['username'] = self.boundjid.user
        resp['register']['password'] = self.password
        try:
            resp.send(now=True)
            logging.info("Account created for %s!" % self.boundjid)
        except IqError as e:
            logging.error("Could not register account: %s" %\
                    e.iq['error']['text'])
        except IqTimeout:
            logging.error("No response from server.")
            traceback.print_exc(file=sys.stdout)
            self.disconnect()

    def __bool_data(self, variable, default = False):
        if isinstance(variable, bool):
            return variable
        elif isinstance(variable, basestring):
            if variable.lower() == "true":
                return True
        return default

    def message(self, msg):
        if not msg['type'] == "chat":
            return
        if msg['from'].bare == self.boundjid.bare :
            return
        dataerreur={
                    "action": "resultmsginfoerror",
                    "sessionid" : "",
                    "ret" : 255,
                    "base64" : False,
                    "data": {"msg" : "ERROR : Message structure"}}
        try :
            dataobj = json.loads(msg['body'])
        except Exception as e:
            logging.error("bad struct Message %s %s " %(msg, str(e)))
            self.send_message(  mto=msg['from'],
                                        mbody=json.dumps(dataerreur),
                                        mtype='chat')
            traceback.print_exc(file=sys.stdout)
            return

        if 'action' in dataobj and dataobj['action'] == 'infomachine':
            dd ={'data' : dataobj,
                 'action' : dataobj['action'],
                 'sessionid' : getRandomName(6, "registration"),
                'ret' : 0
                 }
            dataobj = dd

        list_action_traiter_directement = []
        if dataobj['action'] in list_action_traiter_directement:
            #call function avec dataobj
            return

        ### Call plugin in action
        try :
            if 'action' in dataobj and dataobj['action'] != "" and 'data' in dataobj:
                # il y a une action a traite dans le message
                if 'base64' in dataobj and self.__bool_data(dataobj['data']):
                    mydata = json.loads(base64.b64decode(dataobj['data']))
                else:
                    mydata = dataobj['data']

                if not dataobj.has_key('sessionid'):
                    dataobj['sessionid']= getRandomName(6, "misssingid")
                    logging.warning("sessionid missing in message from %s : attributed sessionid %s " % (msg['from'], dataobj['sessionid']))

                del dataobj['data']
                if dataobj['action'] == 'infomachine': # infomachine call plugin registeryagent
                    dataobj['action'] = 'registeryagent'

                #traite plugin
                try:
                    msg['body'] = dataobj
                    logging.info("call plugin %s from %s" % (dataobj['action'],msg['from'].user))
                    
                    dataerreur={ "action" : "result" + dataobj['action'],
                     "data" : { "msg" : "error plugin : " + dataobj['action']},
                     'sessionid' : getRandomName(6, "misssingid"),
                     'ret' : 255,
                     'base64' : False}
                    module = "%s/plugin_%s.py"%(self.modulepath, dataobj['action'])
                    if not 'ret' in dataobj:
                        dataobj['ret'] = 0
                    call_plugin( module,
                                 self,
                                 dataobj['action'],
                                 dataobj['sessionid'],
                                 mydata,
                                 msg,
                                 dataobj['ret'],
                                 dataerreur)
                except TypeError:
                    if dataobj['action'] != "resultmsginfoerror":
                        dataerreur['data']['msg'] = "ERROR : plugin %s Missing"%dataobj['action']
                        dataerreur['action'] = "result%s"%dataobj['action']
                        self.send_message(  mto=msg['from'],
                                            mbody=json.dumps(dataerreur),
                                            mtype='chat')
                    logging.error("TypeError execution plugin %s : [ERROR : plugin Missing] %s" %(dataobj['action'],sys.exc_info()[0]))
                    traceback.print_exc(file=sys.stdout)

                except Exception as e:
                    logging.error("execution plugin [%s]  : %s " % (dataobj['action'],str(e)))
                    traceback.print_exc(file=sys.stdout)
                    if dataobj['action'].startswith('result'):
                        return
                    if dataobj['action'] != "resultmsginfoerror":
                        dataerreur['data']['msg'] = "ERROR : plugin execution %s"%dataobj['action']
                        dataerreur['action'] = "result%s"%dataobj['action']
                        self.send_message(  mto=msg['from'],
                                            mbody=json.dumps(dataerreur),
                                            mtype='chat')
            else:
                # il n'y pas d action a traite dans le message
                dataerreur['data']['msg'] = "ERROR : Action ignored"
                self.send_message(  mto=msg['from'],
                                        mbody=json.dumps(dataerreur),
                                        mtype='chat')
        except Exception as e:
            logging.error("bad struct Message %s %s " %(msg, str(e)))
            dataerreur['data']['msg'] = "ERROR : Message structure"
            self.send_message(  mto=msg['from'],
                                        mbody=json.dumps(dataerreur),
                                        mtype='chat')
            traceback.print_exc(file=sys.stdout)
