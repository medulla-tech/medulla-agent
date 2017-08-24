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
import sleekxmpp
import platform
import base64
import json
from sleekxmpp.exceptions import IqError, IqTimeout
from sleekxmpp import jid
from lib.networkinfo import networkagentinfo, organizationbymachine, organizationbyuser, powershellgetlastuser
from lib.configuration import confParameter
from lib.managesession import session
from lib.utils import   DEBUGPULSE, getIpXmppInterface, refreshfingerprint,\
                        getRandomName, load_back_to_deploy, cleanbacktodeploy,\
                        call_plugin, searchippublic, subnetnetwork,\
                        protoandport, createfingerprintnetwork, isWinUserAdmin,\
                        isMacOsUserAdmin, check_exist_ip_port, ipfromdns, StreamToLogger
from lib.manage_event import manage_event
from lib.manage_process import mannageprocess,process_on_end_send_message_xmpp
import traceback
from optparse import OptionParser
import time
from multiprocessing import Queue
from lib.manage_scheduler import manage_scheduler
from lib.logcolor import  add_coloring_to_emit_ansi, add_coloring_to_emit_windows
from lib.manageRSAsigned import MsgsignedRSA, installpublickey
from multiprocessing.managers import SyncManager

if sys.platform.startswith('win'):
    import win32api
    import win32con

sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), "lib"))


logger = logging.getLogger()
global restart


if sys.version_info < (3, 0):
    reload(sys)
    sys.setdefaultencoding('utf8')
else:
    raw_input = input

class QueueManager(SyncManager):
    pass

class MUCBot(sleekxmpp.ClientXMPP):
    def __init__(self, conf):#jid, password, room, nick):
        logging.log(DEBUGPULSE, "start machine1  %s Type %s" %(conf.jidagent, conf.agenttype))
        logger.info("start machine1  %s Type %s" %(conf.jidagent, conf.agenttype))
        sleekxmpp.ClientXMPP.__init__(self, jid.JID(conf.jidagent), conf.passwordconnection)
        laps_time_update_plugin = 3600
        laps_time_networkMonitor = 300
        laps_time_handlemanagesession = 15
        self.config = conf
        self.manage_scheduler  = manage_scheduler(self)
        self.machinerelayserver = []
        self.nicklistchatroomcommand = {}
        self.jidchatroomcommand = jid.JID(self.config.jidchatroomcommand)
        self.agentcommand = jid.JID(self.config.agentcommand)
        self.agentsiveo = jid.JID(self.config.jidagentsiveo)
        self.agentmaster = jid.JID("master@pulse")
        self.session = session(self.config.agenttype)
        self.reversessh = None
        self.signalinfo = {}
        self.queue_read_event_from_command = Queue()

        self.ban_deploy_sessionid_list = set() # List id sessions that are banned
        self.lapstimebansessionid = 900     # ban session id 900 secondes

        self.eventmanage = manage_event(self.queue_read_event_from_command, self)
        self.mannageprocess = mannageprocess(self.queue_read_event_from_command)
        self.process_on_end_send_message_xmpp = process_on_end_send_message_xmpp(self.queue_read_event_from_command)

        #use public_ip for localisation
        if self.config.public_ip == "":
            try:
                self.config.public_ip = searchippublic()
            except Exception:
                pass
        if self.config.public_ip == "":
            self.config.public_ip == None
        self.md5reseau = refreshfingerprint()
        self.schedule('schedulerfunction', 10 , self.schedulerfunction, repeat=True)
        self.schedule('update plugin', laps_time_update_plugin, self.update_plugin, repeat=True)
        self.schedule('check network', laps_time_networkMonitor, self.networkMonitor, repeat=True)
        self.schedule('manage session', laps_time_handlemanagesession, self.handlemanagesession, repeat=True)
        self.schedule('event inventory', self.config.inventory_interval, self.handleinventory, repeat=True)
        #self.schedule('queueinfo', 10 , self.queueinfo, repeat=True)
        if  not self.config.agenttype in ['relayserver']:
            self.schedule('session reload', 15, self.reloadsesssion, repeat=False)

        self.schedule('reprise_evenement', 10, self.handlereprise_evenement, repeat=True)

        self.add_event_handler("register", self.register, threaded=True)
        self.add_event_handler("session_start", self.start)
        self.add_event_handler('message', self.message, threaded=True)
        self.add_event_handler("signalsessioneventrestart", self.signalsessioneventrestart)
        self.add_event_handler("loginfotomaster", self.loginfotomaster)
        self.add_event_handler('changed_status', self.changed_status)
        #self.add_event_handler('dedee', self.dede, threaded=True)

        self.RSA = MsgsignedRSA(self.config.agenttype)

        #### manage information extern for Agent RS(relayserver only dont working on windows.)
        ##################
        if  self.config.agenttype in ['relayserver']:
            from lib.manage_info_command import manage_infoconsole
            self.qin = Queue(10)
            self.qoutARS = Queue(10)
            QueueManager.register('json_to_ARS' , self.setinARS)
            QueueManager.register('json_from_ARS', self.getoutARS)
            QueueManager.register('size_nb_msg_ARS' , self.sizeoutARS)
            #queue_in, queue_out, objectxmpp
            self.commandinfoconsole = manage_infoconsole(self.qin, self.qoutARS, self)
            self.managerQueue = QueueManager(("", self.config.parametersscriptconnection['port']),
                                            authkey = self.config.passwordconnection)
            self.managerQueue.start()

        if sys.platform.startswith('win'):
            result = win32api.SetConsoleCtrlHandler(self._CtrlHandler, 1)
            if result == 0:
                logging.log(DEBUGPULSE,'Could not SetConsoleCtrlHandler (error %r)' %
                             win32api.GetLastError())
            else:
                logging.log(DEBUGPULSE,'Set handler for console events.')
                self.is_set = True

    def send_message_to_master(self , msg):
        self.send_message(  mbody = json.dumps(msg),
                            mto = '%s/MASTER'%self.agentmaster,
                            mtype ='chat')

    def _CtrlHandler(self, evt):
        if sys.platform.startswith('win'):
            msgevt={
                    "action": "evtfrommachine",
                    "sessionid" : getRandomName(6, "eventwin"),
                    "ret" : 0,
                    "base64" : False,
                    'data' : { 'machine' : self.boundjid.jid }
                    }
            if evt == win32con.CTRL_SHUTDOWN_EVENT:
                msgevt['data']['event'] = "SHUTDOWN_EVENT"
                self.send_message_to_master(msgevt)
                logging.log(DEBUGPULSE, "CTRL_SHUTDOWN EVENT")
                return True
            elif evt == win32con.CTRL_LOGOFF_EVENT:
                msgevt['data']['event'] = "LOGOFF_EVENT"
                self.send_message_to_master(msgevt)
                logging.log(DEBUGPULSE, "CTRL_LOGOFF EVENT")
                return True
            elif evt == win32con.CTRL_BREAK_EVENT:
                msgevt['data']['event'] = "BREAK_EVENT"
                self.send_message_to_master(msgevt)
                logging.log(DEBUGPULSE, "CTRL_BREAK EVENT")
                return True
            elif evt == win32con.CTRL_CLOSE_EVENT:
                msgevt['data']['event'] = "CLOSE_EVENT"
                self.send_message_to_master(msgevt)
                logging.log(DEBUGPULSE, "CTRL_CLOSE EVENT")
                return True
            elif evt == win32con.CTRL_C_EVENT:
                msgevt['data']['event'] = "CTRL_C_EVENT"
                self.send_message_to_master(msgevt)
                logging.log(DEBUGPULSE, "CTRL-C EVENT")
                return True
            else:
                return False
        else:
            pass

    def __sizeout(self, q):
        return q.qsize()

    def sizeoutARS(self):
        return self.__sizeout(self.qoutARS)

    def __setin(self, data , q):
        self.qin.put(data)

    def setinARS(self, data):
        self.__setin(data , self.qoutARS)

    def __getout(self, timeq, q):
        try:
            valeur = q.get(True, timeq)
        except Exception:
            valeur=""
        return valeur

    def getoutARS(self, timeq=10):
        return self.__getout(timeq, self.qoutARS)

    def gestioneventconsole(self, event, q):
        try:
            dataobj = json.loads(event)
        except Exception as e:
            logging.error("bad struct jsopn Message console %s : %s " %(event, str(e)))
            q.put("bad struct jsopn Message console %s : %s " %(event, str(e)))
        listaction = [] # cette liste contient les function directement appelable depuis console.
        #check action in message
        if 'action' in dataobj:
            if not 'sessionid' in dataobj:
                dataobj['sessionid'] = getRandomName(6, dataobj["action"])
            if dataobj["action"] in listaction:
                #call fubnction agent direct
                func = getattr(self, dataobj["action"])
                if "params_by_val" in dataobj and not "params_by_name" in dataobj:
                    func(*dataobj["params_by_val"])
                elif "params_by_val" in dataobj and "params_by_name" in dataobj:
                    func(*dataobj["params_by_val"], **dataobj["params_by_name"])
                elif "params_by_name" in dataobj and not "params_by_val" in dataobj:
                    func( **dataobj["params_by_name"])
                else :
                    func()
            else:
                #call plugin
                dataerreur = { "action" : "result" + dataobj["action"],
                               "data" : { "msg" : "error plugin : "+ dataobj["action"]
                               },
                               'sessionid' : dataobj['sessionid'],
                               'ret' : 255,
                               'base64' : False
                }
                msg = {'from' : 'console', "to" : self.boundjid.bare, 'type' : 'chat' }
                if not 'data' in dataobj:
                    dataobj['data'] = {}
                call_plugin(dataobj["action"],
                    self,
                    dataobj["action"],
                    dataobj['sessionid'],
                    dataobj['data'],
                    msg,
                    dataerreur)
        else:
            logging.error("action missing in json Message console %s" %(dataobj))
            q.put("action missing in jsopn Message console %s" %(dataobj))
            return
    ##################

    def remove_sessionid_in_ban_deploy_sessionid_list(self, sessionid):
        """
            this function remove sessionid banned
        """
        try:
            self.ban_deploy_sessionid_list.remove(sessionid)
        except Exception as e:
            logger.error(str(e))

    def schedulerfunction(self):
        self.manage_scheduler.process_on_event()

    def changed_status(self, message):
        #print "%s %s"%(message['from'], message['type'])
        if message['from'].user == 'master':
            if message['type'] == 'available':
                self.update_plugin()
        else:
            if self.config.agenttype in ['machine']:
                if self.boundjid.bare != message['from'].bare : 
                    try:
                        if message['type'] == 'available':
                            self.machinerelayserver.append(message['from'].bare)
                        elif message['type'] == 'unavailable':
                            self.machinerelayserver.remove(message['from'].bare)
                    except Exception:
                        pass

    def start(self, event):
        self.get_roster()
        self.send_presence()
        logging.log(DEBUGPULSE,"subscribe xmppmaster")
        self.send_presence ( pto = self.agentmaster , ptype = 'subscribe' )
        self.ipconnection = self.config.Server

        if  self.config.agenttype in ['relayserver']:
            try:
                if self.config.public_ip_relayserver != "":
                    logging.log(DEBUGPULSE,"Attribution ip public by configuration for ipconnexion: [%s]"%self.config.public_ip_relayserver)
                    self.ipconnection = self.config.public_ip_relayserver
            except Exception:
                pass

        self.config.ipxmpp = getIpXmppInterface(self.config.Server, self.config.Port)

        self.agentrelayserverrefdeploy = self.config.jidchatroomcommand.split('@')[0][3:]
        logging.log(DEBUGPULSE,"Roster agent \n%s"%self.client_roster)
        self.logtopulse("Start Agent", who =  self.boundjid.bare)
        try:
            self.back_to_deploy = load_back_to_deploy()
        except IOError:
            self.back_to_deploy = {}
        cleanbacktodeploy(self)

    def send_message_agent( self,
                            mto,
                            mbody,
                            msubject=None,
                            mtype=None,
                            mhtml=None,
                            mfrom=None,
                            mnick=None):
        if mto != "console":
            print "send command %s"%json.dumps(mbody)
            self.send_message(
                                mto,
                                json.dumps(mbody),
                                msubject,
                                mtype,
                                mhtml,
                                mfrom,
                                mnick)
        else :
            if self.config.agenttype in ['relayserver']:
                q = self.qoutARS
            else:
                q = self.qoutAM
            if q.full():
                #vide queue
                while not q.empty():
                    q.get()
            else:
                try :
                    q.put(json.dumps(mbody), True, 10)
                except Exception:
                    print "put in queue impossible"

    def logtopulse(self, text, type = 'noset', sessionname = '', priority = 0, who =""):
        if who == "":
            who = self.boundjid.bare
        msgbody = {
                    'text' : text,
                    'type':type,
                    'session':sessionname,
                    'priority':priority,
                    'who':who
                    }
        self.send_message(  mto = jid.JID("log@pulse"),
                            mbody=json.dumps(msgbody),
                            mtype='chat')

    #jfkjfk
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
        msgbody = {
                    'log' : 'xmpplog',
                    'text' : text,
                    'type': type,
                    'session' : sessionname,
                    'priority': priority,
                    'action' : action ,
                    'who': who,
                    'how' : "",
                    'why' : "",
                    'module': "",
                    'date' : None ,
                    'fromuser' : fromuser,
                    'touser' : touser
                    }
        self.send_message(  mto = jid.JID("log@pulse"),
                            mbody=json.dumps(msgbody),
                            mtype='chat')


    #def queueinfo(self):
        ##if self.qin.qsize() > 0:
            ##print self.qin.get()
        #pass

    def handleinventory(self):
        msg={ 'from' : "master@pulse/MASTER",
              'to': self.boundjid.bare
            }
        sessionid = getRandomName(6, "inventory")
        dataerreur = {}
        dataerreur['action']= "resultinventory"
        dataerreur['data']={}
        dataerreur['data']['msg'] = "ERROR : inventory"
        dataerreur['sessionid'] = sessionid
        dataerreur['ret'] = 255
        dataerreur['base64'] = False
        call_plugin("inventory",
                    self,
                    "inventory",
                    getRandomName(6, "inventory"),
                    {},
                    msg,
                    dataerreur)

    def update_plugin(self):
        # Send plugin and machine informations to Master
        dataobj  = self.seachInfoMachine()
        logging.log(DEBUGPULSE,"SEND REGISTRATION XMPP to %s \n%s"%(self.agentmaster, json.dumps(dataobj, indent=4, sort_keys=True)))
        self.send_message(  mto = self.agentmaster,
                            mbody = json.dumps(dataobj),
                            mtype = 'chat')

    def reloadsesssion(self):
        #recupere les sessions existantes
        self.session.loadsessions()
        #if  not self.config.agenttype in ['relayserver']:
            #executer seulement par machine
        for i in self.session.sessiondata:
            logging.log(DEBUGPULSE,"REPRISE DE DEPLOIEMENT AFTER RESTART OU RESTART BOT")
            msg={
                'from' : self.boundjid.bare,
                'to': self.boundjid.bare
                }

            call_plugin( i.datasession['action'],
                        self,
                        i.datasession['action'],
                        i.datasession['sessionid'],
                        i.datasession['data'],
                        msg,
                        {})

    def loginfotomaster(self, msgdata):
        logstruct={
                    "action": "infolog",
                    "sessionid" : getRandomName(6, "xmpplog"),
                    "ret" : 0,
                    "base64" : False,
                    "msg":  msgdata }
        try:
            self.send_message(  mbody = json.dumps(logstruct),
                                mto = '%s/MASTER'%self.agentmaster,
                                mtype ='chat')
        except Exception as e:
            logging.error("message log to '%s/MASTER' : %s " %  ( self.agentmaster,str(e)))
            traceback.print_exc(file=sys.stdout)
            return

    def handlereprise_evenement(self):
        #self.eventTEVENT = [i for i in self.eventTEVENT if self.session.isexist(i['sessionid'])]
        #appelle plugins en local sur un evenement
        self.eventmanage.manage_event_loop()

    def signalsessioneventrestart(self,result):
        pass

    def handlemanagesession(self):
        self.session.decrementesessiondatainfo()
        print self.machinerelayserver

    def networkMonitor(self):
        try:
            logging.log(DEBUGPULSE,"network monitor time 180s %s!" % self.boundjid.user)
            md5ctl = createfingerprintnetwork()
            if self.md5reseau != md5ctl:
                refreshfingerprint()
                logging.log(DEBUGPULSE,"network changed for %s!\n RESTART AGENT" % self.boundjid.user)
                self.restartBot()
        except Exception as e:
            logging.error(" %s " %(str(e)))
            traceback.print_exc(file=sys.stdout)

    def restartBot(self):
        global restart
        restart = True
        logging.log(DEBUGPULSE,"restart xmpp agent %s!" % self.boundjid.user)
        self.disconnect(wait=10)

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

    def filtre_message(self, msg):
        pass

    def message(self, msg):
        possibleclient = ['master', self.agentcommand.user, self.agentsiveo.user, self.boundjid.user,'log',self.jidchatroomcommand.user]
        if not msg['type'] == "chat":
            return
        try :
            dataobj = json.loads(msg['body'])
           
        except Exception as e:
            logging.error("bad struct Message %s %s " %(msg, str(e)))
            dataerreur={
                    "action": "resultmsginfoerror",
                    "sessionid" : "",
                    "ret" : 255,
                    "base64" : False,
                    "data": {"msg" : "ERROR : Message structure"}
        }
            self.send_message(  mto=msg['from'],
                                        mbody=json.dumps(dataerreur),
                                        mtype='chat')
            traceback.print_exc(file=sys.stdout)
            return

        if not msg['from'].user in possibleclient:
            if not('sessionid' in  dataobj and self.session.isexist(dataobj['sessionid'])):
                #les messages venant d'une machine sont filtré sauf si une session message existe dans le gestionnaire de session.
                if  self.config.ordreallagent:
                    logging.warning("filtre message from %s " % (msg['from'].bare))
                    return

        dataerreur={
                    "action": "resultmsginfoerror",
                    "sessionid" : "",
                    "ret" : 255,
                    "base64" : False,
                    "data": {"msg" : ""}
        }

        if not 'action' in dataobj:
            logging.error("warning message action missing %s"%(msg))
            return

        if dataobj['action'] == "restarfrommaster":
            if sys.platform.startswith('linux'):
                logging.debug("actionrestartmachine  shutdown machine linux")
                os.system("shutdown -r now")
            elif sys.platform.startswith('win'):
                logging.debug("actionrestartmachine  shutdown machine windows")
                os.system("shutdown /r")
            elif sys.platform.startswith('darwin'):
                logging.debug("actionrestartmachine  shutdown machine MacOS")
                os.system("shutdown -r now")
            return

        if dataobj['action'] == "shutdownfrommaster":
            msg = "\"Shutdown from administrator\""
            time = 15 # default 15 seconde
            if 'time' in dataobj['data'] and dataobj['data']['time'] != 0:
                time = dataobj['data']['time']
            if 'msg' in dataobj['data'] and dataobj['data']['msg'] != "":
                msg = '"' + dataobj['data']['msg'] + '"'

            if sys.platform.startswith('linux'):
                if int(time) == 0:
                    cmd = "shutdown now"
                else:
                    cmd = "shutdown -P -f -t %s %s"%(time, msg)
                logging.debug(cmd)
                os.system(cmd)
            elif sys.platform.startswith('win'):
                if int(time) == 0:
                    cmd = "shutdown /p"
                else:
                    cmd = "shutdown -P -f -t %s %s"%(time, msg)
                logging.debug(cmd)
                os.system(cmd)
            elif sys.platform.startswith('darwin'):
                if int(time) == 0:
                    cmd = "shutdown -h now"
                else:
                    cmd = "shutdown -h +%s \"%s\""(time, msg)
                logging.debug(cmd)
                os.system(cmd)
            return

        if dataobj['action'] == "installkeymaster":
            # note install publickeymaster
            self.masterpublickey = installpublickey("master", dataobj['keypublicbase64'] )
            return

        if dataobj['action'] ==  "resultmsginfoerror":
            logging.warning("filtre message from %s for action %s" % (msg['from'].bare,dataobj['action']))
            return
        try :
            #if dataobj['action'] == "resultmsginfoerror":
                #logging.warning("filtre message from %s for action %s" % (msg['from'].bare,dataobj['action']))
                #return
            if dataobj.has_key('action') and dataobj['action'] != "" and dataobj.has_key('data'):
                if dataobj.has_key('base64') and \
                    ((isinstance(dataobj['base64'],bool) and dataobj['base64'] == True) or
                    (isinstance(dataobj['base64'],str) and dataobj['base64'].lower()=='true')):
                        #data in base 64
                        mydata = json.loads(base64.b64decode(dataobj['data']))
                else:
                    mydata = dataobj['data']

                if not dataobj.has_key('sessionid'):
                    dataobj['sessionid']= getRandomName(6, "xmpp")
                    logging.warning("sessionid missing in message from %s : attributed sessionid %s " % (msg['from'],dataobj['sessionid']))
                else:
                    if dataobj['sessionid'] in self.ban_deploy_sessionid_list:
                        ## abort deploy if msg session id is banny
                        logging.info("DEPLOYMENT ABORT Sesion %s"%dataobj['sessionid'])
                        self.logtopulse("<span  style='color:red;'>DEPLOYMENT ABORT</span>",
                                        type = 'deploy',
                                        sessionname =  dataobj['sessionid'],
                                        priority = -1,
                                        who = self.boundjid.bare)
                        return

                del dataobj['data']
                # traitement TEVENT
                # TEVENT event sended by remote machine ou RS
                # message adresse au gestionnaire evenement
                if 'Dtypequery' in mydata and mydata['Dtypequery'] == 'TEVENT' and self.session.isexist(dataobj['sessionid']):
                    mydata['Dtypequery'] = 'TR'
                    datacontinue = {
                            'to' : self.boundjid.bare,
                            'action': dataobj['action'],
                            'sessionid': dataobj['sessionid'],
                            'data' : dict(self.session.sessionfromsessiondata(dataobj['sessionid']).datasession.items() + mydata.items()),
                            'ret' : 0,
                            'base64' : False
                    }
                    #add Tevent gestion event
                    self.eventmanage.addevent(datacontinue)
                    return
                try:
                    msg['body'] = dataobj
                    logging.info("call plugin %s from %s" % (dataobj['action'],msg['from'].user))
                    call_plugin(dataobj['action'],
                                self,
                                dataobj['action'],
                                dataobj['sessionid'],
                                mydata,
                                msg,
                                dataerreur
                                )
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
                    if dataobj['action'].startswith('result'):
                        return
                    if dataobj['action'] != "resultmsginfoerror":
                        dataerreur['data']['msg'] = "ERROR : plugin execution %s"%dataobj['action']
                        dataerreur['action'] = "result%s"%dataobj['action']
                        self.send_message(  mto=msg['from'],
                                            mbody=json.dumps(dataerreur),
                                            mtype='chat')
                    traceback.print_exc(file=sys.stdout)
            else:
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

    def seachInfoMachine(self):
        er = networkagentinfo("master", "infomachine")
        er.messagejson['info'] = self.config.information
        #send key public agent
        er.messagejson['publickey'] =  self.RSA.loadkeypublictobase64()
        #send if master public key public is missing
        er.messagejson['is_masterpublickey'] = self.RSA.isPublicKey("master")
        for t in er.messagejson['listipinfo']:
            # search network info used for xmpp
            if t['ipaddress'] == self.config.ipxmpp:
                xmppmask = t['mask']
                try:
                    xmppbroadcast = t['broadcast']
                except :
                    xmppbroadcast = ""
                xmppdhcp = t['dhcp']
                xmppdhcpserver = t['dhcpserver']
                xmppgateway = t['gateway']
                xmppmacaddress = t['macaddress']
                xmppmacnotshortened = t['macnotshortened']
                portconnection = self.config.Port
                break;
        try:
            subnetreseauxmpp =  subnetnetwork(self.config.ipxmpp, xmppmask)
        except Exception:
            logreception = """
Imposible calculate subnetnetwork verify the configuration of %s [%s]
Check if ip [%s] is correct:
check if interface exist with ip %s

Warning Configuration machine %s
[connection] 
server = It must be expressed in ip notation.

server = 127.0.0.1  correct
server = localhost in not correct
AGENT %s ERROR TERMINATE"""%(self.boundjid.bare,
                             er.messagejson['info']['hostname'],
                             self.config.ipxmpp,
                             self.config.ipxmpp,
                             er.messagejson['info']['hostname'],
                             self.boundjid.bare)
            self.loginfotomaster(logreception)
            sys.exit(0) 
        dataobj = {
            'action' : 'infomachine',
            'from' : self.config.jidagent,
            'compress' : False,
            'deployment' : self.config.jidchatroomcommand,
            'who'    : "%s/%s"%(self.config.jidchatroomcommand,self.config.NickName),
            'machine': self.config.NickName,
            'platform' : platform.platform(),
            'completedatamachine' : base64.b64encode(json.dumps(er.messagejson)),
            'plugin' : {},
            'portxmpp' : self.config.Port,
            'serverxmpp' : self.config.Server,
            'agenttype' : self.config.agenttype,
            'baseurlguacamole': self.config.baseurlguacamole,
            'subnetxmpp':subnetreseauxmpp,
            'xmppip' : self.config.ipxmpp,
            'xmppmask': xmppmask,
            'xmppbroadcast' : xmppbroadcast,
            'xmppdhcp' : xmppdhcp,
            'xmppdhcpserver' : xmppdhcpserver,
            'xmppgateway' : xmppgateway,
            'xmppmacaddress' : xmppmacaddress,
            'xmppmacnotshortened' : xmppmacnotshortened,
            'ipconnection':self.ipconnection,
            'portconnection':portconnection,
            'classutil' : self.config.classutil,
            'ippublic' : self.config.public_ip,
            'remoteservice' : protoandport(),
            'packageserver' : self.config.packageserver,
            'adorgbymachine' : organizationbymachine(),
            'adorgbyuser' : ''
        }

        lastusersession = powershellgetlastuser()
        if lastusersession != "":
            dataobj['adorgbyuser'] = organizationbyuser(lastusersession)
        sys.path.append(self.config.pathplugins)
        for element in os.listdir(self.config.pathplugins):
            if element.endswith('.py') and element.startswith('plugin_'):
                mod = __import__(element[:-3])
                reload(mod)
                module = __import__(element[:-3]).plugin
                dataobj['plugin'][module['NAME']] = module['VERSION']
        return dataobj

    def muc_onlineMaster(self, presence):
        if presence['muc']['nick'] == self.config.NickName:
            return
        if presence['muc']['nick'] == "MASTER":
            self.update_plugin()

def createDaemon(optstypemachine, optsconsoledebug, optsdeamon, tglevellog, tglogfile):
    """
        This function create a service/Daemon that will execute a det. task
    """
    try:
        if sys.platform.startswith('win'):
            import multiprocessing
            p = multiprocessing.Process(name='xmppagent',target=doTask, args=(optstypemachine, optsconsoledebug, optsdeamon, tglevellog, tglogfile,))
            p.daemon = True
            p.start()
            p.join()
            #doTask(optstypemachine, optsconsoledebug, optsdeamon, tglevellog, tglogfile)
        else:
            # Store the Fork PID
            pid = os.fork()
            if pid > 0:
                print 'PID: %d' % pid
                os._exit(0)
            doTask(optstypemachine, optsconsoledebug, optsdeamon, tglevellog, tglogfile)
    except OSError, error:
        logging.error("Unable to fork. Error: %d (%s)" % (error.errno, error.strerror))
        traceback.print_exc(file=sys.stdout)
        os._exit(1)


def doTask( optstypemachine, optsconsoledebug, optsdeamon, tglevellog, tglogfile):
    global restart
    if platform.system()=='Windows':
        # Windows does not support ANSI escapes and we are using API calls to set the console color
        logging.StreamHandler.emit = add_coloring_to_emit_windows(logging.StreamHandler.emit)
    else:
        # all non-Windows platforms are supporting ANSI escapes so we use them
        logging.StreamHandler.emit = add_coloring_to_emit_ansi(logging.StreamHandler.emit)
    # format log more informations
    format = '%(asctime)s - %(levelname)s - %(message)s'
    # more information log
    # format ='[%(name)s : %(funcName)s : %(lineno)d] - %(levelname)s - %(message)s'
    if not optsdeamon :
        if optsconsoledebug :
            logging.basicConfig(level = logging.DEBUG, format=format)
        else:
            logging.basicConfig( level = tglevellog,
                                 format = format,
                                 filename = tglogfile,
                                 filemode = 'a')
    else:
        logging.basicConfig( level = tglevellog,
                             format = format,
                             filename = tglogfile,
                             filemode = 'a')
    if optstypemachine.lower() in ["machine"]:
        sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), "pluginsmachine"))
    else:
        sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), "pluginsrelay"))
    # Setup the command line arguments.
    tg = confParameter(optstypemachine)

    if optstypemachine.lower() in ["machine"]:
        tg.pathplugins = os.path.join(os.path.dirname(os.path.realpath(__file__)), "pluginsmachine")
    else:
        tg.pathplugins = os.path.join(os.path.dirname(os.path.realpath(__file__)), "pluginsrelay")

    while True:
        if ipfromdns(tg.Server) != "" and   check_exist_ip_port(ipfromdns(tg.Server), tg.Port): break
        logging.log(DEBUGPULSE,"Unable to connect. (%s : %s) on xmpp server."\
            " Check that %s can be resolved"%(tg.Server,
                                              tg.Port,
                                              tg.Server))
        logging.log(DEBUGPULSE,"verify a information ip or dns for connection AM")
        if ipfromdns(tg.Server) == "" :
            logging.log(DEBUGPULSE, "not resolution adresse : %s "%tg.Server)
        time.sleep(2)

    while True:
        restart = False
        xmpp = MUCBot(tg)
        xmpp.register_plugin('xep_0030') # Service Discovery
        xmpp.register_plugin('xep_0045') # Multi-User Chat
        xmpp.register_plugin('xep_0004') # Data Forms
        xmpp.register_plugin('xep_0050') # Adhoc Commands
        xmpp.register_plugin('xep_0199', {'keepalive': True, 'frequency':15})
        xmpp.register_plugin('xep_0077') # In-band Registration
        xmpp['xep_0077'].force_registration = True
        # Connect to the XMPP server and start processing XMPP stanzas.address=(args.host, args.port)
        
        
        if xmpp.connect(address=(ipfromdns(tg.Server),tg.Port)):
            xmpp.process(block=True)
            logging.log(DEBUGPULSE,"terminate infocommand")
            if  xmpp.config.agenttype in ['relayserver']:
                xmpp.qin.put("quit")
            xmpp.queue_read_event_from_command.put("quit")
            logging.log(DEBUGPULSE,"wait 2s end thread event loop")
            logging.log(DEBUGPULSE,"terminate manage data sharing")
            if  xmpp.config.agenttype in ['relayserver']:
                xmpp.managerQueue.shutdown()
            time.sleep(2)
            logging.log(DEBUGPULSE,"terminate scheduler")
            xmpp.scheduler.quit()
            logging.log(DEBUGPULSE,"bye bye Agent")
        else:
            logging.log(DEBUGPULSE,"Unable to connect.")
            restart = False
        if not restart: break

if __name__ == '__main__':
    if sys.platform.startswith('linux') and  os.getuid() != 0:
        print "Agent must be running as root"
        sys.exit(0)
    elif sys.platform.startswith('win') and isWinUserAdmin() ==0 :
        print "Pulse agent must be running as Administrator"
        sys.exit(0)
    elif sys.platform.startswith('darwin') and not isMacOsUserAdmin():
        print "Pulse agent must be running as root"
        sys.exit(0)
    optp = OptionParser()
    optp.add_option("-d", "--deamon",action="store_true",
                 dest="deamon", default=False,
                  help="deamonize process")
    optp.add_option("-t", "--type",
                dest="typemachine", default=False,
                help="Type machine : machine or relayserver")
    optp.add_option("-c", "--consoledebug",action="store_true",
                dest="consoledebug", default = False,
                  help="console debug")

    opts, args = optp.parse_args()
    tg = confParameter(opts.typemachine)
    if not opts.deamon :
        doTask(opts.typemachine, opts.consoledebug, opts.deamon, tg.levellog, tg.logfile)
    else:
        createDaemon(opts.typemachine, opts.consoledebug, opts.deamon, tg.levellog, tg.logfile)
