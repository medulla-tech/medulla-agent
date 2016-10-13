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

import sys,os
import logging
import ConfigParser
import sleekxmpp
import platform
import netifaces
import random
import base64
import json
import subprocess
from sleekxmpp.exceptions import IqError, IqTimeout
from sleekxmpp import jid
import hashlib
import shutil
import errno
from lib.networkinfo import networkagentinfo
from lib.configuration import  parametreconf
from lib.managesession import sessiondatainfo, session
from lib.utils import *
from lib.manage_event import manage_event
from lib.manage_process import mannageprocess
import traceback
import pluginsmachine
import pluginsrelay
from optparse import OptionParser
import time
import pprint
from time import mktime
from datetime import datetime
from multiprocessing import Process, Queue, TimeoutError
import threading

from lib.logcolor import  add_coloring_to_emit_ansi, add_coloring_to_emit_windows

sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), "lib"))


logger = logging.getLogger()
global restart


if sys.version_info < (3, 0):
    reload(sys)
    sys.setdefaultencoding('utf8')
else:
    raw_input = input


class MUCBot(sleekxmpp.ClientXMPP):
    def __init__(self,conf):#jid, password, room, nick):
        logging.log(DEBUGPULSE,"start machine1  %s Type %s" %( conf.jidagent, conf.agenttype))
        logger.info("start machine1  %s Type %s" %( conf.jidagent, conf.agenttype))
        sleekxmpp.ClientXMPP.__init__(self, jid.JID(conf.jidagent), conf.passwordconnection)
        # reload plugins list all 15 minutes
        laps_time_update_plugin = 3600
        laps_time_networkMonitor = 180
        laps_time_handlemanagesession = 15
        self.config = conf
        self.nicklistsaloncommand={}

        self.jidsaloncommand = jid.JID(self.config.jidsaloncommand)
        self.agentcommande = jid.JID(self.config.agentcommande)
        self.agentsiveo    = jid.JID(self.config.jidagentsiveo)
        self.agentmaster = jid.JID("master@%s"%self.boundjid.host)

        self.session = session(self.config.agenttype)
        self.signalinfo = {}
        #self.eventTEVENT = []
        # les queues. Ces objets sont comme des listes partageables entrent
        # les process command utilise cette queue pour signaler un evenement a magager event.
        self.queue_read_event_from_command = Queue()
        self.eventmanage = manage_event(self.queue_read_event_from_command, self)
        self.mannageprocess = mannageprocess(self.queue_read_event_from_command)

        self.nicknameagentrelayserverrefdeploy = 'deploy' #nickname used in salon deploy for relay server
        try:
            self.ippublic = searchippublic()
        except:
            self.ippublic = None
        if self.ippublic == "":
            self.ippublic == None
        obj = simplecommandestr("LANG=C ifconfig | egrep '.*(inet|HWaddr).*'")
        self.md5reseau = hashlib.md5(obj['result']).hexdigest()
        # update every hour
        self.schedule('update plugin', laps_time_update_plugin , self.update_plugin, repeat=True)
        self.schedule('check network', laps_time_networkMonitor , self.networkMonitor, repeat=True)
        self.schedule('manage session', laps_time_handlemanagesession , self.handlemanagesession, repeat=True)
        self.schedule('reprise_evenement', 10 , self.handlereprise_evenement, repeat=True)
        self.add_event_handler("register", self.register, threaded=True)
        self.add_event_handler("session_start", self.start)
        self.add_event_handler("muc::%s::presence" % conf.jidsaloncommand,
                               self.muc_presenceCommand)
        """ sortie presense dans salon Command """
        self.add_event_handler("muc::%s::got_offline" % conf.jidsaloncommand,
                               self.muc_offlineCommand)
        """ nouvelle presense dans salon Command """    
        self.add_event_handler("muc::%s::got_online" % conf.jidsaloncommand,
                               self.muc_onlineCommand)
        """ nouvelle presense dans salon Master """
        self.add_event_handler("muc::%s::presence" % conf.jidsalonmaster,
                               self.muc_presenceMaster)
        """ desincription presense dans salon Master """
        self.add_event_handler("muc::%s::got_offline" % conf.jidsalonmaster,
                               self.muc_offlineMaster)
        """ inscription presense dans salon Master """
        self.add_event_handler("muc::%s::got_online" % conf.jidsalonmaster,
                               self.muc_onlineMaster)
        #fonction appele pour tous message
        self.add_event_handler('message', self.message)
        self.add_event_handler("groupchat_message", self.muc_message)
        #fonction appeller pour event
        self.add_event_handler("signalsessioneventrestart", self.signalsessioneventrestart)
        self.add_event_handler("loginfotomaster", self.loginfotomaster)


    def loginfotomaster(self, msgdata):
        # ne sont traite par master seulement action loginfos
        try:
            self.send_message(  mbody = json.dumps(msgdata),
                                mto = 'master@localhost/MASTER',
                                mtype ='chat')
        except Exception as e:
            logging.error("message log to 'master@localhost/MASTER' : %s " %(str(e)))
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

    def networkMonitor(self):
        logging.log(DEBUGPULSE,"network monitor time 180s %s!" % self.boundjid.user)
        obj = simplecommandestr("LANG=C ifconfig | egrep '.*(inet|HWaddr).*'")
        md5ctl = hashlib.md5(obj['result']).hexdigest()
        if self.md5reseau != md5ctl:
            logging.info("network changed %s!" % self.boundjid.user)
            self.restartBot()

    def restartBot(self):
        global restart
        restart = True
        logging.log(DEBUGPULSE,"restart xmpp agent %s!" % self.boundjid.user)
        self.disconnect(wait=10)

    def start(self, event):
        self.get_roster()
        self.send_presence()
        self.config.ipxmpp = getIpXmppInterface(self.config.Server,self.config.Port)
        salon = [jid.JID(self.config.jidsaloncommand), jid.JID(self.config.jidsalonmaster), jid.JID(self.config.jidsalonlog)]
        self.agentrelayserverrefdeploy = self.config.jidsaloncommand.split('@')[0][3:]
        self.config.ipxmpp = getIpXmppInterface(self.config.Server, self.config.Port)
        #salon = [self.config.jidsaloncommand, self.config.jidsalonmaster, self.config.jidsalonlog]
        for x in salon:
        #join salon command
            if x == self.config.jidsaloncommand and self.config.agenttype in ['relayserver','serverrelais']:
                self.plugin['xep_0045'].joinMUC(x,
                                            self.nicknameagentrelayserverrefdeploy,
                                            # If a room password is needed, use:
                                            password=self.config.passwordconnexionmuc,
                                            wait=True)
            else:
                self.plugin['xep_0045'].joinMUC(x,
                                            self.config.NickName,
                                            # If a room password is needed, use:
                                            password=self.config.passwordconnexionmuc,
                                            wait=True)
        #if not self.config.agenttype in ['relayserver']:
            #les machines se declarent aupres de relaisserver dans le salon de deploiement du relais server
            # au demarage
            #msgdata = {'signalpresencesalon' :{ self.config.NickName: { 
                    #'jid' : self.config.jidagent, 
                    #'uuid': '246bc7f2-702b-11e6-8d74-3c970e3e0e47'}}}
            #self.send_message( mbody=json.dumps(msgdata),
                            #mto = "%s"%(self.config.jidsaloncommand),
                                #mtype ='groupchat')

        self.loginformation("agent %s ready"%self.config.jidagent)



    def loginformation(self,msgdata):
        self.send_message( mbody = msgdata,
                           mto = self.config.jidsalonlog,
                           mtype ='groupchat')

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


    def muc_message(self, msg):
        
        if self.config.agenttype in ['relayserver','serveurrelais'] and \
                        not msg['from'].resource in ["deploy","MASTER"] and \
                        not msg['from'].user in ['log']:
            try:
                result = json.loads(msg['body'])
                if "signalpresencesalon" in result:
                    self.nicklistsaloncommand.update(result['signalpresencesalon'])
            except:
                pass


    def filtre_message(self, msg):
        pass

    def issalondeploy(self, jidmessage ):
        return jidmessage in self.nicklistsaloncommand

    def message(self, msg):
        if self.boundjid.bare == msg['from'].bare:
            #ne traite pas message ces  propre message
            return

        if msg['type'] == "chat":
            if not (msg['from'].user == 'master' or  msg['from'].user == self.agentcommande.user or msg['from'].user == self.agentsiveo.user) and \
                (msg['body'] == "This room is not anonymous" or msg['from'].user == "log"):
                logging.warning("filtre message from %s!" % msg['from'].bare)
                return
            dataerreur={
                            "action": "resultmsginfoerror",
                            "sessionid" : "",
                            "ret" :   255,
                            "base64"  : False,
                            "data": {"msg" : ""}
            }
            try :
                dataobj = json.loads(msg['body'])
                if not self.issalondeploy(msg['from']):
                    if self.config.ordreallagent == False:
                        if dataobj.has_key('action') and dataobj['action'] !=  "resultmsginfoerror" and \
                            not (self.config.jidagentsiveo == msg['from'].bare or  msg['from'].user == 'master' or msg['from'].user == self.agentcommande.user or msg['from'].user == self.jidsaloncommand.user ):
                                logging.log(DEBUGPULSE,"agent %s : treatment only message Master or SIVEO [muc or chat from %s] " % (self.boundjid.user,msg['from'].user))
                                dataerreur['data']['msg'] = "treatment only message Master or SIVEO ou Rserver"
                                self.send_message(  mto=msg['from'],
                                                        mbody=json.dumps(dataerreur),
                                                        mtype='chat')
                                return
                if dataobj['action'] == "resultmsginfoerror":
                    logging.warning("filtre message from %s for action %s" % (msg['from'].bare,dataobj['action']))
                    return
                if dataobj.has_key('action') and dataobj['action'] != "" and dataobj.has_key('data'):
                    if dataobj.has_key('base64') and \
                        ((isinstance(dataobj['base64'],bool) and dataobj['base64'] == True) or 
                        (isinstance(dataobj['base64'],str) and dataobj['base64'].lower()=='true')):
                            #data in base 64
                            mydata = json.loads(base64.b64decode(dataobj['data']))
                    else:
                        mydata = dataobj['data']

                    if not dataobj.has_key('sessionid'):
                        dataobj['sessionid']= name_random(6, "xmpp")
                        logging.warning("sessionid missing in message from %s : attributed sessionid %s " % (msg['from'],dataobj['sessionid']))

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
                        msg['body']= dataobj
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

    def muc_offlineCommand(self, presence):
        if  self.config.agenttype in ['relayserver']:
            try:
                del (self.nicklistsaloncommand[presence['from'].resource])
            except KeyError:
                pass 

    def muc_presenceCommand(self, presence):
        if  not self.config.agenttype in ['relayserver'] and  presence['from'].resource in ["deploy"]:
            #executer seulement par machine
            for i in self.session.sessiondata:
                if 'signal' in i.datasession :
                    print "###################################################"
                    print "REPRISE DE DEPLOIEMENT AFTER RESTART OU RESTART BOT"
                    print "###################################################"
                    logging.info("to start again  %s " %(i.datasession['signal']['action']))
                    msgdata = {
                            'action': i.datasession['signal']['action'],
                            'sessionid': i.datasession['signal']['sessionid'],
                            'data' : i.datasession,
                            'ret' : 0,
                            'base64' : False
                        }
                    self.send_message( mto=i.datasession['signal']['retourmessage'],
                                mbody = json.dumps(msgdata),
                                mtype='chat')
                    del i.datasession['signal']

            #les machines se declarent aupres de relayserver dans le salon de deploiement du relais server
            msgdata = {'signalpresencesalon' :{ self.config.jidagent: { 
                    'nick' : self.config.NickName,
                    'uuid': '246bc7f2-702b-11e6-8d74-3c970e3e0e47'}}}
            self.send_message( mbody=json.dumps(msgdata),
                            mto = "%s"%(self.config.jidsaloncommand),
                                mtype ='groupchat')


    def muc_onlineCommand(self, presence):
        #si salon command est cree par master alors reinscrire agent relais dans salon command.
        if self.config.agenttype in ['relayserver']: 
            nickname = self.nicknameagentrelayserverrefdeploy
            if presence['from'] == self.config.jidsaloncommand + '/'+ nickname:
                if self.plugin['xep_0045'].rooms[self.config.jidsaloncommand][nickname]['role']=="":
                    self.plugin['xep_0045'].joinMUC(self.config.jidsaloncommand,
                        nickname,
                        password=self.config.passwordconnexionmuc,
                        wait=True)


    def muc_offlineMaster(self, presence):
        pass

    def muc_presenceMaster(self, presence):
        pass

    def update_plugin(self):
        # Send plugin and machine informations to Master
        dataobj=self.seachInfoMachine()
        self.send_message(mto = "master@%s"%self.config.chatserver,
                            mbody = json.dumps(dataobj),
                            mtype = 'chat')

    def seachInfoMachine(self):
        er = networkagentinfo("master","infomachine")
        er.messagejson['info'] = self.config.information
        for t in er.messagejson['listipinfo']:
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
                xmppmacnonreduite = t['macnonreduite']
                ipconnection = self.config.Server
                portconnection =self.config.Port
                break;

        subnetreseauxmpp =  subnetnetwork(self.config.ipxmpp, xmppmask)

        dataobj = {
            'action' : 'infomachine',
            'from' : self.config.jidagent,
            'compress' : False,
            'deploiement' : self.config.jidsaloncommand,
            'who'    : "%s/%s"%(self.config.jidsaloncommand,self.config.NickName),
            'machine': self.config.NickName,
            'plateforme' : platform.platform(),
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
            'xmppmacnonreduite' : xmppmacnonreduite,
            'ipconnection':ipconnection,
            'portconnection':portconnection,
            'classutil' : self.config.classutil,
            'ippublic' : self.ippublic
        }
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

    if not optsdeamon :
        if optsconsoledebug :
            logging.basicConfig(level = logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')
        else:
            stdout_logger = logging.getLogger('STDOUT')
            sl = StreamToLogger(stdout_logger, tglevellog)
            sys.stdout = sl
            stderr_logger = logging.getLogger('STDERR')
            sl = StreamToLogger(stderr_logger, tglevellog)
            sys.stderr = sl
            logging.basicConfig(level = tglevellog,
                        format ='[%(name)s.%(funcName)s:%(lineno)d] %(message)s',
                        filename = tglogfile,
                        filemode = 'a')
    else:
        stdout_logger = logging.getLogger('STDOUT')
        sl = StreamToLogger(stdout_logger, tglevellog)
        sys.stdout = sl
        stderr_logger = logging.getLogger('STDERR')
        sl = StreamToLogger(stderr_logger, tglevellog)
        sys.stderr = sl
        logging.basicConfig(level = tglevellog,
                    format ='[%(name)s.%(funcName)s:%(lineno)d] %(message)s',
                    filename = tglogfile,
                    filemode = 'a')

    if optstypemachine.lower() in ["machine"]:
        sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), "pluginsmachine"))
    else:
        sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), "pluginsrelay"))

    while True:
        # Setup the command line arguments.
        tg = parametreconf(optstypemachine)

        if optstypemachine.lower() in ["machine"]:
            tg.pathplugins = os.path.join(os.path.dirname(os.path.realpath(__file__)), "pluginsmachine")
        else:
            tg.pathplugins = os.path.join(os.path.dirname(os.path.realpath(__file__)), "pluginsrelay")

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
        if xmpp.connect(address=(tg.Server,tg.Port)):
            xmpp.process(block=True)
            xmpp.queue_read_event_from_command.put("quit")
            logging.error("wait 2s end thread event loop")
            time.sleep(2)
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
    tg = parametreconf(opts.typemachine)
    if not opts.deamon :
        doTask(opts.typemachine, opts.consoledebug, opts.deamon, tg.levellog, tg.logfile)
    else:
        createDaemon(opts.typemachine, opts.consoledebug, opts.deamon, tg.levellog, tg.logfile)
