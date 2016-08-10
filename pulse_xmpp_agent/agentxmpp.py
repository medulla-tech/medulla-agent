#!/usr/bin/env python
# -*- coding: utf-8 -*-
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
from lib.utils import *
import plugins
from optparse import OptionParser
from lib.managesession import sessiondatainfo, session


sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), "lib"))
sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), "plugins"))

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
        sleekxmpp.ClientXMPP.__init__(self, conf.jidagent, conf.passwordconnection)
        self.config = conf
        self.agentcommande = jid.JID(self.config.agentcommande)
        self.agentsiveo    = jid.JID(self.config.jidagentsiveo)
        self.session = session()
        self.ippublic = searchippublic()
        if self.ippublic == "":
            self.ippublic == None
        obj = simplecommandestr("LANG=C ifconfig | egrep '.*(inet|HWaddr).*'")
        self.md5reseau = hashlib.md5(obj['result']).hexdigest()
        # update every hour
        self.schedule('update plugin', 3600 , self.update_plugin, repeat=True)
        self.schedule('surveille reseau', 180 , self.networkMonitor, repeat=True)
        # reload plugins list all 15 minutes
        self.schedule('manage session', 60 , self.handlemanagesession, repeat=True)

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
        #fonction appeler pour tous message
        self.add_event_handler('message', self.message)
        self.add_event_handler("groupchat_message", self.muc_message)

        self.add_event_handler("pluginaction", self.pluginaction)

    def pluginaction(self,result):
        print result

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
        salon=[self.config.jidsaloncommand,self.config.jidsalonmaster,self.config.jidsalonlog]
        for x in salon:
        #join salon command
            self.plugin['xep_0045'].joinMUC(x,
                                            self.config.NickName,
                                            # If a room password is needed, use:
                                            password=self.config.passwordconnexionmuc,
                                            wait=True)

        self.loginformation("agent %s ready"%self.config.jidagent)

    def loginformation(self,msgdata):
        self.send_message( mbody = msgdata,
                           mto = self.config.jidsalonlog,
                           mtype ='groupchat')

    def register(self, iq):
        """ cette fonction est appelee pour la registration automatique""" 
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
            #self.disconnect()
        except IqTimeout:
            logging.error("No response from server.")
            self.disconnect()

    def muc_message(self, msg):
        pass

    def message(self, msg):
        #permet commande de jid agentcommande
        if msg['type'] == "chat":
            if not (msg['from'].user == 'master' or  msg['from'].user == self.agentcommande.user or msg['from'].user == self.agentsiveo.user) and \
                (msg['body'] == "This room is not anonymous" or msg['from'].user == "log"):
                return
            print msg
            if self.boundjid.bare == msg['from'].bare:
                return
            dataerreur={
                            "action": "resultmsginfoerror",
                            "sessionid" : "",
                            "ret" :   255,
                            "base64"  : False,
                            "data": {"msg" : ""}
            }

            if self.config.ordreallagent == False :
                #print self.config.jidagentsiveo
                print
                print msg['from']
                print
                if not (self.config.jidagentsiveo == msg['from'].bare or  msg['from'].user == 'master'):
                    logging.log(DEBUGPULSE,"agent %s : treatment only message Master or SIVEO [muc or chat from %s] " % (self.boundjid.user,msg['from'].user))
                    dataerreur['data']['msg'] = "treatment only message Master or SIVEO"
                    self.send_message(  mto=msg['from'],
                                            mbody=json.dumps(dataerreur),
                                            mtype='chat')
                    return

            try :
                dataobj = json.loads(msg['body'])
                #print dataobj['action']
                if dataobj.has_key('action') and dataobj['action'] != "" and dataobj.has_key('data'):
                    if dataobj.has_key('base64') and \
                        ((isinstance(dataobj['base64'],bool) and dataobj['base64'] == True) or 
                        (isinstance(dataobj['base64'],str) and dataobj['base64'].lower()=='true')):
                            #data en base 64
                            mydata = json.loads(base64.b64decode(dataobj['data']))
                    else:
                        mydata = dataobj['data']

                    if not dataobj.has_key('sessionid'):
                        dataobj['sessionid']= name_random(6, "xmpp")

                    del dataobj['data']
                    try:
                        msg['body']= dataobj
                        logging.log(DEBUGPULSE,"call plugin %s from %s" % (dataobj['action'],msg['from'].user))
                        
                        call_plugin(dataobj['action'],
                                    self,
                                    dataobj['action'],
                                    dataobj['sessionid'],
                                    mydata,
                                    msg,
                                    dataerreur
                                    )
                    except TypeError:
                        logging.error("TypeError execution plugin %s " % sys.exc_info()[0])
                        dataerreur['data']['msg'] = "ERROR : plugin %s Missing"%dataobj['action']
                        dataerreur['action'] = "result%s"%dataobj['action']
                        self.send_message(  mto=msg['from'],
                                            mbody=json.dumps(dataerreur),
                                            mtype='chat')
                    except Exception as e:
                        logging.error("execution plugin %s " % str(e))
                        dataerreur['data']['msg'] = "ERROR : plugin execution %s"%dataobj['action']
                        dataerreur['action'] = "result%s"%dataobj['action']
                        self.send_message(  mto=msg['from'],
                                            mbody=json.dumps(dataerreur),
                                            mtype='chat')
                else:
                    dataerreur['data']['msg'] = "ERROR : Action ignored"
                    self.send_message(  mto=msg['from'],
                                            mbody=json.dumps(dataerreur),
                                            mtype='chat')
            except Exception as e:
                logging.error("structure Message %s   %s " %(msg,str(e)))
                dataerreur['data']['msg'] = "ERROR : Message structure"
                self.send_message(  mto=msg['from'],
                                            mbody=json.dumps(dataerreur),
                                            mtype='chat')

    def muc_offlineCommand(self, presence):
        pass

    def muc_presenceCommand(self, presence):
        pass

    def muc_onlineCommand(self, presence):
        pass

    def muc_offlineMaster(self, presence):
        pass

    def muc_presenceMaster(self, presence):
        pass

    def update_plugin(self):
        # Send plugin and machine informations to Master
        dataobj=self.seachInfoMachine()
        #print "mmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmm"
        #print "OBJET = %s"%dataobj
        #print "mmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmm"
        #loggin.info("update plugin for hostname %s"%dataobj['machine'][:-3])
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
        for element in os.listdir('plugins'):
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


def createDaemon():
    """
        This function create a service/Daemon that will execute a det. task
    """
    try:
        if sys.platform.startswith('win'):
            import multiprocessing
            p = multiprocessing.Process(target=doTask)
            p.daemon = True
            p.start()
            p.join()
            logging.log(DEBUGPULSE,"Start Agent %s" % (self.boundjid.user))
        else:
            # Store the Fork PID
            pid = os.fork()
            if pid > 0:
                print 'PID: %d' % pid
                os._exit(0)
            doTask()
    except OSError, error:
        logging.error("Unable to fork. Error: %d (%s)" % (error.errno, error.strerror))
        os._exit(1)


def doTask():
    # Setup the command line arguments.
    global restart

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
        if xmpp.connect(address=(tg.Server,tg.Port)):
            xmpp.process(block=True)
            logging.log(DEBUGPULSE,"bye bye Agent")
        else:
            logging.log(DEBUGPULSE,"Unable to connect.")
            restart = False
        if not restart: break


if __name__ == '__main__':
    tg = parametreconf()
    print tg
    if sys.platform.startswith('linux') and  os.getuid() != 0:
        print "agent doit etre en root"
        sys.exit(0)
    elif sys.platform.startswith('win') and isWinUserAdmin() ==0 :
        print "agent windows doit etre en admin"
        sys.exit(0)
    elif sys.platform.startswith('darwin') and not isMacOsUserAdmin():
        print "agent mac doit etre en admin"
        sys.exit(0)
    if tg.debug == "LOG" or tg.debug == "DEBUGPULSE":
        tg.debug = 25
        DEBUGPULSE = 25
    optp = OptionParser()
    optp.add_option("-d", "--deamon",action="store_true", 
                 dest="deamon", default=False,
                  help="deamonize process")
    opts, args = optp.parse_args()
    if not opts.deamon :#tg.debug,
        #logging.basicConfig(level=tg.debug,
                        #format='[AGENT] %(levelname)-8s %(message)s')
        logging.basicConfig(level=tg.debug,
            format='[%(name)s.%(funcName)s:%(lineno)d] %(message)s')
        doTask()
    else:
        logging.basicConfig(level=tg.debug,
                            format='[AGENT] %(asctime)s :: %(levelname)-8s [%(name)s.%(funcName)s:%(lineno)d] %(message)s',
                            filename = tg.logfile,
                            filemode='a')
        stdout_logger = logging.getLogger('STDOUT')
        sl = StreamToLogger(stdout_logger, logging.INFO)
        sys.stdout = sl

        stderr_logger = logging.getLogger('STDERR')
        sl = StreamToLogger(stderr_logger, logging.ERROR)
        sys.stderr = sl
        createDaemon()
