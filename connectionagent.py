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
import hashlib
import shutil
import errno
from lib.networkinfo import networkagentinfo
from lib.configuration import  parametreconf, changeconnection
from lib.utils import *
import plugins
from optparse import OptionParser
import pprint
import os 
#addition chemin pour library and plugins
pathbase = os.path.abspath(os.curdir)
pathplugins = os.path.join(pathbase, "plugins")
pathlib     = os.path.join(pathbase, "lib")
sys.path.append(pathplugins)
sys.path.append(pathlib)
logger = logging.getLogger()
global restart
#global DEBUGPULSE
#DEBUGPULSE = 25


if sys.version_info < (3, 0):
    reload(sys)
    sys.setdefaultencoding('utf8')
else:
    raw_input = input

class MUCBot(sleekxmpp.ClientXMPP):
    def __init__(self,conf):#jid, password, room, nick):
        #newjidconf = conf.jidagent.split("@")
        #newjidconf[0] = name_random(10,"conf")
        #conf.jidagent = "@".join(newjidconf)

        #a modifier uand connection regle
        newjidconf = conf.jidagent.split("@")
        newjidconf[0] = "confdede"
        conf.jidagent = "@".join(newjidconf)
        self.session = ""
        logging.log(DEBUGPULSE,"start machine %s Type %s" %( conf.jidagent, conf.agenttype))
        #print conf.passwordconnection
        sleekxmpp.ClientXMPP.__init__(self, conf.jidagent, conf.confpassword)
        self.config = conf
        self.ippublic = searchippublic()
        if self.ippublic == "":
            self.ippublic == None

        self.config.mastersalon="%s/MASTER"%self.config.confjidsalon

        pp = pprint.PrettyPrinter(indent=4)
        pp.pprint(self.config.__dict__)

        obj = simplecommandestr("LANG=C ifconfig | egrep '.*(inet|HWaddr).*'")
        #self.md5reseau = hashlib.md5(obj['result']).hexdigest()
        # demande mise à jour toutes les heures.
        #self.schedule('update plugin', 3600 , self.update_plugin, repeat=True)
        #self.schedule('surveille reseau', 180 , self.networkMonitor, repeat=True)

        self.add_event_handler("register", self.register, threaded=True)
        self.add_event_handler("session_start", self.start)


        # recupere presence dans salonconf
        self.add_event_handler("muc::%s::presence" % conf.confjidsalon,
                               self.muc_presenceConf)
        """ sortie presense dans salon Command """
        self.add_event_handler("muc::%s::got_offline" % conf.confjidsalon,
                               self.muc_offlineConf)
        """ nouvelle presense dans salon Command """    
        self.add_event_handler("muc::%s::got_online" % conf.confjidsalon,
                               self.muc_onlineConf)

        #fonction appeler pour tous message
        self.add_event_handler('message', self.message)
        self.add_event_handler("groupchat_message", self.muc_message)

    def start(self, event):
        self.get_roster()
        self.send_presence()

        self.config.ipxmpp = getIpXmppInterface(self.config.confserver, self.config.confport)

        #join salon command
        self.plugin['xep_0045'].joinMUC(self.config.confjidsalon,
                                        self.config.NickName,
                                        # If a room password is needed, use:
                                        password=self.config.confpasswordmuc,
                                        wait=True)

    def register(self, iq):
        """ cette fonction est appelee pour la registration automatique""" 
        resp = self.Iq()
        resp['type'] = 'set'
        resp['register']['username'] = self.boundjid.user
        resp['register']['password'] = self.password
        #print  self.boundjid.user
        #print self.password
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


    def muc_presenceConf(self, presence):
        """
        traitement seulement si MASTER du salon configmaster
        """
        if presence['from'] == self.config.mastersalon:
            print presence['from']
        #envoi information machine
        pass

    def muc_offlineConf(self, presence):
        if presence['from'] == self.config.mastersalon:
            print presence['from']
        #print "muc_offlineConf"
        #print presence
        pass

    def muc_onlineConf(self, presence):
        if presence['muc']['nick'] == self.config.NickName:
            #elimine sa propre presense
            return
        if presence['muc']['nick'] == "MASTER":
            self.infos_machine()

    def message(self, msg):
        pass

    def muc_message(self, msg):
        if msg['body']=="This room is not anonymous":
            return
        try : 
            data = json.loads(msg['body'])
        except:
            return
        print data['data']
        print "session %s %s"%(self.session , data['sessionid'])
        print "session %s %s"%(msg['from'].user, "master" )
        print "session %s resultconnectionconf"%(data['action'])
        print "session %s %s"%(msg['from'].resource, "MASTER")
        
        if self.session == data['sessionid'] and data['action'] == "resultconnectionconf" and msg['from'].user == "master" and msg['from'].resource=="MASTER":
            print "Start1 agent server relais"
            print "%s"%data['data']
            changeconnection(data['data'][1],data['data'][0],data['data'][2],data['data'][3])
            self.disconnect(wait=5)

    def infos_machine(self):
        #envoi information
        dataobj=self.seachInfoMachine()
        #loggin.info("update plugin for hostname %s"%dataobj['machine'][:-3])
        self.session = name_random(10,"session")
        dataobj['sessionid'] = self.session
        dataobj['base64'] = False
        self.send_message(mto = "master@%s"%self.config.chatserver,
                            mbody = json.dumps(dataobj),
                            mtype = 'groupchat')


    def seachInfoMachine(self):
        er = networkagentinfo("config","inforegle")
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
                break;

        subnetreseauxmpp =  subnetnetwork(self.config.ipxmpp, xmppmask)

        dataobj = {
            'action' : 'connectionconf',
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
            'classutil' : self.config.classutil,
            'ippublic' : self.ippublic
        }
        return dataobj

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
        if tg.agenttype != "relaisserver":
            xmpp = MUCBot(tg)
            xmpp.register_plugin('xep_0030') # Service Discovery
            xmpp.register_plugin('xep_0045') # Multi-User Chat
            xmpp.register_plugin('xep_0004') # Data Forms
            xmpp.register_plugin('xep_0050') # Adhoc Commands
            xmpp.register_plugin('xep_0199', {'keepalive': True, 'frequency':15})
            xmpp.register_plugin('xep_0077') # In-band Registration
            xmpp['xep_0077'].force_registration = True

            # Connect to the XMPP server and start processing XMPP stanzas.address=(args.host, args.port)

            if xmpp.connect(address=(tg.confserver,tg.confport)):
                xmpp.process(block=True)
                logging.log(DEBUGPULSE,"bye bye connecteur")
            else:
                logging.log(DEBUGPULSE,"Unable to connect.")
                restart = False
            if not restart: break
        else:
            break


if __name__ == '__main__':
    tg = parametreconf()

    #pp = pprint.PrettyPrinter(indent=4)
    #pp.pprint(tg.__dict__)
    #sys.exit(0)


    #if sys.platform.startswith('linux') and  os.getuid() != 0:
        #print "agent doit etre en root"
        #sys.exit(0)  
    #elif sys.platform.startswith('win') and isWinUserAdmin() ==0 :
        #print "agent windows doit etre en admin"
        #sys.exit(0)
    #elif sys.platform.startswith('darwin') and not isMacOsUserAdmin():
        #print "agent mac doit etre en admin"
        #sys.exit(0)
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
