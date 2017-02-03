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
import sleekxmpp
import platform
import base64
import json
from sleekxmpp.exceptions import IqError, IqTimeout
from lib.networkinfo import networkagentinfo
from lib.configuration import  confParameter, changeconnection
from lib.agentconffile import conffilename
from lib.utils import *
from optparse import OptionParser


from lib.logcolor import  add_coloring_to_emit_ansi, add_coloring_to_emit_windows

# Additionnal path for library and plugins
pathbase = os.path.abspath(os.curdir)
pathplugins = os.path.join(pathbase, "pluginsmachine")
pathplugins_relay = os.path.join(pathbase, "pluginsrelay")
sys.path.append(pathplugins)

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
        newjidconf = conf.jidagent.split("@")
        resourcejid=newjidconf[1].split("/")
        resourcejid[0]=conf.confdomain
        newjidconf[0] = getRandomName(10,"conf")
        conf.jidagent=newjidconf[0]+"@"+resourcejid[0]+"/"+getRandomName(10,"conf")

        self.session = ""
        logging.log(DEBUGPULSE,"start machine %s Type %s" %( conf.jidagent, conf.agenttype))

        sleekxmpp.ClientXMPP.__init__(self, conf.jidagent, conf.confpassword)
        self.config = conf
        self.ippublic = searchippublic()
        if self.ippublic == "":
            self.ippublic == None

        self.config.masterchatroom="%s/MASTER"%self.config.confjidchatroom

        #self.md5reseau = hashlib.md5(obj['result']).hexdigest()
        # demande mise à jour toutes les heures.
        #self.schedule('update plugin', 3600 , self.update_plugin, repeat=True)
        #self.schedule('surveille reseau', 180 , self.networkMonitor, repeat=True)

        self.add_event_handler("register", self.register, threaded=True)
        self.add_event_handler("session_start", self.start)

        self.add_event_handler("muc::%s::presence" % conf.confjidchatroom,
                               self.muc_presenceConf)
        """ sortie presense dans chatroom Command """
        self.add_event_handler("muc::%s::got_offline" % conf.confjidchatroom,
                               self.muc_offlineConf)
        """ nouvelle presense dans chatroom Command """
        self.add_event_handler("muc::%s::got_online" % conf.confjidchatroom,
                               self.muc_onlineConf)

        #fonction appeler pour tous message
        self.add_event_handler('message', self.message)
        self.add_event_handler("groupchat_message", self.muc_message)

    def start(self, event):
        self.get_roster()
        self.send_presence()

        self.config.ipxmpp = getIpXmppInterface(self.config.confserver, self.config.confport)

        #join chatroom configuration
        self.plugin['xep_0045'].joinMUC(self.config.confjidchatroom,
                                        self.config.NickName,
                                        password=self.config.confpasswordmuc,
                                        wait=True)

    def register(self, iq):
        """ This function is called for automatic registration"""
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
            self.disconnect()


    def muc_presenceConf(self, presence):
        """
        traitement seulement si MASTER du chatroom configmaster
        """
        if presence['from'] == self.config.masterchatroom:
            print presence['from']
        #envoi information machine
        pass

    def muc_offlineConf(self, presence):
        if presence['from'] == self.config.masterchatroom:
            print presence['from']
        pass

    def muc_onlineConf(self, presence):
        if presence['muc']['nick'] == self.config.NickName:
            #elimine sa propre presense
            return
        if presence['muc']['nick'] == "MASTER":
            self.infos_machine()

    def message(self, msg):
        if msg['body']=="This room is not anonymous" or msg['subject']=="Welcome!":
            return
        print msg
        try :
            data = json.loads(msg['body'])
        except:
            return
        if self.session == data['sessionid'] and data['action'] == "resultconnectionconf" and msg['from'].user == "master" and msg['from'].resource=="MASTER" and data['ret'] == 0:
            logging.info("Start relay server agent configuration\n%s"%json.dumps(data['data'], indent=4, sort_keys=True))
            logging.log(DEBUGPULSE,"write new config")
            changeconnection(conffilename(opts.typemachine), data['data'][1],data['data'][0],data['data'][2],data['data'][3])
        elif data['ret'] != 0:
            logging.error("configuration dynamic error")
        else:
            return
        self.disconnect(wait=5)

    def muc_message(self, msg):
        pass

    def infos_machine(self):
        #envoi information
        dataobj=self.seachInfoMachine()
        self.session = getRandomName(10,"session")
        dataobj['sessionid'] = self.session
        dataobj['base64'] = False
        self.send_message(mto = "master@%s"%self.config.confdomain,
                            mbody = json.dumps(dataobj),
                            mtype = 'chat')

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
                xmppmacnotshortened = t['macnotshortened']
                break;

        subnetreseauxmpp =  subnetnetwork(self.config.ipxmpp, xmppmask)

        dataobj = {
            'action' : 'connectionconf',
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
            'classutil' : self.config.classutil,
            'ippublic' : self.ippublic
        }
        return dataobj

def createDaemon(tg):
    """
        This function create a service/Daemon that will execute a det. task
    """
    try:
        if sys.platform.startswith('win'):
            import multiprocessing
            p = multiprocessing.Process(target=doTask, arg=tg)
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
            doTask(tg)
    except OSError, error:
        logging.error("Unable to fork. Error: %d (%s)" % (error.errno, error.strerror))
        os._exit(1)


def doTask(tg):
    # Setup the command line arguments.
    global restart

    while True:
        restart = False
        if tg.agenttype != "relayserver":
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

    if opts.typemachine.lower() in ["machine"]:
        sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), "pluginsmachine"))
        tg.pathplugins="pluginsmachine"
    else:
        tg.pathplugins="pluginsrelay"
        sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), "pluginsrelay"))

    if platform.system()=='Windows':
        # Windows does not support ANSI escapes and we are using API calls to set the console color
        logging.StreamHandler.emit = add_coloring_to_emit_windows(logging.StreamHandler.emit)
    else:
        # all non-Windows platforms are supporting ANSI escapes so we use them
        logging.StreamHandler.emit = add_coloring_to_emit_ansi(logging.StreamHandler.emit)

    if not opts.deamon :
        if opts.consoledebug:
            logging.basicConfig(level = logging.DEBUG, format = '%(asctime)s - %(levelname)s - %(message)s')
            doTask(tg)
        else:
            stdout_logger = logging.getLogger('STDOUT')
            sl = StreamToLogger(stdout_logger, tg.levellog)
            sys.stdout = sl
            stderr_logger = logging.getLogger('STDERR')
            sl = StreamToLogger(stderr_logger, logging.ERROR)
            sys.stderr = sl
            logging.basicConfig(level = tg.levellog,
                        format = '[%(name)s.%(funcName)s:%(lineno)d] %(message)s',
                        filename = tg.logfile,
                        filemode = 'a')
            doTask(tg)
    else:
        stdout_logger = logging.getLogger('STDOUT')
        sl = StreamToLogger(stdout_logger, tg.levellog)
        sys.stdout = sl
        stderr_logger = logging.getLogger('STDERR')
        sl = StreamToLogger(stderr_logger, logging.ERROR)
        sys.stderr = sl
        logging.basicConfig(level = tg.levellog,
                    format ='[%(name)s.%(funcName)s:%(lineno)d] %(message)s',
                    filename = tg.logfile,
                    filemode = 'a')
        createDaemon(tg)
