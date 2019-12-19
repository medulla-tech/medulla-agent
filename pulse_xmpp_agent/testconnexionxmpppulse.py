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
from lib.networkinfo import networkagentinfo, organizationbymachine, organizationbyuser, powershellgetlastuser
from lib.configuration import  confParameter
from lib.utils import getRandomName, DEBUGPULSE, searchippublic, getIpXmppInterface, subnetnetwork, isWinUserAdmin, isMacOsUserAdmin
from optparse import OptionParser

# Additionnal path for library and plugins
pathbase = os.path.abspath(os.curdir)
pathplugins = os.path.join(pathbase, "pluginsmachine")
pathplugins_relay = os.path.join(pathbase, "pluginsrelay")
sys.path.append(pathplugins)

sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), "lib"))

logger = logging.getLogger()

ConfigurationConnexion = "" 

if sys.version_info < (3, 0):
    reload(sys)
    sys.setdefaultencoding('utf8')
else:
    raw_input = input

class MUCBot(sleekxmpp.ClientXMPP):
    def __init__(self,conf):#jid, password, room, nick):
        
        newjidconf = conf.jidagent.split("@")
        resourcejid = newjidconf[1].split("/")
        resourcejid[0] = conf.confdomain
        newjidconf[0] = getRandomName(10,"conf")
        conf.jidagent = newjidconf[0]+"@"+resourcejid[0]+"/"+getRandomName(10,"conf")

        self.session = ""
        logging.log(DEBUGPULSE,"start machine %s Type %s" %( conf.jidagent, conf.agenttype))
        #print conf.__str__()

        if not hasattr(conf, 'confmuc_password'):
            conf.confmuc_password = conf.passwordconnexionmuc
        if hasattr(conf, 'confmuc_domain'):
            print "'confmuc_domain' non defini"
        if not hasattr(conf, 'confpassword'):
            conf.confpassword = conf.passwordconnection

 
        sleekxmpp.ClientXMPP.__init__(self, "testconnexion@pulse", conf.passwordconnection)

        self.config = conf
        self.ippublic = searchippublic()
        if self.ippublic == "":
            self.ippublic == None


        self.config.masterchatroom="configmaster@conference.%s/MASTER"%conf.chatserver

        self.add_event_handler("register", self.register, threaded=True)
        self.add_event_handler("session_start", self.start)

        self.add_event_handler("muc::configmaster@conference.%s::got_offline"%conf.chatserver,
                               self.muc_presenceConf)
        self.add_event_handler("muc::configmaster@conference.%s::got_online"%conf.chatserver,
                               self.muc_offlineConf)
        self.add_event_handler("muc::configmaster@conference.%s::presence"%conf.chatserver,
                               self.muc_onlineConf)

        self.add_event_handler('message', self.message)
        self.add_event_handler("groupchat_message", self.muc_message)


    def start(self, event):
        self.get_roster()
        self.send_presence()
        print self.config
        self.config.ipxmpp = getIpXmppInterface(self.config.Server, self.config.Port)
       
        self.plugin['xep_0045'].joinMUC(self.config.masterchatroom.split('/')[0],
                                        "testconnexion",
                                        password=self.config.passwordconnexionmuc,
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
        global ConfigurationConnexion
        logging.log(DEBUGPULSE,"muc_presenceConf")
        from xml.dom import minidom
        reparsed = minidom.parseString(str(presence))
        logging.log(DEBUGPULSE,reparsed.toprettyxml(indent="\t"))
        if presence['from'] == self.config.masterchatroom:
            print presence['from']
            ConfigurationConnexion += "RECV AND  SEND MASTER MUC CONFIGURATION OK OK\n"

    def muc_offlineConf(self, presence):
        global ConfigurationConnexion
        logging.log(DEBUGPULSE,"muc_offlineConf")
        from xml.dom import minidom
        reparsed = minidom.parseString(str(presence))
        logging.log(DEBUGPULSE,reparsed.toprettyxml(indent="\t"))
        if presence['from'] == self.config.masterchatroom:
            print presence['from']
            ConfigurationConnexion += "DECONNEXION MASTER MUC CONFIGURATION OK\n"
        self.disconnect()


    def muc_onlineConf(self, presence):
        global ConfigurationConnexion
        logging.log(DEBUGPULSE,"muc_onlineConf")
        from xml.dom import minidom
        reparsed = minidom.parseString(str(presence))
        logging.log(DEBUGPULSE,reparsed.toprettyxml(indent="\t"))
        if presence['muc']['nick'] == self.config.NickName:
            #elimine sa propre presense
            return
        if presence['muc']['nick'] == "MASTER":
            #self.infos_machine()
            ConfigurationConnexion += "CONNEXION MASTER MUC CONFIGURATION OK\n"

    def message(self, msg):
        if msg['body']=="This room is not anonymous" or msg['subject']=="Welcome!":
            return
        print msg
        try :
            data = json.loads(msg['body'])
        except:
            return
        if self.session == data['sessionid'] and \
            data['action'] == "resultconnectionconf" and \
            msg['from'].user == "master" and \
            msg['from'].resource=="MASTER" and data['ret'] == 0:
            logging.info("Resultat data : %s"%json.dumps(data, indent=4, sort_keys=True))
            if len(data['data']) == 0 :
                logging.error("Verify table cluster : has_cluster_ars")
                sys.exit(0)
            logging.info("INFORMATION FROM MASTER")
            logging.info("Start relay server agent configuration\n%s"%json.dumps(data['data'], indent=4, sort_keys=True))
        elif data['ret'] != 0:
            logging.error("configuration dynamic error")
        else:
            return
        self.disconnect(wait=5)

    def terminate(self):
        self.disconnect()

    def muc_message(self, msg):
        pass

    def infos_machine(self):
        #envoi information
        dataobj=self.seachInfoMachine()
        self.session = getRandomName(10,"session")
        dataobj['sessionid'] = self.session
        dataobj['base64'] = False
        #----------------------------------
        print "affiche object"
        print json.dumps(dataobj, indent = 4)
        #----------------------------------
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
            'ippublic' : self.ippublic,
            'adorgbymachine' : base64.b64encode(organizationbymachine()),
            'adorgbyuser' : ''
        }
        lastusersession = powershellgetlastuser()
        if lastusersession != "":
            dataobj['adorgbyuser'] = base64.b64encode(organizationbyuser(lastusersession))
        return dataobj

def doTask( optstypemachine, optsconsoledebug, optsdeamon, tglevellog, tglogfile):
    global ConfigurationConnexion
    # format log more informations
    format = '%(asctime)s - %(levelname)s - %(message)s'

    logging.basicConfig(level = logging.DEBUG, format=format)

    #sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), "pluginsrelay"))
    # Setup the command line arguments.
    tg = confParameter("relayserver")
    #tg.pathplugins = os.path.join(os.path.dirname(os.path.realpath(__file__)), "pluginsrelay")
    xmpp = MUCBot(tg)
    xmpp.register_plugin('xep_0030') # Service Discovery
    xmpp.register_plugin('xep_0045') # Multi-User Chat
    xmpp.register_plugin('xep_0004') # Data Forms
    xmpp.register_plugin('xep_0050') # Adhoc Commands
    xmpp.register_plugin('xep_0199', {'keepalive': True, 'frequency':600,'interval' : 600, 'timeout' : 500  })
    xmpp.register_plugin('xep_0077') # In-band Registration
    xmpp['xep_0077'].force_registration = True

    # Connect to the XMPP server and start processing XMPP stanzas.address=(args.host, args.port)
    if xmpp.connect(address=(tg.Server,tg.Port)):
        xmpp.process(block=True)
        ConfigurationConnexion = "\nCONNEXION SERVER JABBERT OK\n" + ConfigurationConnexion

        logging.log(DEBUGPULSE,ConfigurationConnexion)

    else:
        logging.log(DEBUGPULSE,"Unable to connect.")
        logging.log(DEBUGPULSE,"WARNING NO CONNECT")

if __name__ == '__main__':
    if sys.platform.startswith('linux') and  os.getuid() != 0:
        print "Agent must be running as root"
        sys.exit(0)
    elif sys.platform.startswith('win') and isWinUserAdmin() == 0 :
        print "Pulse agent must be running as Administrator"
        sys.exit(0)
    elif sys.platform.startswith('darwin') and not isMacOsUserAdmin():
        print "Pulse agent must be running as root"
        sys.exit(0)
    optp = OptionParser()

    opts, args = optp.parse_args()
    tg = confParameter("relayserver")

    doTask("relayserver", True, False, tg.levellog, tg.logfile)
