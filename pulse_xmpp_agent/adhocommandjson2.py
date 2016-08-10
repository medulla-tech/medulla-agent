#!/usr/bin/env python
# -*- coding: utf-8 -*-
import sys
import logging
from optparse import OptionParser
import base64
import sleekxmpp
import ConfigParser
from sleekxmpp.exceptions import IqError, IqTimeout
import json
import random
import os
import hashlib
from lib.configuration import parametreconf


class Command(object):
    def __init__(self, cmd):
        self.cmd = cmd
        self.process = None

    def run(self, timeout):
        def target():
            print 'Thread started'
            self.process = subprocess.Popen(self.cmd, shell=True)
            self.process.communicate()
            print 'Thread finished'

        thread = threading.Thread(target=target)
        thread.start()

        thread.join(timeout)
        if thread.is_alive():
            print 'Terminating process'
            self.process.terminate()
            thread.join()
        print self.process.returncode

if sys.version_info < (3, 0):
    from sleekxmpp.util.misc_ops import setdefaultencoding
    setdefaultencoding('utf8')
else:
    raw_input = input


class CommandUserBot(sleekxmpp.ClientXMPP):
    def __init__(self, conf, client=None, jsonstr = None):
        self.config=conf
        sleekxmpp.ClientXMPP.__init__(self,conf.jidagent, conf.passwordconnection)
        self.client=client
        self.add_event_handler("session_start", self.start, threaded=True)
        self.add_event_handler("message", self.message)
        self.add_event_handler("groupchat_message", self.muc_message)
        self.add_event_handler("muc::%s::presence" % self.config.jidchannelcommand,
                               self.muc_presenceCommand)
        self.add_event_handler("register", self.register, threaded=True)
        
	self.fichierdata=str(jsonstr)
        
    def start(self, event):       
        self.send_presence()
        self.get_roster()
        
        
        self.plugin['xep_0045'].joinMUC(self.config.jidchannelcommand,
                                        self.config.NickName,
                                        password=self.config.passwordconnexionmuc,
                                        wait=True)

        self.plugin['xep_0045'].joinMUC(self.config.jidchannelmaster,
                                        self.config.NickName,
                                        password=self.config.passwordconnexionmuc,
                                        wait=True)
        #join channel log
        self.plugin['xep_0045'].joinMUC(self.config.jidchannellog,
                                        self.config.NickName,
                                        password=self.config.passwordconnexionmuc,
                                        wait=True)
        self.send_message(  mto=self.client,
                            mbody=self.fichierdata,#json.dumps(self.fichierdata),
                            mtype='groupchat')
        
    def loginformation(self, msgdata):
        self.send_message( mbody=msgdata,
                          mto=self.config.jidchannellog,
                          mtype='groupchat')

    def muc_presenceCommand(self, presence):
         
        pass

    def muc_message(self, msg):
        pass
    
    def messagecommande(self,cmd,cto,cfrom,ctype,):
        Myiq=self.make_iq(id=0, "dede@dede/ddd", "dede@dede/ddd", "get", "kkkk")
    

    def message(self, msg):

        print self.config.jidagent
        if msg['from'].bare == self.config.jidchannellog:
            return

        if msg['from'] == self.config.jidagent or \
                msg['from'].bare == self.config.jidchannelcommand or \
                msg['mucnick'] =='SIVEO':
            return

        

        dataobj= json.loads(msg['body'])
           
                
        if dataobj['action'].startswith("result"):
                print json.dumps(dataobj, indent=4, sort_keys=True)
        self.disconnect(wait=10)

    def register(self, iq):
        """ This function is called for auto-registration """
        resp = self.Iq()
        resp['type'] = 'set'
        resp['register']['username'] = self.boundjid.user
        resp['register']['password'] = self.password
        try:
            resp.send(now=True)
            logging.info("Account created for %s!" % self.boundjid)
        except IqError as e:
            logging.error("Could not register account: %s" %
                    e.iq['error']['text'])
            #self.disconnect()
        except IqTimeout:
            logging.error("No response from server.")
            self.disconnect()

if __name__ == '__main__':
    # Setup the command line arguments.
    tg = parametreconf()
    tg.jidagent="%s@%s/%s"%("agentsiveo",tg.chatserver,"SIVEO")
    tg.NickName="SIVEO"
    print tg.jidagent
    optp = OptionParser()

    optp.add_option("-o", "--other", dest="other",
                    help="JID providing commands")

    optp.add_option("-j", "--jsonstr", dest="jsonstr",
                    help="jsonstr")

    opts, args = optp.parse_args()

    logging.basicConfig(level=tg.debug,
                        format='%(levelname)-8s %(message)s')

    if opts.other is None:
        opts.other = raw_input("JID Providing Commands: ")

    xmpp = CommandUserBot(tg, client=opts.other, jsonstr=opts.jsonstr)
    
    xmpp.register_plugin('xep_0030') # Service Discovery
    xmpp.register_plugin('xep_0004') # Data Forms
    xmpp.register_plugin('xep_0050') # Adhoc Commands
    xmpp.register_plugin('xep_0045') # Multi-User Chat
    xmpp.register_plugin('xep_0199', {'keepalive': True, 'frequency':15})
    xmpp.register_plugin('xep_0077') # In-band Registration
    xmpp['xep_0077'].force_registration = False
    if xmpp.connect(address=(tg.Server,tg.Port)):
        xmpp.process(block=True)                    
        print("Done")
    else:
        print("Unable to connect.")
