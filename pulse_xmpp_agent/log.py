#!/usr/bin/env python
# -*- coding: utf-8 -*-
import sys
import logging
import ConfigParser
import sleekxmpp
import netifaces
import random
from sleekxmpp.exceptions import IqError, IqTimeout
import json
import hashlib

class configuration:
    def __init__(self,typeconf='agent'):
        Config = ConfigParser.ConfigParser()
        Config.read("./agent.ini")
        self.Port= Config.get('domain', 'port')
        self.Server= Config.get('domain', 'server')
        self.Chatadress= Config.get('domain', 'chatadress')
        self.Jid="log@%s/log"% self.Chatadress
        self.Password=Config.get('domaine', 'password')
        self.master="master@%s/master"%self.Chatadress
        self.siveo="agentsiveo@%s/siveo"%self.Chatadress
        self.forceregistration=Config.getboolean('domain', 'registrationauto')
        self.deploiement = Config.get('global', 'deploiement')
        self.commandinteragent = Config.getboolean('global', 'inter_agent')

        if Config.get('global', 'log_level') == "INFO":
            self.debug = logging.INFO
        elif Config.get('global', 'log_level') == "DEBUG":
            self.debug = logging.DEBUG
        elif Config.get('global', 'log_level') == "ERROR":
            self.debug = logging.ERROR
        else:
            self.debug = 5
        """ channel connexion information """
        self.NickName= "LOG"
        self.SalonServer=Config.get('Chatroom', 'server')
        self.SalonCommand="%s_%s@%s"%(self.deploiement,Config.get('Chatroom', 'command'),self.SalonServer)
        self.SalonMaster="%s@%s"%(Config.get('Chatroom', 'master'),self.SalonServer)
        self.SalonLog="%s@%s"%(Config.get('Chatroom', 'log'),self.SalonServer)
        self.SalonPassword=Config.get('Chatroom', 'password')

    def name_random(self, nb, pref=""):
        a="abcdefghijklnmopqrstuvwxyz"
        d=pref
        for t in range(nb):
            d=d+a[random.randint(0,25)]
        return d

    def name_randomID(self, nb, pref=""):
        a="0123456789"
        d=pref
        for t in range(nb):
            d=d+a[random.randint(0,9)]
        return d


    def get_local_ip_adresses(self):
        ip_addresses = list()
        interfaces = netifaces.interfaces()
        for i in interfaces:
            if i == 'lo':
                continue
            iface = netifaces.ifaddresses(i).get(netifaces.AF_INET)
            if iface:
                for j in iface:
                    addr = j['addr']
                    if addr != '127.0.0.1':
                        ip_addresses.append(addr)
        return ip_addresses

    def __str__(self):
        return str(self.re)

    def jsonobj(self):
        return json.dumps(self.re)

def name_random(nb, pref=""):
    a="abcdefghijklnmopqrstuvwxyz0123456789"
    d=pref
    for t in range(nb):
        d=d+a[random.randint(0,35)]
    return d


def md5(fname):
    hash = hashlib.md5()
    with open(fname, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash.update(chunk)
    return hash.hexdigest()


if sys.version_info < (3, 0):
    reload(sys)
    sys.setdefaultencoding('utf8')
else:
    raw_input = input


class MUCBot(sleekxmpp.ClientXMPP):
    def __init__(self,conf):#jid, password, room, nick):
        sleekxmpp.ClientXMPP.__init__(self, conf.Jid, conf.Password)
        self.config = conf
        self.add_event_handler("register", self.register, threaded=True)
        self.add_event_handler("session_start", self.start)
        self.add_event_handler('message', self.message)
        self.add_event_handler("groupchat_message", self.muc_message)

    def start(self, event):
        self.get_roster()
        self.send_presence()
        self.plugin['xep_0045'].joinMUC(self.config.SalonLog,
                                        self.config.NickName,
                                        # If a room password is needed, use:
                                        password=self.config.SalonPassword,
                                        wait=True)

    def register(self, iq):
        """ This function is called for automatic registration """
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

    def message(self, msg):
        pass

    def muc_message(self, msg):
        if msg['type'] == "groupchat":
            print msg['body']



if __name__ == '__main__':
    # Setup the command line arguments.
    conf=configuration()

    logging.basicConfig(level=conf.debug,
                        format='%(levelname)-8s %(message)s')
    xmpp = MUCBot(conf)
    xmpp.register_plugin('xep_0030') # Service Discovery
    xmpp.register_plugin('xep_0045') # Multi-User Chat
    xmpp.register_plugin('xep_0004') # Data Forms
    xmpp.register_plugin('xep_0050') # Adhoc Commands
    xmpp.register_plugin('xep_0199', {'keepalive': True, 'frequency':15})
    xmpp.register_plugin('xep_0077') # In-band Registration

    xmpp['xep_0077'].force_registration = conf.forceregistration

    # Connect to the XMPP server and start processing XMPP stanzas.address=(args.host, args.port)
    if xmpp.connect(address=(conf.Server,conf.Port)):
        # If you do not have the dnspython library installed, you will need
        # to manually specify the name of the server if it does not match
        # the one in the JID. For example, to use Google Talk you would
        # need to use:
        #
        # if xmpp.connect(('talk.google.com', 5222)):
        #     ...
        xmpp.process(block=True)
        print("Done")
    else:
        print("Unable to connect.")
