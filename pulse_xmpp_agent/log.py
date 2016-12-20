#!/usr/bin/env python
# -*- coding: utf-8 -*-
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
import logging
import ConfigParser
import sleekxmpp
import netifaces
import random
from sleekxmpp.exceptions import IqError, IqTimeout
import json
import hashlib
import datetime
from sqlalchemy import create_engine

from sqlalchemy import Column, String, Integer, Boolean, ForeignKey, DateTime
#from sqlalchemy.dialects.mysql import  TINYINT
#from sqlalchemy.ext.declarative import declarative_base
#from mmc.database.database_helper import DBObj
#from sqlalchemy.orm import relationship
#import datetime

from sqlalchemy.orm import sessionmaker

from sqlalchemy.ext.declarative import declarative_base


Base = declarative_base()

class Logs(Base):
    # ====== Table name =========================
    __tablename__ = 'logs'
    # ====== Fields =============================
    # Here we define columns for the table machines.
    # Notice that each column is also a normal Python instance attribute.
    id = Column(Integer, primary_key=True)
    type = Column(String(6), nullable=False,default = "noset")
    date = Column(DateTime, default=datetime.datetime.utcnow)
    text = Column(String(255), nullable=False)
    sessionname = Column(String(20), nullable=False, default = "")
    priority = Column(Integer, default = 0)
    who = Column(String(20), nullable=False, default = "")

class configuration:
    def __init__(self):
        Config = ConfigParser.ConfigParser()
        Config.read("/etc/mmc/plugins/xmppagentlog.ini")

        self.Port= Config.get('domain', 'port')

        self.Server= Config.get('domain', 'server')

        self.Chatadress= Config.get('domain', 'chat')
        
        self.Jid="log@%s/log"% self.Chatadress
        
        self.Password=Config.get('domain', 'password')
        
        self.master=Config.get('domain', 'master')

# database
        self.dbport = Config.get('database', 'dbport')
        self.dbdriver = Config.get('database', 'dbdriver')
        self.dbhost = Config.get('database', 'dbhost')
        self.dbname = Config.get('database', 'dbname')
        self.dbuser = Config.get('database', 'dbuser')
        self.dbpasswd = Config.get('database', 'dbpasswd')

#global
        if Config.get('global', 'log_level') == "INFO":
            self.debug = logging.INFO
        elif Config.get('global', 'log_level') == "DEBUG":
            self.debug = logging.DEBUG
        elif Config.get('global', 'log_level') == "ERROR":
            self.debug = logging.ERROR
        else:
            self.debug = 5

    def getRandomName(self, nb, pref=""):
        a="abcdefghijklnmopqrstuvwxyz"
        d=pref
        for t in range(nb):
            d=d+a[random.randint(0,25)]
        return d

    def getRandomNameID(self, nb, pref=""):
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

    #def __str__(self):
        #return str(self.re)

    def jsonobj(self):
        return json.dumps(self.re)

def getRandomName(nb, pref=""):
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

    def start(self, event):
        self.get_roster()
        self.send_presence()
        
        print self.boundjid
        print self.boundjid
        print self.boundjid
        print self.boundjid
        print self.boundjid
        
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


    def registrelog(self,text, type='noset', sessionname='', priority = 0, who='' ):
        #mysql+mysqlconnector://<user>:<password>@<host>[:<port>]/<dbname>
        engine = create_engine('%s://%s:%s@%s/%s'%( self.config.dbdriver,
                                                                self.config.dbuser,
                                                                self.config.dbpasswd,
                                                                self.config.dbhost,
                                                                self.config.dbname
                                                                  ))
        Session = sessionmaker(bind=engine)
        session = Session()
        log = Logs(text = text, type = type, sessionname= sessionname,priority= priority,who=who)
        session.add(log)
        session.commit()
        session.flush()

    def message(self, msg):
        #save log message
        try :
            dataobj = json.loads(msg['body'])
            if 'text' in dataobj and 'type' in dataobj and 'session' in dataobj and  'priority' in dataobj and  'who' in dataobj:
                self.registrelog(dataobj['text'], dataobj['type'], dataobj['session'], dataobj['priority'], dataobj['who'])
        except Exception as e:
            logging.error("bad struct Message %s %s " %(msg, str(e)))
            dataerreur['data']['msg'] = "ERROR : Message structure"
            self.send_message(  mto=msg['from'],
                                        mbody=json.dumps(dataerreur),
                                        mtype='chat')
            traceback.print_exc(file=sys.stdout)


if __name__ == '__main__':
    # Setup the command line arguments.
    conf=configuration()

    logging.basicConfig(level=conf.debug,
                        format='%(levelname)-8s %(message)s')
    xmpp = MUCBot(conf)
    xmpp.register_plugin('xep_0030') # Service Discovery
    xmpp.register_plugin('xep_0045') # Multi-User Chat
    xmpp.register_plugin('xep_0199', {'keepalive': True, 'frequency':15})
    xmpp.register_plugin('xep_0077') # In-band Registration
    xmpp['xep_0077'].force_registration = True

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
