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
# AGENT log
# pulse_xmpp_agent/pulse-xmpp-agent-log.py
# MA 02110-1301, USA.
import sys, os
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
from sqlalchemy import Column, String, Integer, DateTime, Text
from optparse import OptionParser
from lib.utils import StreamToLogger
#from sqlalchemy.dialects.mysql import  TINYINT
import copy
#from mmc.database.database_helper import DBObj
#from sqlalchemy.orm import relationship
#import datetime
import traceback
from sqlalchemy.orm import sessionmaker
import re
from sqlalchemy.ext.declarative import declarative_base
from lib.logcolor import  add_coloring_to_emit_ansi

logger = logging.getLogger()
Base = declarative_base()

VERSIONLOG = 1.0

#jfkjfk
class Logs(Base):
    # ====== Table name =========================
    __tablename__ = 'logs'
    # ====== Fields =============================
    # Here we define columns for the table machines.
    # Notice that each column is also a normal Python instance attribute.
    id = Column(Integer, primary_key=True)
    type = Column(String(6), nullable=False,default = "noset")
    date = Column(DateTime, default=datetime.datetime.now())
    text = Column(Text, nullable=False)
    sessionname = Column(String(20), nullable=False, default = "")
    priority = Column(Integer, default = 0)
    who = Column(String(45), nullable=False, default = "")
    how = Column(String(255), nullable=False, default = "")
    why = Column(String(255), nullable=False, default = "")
    module = Column(String(45), nullable=False, default = "")
    action = Column(String(45), nullable=False, default = "")
    touser = Column(String(45), nullable=False, default = "")
    fromuser = Column(String(45), nullable=False, default = "")


class Deploy(Base):
    # ====== Table name =========================
    __tablename__ = 'deploy'
    # ====== Fields =============================
    # Here we define columns for the table deploy.
    # Notice that each column is also a normal Python instance attribute.
    id = Column(Integer, primary_key=True)
    title=Column(String(255))
    inventoryuuid = Column(String(11), nullable=False)
    group_uuid = Column(String(11))
    pathpackage = Column(String(100), nullable=False)
    jid_relay = Column(String(45), nullable=False)
    jidmachine = Column(String(45), nullable=False)
    state = Column(String(45), nullable=False)
    sessionid = Column(String(45), nullable=False)
    start = Column(DateTime, default=datetime.datetime.now())
    startcmd = Column(DateTime, default=None)
    endcmd = Column(DateTime, default=None)
    result = Column(Text )
    host = Column(String(45), nullable=False)
    user = Column(String(45), nullable=False, default = "")
    login = Column(String(45), nullable=False)
    command = Column(Integer)
    macadress=Column(String(255))

class Def_remote_deploy_status(Base):
    # ====== Table name =========================
    __tablename__ = 'def_remote_deploy_status'
    # ====== Fields =============================
    # Here we define columns for the table def_remote_deploy_status.
    # Notice that each column is also a normal Python instance attribute.
    id = Column(Integer, primary_key=True)
    regex_logmessage = Column(String(80), nullable=False)
    status = Column(String(80), nullable=False)

class configuration:
    def __init__(self, configfile=""):
        Config = ConfigParser.ConfigParser()
        Config.read("/etc/mmc/plugins/xmppmaster.ini")
        if configfile != "" and os.path.exists(configfile):
            Config.read(configfile)
        elif os.path.exists("/etc/mmc/plugins/xmppmaster.ini.local"):
            Config.read("/etc/mmc/plugins/xmppmaster.ini.local")

        if Config.has_option("main", "jid"):
            self.jid = Config.get("main", "jid")
        else:
            self.jid = "log@pulse"

        if  Config.has_option("connection", "password"):
            self.Password=Config.get('connection', 'password')

        if  Config.has_option("connection", "port"):
            self.Port=Config.get('connection', 'port')

        if  Config.has_option("connection", "Server"):
            self.Server=Config.get('connection', 'Server')

        if  Config.has_option("chat", "domain"):
            self.Chatadress=Config.get('chat', 'domain')

        self.Jid="log@%s/log"% self.Chatadress
        self.master="master@%s/MASTER"%self.Chatadress
# database
        if  Config.has_option("database", "dbport"):
            self.dbport=Config.get('database', 'dbport')

        if  Config.has_option("database", "dbdriver"):
            self.dbdriver=Config.get('database', 'dbdriver')

        if  Config.has_option("database", "dbhost"):
            self.dbhost=Config.get('database', 'dbhost')

        if  Config.has_option("database", "dbname"):
            self.dbname=Config.get('database', 'dbname')

        if  Config.has_option("database", "dbuser"):
            self.dbuser=Config.get('database', 'dbuser')

        if  Config.has_option("database", "dbpasswd"):
            self.dbpasswd=Config.get('database', 'dbpasswd')

        if  Config.has_option("database", "pool_recycle"):
            self.dbpoolrecycle=Config.getint('database', 'dbpoolrecycle')
        else:
            self.dbpoolrecycle=5

        if  Config.has_option("database", "pool_size"):
            self.dbpoolsize=Config.getint('database', 'dbpoolsize')
        else:
            self.dbpoolsize=60

        if  Config.has_option("database", "pool_timeout"):
            self.dbpooltimeout=Config.getint('database', 'dbpooltimeout')
        else:
            self.dbpooltimeout=30

        if  Config.has_option("global", "log_level"):
            self.log_level=Config.get('global', 'log_level')
        else:
            self.log_level=Config.get('global', 'log_level')

        if  Config.has_option("global", "log_level"):
            self.log_level=Config.get('global', 'log_level')
        else:
            self.log_level=Config.get('global', 'log_level')

#global
        if self.log_level == "INFO":
            self.debug = logging.INFO
        elif self.log_level == "DEBUG":
            self.debug = logging.DEBUG
        elif self.log_level == "ERROR":
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
        self.engine = None
        self.config = conf
        self.add_event_handler("register", self.register, threaded=True)
        self.add_event_handler("session_start", self.start)
        self.add_event_handler('message', self.message)
        self.engine = create_engine('%s://%s:%s@%s/%s'%( self.config.dbdriver,
                                                                self.config.dbuser,
                                                                self.config.dbpasswd,
                                                                self.config.dbhost,
                                                                self.config.dbname),
                                    pool_recycle = self.config.dbpoolrecycle,
                                    pool_size = self.config.dbpoolsize,
                                    pool_timeout = self.config.dbpooltimeout
        )
        self.Session = sessionmaker(bind=self.engine)


    def start(self, event):
        self.get_roster()
        self.send_presence()
        print self.boundjid

        self.reglestatus = []
        loggerliststatus = self.get_log_status()
        try:
            for t in self.get_log_status():
                t['compile_re'] = re.compile(t['regexplog'])
                self.reglestatus.append(t)
            logger.debug("regle status initialise%s"% self.reglestatus)
        except:
            logger.error("\n%s"%(traceback.format_exc()))

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
            logger.error("Could not register account: %s" %
                    e.iq['error']['text'])
            #self.disconnect()
        except IqTimeout:
            logger.error("No response from server.")
            self.disconnect()

    def updatedeploytosessionid(self, status, sessionid):
        session = self.Session()
        try:
            sql = """UPDATE `xmppmaster`.`deploy`
                     SET `state`='%s'
                     WHERE `sessionid`='%s';"""%(status, sessionid)
            session.execute(sql)
            session.commit()
            session.flush()
        except Exception, e:
            logging.getLogger().error(str(e))

    def get_log_status(self):
        """ 
            get complete table
        """
        session = self.Session()
        resultat = []
        try:
            ret = session.query(Def_remote_deploy_status).all()
            session.commit()
            session.flush()
            if ret is None:
                resultat = []
            else:
                resultat = [{'index':id, 
                            "id" : regle.id,
                            'regexplog':regle.regex_logmessage, 
                            'status':regle.status} for id, regle in enumerate(ret)]
            return resultat     
        except Exception, e:
            traceback.print_exc(file=sys.stdout)
            return resultat
        
    def updatedeployresultandstate(self, sessionid, state, result ):
        session = self.Session()
        jsonresult = json.loads(result)
        jsonautre = copy.deepcopy(jsonresult)
        del (jsonautre['descriptor'])
        del (jsonautre['packagefile'])
        #DEPLOYMENT START
        try:
            deploysession = session.query(Deploy).filter(Deploy.sessionid == sessionid).one()
            if deploysession:
                if deploysession.result is None or \
                    ("wol" in jsonresult and \
                        jsonresult['wol']  == 1 ) or \
                    ("advanced" in jsonresult and \
                        'syncthing' in jsonresult['advanced'] and \
                            jsonresult['advanced']['syncthing'] == 1):
                    jsonbase = {
                                "infoslist": [jsonresult['descriptor']['info']],
                                "descriptorslist": [jsonresult['descriptor']['sequence']],
                                "otherinfos" : [jsonautre],
                                "title" : deploysession.title,
                                "session" : deploysession.sessionid,
                                "macadress" : deploysession.macadress,
                                "user" : deploysession.login
                    }
                else:
                    jsonbase = json.loads(deploysession.result)
                    jsonbase['infoslist'].append(jsonresult['descriptor']['info'])
                    jsonbase['descriptorslist'].append(jsonresult['descriptor']['sequence'])
                    jsonbase['otherinfos'].append(jsonautre)
                deploysession.result = json.dumps(jsonbase, indent=3)
                if 'infoslist' in jsonbase and \
                    'otherinfos' in jsonbase and \
                     len(jsonbase['otherinfos']) > 0 and \
                      'plan' in jsonbase['otherinfos'][0] and \
                        len(jsonbase['infoslist']) != len(jsonbase['otherinfos'][0]['plan']) and \
                         state == "DEPLOYMENT SUCCESS":
                    state = "DEPLOYMENT PARTIAL SUCCESS"
                deploysession.state = state
            session.commit()
            session.flush()
            session.close()
            return 1
        except Exception, e:
            logging.getLogger().error(str(e))
            traceback.print_exc(file=sys.stdout)
            return -1

    def createlog(self, dataobj):
        """
            this function creating log in base from body message xmpp
        """
        try:
            if 'text' in dataobj :
                text = dataobj['text']
            else:
                logger.error( "Cannot record this log. The content is badly formatted.")
                logger.error( "%s"%dataobj)
                return
            type = dataobj['type'] if 'type' in dataobj else ""
            sessionname = dataobj['session'] if 'session' in dataobj else ""
            priority = dataobj['priority'] if 'priority' in dataobj else ""
            who = dataobj['who'] if 'who' in dataobj else  ""
            how = dataobj['how'] if 'how' in dataobj else ""
            why = dataobj['why'] if 'why' in dataobj else ""
            module = dataobj['module'] if 'module' in dataobj else ""
            action = dataobj['action'] if 'action' in dataobj else ""
            fromuser = dataobj['fromuser'] if 'fromuser' in dataobj else ""
            touser = dataobj['touser'] if 'touser' in dataobj else ""
            self.registerlogxmpp(   text,
                                    type = type,
                                    sessionname = sessionname,
                                    priority = priority,
                                    who = who ,
                                    how  = how,
                                    why  = why,
                                    module = module,
                                    action = action,
                                    fromuser  = fromuser,
                                    touser  = touser)
        except Exception as e:
            logger.error("format log Message  %s %s" %(dataobj, str(e)))
            traceback.print_exc(file=sys.stdout)

    def registerlogxmpp(self,
                        text,
                        type = 'noset',
                        sessionname = '',
                        priority = 0,
                        who = '' ,
                        how  = '',
                        why  = '',
                        module = '',
                        fromuser  = '',
                        touser  = '',
                        action = ''
                        ):
        """
            this function for creating log in base
        """
        session = self.Session()
        log = Logs(text = text,
                   type = type,
                   sessionname = sessionname,
                   priority = priority,
                   who = who,
                   how = how,
                   why = why,
                   module = module,
                   action = action,
                   touser = touser,
                   date = datetime.datetime.now(),
                   fromuser = fromuser)
        session.add(log)
        session.commit()
        session.flush()
        session.close()

    def xmpplogdeploy(self, dataobj):
        """
            this function manage msg deploy log
        """
        try:
            if 'text' in dataobj and 'type' in dataobj and 'session' in dataobj and  'priority' in dataobj and  'who' in dataobj:
                self.registerlogxmpp(dataobj['text'],
                                     type = dataobj['type'],
                                     sessionname = dataobj['session'],
                                     priority = dataobj['priority'],
                                     who = dataobj['who'])
            elif 'action' in dataobj :
                if 'action' in dataobj and  'data' in dataobj and not "action" in dataobj['data']:
                    dataobj['data']['action'] = dataobj['action']
                    dataobj['data']['ret'] =  dataobj['ret']
                    dataobj['data']['sessionid'] =  dataobj['sessionid']
                if "data" in dataobj and 'action' in dataobj['data'] :
                    if dataobj['data']['action'] == 'resultapplicationdeploymentjson':
                        #log dans base resultat
                        if dataobj['ret'] == 0:
                            self.updatedeployresultandstate( dataobj['sessionid'], "DEPLOYMENT SUCCESS", json.dumps(dataobj['data'], indent=4, sort_keys=True) )
                        else:
                            self.updatedeployresultandstate( dataobj['sessionid'], "ABORT PACKAGE EXECUTION ERROR", json.dumps(dataobj['data'], indent=4, sort_keys=True) )
        except Exception as e:
            logger.error("obj Message deploy error  %s %s" %(dataobj, str(e)))
            traceback.print_exc(file=sys.stdout)

    def searchstatus(self, chaine):
        for t in self.reglestatus:
            if  t['compile_re'].match(chaine):
                logger.debug("la chaine \"%s\"  matche pour [%s] et renvoi le status suivant \"%s\""%(chaine,t['regexplog'],t['status']))
                return { "status" : t['status'] , "logmessage" : chaine}
        return { "status" : "" , "logmessage" : chaine}


    def message(self, msg):
        #save log message
        try :
            dataobj = json.loads(msg['body'])
            if 'data' in dataobj and\
                'type' in dataobj['data'] and\
                dataobj['data']['type'] == "deploy" and\
                "text" in dataobj['data'] and \
                    "sessionid" in dataobj['data']:
                re_status = self.searchstatus(dataobj['data']['text'])
                if re_status['status'] != "":
                    self.updatedeploytosessionid( re_status['status'], 
                                                 dataobj['data']['sessionid'])
                    logger.debug("apply status %s for sessionid %s"%(re_status['status'],
                                                                     dataobj['data']['sessionid']))
                #else:
                    #logger.debug("apply pas de status for sessionid %s"%(dataobj['data']['sessionid']))
            #rend agent log compatible standart stucture messages
            if "sessionid" in dataobj :  dataobj["session"] = dataobj["sessionid"]
            if 'data' in dataobj:
                if "sessionid" in dataobj['data'] :  
                    dataobj["data"]["session"] = dataobj["sessionid"]
        except Exception as e:
            logger.error("bad struct Message %s %s " %(msg['from'], str(e)))
            logger.error("\n%s"%(traceback.format_exc()))
            return
        try :
            #logging.debug("recu message from %s \n%s"%(msg['from'], json.dumps(dataobj, indent=4) ))
            if "action" in dataobj:
                if "data" in dataobj and  'action' in dataobj['data']:
                    if dataobj['data']['action'] == "resultapplicationdeploymentjson":
                        self.xmpplogdeploy(dataobj)
                        return
                    elif dataobj['data']['action'] == "" or dataobj['data']['action'] == "xmpplog":
                        self.createlog(dataobj['data'])
                        return
            if 'log' in dataobj:
                if dataobj['log'] == 'xmpplog':
                    self.createlog(dataobj)
                else:
                    # other typê message
                    logging.debug("Verify format log message %s"%str(dataobj))
                    pass
            else:
                if dataobj['action'] == "resultapplicationdeploymentjson":
                    self.xmpplogdeploy(dataobj)
        except Exception as e:
            logger.error("log  from %s error: %s " %(msg['from'], str(e)))
            logger.error("\n%s"%(traceback.format_exc()))
            return

def createDaemon(opts,conf):
    """
        This function create a service/Daemon that will execute a det. task
    """
    try:
        pid = os.fork()
        if pid > 0:
            print 'PID: %d' % pid
            os._exit(0)
        doTask(opts,conf)
    except OSError, error:
        logger.error("Unable to fork. Error: %d (%s)" % (error.errno, error.strerror))
        logger.error("\n%s"%(traceback.format_exc()))
        os._exit(1)


def doTask(opts, conf):
    logging.StreamHandler.emit = add_coloring_to_emit_ansi(logging.StreamHandler.emit)
    #logging.basicConfig(level = logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')


    if opts.consoledebug :
            logging.basicConfig(level = logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')
    else:
        stdout_logger = logging.getLogger('STDOUT')
        sl = StreamToLogger(stdout_logger, logging.INFO)
        sys.stdout = sl
        stderr_logger = logging.getLogger('STDERR')
        sl = StreamToLogger(stderr_logger, logging.INFO)
        sys.stderr = sl
        logging.basicConfig(level = logging.INFO,
                            format ='[%(name)s.%(funcName)s:%(lineno)d] %(message)s',
                            filename = "/var/log/pulse/xmpp-agent-log.log",
                            filemode = 'a')
    xmpp = MUCBot(conf)
    xmpp.register_plugin('xep_0030') # Service Discovery
    xmpp.register_plugin('xep_0045') # Multi-User Chat
    xmpp.register_plugin('xep_0199', {'keepalive': True, 'frequency':600, 'interval' : 600, 'timeout' : 500  })
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
        xmpp.process(block=True)
        print("Done")
    else:
        print("Unable to connect.")

if __name__ == '__main__':
    if not sys.platform.startswith('linux'):
        print "Agent log on systeme linux only"


    if os.getuid() != 0:
        print "Agent must be running as root"
        sys.exit(0)

    optp = OptionParser()
    optp.add_option("-d",
                    "--deamon",
                    action = "store_true",
                    dest = "deamon",
                    default = False,
                    help = "deamonize process")

    optp.add_option("-c",
                    "--consoledebug",
                    action = "store_true",
                    dest = "consoledebug",
                    default = False,
                    help = "console debug")

    optp.add_option("-v",
                    "--version",
                    action = "store_true",
                    dest = "version",
                    default = False,
                    help = "version programme")

    optp.add_option("-f",
                    "--file",
                    metavar="FILE",
                    dest = "configfile",
                    help = "specify the config file")

    opts, args = optp.parse_args()

    configfile = ""
    if opts.configfile:
        configfile = opts.configfile
    if opts.version is True:
        print VERSIONLOG
        sys.exit(0)
    # Setup the command line arguments.
    conf  = configuration(configfile)
    if not opts.deamon :
        doTask(opts, conf)
    else:
        createDaemon(opts, conf)
