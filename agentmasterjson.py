
/**
 * (c) 2016 Siveo, http://http://www.siveo.net
 *
 * $Id$
 *
 * This file is part of Pulse .
 *
 * Pulse is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * Pulse is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Pulse.  If not, see <http://www.gnu.org/licenses/>.
 */
 
#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys, os
import logging
import ConfigParser
import sleekxmpp
import netifaces
import random
import base64
import json
from optparse import OptionParser
from sleekxmpp.exceptions import IqError, IqTimeout
#from lib.network import networkagent
from lib.networkinfo import networkagentinfo
from lib.configuration import parametreconf
from lib.utils import *
import plugins

import mysql.connector
from mysql.connector import errorcode

#addition chemin pour library and plugins
pathbase = os.path.abspath(os.curdir)
pathplugins = os.path.join(pathbase, "plugins")
pathlib     = os.path.join(pathbase, "lib")
sys.path.append(pathplugins)
sys.path.append(pathlib)

if sys.version_info < (3, 0):
    reload(sys)
    sys.setdefaultencoding('utf8')
else:
    raw_input = input

class MUCBot(sleekxmpp.ClientXMPP):
    def __init__(self,conf):#jid, password, room, nick):
        self.loadpluginlist()
        sleekxmpp.ClientXMPP.__init__(self,  conf.jidagent, conf.passwordconnection)
        # reload plugins list all 15 minutes
        self.schedule('update plugin', 900 , self.loadpluginlist, repeat=True)
        self.config = conf
        self.idm = ""
        self.presencedeploiement={}
        self.add_event_handler("session_start", self.start)
        self.add_event_handler("muc::%s::presence" % conf.jidchannelmaster,
                               self.muc_presenceMaster)
        self.add_event_handler("muc::%s::got_offline" % conf.jidchannelmaster,
                               self.muc_offlineMaster)
        self.add_event_handler("muc::%s::got_online" % conf.jidchannelmaster,
                               self.muc_onlineMaster)
        self.add_event_handler('message', self.message)
        self.add_event_handler("groupchat_message", self.muc_message)

    def loadpluginlist(self):
        print "verify base plugin"
        plugindataseach={}
        for element in os.listdir('baseplugins'):
            if element.endswith('.py') and element.startswith('plugin_'):
                f = open(os.path.join('baseplugins',element),'r')
                lignes  = f.readlines()
                f.close() 
                for ligne in lignes:
                    if 'VERSION' in ligne and 'NAME' in ligne:
                        l=ligne.split("=")
                        plugin = eval(l[1])
                        plugindataseach[plugin['NAME']]=plugin['VERSION']
                        break;
        self.plugindata = plugindataseach       


    def loginformation(self,msgdata):
        self.send_message( mbody = msgdata,
                           mto = self.config.jidchannellog,
                           mtype ='groupchat')   

    def start(self, event):
        self.get_roster()
        self.send_presence()
        #join channel Master
        self.plugin['xep_0045'].joinMUC(self.config.jidchannelmaster,
                                        self.config.NickName,
                                        # If a room password is needed, use:
                                        password=self.config.passwordconnexionmuc,
                                        wait=True)
        #join channel log
        self.plugin['xep_0045'].joinMUC(self.config.jidchannellog,
                                        self.config.NickName,
                                        # If a room password is needed, use:
                                        password=self.config.passwordconnexionmuc,
                                        wait=True)

    def register(self, iq):
        """ Function called for automatic Registration """
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

        except IqTimeout:
            logging.error("No response from server.")
            self.disconnect()

    def message(self, msg):
        ### mettre en base
        pass

    def showListClient(self):
        depl={}
        l = self.presencedeploiement.keys()
        for t in l:            
            depl[self.presencedeploiement[t]['deploiement']]=[self.presencedeploiement[t]['deploiement']]
        if len(l) != 0:
            for k in depl.keys():
                print "Déploiement sur [%s]"%k
                print '{0:30}|{1:35}|{2:50}'.format("Machine","jid","plateform")
                for t in l:
                    if self.presencedeploiement[t]['deploiement']==k:

                        jidbarre=self.presencedeploiement[t]['fromjid'].split('/')
                        print '{0:30}|{1:35}|{2:50}'.format(self.presencedeploiement[t]['machine'][:-3],
                                                            jidbarre[0],
                                                            self.presencedeploiement[t]['plateform'] )                   
        else:
            #if self.config.showinfomaster:
            print "AUCUNE MACHINE"

    def deploiePlugin(self, msg, plugin):
        data =''
        fichierdata={}
        namefile =  os.path.join('baseplugins',"plugin_%s.py"%plugin)
        try:
            fileplugin = open(namefile, "rb")                                      
            data=fileplugin.read()
            fileplugin.close()
        except :
            print "erreur lecture fichier"
            return

        fichierdata['action'] = 'installplugin'
        fichierdata['data'] ={}
        dd={}
        dd['datafile']= data
        dd['pluginname'] = "plugin_%s.py"%plugin
        fichierdata['data']= base64.b64encode(json.dumps(dd))    
        fichierdata['sessionid'] = "sans"
        fichierdata['base64'] = True

        self.send_message(mto=msg['from'],
                          mbody=json.dumps(fichierdata),
                          mtype='groupchat')

    def muc_message(self, msg):       
        """
        fonction traitant tous messages venant d un channel        
        attribut type pour selection
        """
        restartagent = False
        if msg['from'].bare == self.config.jidchannellog:
            return

        if msg['type'] == "groupchat":
            if msg['body'] == "This room is not anonymous":
                return
            try:
                data = json.loads(msg['body'])

                    
                if data['action'] == 'infomachine':
                    info=json.loads(base64.b64decode(data['completedatamachine']))
                    self.presencedeploiement[data['machine']]={
                        'machine':data['machine'],
                        'fromchannel':data['who'],
                        'fromjid': data['from'],
                        'deploiement':data['deploiement'],
                        'plateform':data['plateform'],
                        'information':info}
                    data['information'] = info
                    if self.config.showinfomaster:
                        print
                        print "__________________________"
                        print "INFORMATION MACHINE"
                        print "deploie name : %s"%data['deploiement']
                        print "from : %s"%data['who']
                        print "Jid from : %s"%data['from']
                        print "Machine : %s"%data['machine']
                        print "plateform : %s"%data['plateform']                    
                        print 
                        print "DETAILLED INFORMATION"
                        print json.dumps(data['information'], indent=4, sort_keys=True)


                    if self.config.sgbd:
                        sql= "INSERT INTO machines (`machine`, `jid`, `plateform`, `hostname`, `architecture`) VALUES('%s', '%s', '%s', '%s','%s');"%(data['machine'],
                                  data['from'],
                                  data['plateform'],
                                  data['information']['info']['hostname'],
                                  data['information']['info']['hardtype'])

                        logging.debug("injection machine info[%s]"%sql)
                        try:
                            cursor = self.config.conn.cursor()
                            cursor.execute(sql)
                            self.config.conn.commit()
                            cursor.close()
                        except  mysql.connector.Error as err:
                            print str(err)

                        for i in data['information']["listipinfo"]:
                            sql= "INSERT INTO network (macadress, ipadress, broadcast, gateway, mask, machine, mac ) VALUES('%s', '%s', '%s', '%s', '%s', '%s', '%s')"%(
                            i['macaddress'], i['ipaddress'], i['broadcast'], i['gateway'], i['mask'], data['machine'], i['macnonreduite'])
                            
                            logging.debug("injection network info[%s]"%sql)
                            try:
                                cursor = self.config.conn.cursor()
                                cursor.execute(sql)
                                self.config.conn.commit()
                                cursor.close()
                            except  mysql.connector.Error as err:
                                print str(err)
                        sql = "SELECT group_concat(concat('%s',mac,'%s')) as listmac FROM agentxmpp.network where machine = '%s';"%('"','"',data['machine'])
                        logging.debug("macadress list for machine [%s] sql[%s]"%(data['machine'],sql))
                        try:
                            cursor = self.config.conn.cursor()
                            cursor.execute(sql)
                            for listmac in cursor:
                                maclist = listmac[0]
                                logging.debug("macadress list [%s] for machine [%s]"%(maclist, data['machine']))
                            cursor.close()
                        except  mysql.connector.Error as err:
                            print str(err)

                        if self.config.inventory == "glpi":
                            sql = "SELECT DISTINCT items_id FROM glpi.glpi_networkports where mac in (%s)group by items_id;"%(maclist)
                            logging.debug("consolidation [%s] from glpi for machine [%s]"%(sql, data['machine']))
                            try:
                                cursor = self.config.conn.cursor()
                                cursor.execute(sql)
                                for items_id in cursor:
                                    machineid =  items_id[0]
                                logging.debug("machine glpi [%s] mac adres [%s]"%(machineid,maclist))
                                cursor.close()
                            except  mysql.connector.Error as err:
                                print str(err)


                        sql = "UPDATE `machines` SET `uuid_inventorymachine`='UUID%s' WHERE `machine`='%s';"%(machineid,data['machine'])
                        logging.debug("update machine avec ref machine id inventory [%s]"%(sql))
                        try:
                            cursor = self.config.conn.cursor()
                            cursor.execute(sql)
                            self.config.conn.commit()
                            cursor.close()
                        except  mysql.connector.Error as err:
                            print str(err)
                            
                    else:
                        print "information non base"
                     
                    if self.config.showplugins:
                        print "___________________________"
                        print "LIST PLUGINS INSTALLED AGENT"
                        print json.dumps(data['plugin'], indent=4, sort_keys=True)
                        print "___________________________"
                    restartagent = False
                    for k,v in self.plugindata.iteritems():
                        deploie = False
                        try:
                           if data['plugin'][k] != v:
                               print "update %s version %s to version %s"%(k,data['plugin'][k],v)
                               deploie = True
                        except:
                            print "deploie %s version %s"%(k,v)
                            deploie = True
                        if deploie:
                            restartagent = True
                            self.deploiePlugin(msg,k)
                    if restartagent:
                        self.send_message(mto=msg['from'],
                            mbody=json.dumps({'action':'restartbot'}),
                            mtype='groupchat')
                    if self.config.showinfomaster:
                        print "___________________________"
                    self.showListClient()
                elif data['action'] == 'participant':
                    resultcommand={'action' : 'participant',
                                   'participant' : self.presencedeploiement }
                    self.send_message(mto=msg['from'],
                            mbody=json.dumps(resultcommand),
                            mtype='groupchat')
                elif data['action'] == 'listparticipant':
                    resultcommand={'action' : 'listparticipant',
                                   'participant' : self.presencedeploiement }
                    self.send_message(mto=msg['from'],
                            mbody=json.dumps(resultcommand),
                            mtype='groupchat')           
            except:
                pass

    def muc_offlineMaster(self, presence):

        if presence['muc']['nick'] != self.config.NickName and presence['muc']['nick'] != "SIVEO":
            if self.config.showinfomaster:
                print "deconnexion %s"% presence['muc']['nick']
            try:
                del self.presencedeploiement[presence['muc']['nick']]
                sql = "DELETE FROM `machines` WHERE `machine`='%s';"%presence['muc']['nick']
                print sql
                try:
                    cursor = self.config.conn.cursor()
                    cursor.execute(sql)
                    self.config.conn.commit()
                    cursor.close()
                except  mysql.connector.Error as err:
                    print str(err)
                sql = "DELETE FROM `network` WHERE `machine`='%s';"%presence['muc']['nick']
                print sql
                try:
                    cursor = self.config.conn.cursor()
                    cursor.execute(sql)
                    self.config.conn.commit()
                    cursor.close()
                except  mysql.connector.Error as err:
                    print str(err) 
            except:
                pass
            self.showListClient()

    def muc_presenceMaster(self, presence):

        if presence['muc']['nick'] != self.config.NickName:
            if self.config.showinfomaster:
                print "presence %s"%presence['muc']['nick']


    def muc_onlineMaster(self, presence):

        if presence['muc']['nick'] != self.config.NickName:

            pass



def createDaemon():
    """ 
        This function create a service/Daemon that will execute a det. task
    """
    if sys.platform.startswith('linux') and  os.getuid() != 0:
        print "agent doit etre en root"
        sys.exit(0)  
   
    try:
        pid = os.fork()
        if pid > 0:
            print 'PID: %d' % pid
            os._exit(0)
        doTask()
    except OSError, error:
        print 'Unable to fork. Error: %d (%s)' % (error.errno, error.strerror)
        os._exit(1)


def doTask():
    # Setup the command line arguments.
    xmpp = MUCBot(tg)
    xmpp.register_plugin('xep_0030') # Service Discovery
    xmpp.register_plugin('xep_0045') # Multi-User Chat
    xmpp.register_plugin('xep_0004') # Data Forms
    xmpp.register_plugin('xep_0050') # Adhoc Commands
    xmpp.register_plugin('xep_0199', {'keepalive': True, 'frequency':15})
    xmpp.register_plugin('xep_0077') # In-band Registration

    xmpp['xep_0077'].force_registration = False

    if xmpp.connect(address=(tg.Server,tg.Port)):
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
    
if __name__ == '__main__':
    #optp = OptionParser()
    tg=parametreconf()
  
  
    if tg.sgbd:
        try:
            tg.conn = mysql.connector.connect(host=tg.host, user=tg.user, password=tg.password, database=tg.database)
            cursor = tg.conn.cursor()
            cursor.execute('TRUNCATE machines');cursor.execute('TRUNCATE network');
            tg.conn.commit()
            cursor.close()

        except mysql.connector.Error as err:
            print str(err)
            tg.sgbd = False

    tg.jidagent="%s@%s/%s"%("master",tg.chatserver,"MASTER")
    print tg.jidagent
    tg.NickName="MASTER"
    optp = OptionParser()
    optp.add_option("-d", "--deamon",
                 dest="deamon", default=False,
                  help="deamonize process")
    opts, args = optp.parse_args()
    if not opts.deamon :
        logging.basicConfig(level=tg.debug,
                        format='[MASTER] %(levelname)-8s %(message)s')
    else:
        logging.basicConfig(level=tg.debug,
                            format='[MASTER] %(asctime)s :: %(levelname)-8s [%(name)s.%(funcName)s:%(lineno)d] %(message)s',
                            filename = tg.logfile,
                            filemode='a')
        stdout_logger = logging.getLogger('STDOUT')
        sl = StreamToLogger(stdout_logger, logging.INFO)
        sys.stdout = sl

        stderr_logger = logging.getLogger('STDERR')
        sl = StreamToLogger(stderr_logger, logging.ERROR)
        sys.stderr = sl
    if opts.deamon:
        createDaemon()
    else:
        doTask()
    
    
