#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys,os,platform
import os.path
import json
from utils import simplecommandestr, getMacAdressList, getIPAdressList, MacAdressToIp
import pprint
import traceback
import logging
import netifaces
import re
import time
if sys.platform.startswith('win'):
    from lib.registerwindows import constantregisterwindows
    import _winreg


logger = logging.getLogger()


class sequentialevolutionquery:

    def __init__(self, objetxmpp, msglog, datasignal, data, init=False, sessionid = None, action=None):
        self.data = data
        self.datasignal = datasignal
        self.msglog = msglog
        self.objetxmpp = objetxmpp
        self.eventlist = []
        self.err = 0
        self.sessionid = self.datasignal['sessionid']
        self.action = self.datasignal['action']


        # verifie existance descriptor
        if not 'descriptor' in data:
            self.err = 100
            self.data['Dtypequery'] = "TE"
            self.data['msg']= "ERRORGRAPHSET : [pas de descriptor]"
        else:
            self.descriptor = data['descriptor']

        if self.__initevent__():
            if init == True:
                self.initialstep()
            else:
                if self.data['Devent'] in self.eventlist:
                    indexeventinlistevent = self.eventlist.index(self.data['Devent'])
                    sequencedata = self.descriptor[self.sequenceos]['sequence'][indexeventinlistevent]

                    self.__callaction__(sequencedata['action'], sequencedata, indexeventinlistevent)
                else:
                    self.msglog['data']['msg'] = "ERRORGRAPHSET deploy :%s : %s [action %s event %s is not in the list %s]"%(self.data['name'],self.sessionid, self.data['Devent'], self.data['Daction'], self.eventlist)
                    self.msglog['ret'] = 254
                    self.objetxmpp.event("loginfotomaster", self.msglog)
                    self.data['Dtypequery'] = "TE"
        else:
            self.msglog['data']['msg']="ERRORGRAPHSET deploy : %s :%s[os ne peut pas deployer ce package : ]"%(self.data['name'], self.sessionid )
            self.data['msg']= self.msglog['data']['msg']
            self.msglog['ret'] = 254
            self.objetxmpp.event("loginfotomaster", self.msglog)
            self.err = 255
            self.data['Dtypequery'] = "TE"

    def tempdir(self):
        if sys.platform.startswith('linux'):
            return os.path.join("/","tmp")
        elif sys.platform.startswith('win'):
            return os.path.join(os.environ["ProgramFiles"], "Pulse", "tmp")
        elif sys.platform.startswith('darwin'):
            return os.path.join("/","tmp")

    def replaceTEMPLATE(self, cmd):
        print "__________________________________"
        print "replaceTEMPLATE in %s"% cmd
        print "__________________________________"
        print "replaceTEMPLATE  %s"% cmd
        cmd = cmd.replace('@@@JID_MASTER@@@', self.data['jidmaster'])
        cmd = cmd.replace('@@@JID_RELAYSERVER@@@', self.data['jidrelay'])
        cmd = cmd.replace('@@@JID_MACHINE@@@', self.data['jidmachine'])

        cmd = cmd.replace('@@@IP_MACHINE@@@', self.data['ipmachine'])
        cmd = cmd.replace('@@@IP_RELAYSERVER@@@', self.data['iprelay'])
        cmd = cmd.replace('@@@IP_MASTER@@@', self.data['ipmaster'])

        cmd = cmd.replace('@@@PACKAGE_NAME@@@', self.data['name'])
        cmd = cmd.replace('@@@SESSION_ID@@@', self.sessionid)

        cmd = cmd.replace('@@@HOSTNAME@@@', platform.node())

        cmd = cmd.replace('@@@PYTHON_IMPLEMENTATION@@@', platform.python_implementation())

        cmd = cmd.replace('@@@ARCHI_MACHINE@@@',platform.machine())
        cmd = cmd.replace('@@@OS_FAMILY@@@', platform.system())

        cmd = cmd.replace('@@@OS_COMPLET_NAME@@@', platform.platform())

        cmd = cmd.replace('@@@UUID_PACKAGE@@@',self.data['srcpackageuuid'])

        cmd = cmd.replace('@@@PACKAGE_DIRECTORY_ABS_MACHINE@@@',self.data['srcdestmachine'])

        cmd = cmd.replace('@@@LIST_INTERFACE_NET@@@', " ".join(netifaces.interfaces()))

        # replace template valeur de la base de registre windows (uniquement pour windows)
        #@@@VRW@@@HKEY@@K@@Souskey@@K@@value@@@VRW@@@
        for t in re.findall("@@@VRW@@@.*?@@@VRW@@@", cmd ):
            if not sys.platform.startswith('win'):
                cmd = cmd.replace(t, "")
                logging.warning("bad descriptor : Regiter only windows")
            else:
                import _winreg
                keywindows = t.replace("@@@VRW@@@","").split("@@K@@")
                key = _winreg.OpenKey(constantregisterwindows.getkey(keywindows[0]), keywindows[1], 0, _winreg.KEY_READ)
                (valeur, typevaleur) = _winreg.QueryValueEx(key,keywindows[1]) 
                _winreg.CloseKey(key)
                cmd = cmd.replace( t , str(valeur))

        # replace template type de la valeur dans la base de registre windows
        #@@@TRW@@@HKEY@@K@@Souskey@@K@@value@@@TRW@@@
        for t in re.findall("@@@TRW@@@.*?@@@TRW@@@", cmd ):
            if not sys.platform.startswith('win'):
                cmd = cmd.replace(t, " ")
                logging.warning("bad descriptor : Regiter only windows")
            else:
                import _winreg
                keywindows = t.replace("@@@TRW@@@","").split("@@K@@")
                key = _winreg.OpenKey(constantregisterwindows.getkey(keywindows[0]), keywindows[1], 0, _winreg.KEY_READ)
                (valeur, typevaleur) = _winreg.QueryValueEx(key,keywindows[1]) 
                _winreg.CloseKey(key)
                cmd = cmd.replace( t , typevaleur)


        cmd = cmd.replace('@@@LIST_INTERFACE_NET_NO_LOOP@@@', " ".join([x for x in netifaces.interfaces() if x !='lo']))

        cmd = cmd.replace('@@@LIST_MAC_ADRESS@@@', " ".join(getMacAdressList()))

        cmd = cmd.replace('@@@LIST_IP_ADRESS@@@', " ".join(getIPAdressList()))

        cmd = cmd.replace('@@@IP_MACHINE_XMPP@@@', self.data['ipmachine'])
        cmd = cmd.replace('@@@MAC_ADRESS_MACHINE_XMPP@@@', MacAdressToIp(self.data['ipmachine']))

        cmd = cmd.replace('@@@TMP_DIR@@@', self.tempdir())
        #recherche variable environnement
        for t in re.findall("@_@.*?@_@", cmd ):
            z = t.replace("@_@","")
            cmd = cmd.replace( t, os.environ[z])
        print "__________________________________"
        print "replaceTEMPLATE ou %s"% cmd
        print "__________________________________"
        return cmd

    def __nextaction__(self, indexeventinlistevent):
        indexeventinlistevent = indexeventinlistevent+1
        if indexeventinlistevent < len(self.eventlist):
            return self.descriptor[self.sequenceos]['sequence'][indexeventinlistevent]['event']
        else:
            self.msglog['data']['msg']="GRAPHSET deploy : %s :%s [END DEPLOY]"%(self.data['name'], self.sessionid )
            self.msglog['ret'] = 0
            self.objetxmpp.event("loginfotomaster", self.msglog)
            return "ENDDEPLOY"

    def getdata(self):
        return self.data

    def geterrorcode(self):
        return self.err

    def __initevent__(self):
        if self.data['osmachine'].startswith('linux') and "linux" in self.descriptor:
            self.sequenceos = "linux"
        elif self.data['osmachine'].startswith('win') and "win" in self.descriptor:
            self.sequenceos = "win"
        elif self.data['osmachine'].startswith('dar') and "mac" in self.descriptor:
            self.sequenceos = "mac"
        else:
            self.data['Dtypequery'] = "TE"
            return False
        for step in self.descriptor[self.sequenceos]['sequence']:
            self.eventlist.append(step['event'])
        return True

    def __callaction__(self, functionname, *args, **kwargs ):
        print "**call function graphcet %s %s %s"%(functionname, args, kwargs)
        return getattr(self,functionname)( *args, **kwargs)

    def initialstep(self):
        # initialstep currentaction=None
        # cette etape assure synchro file in MAchines
        # puis lance sequence 1er action
        sequencedata = self.descriptor[self.sequenceos]['sequence'][0]
        # call function avec sequence data
        self.data['Dtypequery'] = "TQ"
        self.data['Devent'] = self.descriptor[self.sequenceos]['sequence'][0]['event']
        self.data['Daction'] = self.descriptor[self.sequenceos]['sequence'][0]['action']
        #self.__callaction__(sequencedata['action'], sequencedata, 0)

    def actiondirectorycurentpackage(self, sequencedata, indexeventinlistevent):
        self.data['Daction'] = 'actiondirectorycurentpackage'
        try:
            if self.data['Dtypequery'] == "TQ":
                self.data['Dtypequery'] = "TR"
                self.msglog['data']['msg'] = "GRAPHSET deploy : %s :%s etape %s [actiondirectorycurentpackage: %s]"%(self.data['name'],
                                                                                                                   self.sessionid,
                                                                                                                   self.data['Daction'],
                                                                                                                   self.data['path'])
                self.msglog['ret'] = 0
                self.objetxmpp.event("loginfotomaster", self.msglog)
                logging.debug("actiondirectorycurentpackage: %s %s"%(self.sessionid, self.data['path']))
                os.chdir( self.data['path'])
                print "================================================"
                print " directory current "
                print "================================================"
                print os.getcwd()
                print "================================================"
                # Check current working directory.
                logging.debug("working directory: %s"%(os.getcwd()))
                return
            else:
                # on a recu une reponse
                # traitement result si il y a
                self.data['Devent'] = self.__nextaction__(indexeventinlistevent)
                self.data['Daction'] = self.descriptor[self.sequenceos]['sequence'][indexeventinlistevent]['action']
                self.msglog['ret'] = 0
                self.msglog['data']['msg']="GRAPHSET deploy : %s : %s Transition %s -> etape %s"%(self.data['name'],
                                                                                                  self.sessionid,
                                                                                                  self.data['Devent'],
                                                                                                  self.data['Daction'])
                self.objetxmpp.event("loginfotomaster", self.msglog)
                logging.debug("actiondirectorycurentpackage TR or TE")
                if "ENDDEPLOY" == self.data['Devent']:
                    self.data['Dtypequery'] = "TED"
                else:
                    self.data['Dtypequery'] = "TQ"

        except Exception as e:
            self.msglog['ret'] = 155
            self.msglog['data']['msg']="ERRORGRAPHSET deploy : %s : %s [function actionshellscript] %s"%(self.data['name'],
                                                                                                         self.sessionid,
                                                                                                         str(e))
            self.objetxmpp.event("loginfotomaster", self.msglog)
            traceback.print_exc(file=sys.stdout)


    def actionshellscript(self, sequencedata, indexeventinlistevent):
        #path': u'/var/lib/pulse2/packages/0be145fa-973c-11e4-8dc5-0800275891ef
        self.data['Daction'] = 'actionshellscript'
        try:
            if self.data['Dtypequery'] == "TQ":
                self.data['Dtypequery'] = "TR"
                command = self.replaceTEMPLATE(sequencedata['command'])
                sequencedata['command'] = command
                self.msglog['data']['msg']="GRAPHSET deploy : %s :%s etape %s [EXEC cmd : %s]"%(self.data['name'],
                                                                                                self.sessionid,
                                                                                                self.data['Daction'],
                                                                                                command)
                self.msglog['ret'] = 0
                self.objetxmpp.event("loginfotomaster", self.msglog)
                logging.debug("actionshellscript cmd [%s] sessionid%s"%(command, self.sessionid))
                #todo si action deja faite return
                #todo ajouter un timeout
                
                a = simplecommandestr(command)
                resulsequence = {}
                result  = [x for x in a['result'].split(os.linesep) if x !='']
                resultstr = os.linesep.join(result)
                print "================================================"
                print " execution commande in thread %s "%command
                print "================================================"
                print result
                print "codeerror ", a['code']
                print "result \n",resultstr
                print "================================================"
                resulsequence = sequencedata
                for t in sequencedata:
                    if t == "codeerror":
                        resulsequence[t] = a['code']
                    elif t == "@resultcommand":
                        resulsequence[t] = resultstr
                    elif t.endswith('lastlines'):
                        nb = t.split("@")
                        nb1 = -int(nb[0])
                        print "=======lastlines============%s============================="%nb1
                        tab = result[nb1:]
                        print result
                        print nb1
                        print tab
                        print "================================================"
                        resulsequence[t] = os.linesep.join(tab)
                    elif t.endswith('firstlines'):
                        nb = t.split("@")
                        nb1 = int(nb[0])
                        print "=======firstlines============%s============================="%nb1
                        tab = result[:nb1]
                        print nb1
                        print result
                        print tab
                        print "================================================"
                        resulsequence[t] = os.linesep.join(tab)
                    else:
                        resulsequence[t] = sequencedata[t]
                sequencedata = resulsequence

                if a['code'] != 0:
                    self.msglog['data']['msg'] = "ERRORGRAPHSET deploy : %s :%s [return code : %s   result cmd %s]"%(self.data['name'],
                                                                                                                     self.sessionid,
                                                                                                                     a['code'],
                                                                                                                     resultstr)
                    self.msglog['ret'] = a['code']
                    self.objetxmpp.event("loginfotomaster", self.msglog)
                return
            else:
                # on a recu une reponse
                # traitement result si il y a
                self.data['Devent'] = self.__nextaction__(indexeventinlistevent)
                self.data['Daction'] = self.descriptor[self.sequenceos]['sequence'][indexeventinlistevent]['action']
                self.msglog['ret'] = 0
                self.msglog['data']['msg']="GRAPHSET deploy : %s : %s Transition %s -> etape %s"%(self.data['name'], 
                                                                                                  self.sessionid,
                                                                                                  self.data['Devent'],
                                                                                                  self.data['Daction'])
                self.objetxmpp.event("loginfotomaster", self.msglog)
                logging.debug("actionshellscript TR or TE")
                if "ENDDEPLOY" == self.data['Devent']:
                    self.data['Dtypequery'] = "TED"
                else:
                    self.data['Dtypequery'] = "TQ"

        except Exception as e:
            self.msglog['ret'] = 155
            self.msglog['data']['msg']="ERRORGRAPHSET deploy : %s : %s [function actionshellscript] %s"%(self.data['name'], 
                                                                                                         self.sessionid,
                                                                                                         str(e))
            self.objetxmpp.event("loginfotomaster", self.msglog)
            traceback.print_exc(file=sys.stdout)

    def actionprocessscript(self, sequencedata, indexeventinlistevent):
        self.data['Daction'] = 'actionprocessscript'
        try:
            if self.data['Dtypequery'] == "TQ":
                self.data['Dtypequery'] = "TR"
                command = self.replaceTEMPLATE(sequencedata['command'])
                sequencedata['command'] = command
                self.msglog['data']['msg'] = "GRAPHSET deploy : %s :%s etape %s [EXEC cmd : %s]"%(self.data['name'],
                                                                                                self.sessionid,
                                                                                                self.data['Daction'],
                                                                                                command)
                self.msglog['ret'] = 0
                self.objetxmpp.event("loginfotomaster", self.msglog)
                datasignal = {
                    'action': self.action,
                    'sessionid': self.sessionid,
                    'data' : {},
                    'ret' : 0,
                    'base64' : False
                }
                #on signal que le grapphcet s'arrete
                self.data['signal'] = datasignal
                # ne pas executer acquitement en sortie de action process script
                #aquitemment par fin de process
                self.data['signal']['continue'] = 'break'

                objsession = self.objetxmpp.session.sessionfromsessiondata(self.sessionid)
                # utiliser setdatasession sauve session dans fichier
                objsession.setdatasession(self.data)
                #le graphcet reprendra depuis un TEVENT de process
                try:
                    logging.debug("actionprocessscript cmd [%s] sessionid%s"%(command, self.sessionid))
                    print "mmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmm"
                    print sequencedata.keys()
                    print "mmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmmm"
                    self.objetxmpp.mannageprocess.add_processcommand( command ,
                                               self.sessionid,
                                               False,
                                               self.objetxmpp.eventmanage.create_EVENT_TR(self.objetxmpp.boundjid.bare, self.action,  self.sessionid, self.data['Devent'] ),
                                               self.objetxmpp.eventmanage.create_EVENT_ERR(self.objetxmpp.boundjid.bare, self.action, self.sessionid, self.data['Devent'] ),
                                               sequencedata['timeout'],sequencedata.keys())
                except:
                    traceback.print_exc(file=sys.stdout)
                return
            else:
                # on a recu une reponse
                # traitement result si il y a
                logging.debug("actionprocessscript TR or TE")
                self.data['Devent'] = self.__nextaction__(indexeventinlistevent)
                self.data['Daction'] = self.descriptor[self.sequenceos]['sequence'][indexeventinlistevent]['action']
                self.msglog['ret'] = 0
                self.msglog['data']['msg'] = "GRAPHSET deploy : %s : %s Transition %s -> etape %s"%(self.data['name'], 
                                                                                                    self.sessionid,
                                                                                                    self.data['Devent'],
                                                                                                    self.data['Daction'])
                self.objetxmpp.event("loginfotomaster", self.msglog)

                if "ENDDEPLOY" == self.data['Devent']:
                    self.data['Dtypequery'] = "TED"
                else:
                    self.data['Dtypequery'] = "TQ"

        except Exception as e:
            self.msglog['ret'] = 155
            self.msglog['data']['msg']="ERRORGRAPHSET deploy : %s : %s [function actionshellscript] %s"%(self.data['name'],
                                                                                                         self.sessionid,
                                                                                                         str(e))
            self.objetxmpp.event("loginfotomaster", self.msglog)
            traceback.print_exc(file=sys.stdout)


    def actionrestartmachine(self, sequencedata, indexeventinlistevent):
        self.data['Daction'] = 'actionrestartmachine'
        try:
            if self.data['Dtypequery'] == "TQ":
                self.data['Dtypequery'] = "TR"
                #sauve session
                #signal reprise apres redemarrage dans session
                self.msglog['data']['msg']="GRAPHSET deploy : %s :%s etape %s [actionrestartmachine]"%(self.data['name'],
                                                                                                       self.sessionid,
                                                                                                       self.data['Daction'])
                self.msglog['ret'] = 0
                self.objetxmpp.event("loginfotomaster", self.msglog)
                #signaler la session
                self.data['signal'] = self.datasignal
                # ne pas executer acquitement en sortie de action restart
                #aquitemment par reprise de sessions
                self.data['signal']['continue'] = 'break'
                objsession = self.objetxmpp.session.sessionfromsessiondata(self.sessionid)
                # utiliser setdatasession sauve session dans fichier
                objsession.setdatasession(self.data)
                #redémaré machine suivant OS
                logging.debug("actionrestartmachine  RESTART MACHINE")
                if sys.platform.startswith('linux'):
                    logging.debug("actionrestartmachine  shutdown machine linux")
                    os.system("shutdown -r now")
                elif sys.platform.startswith('win'):
                    logging.debug("actionrestartmachine  shutdown machine windows")
                    os.system("shutdown /r")
                elif sys.platform.startswith('darwin'):
                    logging.debug("actionrestartmachine  shutdown machine MacOS")
                    os.system("shutdown -r now")
                return
            else:
                # on a recu une reponse:
                logging.debug("actionrestartmachine TR or TE")
                self.data['Devent'] = self.__nextaction__(indexeventinlistevent)
                self.data['Daction'] = self.descriptor[self.sequenceos]['sequence'][indexeventinlistevent]['action']
                self.msglog['ret'] = 0
                self.msglog['data']['msg']="GRAPHSET deploy : %s : %s Transition %s -> etape %s"%(self.data['name'],
                                                                                                  self.sessionid,
                                                                                                  self.data['Devent'],
                                                                                                  self.data['Daction'])
                self.objetxmpp.event("loginfotomaster", self.msglog)
                if "ENDDEPLOY" == self.data['Devent']:
                    self.data['Dtypequery'] = "TED"
                else:
                    self.data['Dtypequery'] = "TQ"
                #else:
                ## on a recu une reponse
                    #self.data['Devent'] = self.__nextaction__(indexeventinlistevent)
                    #if "ENDDEPLOY" == self.data['Devent']:
                        #self.data['Dtypequery'] = "TED"
                    #else:
                        #self.data['Dtypequery'] = "TQ"
        except Exception as e:
            self.msglog['ret'] = 155
            self.msglog['data']['msg']="ERRORGRAPHSET deploy : %s : %s [function actionrestartmachine] %s"%(self.data['name'],
                                                                                                            self.sessionid,
                                                                                                            str(e))
            self.objetxmpp.event("loginfotomaster", self.msglog)
            traceback.print_exc(file=sys.stdout)


    def actionrestartbot(self, sequencedata, indexeventinlistevent):
        self.data['Daction'] = 'actionrestartmachine'
        try:
            if self.data['Dtypequery'] == "TQ":
                self.data['Dtypequery'] = "TR"
                #sauve session
                #signal reprise apres redemarrage dans session
                self.msglog['data']['msg']="GRAPHSET deploy : %s :%s etape %s [actionrestartmachine]"%(self.data['name'],
                                                                                                       self.sessionid,
                                                                                                       self.data['Daction'])
                self.msglog['ret'] = 0
                self.objetxmpp.event("loginfotomaster", self.msglog)
                self.data['signal'] = self.datasignal
                # ne pas executer acquitement en sortie de action restart
                #aquitemment par reprise de sessions
                self.data['signal']['continue'] = 'break'
                objsession = self.objetxmpp.session.sessionfromsessiondata(self.sessionid)
                # utiliser setdatasession sauve session dans fichier
                objsession.setdatasession(self.data)
                #appellse de la vrai function qui va redémaré machine suivant OS
                logging.debug("actionrestartbot  RESTART XMPPCLIENT")
                self.objetxmpp.restartBot()
                return
            else:
                # on a recu une reponse:
                logging.debug("actionrestartbot TR or TE")
                self.data['Devent'] = self.__nextaction__(indexeventinlistevent)
                self.data['Daction'] = self.descriptor[self.sequenceos]['sequence'][indexeventinlistevent]['action']
                self.msglog['ret'] = 0
                self.msglog['data']['msg']="GRAPHSET deploy : %s : %s Transition %s -> etape %s"%(self.data['name'],
                                                                                                  self.sessionid,
                                                                                                  self.data['Devent'],
                                                                                                  self.data['Daction'])
                self.objetxmpp.event("loginfotomaster", self.msglog)
                if "ENDDEPLOY" == self.data['Devent']:
                    self.data['Dtypequery'] = "TED"
                else:
                    self.data['Dtypequery'] = "TQ"
                #else:
                ## on a recu une reponse
                    #self.data['Devent'] = self.__nextaction__(indexeventinlistevent)
                    #if "ENDDEPLOY" == self.data['Devent']:
                        #self.data['Dtypequery'] = "TED"
                    #else:
                        #self.data['Dtypequery'] = "TQ"
        except Exception as e:
            self.msglog['ret'] = 155
            self.msglog['data']['msg']="ERRORGRAPHSET deploy : %s : %s [function actionrestartmachine] %s"%(self.data['name'],
                                                                                                            self.sessionid,
                                                                                                            str(e))
            self.objetxmpp.event("loginfotomaster", self.msglog)
            logging.error(self.msglog['data']['msg'])
            traceback.print_exc(file=sys.stdout)


    def actionwaiting(self, sequencedata, indexeventinlistevent):
        self.data['Daction'] = 'actionwaiting'
        try:
            if self.data['Dtypequery'] == "TQ":
                self.data['Dtypequery'] = "TR"
                self.msglog['data']['msg']="GRAPHSET deploy : %s :%s etape %s [actionwaiting]"%(self.data['name'],
                                                                                                            self.sessionid,
                                                                                                            self.data['Daction'])
                self.msglog['ret'] = 0
                self.objetxmpp.event("loginfotomaster", self.msglog)
                logging.info(self.msglog['data']['msg'])
                if "time_s" in sequencedata and (type(sequencedata['time_s']) == type(int()) or type(sequencedata['time_s']) == type(float())):
                    print "================================================"
                    print " waitting %s seconde"%sequencedata['time_s']
                    print "================================================"
                    time.sleep(sequencedata['time_s'])
                    print "====================reprise====================="
                return
            else:
                # on a recu une reponse
                self.data['Devent'] = self.__nextaction__(indexeventinlistevent)
                self.data['Daction'] = self.descriptor[self.sequenceos]['sequence'][indexeventinlistevent]['action']
                self.msglog['ret'] = 0
                self.msglog['data']['msg']="GRAPHSET deploy : %s : %s Transition %s -> etape %s"%(self.data['name'],
                                                                                                  self.sessionid,
                                                                                                  self.data['Devent'],
                                                                                                  self.data['Daction'])
                self.objetxmpp.event("loginfotomaster", self.msglog)
                if "ENDDEPLOY" == self.data['Devent']:
                    self.data['Dtypequery'] = "TED"
                else:
                    self.data['Dtypequery'] = "TQ"
        except Exception as e:
            self.msglog['ret'] = 155
            self.msglog['data']['msg']="ERRORGRAPHSET deploy : %s : %s [function actionwaiting] %s"%(self.data['name'],
                                                                                                     self.sessionid,
                                                                                                     str(e))
            self.objetxmpp.event("loginfotomaster", self.msglog)
            logging.error(self.msglog['data']['msg'])

    def actiondeploymentcomplete(self, sequencedata, indexeventinlistevent):
        """ action qui ne fait rien
                elle est utilise pour signaler la fin du deploiement"""
        self.data['Daction'] = 'actiondeploymentcomplete'
        try:
            if self.data['Dtypequery'] == "TQ":
                self.data['Dtypequery'] = "TED"
                logging.debug("actiondeploymentcomplete  signaler fin du deploiement")

            else:
                # on a recu une reponse
                logging.debug("actiondeploymentcomplete  TR ou TE")
                self.data['Devent'] = self.__nextaction__(indexeventinlistevent)
                self.data['Daction'] = self.descriptor[self.sequenceos]['sequence'][indexeventinlistevent]['action']
                self.msglog['ret'] = 0
                self.msglog['data']['msg']="GRAPHSET deploy : %s : %s Transition %s -> etape %s"%(self.data['name'],
                                                                                                  self.sessionid,
                                                                                                  self.data['Devent'],
                                                                                                  self.data['Daction'])
                self.objetxmpp.event("loginfotomaster", self.msglog)
                if "ENDDEPLOY" == self.data['Devent']:
                    self.data['Dtypequery'] = "TED"
                else:
                    self.data['Dtypequery'] = "TQ"
        except Exception as e:
            self.msglog['ret'] = 155
            self.msglog['data']['msg']="ERRORGRAPHSET deploy : %s : %s [function actiondeploymentcomplete] %s"%(self.data['name'],
                                                                                                                self.sessionid,
                                                                                                                str(e))
            self.objetxmpp.event("loginfotomaster", self.msglog)
            traceback.print_exc(file=sys.stdout)

    def actionsetwindowsregistry(self, sequencedata, indexeventinlistevent):
        self.data['Daction'] = 'actionsetwindowsregistry'
        try:
            if self.data['Dtypequery'] == "TQ":
                self.data['Dtypequery'] = "TR"
                self.msglog['data']['msg']="GRAPHSET deploy : %s :%s etape %s [actionsetwindowsregistry]"%(self.data['name'],
                                                                                                            self.sessionid,
                                                                                                            self.data['Daction'])
                self.msglog['ret'] = 0
                self.objetxmpp.event("loginfotomaster", self.msglog)
                logging.info(self.msglog['data']['msg'])
                if not sys.platform.startswith('win'):
                    logging.warning("bad descriptor : actionsetwindowsregistry only windows")
                    #ne fait encore rien
                    return
                else:
                    key = _winreg.OpenKey( constantregisterwindows.getkey(sequencedata['hkey']), sequencedata['souskey'],0, _winreg.KEY_SET_VALUE) 
                    _winreg.SetValueEx(key, sequencedata['nanedata'], 0,constantregisterwindows.getType(sequencedata['typedataregister'],sequencedata['namevalue']))
                    _winreg.CloseKey(key)
                return
            else:
                # on a recu une reponse
                self.data['Devent'] = self.__nextaction__(indexeventinlistevent)
                self.data['Daction'] = self.descriptor[self.sequenceos]['sequence'][indexeventinlistevent]['action']
                self.msglog['ret'] = 0
                self.msglog['data']['msg']="GRAPHSET deploy : %s : %s Transition %s -> etape %s"%(self.data['name'],
                                                                                                  self.sessionid,
                                                                                                  self.data['Devent'],
                                                                                                  self.data['Daction'])
                self.objetxmpp.event("loginfotomaster", self.msglog)
                if "ENDDEPLOY" == self.data['Devent']:
                    self.data['Dtypequery'] = "TED"
                else:
                    self.data['Dtypequery'] = "TQ"
        except Exception as e:
            self.msglog['ret'] = 155
            self.msglog['data']['msg']="ERRORGRAPHSET deploy : %s : %s [function actionsetwindowsregistry] %s"%(self.data['name'],
                                                                                                                 self.sessionid,
                                                                                                                 str(e))
            self.objetxmpp.event("loginfotomaster", self.msglog)
            logging.error(self.msglog['data']['msg'])


    def actionend(self):
        self.data['Daction'] = 'actionend'
        self.data['Dtypequery'] = "TED"
        pass
