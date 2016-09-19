#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys,os,platform
import os.path
import json
from utils import  simplecommandestr
import pprint
#{
   #"sub_packages": [],
    #"info": {
            #"name": "7-Zip-Win32-Multi",
            #"description": "7zip Windows 32bits package for compress/decompress files",
            #"version": "9.20",
            #"software": "7-Zip 9.20"
    #} ,
    #"win":{
        #"sequence":[
                #{ "event" : "query_eventexec", #query event remote
                    #"action" : "actionShellScript", #action remote
                    #"command" : "./7z920.exe /S && cmd.exe /C 7-Zip-extensions.bat",
                    #"parameter":{},
                    #"listevenementtransition":[
                    #"reponce_eventcommandterminer","reponce_eventerreurcommandterminer"],
                    #"coderetour":""
                    #},
                #{ "event" : "query_eventcommandterminer",#query event remote
                    #"action" : "restartmachine",
                    #"listevenementtransition":["reponse_eventpresencemachine"],
                    #"jidmachine":""
                    #},
                #{ "event" : "query_eventpresencemachine" ,#query event remote
                    #"action" : "AttenteMAchinestart",
                    #"jidmachine":"",
                    #"listevenementtransition":["terminerdeploie"]
                #},
                #{  "event" : "query_terminerdeploie" ,#query event remote
                    #"action" : "terminedeploiement"
                #}
        #]
    #}
#}

class sequentialevolutionquery:

    def __init__(self, objetxmpp, msglog, datasignal, data,init=False):
        self.data = data
        self.datasignal = datasignal
        self.msglog = msglog
        self.objetxmpp = objetxmpp
        self.eventlist=[]
        self.err = 0
        self.sessionid=self.datasignal['sessionid']

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
                #print self.eventlist , self.data['Devent']
                if self.data['Devent'] in self.eventlist:
                    indexeventinlistevent = self.eventlist.index(self.data['Devent'])
                    sequencedata = self.descriptor[self.sequenceos]['sequence'][indexeventinlistevent]
                    self.__callaction__(sequencedata['action'], sequencedata, indexeventinlistevent)
                else:
                    self.msglog['data']['msg'] = "ERRORGRAPHSET deploy :%s : %s [action %s event %s is not in the list %s]"%(self.data['name'],self.datasignal['sessionid'], self.data['Devent'], self.data['Daction'], self.eventlist)
                    self.msglog['ret'] = 254
                    self.objetxmpp.event("loginfotomaster", self.msglog)
                    self.data['Dtypequery'] = "TE"
        else:
            self.msglog['data']['msg']="ERRORGRAPHSET deploy : %s :%s[os ne peut pas deployer ce package : ]"%(self.data['name'], self.datasignal['sessionid'] )
            self.data['msg']= self.msglog['data']['msg']
            self.msglog['ret'] = 254
            self.objetxmpp.event("loginfotomaster", self.msglog)
            self.err = 255
            self.data['Dtypequery'] = "TE"

    def __nextaction__(self, indexeventinlistevent):
        indexeventinlistevent = indexeventinlistevent+1
        if indexeventinlistevent < len(self.eventlist):
            return self.descriptor[self.sequenceos]['sequence'][indexeventinlistevent]['event']
        else:
            self.msglog['data']['msg']="GRAPHSET deploy : %s :%s [END DEPLOY]"%(self.data['name'], self.datasignal['sessionid'] )
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
        #print "**call function graphcet %s %s %s"%(functionname, args, kwargs)
        return getattr(self,functionname)( *args, **kwargs)

    def initialstep(self):
        print "INITIALISE PAS 0 GRAPHSET"
        # initialstep currentaction=None
        # cette etape assure synchro file in MAchines
        # puis lance sequence 1er action
        sequencedata = self.descriptor[self.sequenceos]['sequence'][0]
        # call function avec sequence data
        self.data['Dtypequery'] = "TQ"
        self.data['Devent'] = self.descriptor[self.sequenceos]['sequence'][0]['event']
        self.data['Daction'] = self.descriptor[self.sequenceos]['sequence'][0]['action']
        #self.__callaction__(sequencedata['action'], sequencedata, 0)

    def actionshellscript(self, sequencedata, indexeventinlistevent):
        self.data['Daction'] = 'actionshellscript'
        try:
            if self.data['Dtypequery'] == "TQ":
                self.data['Dtypequery'] = "TR"
                self.msglog['data']['msg']="GRAPHSET deploy : %s :%s etape %s [EXEC cmd : %s]"%(self.data['name'], self.datasignal['sessionid'], self.data['Daction'], sequencedata['command'])
                self.msglog['ret'] = 0
                self.objetxmpp.event("loginfotomaster", self.msglog)
                a = simplecommandestr(sequencedata['command'])
                if a['code'] != 0:
                    self.msglog['data']['msg']="ERRORGRAPHSET deploy : %s :%s [return code : %s   result cmd %s]"%(self.data['name'], self.datasignal['sessionid'], a['code'],a['result'])
                    self.msglog['ret'] = a['code']
                    self.objetxmpp.event("loginfotomaster", self.msglog)
                return
            else:
                # on a recu une reponse
                # traitement result si il y a
                self.data['Devent'] = self.__nextaction__(indexeventinlistevent)
                self.data['Daction'] = self.descriptor[self.sequenceos]['sequence'][indexeventinlistevent]['action']
                self.msglog['ret'] = 0
                self.msglog['data']['msg']="GRAPHSET deploy : %s : %s Transition %s -> etape %s"%(self.data['name'], self.datasignal['sessionid'],self.data['Devent'],self.data['Daction'])
                self.objetxmpp.event("loginfotomaster", self.msglog)

                if "ENDDEPLOY" == self.data['Devent']:
                    self.data['Dtypequery'] = "TED"
                else:
                    self.data['Dtypequery'] = "TQ"

        except Exception as e:
            self.msglog['ret'] = 155
            self.msglog['data']['msg']="ERRORGRAPHSET deploy : %s : %s [function actionshellscript] %s"%(self.data['name'], self.datasignal['sessionid'],str(e))
            self.objetxmpp.event("loginfotomaster", self.msglog)

    def actionprocessscript(self, sequencedata, indexeventinlistevent):
        self.data['Daction'] = 'actionprocessscript'
        try:
            if self.data['Dtypequery'] == "TQ":
                self.data['Dtypequery'] = "TR"
                self.msglog['data']['msg']="GRAPHSET deploy : %s :%s etape %s [EXEC cmd : %s]"%(self.data['name'], self.datasignal['sessionid'], self.data['Daction'], sequencedata['command'])
                self.msglog['ret'] = 0
                self.objetxmpp.event("loginfotomaster", self.msglog)


                a = simplecommandestr(sequencedata['command'])
                if a['code'] != 0:
                    self.msglog['data']['msg']="ERRORGRAPHSET deploy : %s :%s [return code : %s   result cmd %s]"%(self.data['name'], self.datasignal['sessionid'], a['code'],a['result'])
                    self.msglog['ret'] = a['code']
                    self.objetxmpp.event("loginfotomaster", self.msglog)
                return
            else:
                # on a recu une reponse
                # traitement result si il y a
                self.data['Devent'] = self.__nextaction__(indexeventinlistevent)
                self.data['Daction'] = self.descriptor[self.sequenceos]['sequence'][indexeventinlistevent]['action']
                self.msglog['ret'] = 0
                self.msglog['data']['msg']="GRAPHSET deploy : %s : %s Transition %s -> etape %s"%(self.data['name'], self.datasignal['sessionid'],self.data['Devent'],self.data['Daction'])
                self.objetxmpp.event("loginfotomaster", self.msglog)

                if "ENDDEPLOY" == self.data['Devent']:
                    self.data['Dtypequery'] = "TED"
                else:
                    self.data['Dtypequery'] = "TQ"

        except Exception as e:
            self.msglog['ret'] = 155
            self.msglog['data']['msg']="ERRORGRAPHSET deploy : %s : %s [function actionshellscript] %s"%(self.data['name'], self.datasignal['sessionid'],str(e))
            self.objetxmpp.event("loginfotomaster", self.msglog)

    ##################################
    def actionrestartmachine(self, sequencedata, indexeventinlistevent):
        self.data['Daction'] = 'actionrestartmachine'
        try:
            if self.data['Dtypequery'] == "TQ":
                self.data['Dtypequery'] = "TR"
                #sauve session
                #signal reprise apres redemarrage dans session
                self.msglog['data']['msg']="GRAPHSET deploy : %s :%s etape %s [actionrestartmachine]"%(self.data['name'], self.datasignal['sessionid'], self.data['Daction'])
                self.msglog['ret'] = 0
                self.objetxmpp.event("loginfotomaster", self.msglog)
                self.data['signal'] = self.datasignal
                # ne pas executer acquitement en sortie de action restart
                #aquitemment par reprise de sessions
                self.data['signal']['continue']='break'
                objsession = self.objetxmpp.session.sessionfromsessiondata(self.datasignal['sessionid'])
                # utiliser setdatasession sauve session dans fichier
                objsession.setdatasession(self.data)
                #appellse de la vrai function qui va redémaré machine suivant OS
                self.objetxmpp.restartBot()
                return
            else:
                # on a recu une reponse:
                self.data['Devent'] = self.__nextaction__(indexeventinlistevent)
                self.data['Daction'] = self.descriptor[self.sequenceos]['sequence'][indexeventinlistevent]['action']
                self.msglog['ret'] = 0
                self.msglog['data']['msg']="GRAPHSET deploy : %s : %s Transition %s -> etape %s"%(self.data['name'], self.datasignal['sessionid'],self.data['Devent'],self.data['Daction'])
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
            self.msglog['data']['msg']="ERRORGRAPHSET deploy : %s : %s [function actionrestartmachine] %s"%(self.data['name'], self.datasignal['sessionid'],str(e))
            self.objetxmpp.event("loginfotomaster", self.msglog)


    def actionwaitingmachinestart(self, sequencedata, indexeventinlistevent):
        self.data['Daction'] = 'actionwaitingmachinestart'
        try:
            if self.data['Dtypequery'] == "TQ":
                self.data['Dtypequery'] = "TR"
                self.msglog['data']['msg']="GRAPHSET deploy : %s :%s etape %s [actionwaitingmachinestart]"%(self.data['name'], self.datasignal['sessionid'], self.data['Daction'])
                self.msglog['ret'] = 0
                self.objetxmpp.event("loginfotomaster", self.msglog)
                return
            else:
                # on a recu une reponse
                self.data['Devent'] = self.__nextaction__(indexeventinlistevent)
                self.data['Daction'] = self.descriptor[self.sequenceos]['sequence'][indexeventinlistevent]['action']
                self.msglog['ret'] = 0
                self.msglog['data']['msg']="GRAPHSET deploy : %s : %s Transition %s -> etape %s"%(self.data['name'], self.datasignal['sessionid'],self.data['Devent'],self.data['Daction'])
                self.objetxmpp.event("loginfotomaster", self.msglog)
                if "ENDDEPLOY" == self.data['Devent']:
                    self.data['Dtypequery'] = "TED"
                else:
                    self.data['Dtypequery'] = "TQ"
        except Exception as e:
            self.msglog['ret'] = 155
            self.msglog['data']['msg']="ERRORGRAPHSET deploy : %s : %s [function actionwaitingmachinestart] %s"%(self.data['name'], self.datasignal['sessionid'],str(e))
            self.objetxmpp.event("loginfotomaster", self.msglog)

    def actiondeploymentcomplete(self, sequencedata, indexeventinlistevent):
        self.data['Daction'] = 'actiondeploymentcomplete'
        try:
            if self.data['Dtypequery'] == "TQ":
                self.data['Dtypequery'] = "TED"
            else:
                # on a recu une reponse
                self.data['Devent'] = self.__nextaction__(indexeventinlistevent)
                self.data['Daction'] = self.descriptor[self.sequenceos]['sequence'][indexeventinlistevent]['action']
                self.msglog['ret'] = 0
                self.msglog['data']['msg']="GRAPHSET deploy : %s : %s Transition %s -> etape %s"%(self.data['name'], self.datasignal['sessionid'],self.data['Devent'],self.data['Daction'])
                self.objetxmpp.event("loginfotomaster", self.msglog)
                if "ENDDEPLOY" == self.data['Devent']:
                    self.data['Dtypequery'] = "TED"
                else:
                    self.data['Dtypequery'] = "TQ"
        except Exception as e:
            self.msglog['ret'] = 155
            self.msglog['data']['msg']="ERRORGRAPHSET deploy : %s : %s [function actiondeploymentcomplete] %s"%(self.data['name'], self.datasignal['sessionid'],str(e))
            self.objetxmpp.event("loginfotomaster", self.msglog)

    def actionend(self):
        self.data['Daction'] = 'actionend'
        self.data['Dtypequery'] = "TED"
        pass
