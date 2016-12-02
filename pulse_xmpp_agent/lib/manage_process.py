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

import sys,os,platform
import os.path
import json
from multiprocessing import Process, Queue, TimeoutError
import threading
from lib.utils import simplecommandstr
import traceback
import logging
import subprocess
from threading import Timer
#logger = logging.getLogger()

import time
class process_on_end_send_message_xmpp:

    def __init__(self, queue_out_session) :
        self.processtable = []
        self.queue_out_session = queue_out_session
        logging.info('manage process start')

    def add_processcommand(self, command ,message ,tosucces=None, toerror=None, timeout = 50):
        if tosucces is None and toerror is None:
            return
        message['data']['tosucces'] = tosucces
        message['data']['toerror']  = toerror
        createprocesscommand = Process(target=self.processcommand, args=(command ,
                                                                         self.queue_out_session,
                                                                         message,
                                                                         timeout))
        self.processtable.append(createprocesscommand)
        createprocesscommand.start()

    def processcommand( self,  command , queue_out_session, message, timeout):
        try:
            #structure message for msgout
            msgoutsucces = {
                        'eventMessageraw': message
            }
            logging.debug("================================================")
            logging.debug(" execution command in process")
            logging.debug("command : \n%s"%command)
            logging.debug("================================================")
            cmd = cmdx(command,timeout)
            msgoutsucces['eventMessageraw']['data']['codeerror'] = cmd.code_error
            msgoutsucces['eventMessageraw']['data']['result'] = cmd.stdout
            logging.debug("code error  %s"% cmd.code_error)
            logging.debug("msg succes to manager evenement: mode 'eventMessageraw'")
            queue_out_session.put(msgoutsucces)
            #logging.debug("code error  %s"% cmd.code_error)
            #logging.debug("result  %s"% cmd.stdout) 
            logging.debug("================================================")

        except TimeoutError:
            logging.error("TimeoutError process  %s sessionid : %s"%(command,message['sessionid']))
        except KeyboardInterrupt:
            logging.warn("KeyboardInterrupt process  %s sessionid : %s"%(command,message['sessionid']))
            sys.exit(0)
        except :
            traceback.print_exc(file=sys.stdout)
            logging.error("error execution process %s sessionid : %s"%(command,message['sessionid']))
            sys.exit(0)

class mannageprocess:

    def __init__(self, queue_out_session) :
        self.processtable = []
        self.queue_out_session = queue_out_session
        logging.info('manage process start')


    def add_processcommand(self, command , sessionid, eventstart = False, eventfinish = False, eventerror = False, timeout = 50, keysdescriptor = []):
        createprocesscommand = Process(target=self.processcommand, args=(command ,
                                                                         self.queue_out_session,
                                                                         sessionid,
                                                                         eventstart,
                                                                         eventfinish ,
                                                                         eventerror ,
                                                                         timeout ,
                                                                         keysdescriptor))
        self.processtable.append(createprocesscommand)
        createprocesscommand.start()

    def processcommand( self,  command , queue_out_session, sessionid, eventstart, eventfinish, eventerror, timeout, keysdescriptor):
        #il y a 2 types de messages event ceux de la boucle interne et ceux envoyé en TEVENT
        try:
            #structure message for msgout
            msgout = {
                        'event': "",
                        'sessionid': sessionid,
                        'result' : { 'codeerror' : 0, 'resultcommand' : '','command' : command },
            }
            if eventstart != False:
                #ecrit dans queue_out_session l'evenement eventstart
                if '_eventype' in eventstart and '_eventype' == 'TEVENT':
                    msgout['event'] = eventstart
                    queue_out_session.put(msgout)
                else:
                    queue_out_session.put(eventstart)
            cmd = cmdx(command,timeout)
            if cmd.code_error == 0 and eventfinish != False:
                ev = eventfinish
            elif cmd.code_error != 0 and eventfinish != False:
                ev = eventerror
            else:
                ev = False

            print "================================================"
            print " execution command in process"
            print "================================================"
            print cmd.code_error
            print cmd.stdout
            print "================================================"
            
            if ev != False:
                if '_eventype' in ev and '_eventype' == 'TEVENT':
                    #ecrit dans queue_out_session le TEVENT
                    msgout['event'] = ev
                    #msgout['result']['resultcommand'] = cmd['result']
                    msgout['result']['resultcommand'] = cmd.stdout
                    msgout['result']['codeerror'] = cmd.code_error
                    queue_out_session.put(msgout)
                else:
                    
                    #"10@firstlines" : "",
                    #"10@lastlines": "",
                    #"@resultcommand":""
                    
                    #ev['data']['result'] = {'codeerror': cmd['code'],'resultcommand' : cmd['result'],'command' : command  }
                    ev['data']['result'] = {'codeerror': cmd.code_error,'command' : command  }
                    for t in keysdescriptor:
                        if t == 'codeerror' or t=='command': 
                            pass
                        elif t == '@resultcommand' :
                            ev['data']['result']['@resultcommand'] = cmd.stdout
                        elif  t.endswith('lastlines'):
                            nb = t.split("@")
                            nb1 = -int(nb[0])
                            tab = [x for x in cmd.stdout.split(os.linesep) if x !='']
                            tab = tab[nb1:]
                            ev['data']['result'][t] = os.linesep.join(tab)
                        elif t.endswith('firstlines'):
                            nb = t.split("@")
                            nb1 = int(nb[0])
                            tab = [x for x in cmd.stdout.split(os.linesep) if x !='']
                            tab = tab[:nb1]
                            ev['data']['result'][t] = os.linesep.join(tab)
                    queue_out_session.put(ev)

            #cmd = simplecommandstr(command)

            #if cmd['code'] == 0 and eventfinish != False:
                #ev = eventfinish
            #elif cmd['code'] != 0 and eventfinish != False:
                #ev = eventerror
            #else:
                #ev = False
                
                
            #print "================================================"
            #print " execution command in process"
            #print "================================================"
            #print cmd['code']
            #print cmd['result']
            #print "================================================"
            
            #if ev != False:
                #if '_eventype' in ev and '_eventype' == 'TEVENT':
                    ##ecrit dans queue_out_session le TEVENT
                    #msgout['event'] = ev
                    #msgout['result']['resultcommand'] = cmd['result']
                    #msgout['result']['codeerror'] = cmd['code']
                    #queue_out_session.put(msgout)
                #else:
                    #ev['data']['result'] = {'codeerror': cmd['code'],'resultcommand' : cmd['result'],'command' : command  }
                    #queue_out_session.put(ev)

        except TimeoutError:
            logging.error("TimeoutError process  %s sessionid : %s"%(command,sessionid))
        except KeyboardInterrupt:
            logging.warn("KeyboardInterrupt process  %s sessionid : %s"%(command,sessionid))
            sys.exit(0)
        except :
            traceback.print_exc(file=sys.stdout)
            logging.error("error execution process %s sessionid : %s"%(command,sessionid))
            sys.exit(0)




class cmdx(object):
    def __init__(self, cmd, timeout):
        self.cmd=cmd
        self.timeout = timeout
        self.timeoutbool = False
        self.code_error = 0
        self.run()

    def kill_proc(self, proc):
        self.timeoutbool = True;
        proc.kill()

    def run(self):
        self.proc = subprocess.Popen(self.cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        #kill_proc = lambda p: p.kill()
        timer = Timer(self.timeout, self.kill_proc, [self.proc])
        try:
            timer.start()
            stdout,stderr = self.proc.communicate()
        finally:
            timer.cancel()
        #self.stderr = stderr
        self.stdout = stdout

        self.code_error = self.proc.returncode
        if self.timeoutbool:
            self.stdout = "error : timeout %s"%self.timeout
            #self.code_error = 150
#ff = cmdx ("echo 'Process started';echo; echo; sleep 2; echo 'Process finished';ls;",3)

#print "stdout",ff.stdout

#print "code_error" ,ff.code_error
