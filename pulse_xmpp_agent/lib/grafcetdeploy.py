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
import os
import json
from utils import simplecommandstr, getMacAdressList, getIPAdressList, MacAdressToIp, shellcommandtimeout
import pprint
import traceback
import logging
import netifaces
import re
import time
import zipfile


from managepackage import managepackage
if sys.platform.startswith('win'):
    from lib.registerwindows import constantregisterwindows
    import _winreg

logger = logging.getLogger()


class grafcet:

    def __init__(self, objectxmpp, datasend):
        self.datasend = datasend
        self.objectxmpp = objectxmpp
        #logging.getLogger().debug("===========Class grafcet========= %s "%self.objectxmpp.boundjid.bare)
        self.data = datasend['data']
        self.sessionid = datasend['sessionid']
        self.sequence = self.data['descriptor']['sequence']
        if not 'stepcurrent' in self.data:
            return
        try:
            self.workingstep = self.sequence[self.data['stepcurrent']]
            #logging.getLogger().debug("===========workingstep ========= %s "% json.dumps(self.workingstep, indent=4, sort_keys=True))
            self.__execstep__()
        except:
            logging.getLogger().error("END DEPLOY ON ERROR")
            # step no exist
            # end deploy
            # traitement
            self.datasend['ret'] = 255

            logging.getLogger().debug("object datasend \n%s "% json.dumps(self.datasend, indent=4, sort_keys=True))

            self.objectxmpp.send_message(    mto=self.datasend['data']['jidmaster'],
                                                    mbody=json.dumps(self.datasend),
                                                    mtype='chat')
            self.objectxmpp.session.clearnoevent(self.sessionid)

            ######
            #retourne master resultat de deploiement

    def __execstep__(self):
        # call function self.workingstep['action']
        method =  getattr(self,self.workingstep['action'])
        method()

    def __Etape_Next__(self):
        #next Step for xmpp message
        if not 'stepcurrent' in self.data:
            return
        self.data['stepcurrent'] = self.data['stepcurrent'] + 1
        self.sendnextstep()

    def sendnextstep(self):#self.objectxmpp.boundjid.bare
        #logging.getLogger().debug("===========sendnextstep ========= %s "% json.dumps(self.datasend, indent=4, sort_keys=True))
        self.objectxmpp.send_message(    mto=self.objectxmpp.boundjid.bare,
                                                    mbody=json.dumps(self.datasend),
                                                    mtype='chat')

    def __Etape_Next_in__(self):
        if not 'stepcurrent' in self.data:
            return
        self.data['stepcurrent'] = self.data['stepcurrent'] + 1
        self.workingstep = self.sequence[self.data['stepcurrent']]
        self.__execstep__()
 
    def __set_backtoworksession__(self):
        self.datasend['data']['restart']= True
        self.datasend['data']['sessionreload']=True

    def __unset_backtoworksession(self):
        self.datasend['data']['sessionreload']=False
        self.datasend['data']['restart']= False

    def __next_current_step__(self):
        self.data['stepcurrent'] = self.data['stepcurrent'] + 1

    def __action_completed__(self, datajson):
        try:
            if 'completed' in datajson:
                datajson['completed'] = datajson['completed'] + 1
            else:
                datajson['completed'] = 1
        except Exception as e:
            print str(e)
            traceback.print_exc(file=sys.stdout)

    def replaceTEMPLATE(self, cmd):
        #print "__________________________________"
        #print  "replaceTEMPLATE in %s"% cmd
        #print "__________________________________"

        cmd = cmd.replace('@@@JID_MASTER@@@', self.datasend['data']['jidmaster'])
        cmd = cmd.replace('@@@JID_RELAYSERVER@@@', self.datasend['data']['jidrelay'])
        cmd = cmd.replace('@@@JID_MACHINE@@@', self.datasend['data']['jidmachine'])

        cmd = cmd.replace('@@@IP_MACHINE@@@', self.datasend['data']['ipmachine'])
        cmd = cmd.replace('@@@IP_RELAYSERVER@@@', self.datasend['data']['iprelay'])
        cmd = cmd.replace('@@@IP_MASTER@@@', self.datasend['data']['ipmaster'])

        cmd = cmd.replace('@@@PACKAGE_NAME@@@', self.datasend['data']['name'])
        cmd = cmd.replace('@@@SESSION_ID@@@', self.datasend['sessionid'])

        cmd = cmd.replace('@@@HOSTNAME@@@', platform.node())

        cmd = cmd.replace('@@@PYTHON_IMPLEMENTATION@@@', platform.python_implementation())

        cmd = cmd.replace('@@@ARCHI_MACHINE@@@',platform.machine())
        cmd = cmd.replace('@@@OS_FAMILY@@@', platform.system())

        cmd = cmd.replace('@@@OS_COMPLET_NAME@@@', platform.platform())

        ### cmd = cmd.replace('@@@UUID_PACKAGE@@@',self.data['srcpackageuuid'])

        cmd = cmd.replace('@@@PACKAGE_DIRECTORY_ABS_MACHINE@@@', self.datasend['data']['pathpackageonmachine'])

        cmd = cmd.replace('@@@LIST_INTERFACE_NET@@@', " ".join(netifaces.interfaces()))

        # Replace windows registry value in template (only for windows)
        #@@@VRW@@@HKEY@@K@@Subkey@@K@@value@@@VRW@@@
        for t in re.findall("@@@VRW@@@.*?@@@VRW@@@", cmd ):
            if not sys.platform.startswith('win'):
                cmd = cmd.replace(t, "")
                logging.warning("bad descriptor : Registry update only works on Windows")
            else:
                import _winreg
                keywindows = t.replace("@@@VRW@@@","").split("@@K@@")
                key = _winreg.OpenKey(constantregisterwindows.getkey(keywindows[0]), keywindows[1], 0, _winreg.KEY_READ)
                (valeur, typevaleur) = _winreg.QueryValueEx(key,keywindows[1])
                _winreg.CloseKey(key)
                cmd = cmd.replace( t , str(valeur))

        # Replace windows registry value type in template (only for windows)
        #@@@TRW@@@HKEY@@K@@Subkey@@K@@value@@@TRW@@@
        for t in re.findall("@@@TRW@@@.*?@@@TRW@@@", cmd ):
            if not sys.platform.startswith('win'):
                cmd = cmd.replace(t, " ")
                logging.warning("bad descriptor : Registry update only works on Windows")
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
        ip = MacAdressToIp(self.data['ipmachine'])
        if ip is not None:
            cmd = cmd.replace('@@@MAC_ADRESS_MACHINE_XMPP@@@', ip)

        cmd = cmd.replace('@@@TMP_DIR@@@', self.tempdir())
        #recherche variable environnement
        for t in re.findall("@_@.*?@_@", cmd ):
            z = t.replace("@_@","")
            cmd = cmd.replace( t, os.environ[z])
        #print "__________________________________"
        #print "replace TEMPLATE ou %s"% cmd
        #print "__________________________________"
        return cmd

    def tempdir(self):
        if sys.platform.startswith('linux'):
            return os.path.join("/","tmp")
        elif sys.platform.startswith('win'):
            return os.path.join(os.environ["ProgramFiles"], "Pulse", "tmp")
        elif sys.platform.startswith('darwin'):
            return os.path.join("/","tmp")

    def __search_Next_step_int__( self, val ):
        valstep = 0
        if isinstance(val, int):
            for i in self.sequence:
                if int(i['step']) == val:
                    self.data['stepcurrent'] = valstep
                    self.workingstep = self.sequence[self.data['stepcurrent']]
                    return 0
                valstep=valstep+1
            logging.getLogger().error("inconsistency in descriptor")
            return 5
        elif isinstance(val, str):
            if val == 'next':
                self.data['stepcurrent'] = self.data['stepcurrent'] + 1
                self.workingstep = self.sequence[self.data['stepcurrent']]
                return 0
            elif val == 'end':
                for i in self.sequence:
                    if self.sequence['action']=='actiondeploymentcomplete':
                        self.data['stepcurrent'] = valstep
                        self.workingstep = self.sequence[self.data['stepcurrent']]
                        return 0
                    valstep = valstep+1
                    logging.getLogger().error("inconsistency in descriptor")
                return 5
            elif val == 'error':
                for i in self.sequence:
                    if self.sequence['action']=='actionerrordeployment':
                        self.data['stepcurrent'] = valstep
                        self.workingstep = self.sequence[self.data['stepcurrent']]
                        return 0
                    valstep = valstep+1
                    logging.getLogger().error("inconsistency in descriptor")
                return 5

    def terminate(self,ret, clear = True):
        try:
            self.__action_completed__(self.workingstep)
            self.objectxmpp.session.clearnoevent(self.sessionid)
            self.datasend['action'] = "result" + self.datasend['action']
            try:
                del self.datasend['data']['result']
            except :
                pass
            try:
                del self.datasend['data']['methodetransfert']
                del self.datasend['data']['path']
            except :
                pass
            try:
                del self.datasend['data']['restart']
            except KeyError:
                pass
            try:
                del self.datasend['data']['sessionreload']
            except KeyError:
                pass
            del self.datasend['data']['stepcurrent']
            del self.datasend['data']['Devent']
            del self.datasend['data']['Dtypequery']
            try:
                self.datasend['data']['environ'] = str(os.environ)
            except:
                pass
            self.datasend['ret'] = ret
            os.chdir( managepackage.packagedir())
            if clear:
                if sys.platform.startswith('win'):
                    print "supprime file"
                    print "rmdir /s /q \"%s\""%self.datasend['data']['pathpackageonmachine']
                    os.system("rmdir /s /q \"%s\""%self.datasend['data']['pathpackageonmachine'])
                else:
                    os.system("rm -Rf %s"%self.datasend['data']['pathpackageonmachine'])
            #os.system("rm -Rf %s"%self.datasend['data']['pathpackageonmachine'])
            datas = {}
            datas = self.datasend
            self.objectxmpp.send_message(   mto='log@pulse',
                                            mbody=json.dumps(self.datasend),
                                            mtype='chat')
            try:
                del datas['data']['descriptor']['sequence']
            except:
                pass
            try:
                del datas['data']['environ']
                del datas['data']['packagefile']
                del datas['data']['transfert']
            except:
                pass

            self.objectxmpp.send_message(   mto=self.datasend['data']['jidmaster'],
                                            mbody=json.dumps(datas),
                                            mtype='chat')

        except Exception as e:
            print str(e)
            traceback.print_exc(file=sys.stdout)
            self.datasend['ret'] = 255
            self.datas['ret'] = 255
            self.objectxmpp.send_message(   mto='log@pulse',
                                            mbody=json.dumps(self.datasend),
                                            mtype='chat')
            self.objectxmpp.send_message(   mto=self.datasend['data']['jidmaster'],
                                            mbody=json.dumps(datas),
                                            mtype='chat')

    def steplog(self):
        logging.getLogger().debug("deploy %s on machine %s [%s] STEP %s\n %s "% (  self.data['descriptor']['info']['name'],
                                                                                self.objectxmpp.boundjid.bare,
                                                                                self.sessionid,
                                                                                self.workingstep['step'],
                                                                                json.dumps(self.workingstep, indent=4, sort_keys=True)))
    def __terminateifcompleted__(self,workingstep):
        if 'completed' in self.workingstep:
            if self.workingstep['completed'] >=1:
                return True
        return False

    def action_pwd_package(self):
        try:
            if self.__terminateifcompleted__(self.workingstep) : return
            self.__action_completed__(self.workingstep)
            os.chdir( self.datasend['data']['pathpackageonmachine'])
            self.workingstep['pwd']= os.getcwd()
            self.objectxmpp.logtopulse('[%s]: current directory %s'%(self.workingstep['step'],self.workingstep['pwd']),
                                       type='deploy',
                                       sessionname = self.sessionid ,
                                       priority =self.workingstep['step'],
                                       who=self.objectxmpp.boundjid.bare)
            self.steplog()
            self.__Etape_Next_in__()
        except Exception as e:
            print str(e)
            traceback.print_exc(file=sys.stdout)

    def __resultinfo__(self, workingstepinfo, listresult):
        for t in workingstepinfo:
            if t == "@resultcommand":
                workingstepinfo[t] = os.linesep.join(listresult)
            elif t.endswith('lastlines'):
                nb = t.split("@")
                nb1 = -int(nb[0])
                logging.getLogger().debug( "=======lastlines============%s============================="%nb1)
                tab = listresult[nb1:]
                workingstepinfo[t] = os.linesep.join(tab)
            elif t.endswith('firstlines'):
                nb = t.split("@")
                nb1 = int(nb[0])
                logging.getLogger().debug( "=======firstlines============%s============================="%nb1)
                tab = listresult[:nb1]
                workingstepinfo[t] = os.linesep.join(tab)

    def action_unzip_file(self):
        """
        unzip file from python
        descriptor type
        {
            "step" : intnb,
            "action" : "action_unzip_file",
            "filename" : "namefile",
            "pathdirectorytounzip" : "pathdirextract",
            "@resultcommand" : ""
        }
        filename if current directory or pathfilename
        optionnel
            @resultcommand list files
            10@lastlines 10 last lines
            10@firstlines 10 first lines
            succes
            error
            goto
        """
        try:
            if self.__terminateifcompleted__(self.workingstep) : return
            self.__action_completed__(self.workingstep)
            zip_ref = zipfile.ZipFile(self.workingstep['filename'], 'r')
            zip_ref.extractall(self.workingstep['pathdirectorytounzip'])
            listname = zip_ref.namelist()
            self.__resultinfo__(self.workingstep, listname)
            zip_ref.close()

            self.objectxmpp.logtopulse('[%s]: unzip %s to directory %s'%(self.workingstep['step'],self.workingstep['filename'],self.workingstep['pathdirectorytounzip']),
                                       type='deploy',
                                       sessionname = self.sessionid ,
                                       priority =self.workingstep['step'],
                                       who=self.objectxmpp.boundjid.bare)
            if 'goto' in self.workingstep :
                self.__search_Next_step_int__(self.workingstep['goto'])
                self.__execstep__()
                return

            if 'succes' in self.workingstep:
                #goto succes
                self.__search_Next_step_int__(self.workingstep['succes'])
                self.__execstep__()
            else:
                self.__Etape_Next_in__()
                self.steplog()

        except Exception as e:
            self.workingstep['@resultcommand'] = traceback.format_exc()
            print str(e)
            #traceback.print_exc(file=sys.stdout)
            self.objectxmpp.logtopulse('[%s]: error unzip %s to directory %s : %s'%(self.workingstep['step'],
                                                                                    self.workingstep['filename'],
                                                                                    self.workingstep['pathdirectorytounzip']),
                                       type='deploy',
                                       sessionname = self.sessionid ,
                                       priority =self.workingstep['step'],
                                       who=self.objectxmpp.boundjid.bare)
            if 'error' in self.workingstep:
                self.__search_Next_step_int__(self.workingstep['error'])
                self.__execstep__()
            else:
                self.__Etape_Next_in__()
                self.steplog()

    def actionprocessscript(self):
        try:
            if self.__terminateifcompleted__(self.workingstep) : return
            self.workingstep['command'] = self.replaceTEMPLATE(self.workingstep['command'])
            if not  "timeout" in self.workingstep:
                self.workingstep['timeout'] = 15
                logging.getLogger().warn( "timeout missing : default value 15s")
            # working Step recup from process et session
            comdbool = self.objectxmpp.process_on_end_send_message_xmpp.add_processcommand( self.workingstep['command'] ,
                                                                                self.datasend,
                                                                                self.objectxmpp.boundjid.bare, 
                                                                                self.objectxmpp.boundjid.bare,
                                                                                self.workingstep['timeout'],
                                                                                self.workingstep['step'])
            if not comdbool:
                self.objectxmpp.logtopulse('[%s]: Descriptor error '%(self.workingstep['step']),
                                       type='deploy',
                                       sessionname = self.sessionid ,
                                       priority =self.workingstep['step'],
                                       who=self.objectxmpp.boundjid.bare)
        except Exception as e:
            self.steplog()
            print str(e)
            traceback.print_exc(file=sys.stdout)


    def action_command_natif_shell(self):
        """ information
        "@resultcommand or nb@lastlines or nb@firstlines": "", 
        "action": "action_command_natif_shell", 
        "codereturn": "", 
        "command": "ls", 
        "error": "END", 
        "step": "1", 
        "succes": 3
        timeout
        """

        try:
            if self.__terminateifcompleted__(self.workingstep) : return
            self.workingstep['command'] = self.replaceTEMPLATE(self.workingstep['command'])

            ##########self.objectxmpp.logtopulse("action_command_natif_shell")
            #todo si action deja faite return
            if not  "timeout" in self.workingstep:
                self.workingstep['timeout'] = 15
                logging.getLogger().warn( "timeout missing : default value 15s")
            re = shellcommandtimeout(self.workingstep['command'],self.workingstep['timeout']).run()
            self.__action_completed__(self.workingstep)
            self.workingstep['codereturn'] = re['codereturn']
            result  = [x.strip('\n') for x in re['result'] if x !='']
            #result  = [x for x in a['result'].split(os.linesep) if x !='']
            #logging.getLogger().debug("================================================")
            #logging.getLogger().debug( " execution command in thread %s "%self.workingstep['command'])
            #logging.getLogger().debug( "================================================")
            #logging.getLogger().debug( "codeerror %s"% self.workingstep['codereturn'])
            #logging.getLogger().debug( "result \n%s"%os.linesep.join(result))
            #logging.getLogger().debug( "================================================")
            for t in self.workingstep:
                if t == "@resultcommand":
                    self.workingstep[t] = os.linesep.join(result)
                elif t.endswith('lastlines'):
                    nb = t.split("@")
                    nb1 = -int(nb[0])
                    logging.getLogger().debug( "=======lastlines============%s============================="%nb1)
                    tab = result[nb1:]
                    self.workingstep[t] = os.linesep.join(tab)
                elif t.endswith('firstlines'):
                    nb = t.split("@")
                    nb1 = int(nb[0])
                    logging.getLogger().debug( "=======firstlines============%s============================="%nb1)
                    tab = result[:nb1]
                    self.workingstep[t] = os.linesep.join(tab)
            self.objectxmpp.logtopulse('[%s]: errorcode %s for command : %s '%(self.workingstep['step'],self.workingstep['codereturn'],self.workingstep['command']),
                                       type='deploy',
                                       sessionname = self.sessionid ,
                                       priority =self.workingstep['step'],
                                       who = self.objectxmpp.boundjid.bare)
            self.steplog()
            if 'succes' in self.workingstep and  self.workingstep['codereturn'] == 0:
                #goto succes
                self.__search_Next_step_int__(self.workingstep['succes'])
                self.__execstep__()
            elif 'error' in self.workingstep and  self.workingstep['codereturn'] != 0:
                self.__search_Next_step_int__(self.workingstep['error'])
                self.__execstep__()
            else:
                self.__Etape_Next_in__()
        except Exception as e:
            print str(e)
            traceback.print_exc(file=sys.stdout)

    def actionsuccescompletedend(self):
        """
        descriptor type
        {
            "step" : 11,
            "action" : "actionsuccescompletedend",
            "clear" : True
        }
        clear optionnel option
        if clear is not defini then clear = True
        """
        clear = True
        if 'clear' in self.workingstep:
            if isinstance(self.workingstep['clear'], bool):
                clear = self.workingstep['clear']
        self.objectxmpp.logtopulse('[%s]: Terminate deploy SUCCESS'%(self.workingstep['step']),
                                       type='deploy',
                                       sessionname = self.sessionid ,
                                       priority =self.workingstep['step'],
                                       who=self.objectxmpp.boundjid.bare)
        if self.__terminateifcompleted__(self.workingstep) : return
        self.terminate(0, clear)
        self.steplog()

    def actionerrorcompletedend(self):
        """
        descriptor type
        {
            "step" : 11,
            "action" : "actionerrorcompletedend",
            "clear" : True
        }
        clear optionnel option
        if clear is not defini then clear = True
        """
        clear = True
        if 'clear' in self.workingstep and isinstance(self.workingstep['clear'], bool):
            clear = self.workingstep['clear']
        self.objectxmpp.logtopulse('[%s]: Terminate deploy ERROR'%(self.workingstep['step']),
                                       type='deploy',
                                       sessionname = self.sessionid ,
                                       priority =self.workingstep['step'],
                                       who=self.objectxmpp.boundjid.bare)
        if self.__terminateifcompleted__(self.workingstep) : return
        self.terminate(-1, clear)
        self.steplog()

    def actionconfirm(self):
        """
        descriptor type
        {
            "step" : 7,
            "action": "actionconfirm",
            "title" : "titre de la fenetre",
            "query" : "Question demandé",
            "boutontype" :[yes | no | Open | Save | Cancel | Close | Discard | Apply | Reset|  RestoreDefaults |Abort | Retry | Ignore ]
            "icon" :  ["noIcon" |  question | information | warning | critical }
            "goto" : numStep
            "gotoyes" : numStep
            "gotono" :numStep
            "gotoopen": numStep
            "gotosave" :numStep
            "gotocancel" : numStep
            "gotoclose" :numStep
            "gotodiscard" : numStep
            "gotoapply" :numStep
            "gotoreset" :numStep
            "gotorestoreDefaults" :numStep
            "gotoabort":numStep
            "gotoretry":numStep
            "gotoIgnore": numStep
        gotoxxx assure le branchement a l'etape precisé
        # goto est 1 branchement prioritaire non conditionel quelque soit le choix de la doalog box il y a branchement.
        # gotoxxx suivant le choix des boutons, xxx le bouton choix
        #list des boutons possibles

        # bouton yes -> branchement etape pointer par gotoyes
        # bouton no -> branchement etape pointer par gotono

        """

        #composition command
        if not 'title' in self.workingstep:
            self.workingstep['title']="Confirmation"
        if not 'icon' in self.workingstep:
            self.workingstep['icon']="information"
        if not 'query' in self.workingstep:
            self.workingstep['query']="Yes or No"
        if not 'boutontype' in self.workingstep:
            self.workingstep['boutontype']=['yes','no']


        if sys.platform.startswith('linux'):
            logging.debug("machine linux")
            try:
                os.environ['DISPLAY']
                logging.debug("linux avec serveur X  %s"%os.environ['DISPLAY'])
                logging.debug("############################################")
                logging.debug("linux avec serveur X")
                linux_executable_dlg_confirm = "dlg_comfirm_pulse"
                command = linux_executable_dlg_confirm + \
                                            " -T " + self.workingstep['title'] + \
                                            " -I " + self.workingstep['icon']+ \
                                            " -Q " + self.workingstep['query'] + \
                                            " -B " + ",".join(self.workingstep['boutontype'])
                logging.debug("################LINUX  command ############################ %s"%command)
            except KeyError:
                logging.debug("linux pas de serveur X")
                os.system("echo \"" + self.workingstep['title'] + "\n" + self.workingstep['query'] + "\n\" | wall" )

                self.__Etape_Next_in__()
                return

        elif sys.platform.startswith('win'):
            logging.debug("command on windows")
            win_executable_dlg_confirm = "dlg_comfirm_pulse"
            command = win_executable_dlg_confirm + \
                                        " -T " + self.workingstep['title'] + \
                                        " -I " + self.workingstep['icon']+ \
                                        " -Q " + self.workingstep['query'] + \
                                        " -B " + ",".join(self.workingstep['boutontype'])
        elif sys.platform.startswith('darwin'):
            logging.debug("command on windows")
            Macos_executable_dlg_confirm = "dlg_comfirm_pulse"
            command = Macos_executable_dlg_confirm + \
                                        " -T " + self.workingstep['title'] + \
                                        " -I " + self.workingstep['icon']+ \
                                        " -Q " + self.workingstep['query'] + \
                                        " -B " + ",".join(self.workingstep['boutontype'])
        #todo si action deja faite return
       
        # appelle boite de dialog 
        

        re = shellcommandtimeout(command, 60).run()
        self.steplog()
        result  = [x.strip('\n') for x in re['result'] if x !='']
        logging.getLogger().debug( "result action actionconfirm:")
        self.objectxmpp.logtopulse('[%s]: Dialog : Reponse %s'%(self.workingstep['step'],result[-1]),
                                       type='deploy',
                                       sessionname = self.sessionid ,
                                       priority =self.workingstep['step'],
                                       who=self.objectxmpp.boundjid.bare)

        if 'goto' in self.workingstep :
            self.__search_Next_step_int__(self.workingstep['goto'])
            self.__execstep__()
        elif 'gotoyes' in self.workingstep and result[0] == "yes":
            #goto Faire directement reboot
            self.__search_Next_step_int__(self.workingstep['gotoyes'])
            self.__execstep__()
        elif 'gotono' in self.workingstep and result[0] == "no":
            #goto attendre pour Faire reboot
            self.__search_Next_step_int__(self.workingstep['gotono'])
            self.__execstep__()
        elif 'gotoopen' in self.workingstep and result[0] == "open":
            #goto attendre pour Faire reboot
            self.__search_Next_step_int__(self.workingstep['gotoopen'])
            self.__execstep__()
        elif 'gotosave' in self.workingstep and result[0] == "save":
            #goto attendre pour Faire reboot
            self.__search_Next_step_int__(self.workingstep['gotosave'])
            self.__execstep__()
        elif 'gotocancel' in self.workingstep and result[0] == "cancel":
            #goto attendre pour Faire reboot
            self.__search_Next_step_int__(self.workingstep['gotocancel'])
            self.__execstep__()
        elif 'gotoclose' in self.workingstep and result[0] == "close":
            #goto attendre pour Faire reboot
            self.__search_Next_step_int__(self.workingstep['gotoclose'])
            self.__execstep__()
        elif 'gotodiscard' in self.workingstep and result[0] == "discard":
            #goto attendre pour Faire reboot
            self.__search_Next_step_int__(self.workingstep['gotodiscard'])
            self.__execstep__()
        elif 'gotoapply' in self.workingstep and result[0] == "apply":
            #goto attendre pour Faire reboot
            self.__search_Next_step_int__(self.workingstep['gotoapply'])
            self.__execstep__()
        elif 'gotoreset' in self.workingstep and result[0] == "reset":
            #goto attendre pour Faire reboot
            self.__search_Next_step_int__(self.workingstep['gotoreset'])
            self.__execstep__()
        elif 'gotorestoreDefaults' in self.workingstep and result[0] == "restoreDefaults":
            #goto attendre pour Faire reboot
            self.__search_Next_step_int__(self.workingstep['gotorestoreDefaults'])
            self.__execstep__()
        elif 'gotoabort' in self.workingstep and result[0] == "abort":
            #goto attendre pour Faire reboot
            self.__search_Next_step_int__(self.workingstep['gotoabort'])
            self.__execstep__()
        elif 'gotoretry' in self.workingstep and result[0] == "retry":
            #goto attendre pour Faire reboot
            self.__search_Next_step_int__(self.workingstep['gotoretry'])
            self.__execstep__()
        elif 'gotoignore' in self.workingstep and result[0] == "ignore":
            #goto attendre pour Faire reboot
            self.__search_Next_step_int__(self.workingstep['gotoignore'])
            self.__execstep__()
        elif re['codereturn'] != 0 and 'error' in self.workingstep:
            self.__search_Next_step_int__(self.workingstep['error'])
            self.__execstep__()
        elif re['codereturn'] == 0 and 'succes' in self.workingstep:
            self.__search_Next_step_int__(self.workingstep['succes'])
            self.__execstep__()
        else:
            self.__Etape_Next_in__()
            return
        #self.objectxmpp.logtopulse('[%s]: Dialog : Reponse %s'%(self.workingstep['step'],result[0]),
                                       #type='deploy',
                                       #sessionname = self.sessionid ,
                                       #priority =self.workingstep['step'] )

    def actionwaitandgoto(self):
        """
        descriptor type
         {
                       "step" : 8,
                       "action": "actionwaitandgoto",
                       "waiting" : 60,
                       "goto" : 7
        }

        """
        #todo si action deja faite return
        self.steplog() 
        if not  "waiting" in self.workingstep:
            self.workingstep['waiting'] = 180
            logging.getLogger().warn( "waiting missing : default value 180s")
        timewaiting = int(self.workingstep['waiting']) + 60
        logging.getLogger().warn( "timeout  waiting : %s"%timewaiting)
        self.objectxmpp.logtopulse('[%s]: Waitting %s s for continue'%(self.workingstep['step'],timewaiting),
                                       type='deploy',
                                       sessionname = self.sessionid ,
                                       priority =self.workingstep['step'],
                                       who=self.objectxmpp.boundjid.bare)
        comdbool = self.objectxmpp.process_on_end_send_message_xmpp.add_processcommand( "sleep "+ str(self.workingstep['waiting']) ,
                                                                            self.datasend,
                                                                            self.objectxmpp.boundjid.bare, 
                                                                            self.objectxmpp.boundjid.bare,
                                                                            timewaiting,
                                                                            self.workingstep['step'])
        if not comdbool:
            self.objectxmpp.logtopulse('[%s]: Error descriptoractionwaitandgoto '%(self.workingstep['step']),
                                       type='deploy',
                                       sessionname = self.sessionid ,
                                       priority =self.workingstep['step'],
                                       who=self.objectxmpp.boundjid.bare)

    def actionrestart(self):
        """
        descriptor type :
        {
            "step" : 9,
            "action": "actionrestart"
        }
        """ 
        try:
            if self.__terminateifcompleted__(self.workingstep) : return
            self.__next_current_step__() #prepare action suivante
            self.__set_backtoworksession__()#session reprise after restart start
            #rewrite session 
            objsession =   self.objectxmpp.session.sessionfromsessiondata(self.sessionid)
            objsession.setdatasession(self.datasend)
            # Restart machine based on OS
            self.__action_completed__(self.workingstep)
            self.steplog()
            self.objectxmpp.logtopulse('[%s]: Restart machine'%(self.workingstep['step']),
                                       type='deploy',
                                       sessionname = self.sessionid ,
                                       priority =self.workingstep['step'] ,
                                       who=self.objectxmpp.boundjid.bare)
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
            #os.system("pkill -f agentxmpp")
        except Exception as e:
            print str(e)
            traceback.print_exc(file=sys.stdout)


    def actionrestartbot(self):
        """
        descriptor type :
        {
            "step" : 9,
            "action": "actionrestartbot"
        }
        """ 
        try:
            if self.__terminateifcompleted__(self.workingstep) : return
            self.__action_completed__(self.workingstep)
            self.__next_current_step__() #prepare action suivante
            self.__set_backtoworksession__()#session reprise after restart start
            #rewrite session 
            objsession =   self.objectxmpp.session.sessionfromsessiondata(self.sessionid)
            objsession.setdatasession(self.datasend)
            self.steplog()
            self.objectxmpp.logtopulse('[%s]: Restart agent machine'%(self.workingstep['step']),
                                       type='deploy',
                                       sessionname = self.sessionid ,
                                       priority =self.workingstep['step'],
                                       who=self.objectxmpp.boundjid.bare)
            self.objectxmpp.restartBot()
        except Exception as e:
            print str(e)
            traceback.print_exc(file=sys.stdout)

    def actioncleaning(self):
        ##logtopulse(self,text,type='noset',sessionname = '',priority = 0, who = '')
        self.objectxmpp.logtopulse('actiondeploymentcomplete', type='deploy', sessionname = self.sessionid,who=self.objectxmpp.boundjid.bare)
        try:
            if self.__terminateifcompleted__(self.workingstep) : return
            self.__action_completed__(self.workingstep)
            #logging.getLogger().debug("rm -Rf %s"%self.datasend['data']['pathpackageonmachine'])
            if  managepackage.packagedir() in self.datasend['data']['pathpackageonmachine']:
                os.chdir( managepackage.packagedir())
                if sys.platform.startswith('win'):
                    print "supprime file %s "
                    print "rmdir /s /q \"%s\""%self.datasend['data']['pathpackageonmachine']
                    os.system("rmdir /s /q \"%s\""%self.datasend['data']['pathpackageonmachine'])
                else:
                    os.system("rm -Rf %s"%self.datasend['data']['pathpackageonmachine'])
            #os.system("rm -Rf %s"%self.datasend['data']['pathpackageonmachine'])
                self.objectxmpp.logtopulse('[%s]: clear file package on machine'%(self.workingstep['step']),
                                       type='deploy',
                                       sessionname = self.sessionid ,
                                       priority =self.workingstep['step'],
                                       who=self.objectxmpp.boundjid.bare)
            self.steplog()
            self.__Etape_Next_in__()
        except Exception as e:
            print str(e)
            traceback.print_exc(file=sys.stdout)

  #WIP
    def linuxinstallfrommanagerpackages(self):
        if os.path.isfile("/etc/mageia-release"):
            return 'urpmi --auto'
        if os.path.isfile("/etc/redhat-release"):
            return 'yum'
        elif os.path.isfile("/etc/arch-release"):
            return 'pacman'
        elif os.path.isfile("/etc/gentoo-release"):
            return 'emerge'
        elif os.path.isfile("/etc/SuSE-release"):
            return 'zypp'
        elif os.path.isfile("/etc/debian_version"):
            return 'apt-get -q -y install '
        else:
            return ""
