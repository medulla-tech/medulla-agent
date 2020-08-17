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
# file : pulse_xmpp_agent/lib/grafcetdeploy.py

import sys
import os
import platform
import os.path
import json
from utils import getMacAdressList, getIPAdressList, shellcommandtimeout, shutdown_command, reboot_command, isBase64, downloadfile
from configuration import setconfigfile
import traceback
import logging
import netifaces
import re
from managepackage import managepackage
from tempfile import mkstemp
import zipfile
import base64
import time
import copy
from agentconffile import pulseTempDir

if sys.platform.startswith('win'):
    from lib.registerwindows import constantregisterwindows

logger = logging.getLogger()


class grafcet:

    def __init__(self, objectxmpp, datasend):
        # verify exist directory packagedir
        if not os.path.isdir(managepackage.packagedir()):
            os.makedirs(managepackage.packagedir())
        self.datasend = datasend
        self.parameterdynamic = {}
        self.descriptorsection = {'action_section_install': -1}
        self.objectxmpp = objectxmpp
        self.data = datasend['data']
        if 'advanced' in self.data and "paramdeploy" in self.data['advanced'] and isinstance(self.data['advanced']['paramdeploy'], dict):
            # there are  dynamic parameters.
            for k, v in self.data['advanced']['paramdeploy'].items():
                self.parameterdynamic[k] = v

        self.sessionid = datasend['sessionid']
        self.sequence = self.data['descriptor']['sequence']

        if 'stepcurrent' not in self.data:
            return
        try:
            # search section in sequence
            self.find_step_type()
            # attribute step curent in function section
            if int(self.data['stepcurrent']) == 0:
                mesg_install = ""
                if "section" not in self.parameterdynamic:
                    self.parameterdynamic['section'] = "install"
                if "section" in self.parameterdynamic:
                    strsection = str(self.parameterdynamic['section']).lower()
                    if strsection == "install":
                        # attribute section "install" if exists
                        mesg_install = "Starting Install section"
                        if self.descriptorsection['action_section_install'] != -1:
                            self.__action_completed__(self.sequence[self.descriptorsection['action_section_install']])  # stage status marked as complete
                            self.data['stepcurrent'] = self.descriptorsection['action_section_install'] + 1
                    elif strsection == "update":
                        # attribute section "update" if exists
                        mesg_install = "Starting Update section"
                        if "action_section_update" in self.descriptorsection:
                            self.__action_completed__(self.sequence[self.descriptorsection['action_section_update']])
                            self.data['stepcurrent'] = self.descriptorsection['action_section_update'] + 1
                    elif strsection == "uninstall":
                        # Attribute section "uninstall" if exists
                        mesg_install = "Starting Uninstall section"
                        if "action_section_uninstall" in self.descriptorsection:
                            self.__action_completed__(self.sequence[self.descriptorsection['action_section_uninstall']])
                            self.data['stepcurrent'] = self.descriptorsection['action_section_uninstall'] + 1
                    self.objectxmpp.xmpplog('[%s]-[%s]: %s' % (self.data['name'], self.data['stepcurrent'], mesg_install),
                                            type='deploy',
                                            sessionname=self.sessionid,
                                            priority=self.data['stepcurrent'],
                                            action="xmpplog",
                                            who=self.objectxmpp.boundjid.bare,
                                            how="",
                                            why=self.data['name'],
                                            module="Deployment | Execution",
                                            date=None,
                                            fromuser=self.data['login'],
                                            touser="")
            self.workingstep = self.sequence[self.data['stepcurrent']]
            self.__execstep__()  # call action workingstep
        except BaseException as e:
            logging.getLogger().error("END DEPLOY ON ERROR INITIALISATION")
            self.datasend['ret'] = 255

            logging.getLogger().debug("object datasend \n%s " % json.dumps(self.datasend,
                                                                           indent=4,
                                                                           sort_keys=True))
            if 'jidmaster' in self.datasend['data']:
                # retourne resultat error to master for end session on master.
                self.objectxmpp.send_message(mto=self.datasend['data']['jidmaster'],
                                             mbody=json.dumps(self.datasend),
                                             mtype='chat')
            self.objectxmpp.session.clearnoevent(self.sessionid)

            self.objectxmpp.xmpplog('<span class="log_err">Error initializing grafcet</span>',
                                    type='deploy',
                                    sessionname=self.sessionid,
                                    priority=-1,
                                    action="xmpplog",
                                    who=self.objectxmpp.boundjid.bare,
                                    how="",
                                    why=self.data['name'],
                                    module="Deployment | Error | Execution",
                                    date=None,
                                    fromuser="",
                                    touser="")
            self.objectxmpp.xmpplog('<span class="log_err">' + str(e) + '</span>',
                                    type='deploy',
                                    sessionname=self.sessionid,
                                    priority=-1,
                                    action="xmpplog",
                                    who=self.objectxmpp.boundjid.bare,
                                    how="",
                                    why=self.data['name'],
                                    module="Deployment | Error | Execution",
                                    date=None,
                                    fromuser=self.data['login'],
                                    touser="")
            self.terminate(-1, True, "end error initialisation deploy")

    def find_step_type(self):
        for stepseq in self.sequence:
            if 'action' in stepseq:
                if stepseq['action'] == "action_section_install":
                    self.descriptorsection['action_section_install'] = stepseq['step']
                elif stepseq['action'] == "action_section_uninstall":
                    self.descriptorsection['action_section_uninstall'] = stepseq['step']
                elif stepseq['action'] == "action_section_update":
                    self.descriptorsection['action_section_update'] = stepseq['step']
                elif stepseq['action'] == "action_section_launch":
                    self.descriptorsection['action_section_launch'] = stepseq['step']
                elif stepseq['action'] == "actionsuccescompletedend":
                    self.descriptorsection['actionsuccescompletedend'] = stepseq['step']

    def __execstep__(self):
        # call function self.workingstep['action']
        # execute step current
        method = getattr(self, self.workingstep['action'])
        method()

    def __Next_Step__(self):
        # next Step for xmpp message
        if 'stepcurrent' not in self.data:
            return
        self.data['stepcurrent'] = self.data['stepcurrent'] + 1
        self.sendnextstep()

    def sendnextstep(self):  # self.objectxmpp.boundjid.bare
        self.objectxmpp.send_message(mto=self.objectxmpp.boundjid.bare,
                                     mbody=json.dumps(self.datasend),
                                     mtype='chat')

    def __Etape_Next_in__(self):
        if 'stepcurrent' not in self.data:
            return
        self.data['stepcurrent'] = self.data['stepcurrent'] + 1
        self.workingstep = self.sequence[self.data['stepcurrent']]
        self.__execstep__()

    def __set_backtoworksession__(self):
        # tag les signaux "restart" and "reload" dans le descripteur de session
        self.datasend['data']['restart'] = True
        self.datasend['data']['sessionreload'] = True

    def __unset_backtoworksession(self):
        # Removes the "restart" and "reload" signals in the session descriptor
        # next running if session existe then session clearing
        self.datasend['data']['sessionreload'] = False
        self.datasend['data']['restart'] = False

    def __next_current_step__(self):
        # pointer to the next step
        self.data['stepcurrent'] = self.data['stepcurrent'] + 1

    def __action_completed__(self, datajson):
        """
        update compteur step used
        """
        try:
            if 'completed' in datajson:
                datajson['completed'] = datajson['completed'] + 1
            else:
                datajson['completed'] = 1
        except Exception as e:
            logging.getLogger().error(str(e))
            logger.error("\n%s" % (traceback.format_exc()))

    def replaceTEMPLATE(self, cmd):
        # print "__________________________________"
        # print  "replaceTEMPLATE in %s"% cmd
        # print "__________________________________"

        # remplace all dynamic parameters by values.
        # eg :  @@@DYNAMIC_PARAM@@@section@@@ is dynamique parameter "section"
        # Si le parameter dynamic section exist, it is replace by value.
        # for def a paramater dynamic. "Dynamic parameters Packages" Single advanced launch.
        # eg  In Single advanced launch:     "section" : "install", "otherparameter" : "data"
        #
        if "@@@DYNAMIC_PARAM@@@" in cmd:
            listname = re.findall(r"@@@DYNAMIC_PARAM@@@(.*?)@@@", cmd)
            for nameparameter in listname:
                if nameparameter in self.parameterdynamic:
                    cmd = cmd.replace('@@@DYNAMIC_PARAM@@@%s@@@' % nameparameter,
                                      self.parameterdynamic[nameparameter])
        if 'oldresult' in self.datasend['data']:
            cmd = cmd.replace('@@@PREC_RESULT@@@',
                              self.datasend['data']['oldresult'])
        if 'oldreturncode' in self.datasend['data']:
            cmd = cmd.replace('@@@PREC_RETURNCODE@@@',
                              self.datasend['data']['oldreturncode'])
        cmd = cmd.replace('@@@JID_MASTER@@@',
                          self.datasend['data']['jidmaster'])
        cmd = cmd.replace('@@@JID_RELAYSERVER@@@',
                          self.datasend['data']['jidrelay'])
        cmd = cmd.replace('@@@JID_MACHINE@@@',
                          self.datasend['data']['jidmachine'])
        cmd = cmd.replace('@@@IP_MACHINE@@@',
                          self.datasend['data']['ipmachine'])
        cmd = cmd.replace('@@@IP_RELAYSERVER@@@',
                          self.datasend['data']['iprelay'])
        cmd = cmd.replace('@@@IP_MASTER@@@',
                          self.datasend['data']['ipmaster'])
        cmd = cmd.replace('@@@PACKAGE_NAME@@@',
                          self.datasend['data']['name'])
        cmd = cmd.replace('@@@SESSION_ID@@@',
                          self.datasend['sessionid'])
        cmd = cmd.replace('@@@HOSTNAME@@@',
                          platform.node())

        cmd = cmd.replace('@@@PYTHON_IMPLEMENTATION@@@',
                          platform.python_implementation())

        cmd = cmd.replace('@@@ARCHI_MACHINE@@@', platform.machine())
        cmd = cmd.replace('@@@OS_FAMILY@@@', platform.system())

        cmd = cmd.replace('@@@OS_COMPLET_NAME@@@', platform.platform())

        cmd = cmd.replace('@@@UUID_PACKAGE@@@',
                          os.path.basename(self.datasend['data']['pathpackageonmachine']))

        cmd = cmd.replace('@@@PACKAGE_DIRECTORY_ABS_MACHINE@@@',
                          self.datasend['data']['pathpackageonmachine'])

        cmd = cmd.replace('@@@LIST_INTERFACE_NET@@@',
                          " ".join(netifaces.interfaces()))

        # Replace windows registry value in template (only for windows)
        # @@@VRW@@@HKEY@@K@@Subkey@@K@@value@@@VRW@@@
        for t in re.findall("@@@VRW@@@.*?@@@VRW@@@", cmd):
            if not sys.platform.startswith('win'):
                cmd = cmd.replace(t, "")
                logging.warning("bad descriptor : Registry update only works on Windows")
            else:
                import _winreg
                keywindows = t.replace("@@@VRW@@@", "").split("@@K@@")
                key = _winreg.OpenKey(constantregisterwindows.getkey(keywindows[0]),
                                      keywindows[1], 0, _winreg.KEY_READ)
                (valeur, typevaleur) = _winreg.QueryValueEx(key, keywindows[1])
                _winreg.CloseKey(key)
                cmd = cmd.replace(t, str(valeur))

        # Replace windows registry value type in template (only for windows)
        # @@@TRW@@@HKEY@@K@@Subkey@@K@@value@@@TRW@@@
        for t in re.findall("@@@TRW@@@.*?@@@TRW@@@", cmd):
            if not sys.platform.startswith('win'):
                cmd = cmd.replace(t, " ")
                logging.warning("bad descriptor : Registry update only works on Windows")
            else:
                import _winreg
                keywindows = t.replace("@@@TRW@@@", "").split("@@K@@")
                key = _winreg.OpenKey(constantregisterwindows.getkey(keywindows[0]),
                                      keywindows[1], 0, _winreg.KEY_READ)
                (valeur, typevaleur) = _winreg.QueryValueEx(key, keywindows[1])
                _winreg.CloseKey(key)
                cmd = cmd.replace(t, typevaleur)

        cmd = cmd.replace('@@@LIST_INTERFACE_NET_NO_LOOP@@@', " ".join(
            [x for x in netifaces.interfaces() if x != 'lo']))

        cmd = cmd.replace('@@@LIST_MAC_ADRESS@@@',
                          " ".join(getMacAdressList()))

        cmd = cmd.replace('@@@LIST_IP_ADRESS@@@', " ".join(getIPAdressList()))

        cmd = cmd.replace('@@@IP_MACHINE_XMPP@@@', self.data['ipmachine'])

        # Quick fix for blacklisted mac addresses
        # TODO: A proper fix to blacklisted mac addresses will allow uncommenting
        # the below block
        # cmd = cmd.replace(
        #     '@@@MAC_ADRESS_MACHINE_XMPP@@@',
        #     MacAdressToIp(
        #         self.data['ipmachine']))

        cmd = cmd.replace('@@@TMP_DIR@@@', pulseTempDir())
        # recherche variable environnement
        for t in re.findall("@_@.*?@_@", cmd):
            z = t.replace("@_@", "")
            cmd = cmd.replace(t, os.environ[z])
        # print "__________________________________"
        # print "replace TEMPLATE ou %s"% cmd
        # print "__________________________________"
        return cmd

    def __search_Next_step_int__(self, val):
        """
        goto to val
        search step next for step number value
        workingstep is the new step current
        """
        valstep = 0
        if isinstance(val, int):
            for step_in_sequence in self.sequence:
                if int(step_in_sequence['step']) == val:
                    self.data['stepcurrent'] = val
                    self.workingstep = self.sequence[self.data['stepcurrent']]
                    return 0
                valstep = valstep + 1
            logging.getLogger().error("inconsistency in descriptor")
            self.terminate(
                -1,
                False,
                "end error inconsistency in descriptor verify the step number [step %s not exist]" % val)
            self.objectxmpp.xmpplog("[%s] : Descriptor error: Verify the step number [step %s not exist]" % (val, self.data['name']),
                                    type='deploy',
                                    sessionname=self.sessionid,
                                    priority=val,
                                    action="xmpplog",
                                    who=self.objectxmpp.boundjid.bare,
                                    how="",
                                    why="",
                                    module="Deployment | Error | Execution",
                                    date=None,
                                    fromuser=self.data['login'],
                                    touser="")
            return 5
        elif isinstance(val,  basestring):
            if val == 'next':
                self.data['stepcurrent'] = self.data['stepcurrent'] + 1
                self.workingstep = self.sequence[self.data['stepcurrent']]
                return 0
            elif val == 'end':
                for step_in_sequence in self.sequence:
                    if self.sequence['action'] == 'actiondeploymentcomplete':
                        self.data['stepcurrent'] = int(step_in_sequence['step'])
                        self.workingstep = self.sequence[self.data['stepcurrent']]
                        return 0
                    valstep = valstep + 1
                    logging.getLogger().error("inconsistency in descriptor")
                return 5
            elif val == 'error':
                for step_in_sequence in self.sequence:
                    if self.sequence['action'] == 'actionerrordeployment':
                        self.data['stepcurrent'] = int(step_in_sequence['step'])
                        self.workingstep = self.sequence[self.data['stepcurrent']]
                        return 0
                    valstep = valstep + 1
                    logging.getLogger().error("inconsistency in descriptor")
                return 5
            else:
                for step_in_sequence in self.sequence:
                    if step_in_sequence['actionlabel'] == val:
                        self.data['stepcurrent'] = int(step_in_sequence['step'])
                        logging.getLogger().debug("goto step %s"%self.data['stepcurrent'])
                        self.workingstep = self.sequence[self.data['stepcurrent']]
                        return 0
                valstep = valstep + 1
                logging.getLogger().error("inconsistency in descriptor")
                return 5
        else:
            logging.getLogger().error("label error")
            self.data['stepcurrent'] = self.data['stepcurrent'] +1
            return 5

    def terminate(self, ret, clear=True, msgstate=""):
        """
            use for terminate deploy
            send msg to log sequence
            Clean client disk packages (ie clear)
        """
        login = self.data['login']
        restarmachine = False
        shutdownmachine = False
        #print "TERMINATE %s"%json.dumps(self.datasend, indent = 4)
        if 'advanced' in self.datasend['data'] \
            and 'shutdownrequired' in self.datasend['data']['advanced'] \
                and self.datasend['data']['advanced']['shutdownrequired'] is True:
            shutdownmachine = True
            self.objectxmpp.xmpplog("Shutdown required for machine after deployment on %s" % (self.datasend['data']['name']),
                                    type='deploy',
                                    sessionname=self.sessionid,
                                    priority=-2,
                                    action="xmpplog",
                                    who=self.objectxmpp.boundjid.bare,
                                    how="",
                                    why="",
                                    module="Deployment|Terminate|Execution|Restart|Notify",
                                    date=None,
                                    fromuser=self.data['login'],
                                    touser="")

        if not shutdownmachine and 'advanced' in self.datasend['data'] \
            and 'rebootrequired' in self.datasend['data']['advanced'] \
                and self.datasend['data']['advanced']['rebootrequired'] is True:
            restarmachine = True
            self.objectxmpp.xmpplog("Reboot required for machine after deploy on %s" % (self.datasend['data']['name']),
                                    type='deploy',
                                    sessionname=self.sessionid,
                                    priority=-2,
                                    action="xmpplog",
                                    who=self.objectxmpp.boundjid.bare,
                                    how="",
                                    why="",
                                    module="Deployment|Terminate|Execution|Restart|Notify",
                                    date=None,
                                    fromuser=self.data['login'],
                                    touser="")
        datas = {}
        datas = self.datasend
        try:
            self.__action_completed__(self.workingstep)
        except AttributeError:
            #grafcet instance has no attribute 'workingstep'
            self.datasend['data']['status'] = "ABORT PACKAGE WORKFLOW ERROR"
            self.objectxmpp.xmpplog('<span class="log_err">Workflow error. Please check your package<span>',
                                    type='deploy',
                                    sessionname=self.sessionid,
                                    priority=-2,
                                    action="xmpplog",
                                    who=self.objectxmpp.boundjid.bare,
                                    how="",
                                    why="",
                                    module="Deployment | Error | Terminate | Notify",
                                    date=None,
                                    fromuser=login,
                                    touser="")
        try:
            self.objectxmpp.session.clearnoevent(self.sessionid)
            logging.getLogger().debug("terminate install package %s" %
                                      self.datasend['data']['descriptor']['info']['name'])
            self.datasend['action'] = "result" + self.datasend['action']
            if "quitonerror" not in self.datasend['data']['descriptor']['info']:
                quiterror = True
            else:
                quiterror = self.datasend['data']['descriptor']['info']['quitonerror']
            try:
                del self.datasend['data']['result']
            except BaseException:
                pass
            try:
                del self.datasend['data']['methodetransfert']
                del self.datasend['data']['path']
            except BaseException:
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
            except BaseException:
                pass
            self.datasend['ret'] = ret
            os.chdir(managepackage.packagedir())
            if clear:
                if sys.platform.startswith('win'):
                    print "supprime file"
                    print "rmdir /s /q \"%s\"" % self.datasend['data']['pathpackageonmachine']
                    os.system("rmdir /s /q \"%s\"" %
                              self.datasend['data']['pathpackageonmachine'])
                else:
                    os.system("rm -Rf %s" %
                              self.datasend['data']['pathpackageonmachine'])
            datas = self.datasend
            if msgstate != "":
                self.datasend['data']['msgstate'] = msgstate
            self.datasend['data']['uname'] = [x for x in platform.uname()]
            logstruct = copy.deepcopy(self.datasend)
            logstruct['data']['action'] = logstruct['action']
            logstruct['action'] = "xmpplog"
            logstruct['data']['ret'] = ret
            logstruct['data']['sessionid'] = self.sessionid
            self.objectxmpp.send_message(mto=self.objectxmpp.sub_logger,
                                         mbody=json.dumps(logstruct),
                                         mtype='chat')
            try:
                del datas['data']['descriptor']['sequence']
            except BaseException:
                pass
            try:
                del datas['data']['environ']
                del datas['data']['packagefile']
                del datas['data']['transfert']
            except BaseException:
                pass
            self.objectxmpp.send_message(mto=self.datasend['data']['jidmaster'],
                                         mbody=json.dumps(datas),
                                         mtype='chat')
            datapackage = self.datasend
            mach = self.datasend['data']['jidmachine']
            datapackage['data'] = {}
            if(msgstate != ""):
                datapackage['msgstate'] = {"msg": msgstate,
                                           "quitonerror": quiterror}
            datapackage['action'] = 'applicationdeploymentjson'
            print "signal grafcet terminate%s" % datapackage
            self.objectxmpp.send_message(mto=mach,
                                         mbody=json.dumps(datapackage,
                                                          encoding="utf-8"),
                                         mtype='chat')

            if shutdownmachine or restarmachine:
                self.objectxmpp.xmpplog('DEPLOYMENT TERMINATE',
                                        type='deploy',
                                        sessionname=self.sessionid,
                                        priority=-2,
                                        action="xmpplog",
                                        who=self.objectxmpp.boundjid.bare,
                                        how="",
                                        why="",
                                        module="Deployment | Error | Terminate | Notify",
                                        date=None,
                                        fromuser=login,
                                        touser="")
            if shutdownmachine:
                shutdown_command()

            if restarmachine :
                reboot_command()

        except Exception as e:
            logging.getLogger().error(str(e))
            logger.error("\n%s" % (traceback.format_exc()))
            self.datasend['ret'] = 255
            datas['ret'] = 255
            logstruct = copy.deepcopy(self.datasend)
            logstruct['data']['action'] = logstruct['action']
            logstruct['action'] = "xmpplog"
            logstruct['data']['ret'] = ret
            logstruct['data']['sessionid'] = self.sessionid
            self.objectxmpp.send_message(mto=self.objectxmpp.sub_logger,
                                         mbody=json.dumps(logstruct),
                                         mtype='chat')
            self.objectxmpp.send_message(mto=self.datasend['data']['jidmaster'],
                                         mbody=json.dumps(datas),
                                         mtype='chat')

    def steplog(self):
        """inscrit log"""
        logging.getLogger().debug("deploy %s on machine %s [%s] STEP %s\n %s " % (self.data['descriptor']['info']['name'],
                                                                                  self.objectxmpp.boundjid.bare,
                                                                                  self.sessionid,
                                                                                  self.workingstep['step'],
                                                                                  json.dumps(self.workingstep, indent=4, sort_keys=True)))

    def __terminateifcompleted__(self, workingstep):
        """test if step taged completed"""
        if 'completed' in self.workingstep:
            if self.workingstep['completed'] >= 1:
                return True
        return False

    def __resultinfo__(self, workingstepinfo, listresult):
        for t in workingstepinfo:
            if t == "@resultcommand":
                workingstepinfo[t] = os.linesep.join(listresult)
            elif t.endswith('lastlines'):
                nb = t.split("@")
                nb1 = -int(nb[0])
                logging.getLogger().debug("=======lastlines============%s=============================" %
                                          nb1)
                tab = listresult[nb1:]
                workingstepinfo[t] = os.linesep.join(tab)
            elif t.endswith('firstlines'):
                nb = t.split("@")
                nb1 = int(nb[0])
                logging.getLogger().debug("=======firstlines============%s=============================" %
                                          nb1)
                tab = listresult[:nb1]
                workingstepinfo[t] = os.linesep.join(tab)

    def __Go_to_by_jump_succes_and_error__(self, returncode):
        """
        check return code and jump
        gotoreturncode@n n is nomber eg gotoreturncode@5 : 3
        {
                ......
                ......
                ......
                "step": 5    STEP WITH CODERETURN

                "codereturn": "",
                "gotoreturncode@5" : "3"   => if return code is 5 goto step 3
        }
        check return code and sucess
        {
                ......
                ......
                ......
                "step": 5    Step with success return code 0
                "codereturn": "",
                "success": 3,    => if return code is 0 goto step 3
        }
        check return code and error
        {
                ......
                ......
                ......
                "step": 5    Step with error return code diff 0
                "codereturn": "",
                "error": 3,    => if return code is dofferent of 0 goto step 3
        }
        """
        for t in self.workingstep:
            if t.startswith("gotoreturncode"):
                tab = t.split("@")
                if len(tab) == 2:
                    val = int(tab[1])
                    self.__search_Next_step_int__(val)
                    self.__execstep__()
                    return True
        # if 'goto' in self.workingstep :
        if returncode != 0 and 'error' in self.workingstep:
            self.__search_Next_step_int__(self.workingstep['error'])
            self.__execstep__()
            return True
        elif re['codereturn'] == 0 and 'succes' in self.workingstep:
            self.__search_Next_step_int__(self.workingstep['succes'])
            self.__execstep__()
            return True
        else:
            return False

    def __Go_to_by_jump__(self, result):
        if 'goto' in self.workingstep:
            self.__search_Next_step_int__(self.workingstep['goto'])
            self.__execstep__()
            return True
        elif 'gotoyes' in self.workingstep and result == "yes":
            # goto Faire directement reboot
            self.__search_Next_step_int__(self.workingstep['gotoyes'])
            self.__execstep__()
            return True
        elif 'gotono' in self.workingstep and result == "no":
            # goto attendre pour Faire reboot
            self.__search_Next_step_int__(self.workingstep['gotono'])
            self.__execstep__()
            return True
        elif 'gotoopen' in self.workingstep and result == "open":
            # goto attendre pour Faire reboot
            self.__search_Next_step_int__(self.workingstep['gotoopen'])
            self.__execstep__()
            return True
        elif 'gotosave' in self.workingstep and result == "save":
            # goto attendre pour Faire reboot
            self.__search_Next_step_int__(self.workingstep['gotosave'])
            self.__execstep__()
            return True
        elif 'gotocancel' in self.workingstep and result == "cancel":
            # goto attendre pour Faire reboot
            self.__search_Next_step_int__(self.workingstep['gotocancel'])
            self.__execstep__()
            return True
        elif 'gotoclose' in self.workingstep and result == "close":
            # goto attendre pour Faire reboot
            self.__search_Next_step_int__(self.workingstep['gotoclose'])
            self.__execstep__()
            return True
        elif 'gotodiscard' in self.workingstep and result == "discard":
            # goto attendre pour Faire reboot
            self.__search_Next_step_int__(self.workingstep['gotodiscard'])
            self.__execstep__()
            return True
        elif 'gotoapply' in self.workingstep and result == "apply":
            # goto attendre pour Faire reboot
            self.__search_Next_step_int__(self.workingstep['gotoapply'])
            self.__execstep__()
            return True
        elif 'gotoreset' in self.workingstep and result == "reset":
            # goto attendre pour Faire reboot
            self.__search_Next_step_int__(self.workingstep['gotoreset'])
            self.__execstep__()
            return True
        elif 'gotorestoreDefaults' in self.workingstep and result == "restoreDefaults":
            # goto attendre pour Faire reboot
            self.__search_Next_step_int__(
                self.workingstep['gotorestoreDefaults'])
            self.__execstep__()
            return True
        elif 'gotoabort' in self.workingstep and result == "abort":
            # goto attendre pour Faire reboot
            self.__search_Next_step_int__(self.workingstep['gotoabort'])
            self.__execstep__()
            return True
        elif 'gotoretry' in self.workingstep and result == "retry":
            # goto attendre pour Faire reboot
            self.__search_Next_step_int__(self.workingstep['gotoretry'])
            self.__execstep__()
            return True
        elif 'gotoignore' in self.workingstep and result == "ignore":
            # goto attendre pour Faire reboot
            self.__search_Next_step_int__(self.workingstep['gotoignore'])
            self.__execstep__()
            return True
        else:
            return False

    # DEFINITIONS OF EXISTING ACTIONS FOR A DESCRIPTOR###

    def action_pwd_package(self):
        """
        {
                "action": "action_pwd_package",
                "step": 0,
                "packageuuid" : ""  obtionnel
        }
        """
        try:
            if self.__terminateifcompleted__(self.workingstep):
                return
            self.__action_completed__(self.workingstep)
            self.__alternatefolder()
            self.steplog()
            self.__Etape_Next_in__()
        except Exception as e:
            logger.error("\n%s"%(traceback.format_exc()))
            self.terminate(-1, False, "end error in action_pwd_package step %s" % self.workingstep['step'])
            self.objectxmpp.xmpplog('[%s] - [%s]: Error action_pwd_package : %s' % (self.data['name'], self.workingstep['step'], str(e)),
                                    type='deploy',
                                    sessionname=self.sessionid,
                                    priority=self.workingstep['step'],
                                    action="xmpplog",
                                    who=self.objectxmpp.boundjid.bare,
                                    how="",
                                    why=self.data['name'],
                                    module="Deployment | Execution | Error",
                                    date=None,
                                    fromuser=self.data['login'],
                                    touser="")

    def action_section_install(self):
        """
        {
                "action": "action_section_install",
                "step": 1
        }
        """
        try:
            if self.__terminateifcompleted__(self.workingstep):
                return
            if "section" in self.parameterdynamic:
                strsection = str(self.parameterdynamic['section']).upper()
                self.objectxmpp.xmpplog('[%s]-[%s]: End of section %s' % (self.data['name'], self.workingstep['step'], strsection),
                                        type='deploy',
                                        sessionname=self.sessionid,
                                        priority=self.workingstep['step'],
                                        action="xmpplog",
                                        who=self.objectxmpp.boundjid.bare,
                                        how="",
                                        why=self.data['name'],
                                        module="Deployment | Execution",
                                        date=None,
                                        fromuser=self.data['login'],
                                        touser="")
            # goto succes
            self.__search_Next_step_int__(self.descriptorsection['actionsuccescompletedend'])
            self.__execstep__()
            return
        except Exception as e:
            logger.error("\n%s" % (traceback.format_exc()))
            self.terminate(-1, False, "end error in action_section_install step %s" %
                           self.workingstep['step'])
            self.objectxmpp.xmpplog('[%s] - [%s]: Error action_section_install : %s' % (self.data['name'], self.workingstep['step'], str(e)),
                                    type='deploy',
                                    sessionname=self.sessionid,
                                    priority=self.workingstep['step'],
                                    action="xmpplog",
                                    who=self.objectxmpp.boundjid.bare,
                                    how="",
                                    why=self.data['name'],
                                    module="Deployment | Execution | Error",
                                    date=None,
                                    fromuser=self.data['login'],
                                    touser="")

    def action_section_uninstall(self):
        """
        {
                "action": "action_section_uninstall",
                "step": 1
        }
        """
        try:
            if self.__terminateifcompleted__(self.workingstep):
                return
            if "section" in self.parameterdynamic:
                strsection = str(self.parameterdynamic['section']).upper()
                self.objectxmpp.xmpplog('[%s]-[%s]: End of section %s' % (self.data['name'], self.workingstep['step'], strsection),
                                        type='deploy',
                                        sessionname=self.sessionid,
                                        priority=self.workingstep['step'],
                                        action="xmpplog",
                                        who=self.objectxmpp.boundjid.bare,
                                        how="",
                                        why=self.data['name'],
                                        module="Deployment | Execution",
                                        date=None,
                                        fromuser=self.data['login'],
                                        touser="")
            # goto succes
            self.__search_Next_step_int__(self.descriptorsection['actionsuccescompletedend'])
            self.__execstep__()
            return
        except Exception as e:
            logger.error("\n%s"%(traceback.format_exc()))
            self.terminate(-1, False, "end error in action_section_uninstall step %s" %
                           self.workingstep['step'])
            self.objectxmpp.xmpplog('[%s] - [%s]: Error action_section_uninstall : %s' % (self.data['name'], self.workingstep['step'], str(e)),
                                    type='deploy',
                                    sessionname=self.sessionid,
                                    priority=self.workingstep['step'],
                                    action="xmpplog",
                                    who=self.objectxmpp.boundjid.bare,
                                    how="",
                                    why=self.data['name'],
                                    module="Deployment | Execution | Error",
                                    date=None,
                                    fromuser=self.data['login'],
                                    touser="")

    def action_section_update(self):
        """
        {
                "action": "action_section_update",
                "step": 1
        }
        """
        try:
            if self.__terminateifcompleted__(self.workingstep):
                return
            if "section" in self.parameterdynamic:
                strsection = str(self.parameterdynamic['section']).upper()
                self.objectxmpp.xmpplog('[%s]-[%s]: End of section %s' % (self.data['name'], self.workingstep['step'], strsection),
                                        type='deploy',
                                        sessionname=self.sessionid,
                                        priority=self.workingstep['step'],
                                        action="xmpplog",
                                        who=self.objectxmpp.boundjid.bare,
                                        how="",
                                        why=self.data['name'],
                                        module="Deployment | Execution",
                                        date=None,
                                        fromuser=self.data['login'],
                                        touser="")
            # goto succes
            self.__search_Next_step_int__(self.descriptorsection['actionsuccescompletedend'])
            self.__execstep__()
            return
        except Exception as e:
            logger.error("\n%s"%(traceback.format_exc()))
            self.terminate(-1, False, "end error in action_section_update step %s" %
                           self.workingstep['step'])
            self.objectxmpp.xmpplog('[%s] - [%s]: Error action_section_update : %s' % (self.data['name'], self.workingstep['step'], str(e)),
                                    type='deploy',
                                    sessionname=self.sessionid,
                                    priority=self.workingstep['step'],
                                    action="xmpplog",
                                    who=self.objectxmpp.boundjid.bare,
                                    how="",
                                    why=self.data['name'],
                                    module="Deployment | Execution | Error",
                                    date=None,
                                    fromuser=self.data['login'],
                                    touser="")


    def action_section_launch(self):
        """
        {
                "action": "action_section_launch",
                "step": 1
        }
        """
        try:
            if self.__terminateifcompleted__(self.workingstep):
                return
            if "section" in self.parameterdynamic:
                strsection = str(self.parameterdynamic['section']).upper()
                self.objectxmpp.xmpplog('[%s]-[%s]: End of section %s' % (self.data['name'], self.workingstep['step'], strsection),
                                        type='deploy',
                                        sessionname=self.sessionid,
                                        priority=self.workingstep['step'],
                                        action="xmpplog",
                                        who=self.objectxmpp.boundjid.bare,
                                        how="",
                                        why=self.data['name'],
                                        module="Deployment | Execution",
                                        date=None,
                                        fromuser=self.data['login'],
                                        touser="")
            # goto succes
            self.__search_Next_step_int__(self.descriptorsection['actionsuccescompletedend'])
            self.__execstep__()
            return
        except Exception as e:
            logger.error("\n%s"%(traceback.format_exc()))
            self.terminate(-1, False, "end error in action_section_launch step %s" %
                           self.workingstep['step'])
            self.objectxmpp.xmpplog('[%s] - [%s]: Error action_section_launch : %s' % (self.data['name'], self.workingstep['step'], str(e)),
                                    type='deploy',
                                    sessionname=self.sessionid,
                                    priority=self.workingstep['step'],
                                    action="xmpplog",
                                    who=self.objectxmpp.boundjid.bare,
                                    how="",
                                    why=self.data['name'],
                                    module="Deployment | Execution | Error",
                                    date=None,
                                    fromuser=self.data['login'],
                                    touser="")

    def action_comment(self):
        """
        {
                "action": "action_comment",
                "step": n,
                "comment" : "salut la compagnie"
        }
        """
        try:
            if self.__terminateifcompleted__(self.workingstep):
                return
            self.__action_completed__(self.workingstep)
            print self.workingstep
            if 'comment' in self.workingstep :
                self.workingstep['comment'] = self.replaceTEMPLATE(self.workingstep['comment'] )
            else:
                self.workingstep['comment'] = "no comment user"
            self.objectxmpp.xmpplog('[%s]-[%s]: User comment : %s' % (self.data['name'], self.workingstep['step'], self.workingstep['comment']),
                                    type='deploy',
                                    sessionname=self.sessionid,
                                    priority=self.workingstep['step'],
                                    action="xmpplog",
                                    who=self.objectxmpp.boundjid.bare,
                                    how="",
                                    why=self.data['name'],
                                    module="Deployment | Execution",
                                    date=None,
                                    fromuser=self.data['login'],
                                    touser="")

            self.steplog()
            self.__Etape_Next_in__()
        except Exception as e:
            logger.error("\n%s"%(traceback.format_exc()))
            self.terminate(-1, False, "end error in action_comment step %s" %
                           self.workingstep['step'])
            self.objectxmpp.xmpplog('[%s] - [%s]: Error action_comment : %s' % (self.data['name'], self.workingstep['step'], str(e)),
                                    type='deploy',
                                    sessionname=self.sessionid,
                                    priority=self.workingstep['step'],
                                    action="xmpplog",
                                    who=self.objectxmpp.boundjid.bare,
                                    how="",
                                    why=self.data['name'],
                                    module="Deployment | Execution | Error",
                                    date=None,
                                    fromuser=self.data['login'],
                                    touser="")


    def action_set_environ(self):
        """
        {
                "action": "action_set_environ",
                "step": 0,
                "environ" : {"PLIP22" : "plop"  }
        }
        """
        try:
            if self.__terminateifcompleted__(self.workingstep):
                return
            self.__action_completed__(self.workingstep)
            if 'environ' in self.workingstep:
                if isinstance(self.workingstep['environ'], dict):
                    for z in self.workingstep['environ']:
                        a = self.replaceTEMPLATE(z)
                        b = self.replaceTEMPLATE(
                            self.workingstep['environ'][a])
                        os.environ[a] = b
                        self.objectxmpp.xmpplog('[%s]-[%s] : Set environment parameter %s = %s' % (self.data['name'], self.workingstep['step'], a, b),
                                                type='deploy',
                                                sessionname=self.sessionid,
                                                priority=self.workingstep['step'],
                                                action="xmpplog",
                                                who=self.objectxmpp.boundjid.bare,
                                                how="",
                                                why=self.data['name'],
                                                module="Deployment | Error | Execution",
                                                date=None,
                                                fromuser=self.data['login'],
                                                touser="")
            self.steplog()
            self.__Etape_Next_in__()
        except Exception as e:
            logging.getLogger().error(str(e))
            logger.error("\n%s" % (traceback.format_exc()))
            self.terminate(-1, False, "end error in action_set_environ step %s" %
                           self.workingstep['step'])
            self.objectxmpp.xmpplog('[%s]-[%s]: Error action_set_environ ' % (self.data['name'],self.workingstep['step']),
                                    type='deploy',
                                    sessionname=self.sessionid,
                                    priority=self.workingstep['step'],
                                    action="xmpplog",
                                    who=self.objectxmpp.boundjid.bare,
                                    how="",
                                    why=self.data['name'],
                                    module="Deployment | Error | Execution",
                                    date=None,
                                    fromuser=self.data['login'],
                                    touser="")

    def action_set_config_file(self):
        """
        {
                "action": "action_set_config_file",
                "step": 0,
                "set" : "add@__@agentconf@__@global@__@log_level@__@DEBUG" or "del@__@agentconf@__@global@__@log_level"
        }
        """
        try:
            if self.__terminateifcompleted__(self.workingstep):
                return
            self.__action_completed__(self.workingstep)
            if 'set' in self.workingstep:
                if isinstance(self.workingstep['set'], (str, unicode)):
                    self.workingstep['set'] = str(self.workingstep['set'])
                    if self.workingstep['set'] != "":
                        dataconfiguration = self.workingstep['set'].split("@__@")
                        if len(dataconfiguration) > 0 and (dataconfiguration[0].lower() == "add" or dataconfiguration[0].lower() =="del" ):
                            # traitement configuration.
                            if not setconfigfile(dataconfiguration):
                                self.objectxmpp.xmpplog('[%s]-[%s] : Error setting configuration option %s' % (self.data['name'], self.workingstep['step'],self.workingstep['set']),
                                                        type='deploy',
                                                        sessionname=self.sessionid,
                                                        priority=self.workingstep['step'],
                                                        action="xmpplog",
                                                        who=self.objectxmpp.boundjid.bare,
                                                        how="",
                                                        why=self.data['name'],
                                                        module="Deployment | Error | Configuration",
                                                        date=None,
                                                        fromuser=self.data['login'],
                                                        touser="")
                            else:
                                self.objectxmpp.xmpplog('[%s]-[%s] : Set configuration option %s' % (self.data['name'], self.workingstep['step'],self.workingstep['set']),
                                                        type='deploy',
                                                        sessionname=self.sessionid,
                                                        priority=self.workingstep['step'],
                                                        action="xmpplog",
                                                        who=self.objectxmpp.boundjid.bare,
                                                        how="",
                                                        why=self.data['name'],
                                                        module="Deployment | Notify | Configuration",
                                                        date=None,
                                                        fromuser=self.data['login'],
                                                        touser="")
            self.steplog()
            self.__Etape_Next_in__()
        except Exception as e:
            logging.getLogger().error(str(e))
            logger.error("\n%s"%(traceback.format_exc()))
            self.terminate(-1, False, "end error in action_set_config_file step %s" %
                           self.workingstep['step'])
            self.objectxmpp.xmpplog('[%s]-[%s]: Error action_set_config_file ' % (self.data['name'],self.workingstep['step']),
                                    type='deploy',
                                    sessionname=self.sessionid,
                                    priority=self.workingstep['step'],
                                    action="xmpplog",
                                    who=self.objectxmpp.boundjid.bare,
                                    how="",
                                    why=self.data['name'],
                                    module="Deployment | Error | Execution",
                                    date=None,
                                    fromuser=self.data['login'],
                                    touser="")


    def action_no_operation(self):
        """
        {
                "action": "action_no_operation",
                "step": n,
                "environ" : {"PLIP22" : "plop" ,"dede","kk" }
        }
        """
        try:
            if self.__terminateifcompleted__(self.workingstep):
                return
            self.__action_completed__(self.workingstep)
            self.steplog()
            self.__Etape_Next_in__()
        except Exception as e:
            logging.getLogger().error(str(e))
            logger.error("\n%s"%(traceback.format_exc()))
            self.terminate(-1, False, "end error in action_no_operation step %s" %
                           self.workingstep['step'])
            self.objectxmpp.xmpplog('[%s]-[%s]: Error action_no_operation' % (self.data['name'], self.workingstep['step']),
                                    type='deploy',
                                    sessionname=self.sessionid,
                                    priority=self.workingstep['step'],
                                    action="xmpplog",
                                    who=self.objectxmpp.boundjid.bare,
                                    how="",
                                    why=self.data['name'],
                                    module="Deployment | Error | Execution",
                                    date=None,
                                    fromuser=self.data['login'],
                                    touser="")

    def action_unzip_file(self):
        """
        unzip file from python
        descriptor type
        {
            "step" : intnb,
            "action" : "action_unzip_file",
            "filename" : "namefile",
            "pathdirectorytounzip" : "pathdirextract",
            "@resultcommand": "",
            "packageuuid" : ""

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
            if self.__terminateifcompleted__(self.workingstep):
                return
            self.__action_completed__(self.workingstep)
            self.workingstep['filename'] = self.replaceTEMPLATE(
                self.workingstep['filename'])
            self.workingstep['pwd'] = ""
            if os.path.isdir(self.datasend['data']['pathpackageonmachine']):
                os.chdir(self.datasend['data']['pathpackageonmachine'])
                self.workingstep['pwd'] = os.getcwd()
            self.__alternatefolder()
            zip_ref = zipfile.ZipFile(self.workingstep['filename'], 'r')
            if 'pathdirectorytounzip' not in self.workingstep:
                self.workingstep['pathdirectorytounzip'] = self.replaceTEMPLATE('.')
                zip_ref.extractall(
                    self.datasend['data']['pathpackageonmachine'])
            else:
                self.workingstep['pathdirectorytounzip'] = self.replaceTEMPLATE(
                    self.workingstep['pathdirectorytounzip'])
                zip_ref.extractall(self.workingstep['pathdirectorytounzip'])
            listname = zip_ref.namelist()
            self.__resultinfo__(self.workingstep, listname)
            zip_ref.close()
            self.objectxmpp.xmpplog('[%s]-[%s]: Extracting %s to directory %s' % (self.data['name'],
                                                                                  self.workingstep['step'],
                                                                                  self.workingstep['filename'],
                                                                                  self.workingstep['pathdirectorytounzip']),
                                    type='deploy',
                                    sessionname=self.sessionid,
                                    priority=self.workingstep['step'],
                                    action="xmpplog",
                                    who=self.objectxmpp.boundjid.bare,
                                    how="",
                                    why=self.data['name'],
                                    module="Deployment | Error | Execution",
                                    date=None,
                                    fromuser=self.data['login'],
                                    touser="")
            if 'goto' in self.workingstep:
                self.__search_Next_step_int__(self.workingstep['goto'])
                self.__execstep__()
                return

            if 'succes' in self.workingstep:
                # goto succes
                self.__search_Next_step_int__(self.workingstep['succes'])
                self.__execstep__()
            else:
                self.__Etape_Next_in__()
                self.steplog()
        except Exception as e:
            self.workingstep['@resultcommand'] = traceback.format_exc()
            logging.getLogger().error(str(e))
            self.objectxmpp.xmpplog('[%s]-[%s]: Error extracting %s to directory %s' % (self.data['name'],
                                                                                             self.workingstep['step'],
                                                                                             self.workingstep['filename'],
                                                                                             self.workingstep['pathdirectorytounzip']),
                                    type='deploy',
                                    sessionname=self.sessionid,
                                    priority=self.workingstep['step'],
                                    action="xmpplog",
                                    who=self.objectxmpp.boundjid.bare,
                                    how="",
                                    why=self.data['name'],
                                    module="Deployment | Error | Execution",
                                    date=None,
                                    fromuser=self.data['login'],
                                    touser="")
            if 'error' in self.workingstep:
                self.__search_Next_step_int__(self.workingstep['error'])
                self.__execstep__()
            else:
                self.__Etape_Next_in__()
                self.steplog()

    def actionprocessscript(self):
        """
        {
                "step": intnb,
                "action": "actionprocessscript",
                "command": "xmppdeploy.bat",

                "codereturn": "",
                "timeout": 900,
                "error": 5,
                "success": 3,
                "@resultcommand": "",
                "packageuuid" : ""
        }
        """
        try:
            if self.__terminateifcompleted__(self.workingstep):
                return
            if (isBase64(self.workingstep['command'])):
                self.workingstep['command'] = base64.b64decode(self.workingstep['command'])
            self.workingstep['command'] = self.replaceTEMPLATE(
                self.workingstep['command'])
            if "timeout" not in self.workingstep:
                ###
                try:
                    self.workingstep['timeout'] = int(self.objectxmpp.config.default_timeout)
                except:
                    self.workingstep['timeout'] = 800
                logging.getLogger().warn("timeout missing : default value %ss" % self.workingstep['timeout'])
            else:
                try:
                    self.workingstep['timeout'] = int(self.workingstep['timeout'])
                except:
                    self.workingstep['timeout'] = 800
                    logging.getLogger().warn("timeout integer error : default value %ss" % self.workingstep['timeout'])
            # working Step recup from process et session

            self.workingstep['pwd'] = ""
            if os.path.isdir(self.datasend['data']['pathpackageonmachine']):
                os.chdir(self.datasend['data']['pathpackageonmachine'])
                self.workingstep['pwd'] = os.getcwd()

            self.__alternatefolder()
            self.objectxmpp.process_on_end_send_message_xmpp.add_processcommand(self.workingstep['command'],
                                                                                self.datasend,
                                                                                self.objectxmpp.boundjid.bare,
                                                                                self.objectxmpp.boundjid.bare,
                                                                                self.workingstep['timeout'],
                                                                                self.workingstep['step'])
            # if not comdbool:
            # self.objectxmpp.logtopulse('[%s]: Error descriptor actionprocessscript %s'%(self.workingstep['step'],
            # self.workingstep['pwd']),
            # type='deploy',
            # sessionname = self.sessionid ,
            # priority =self.workingstep['step'],
            # who=self.objectxmpp.boundjid.bare)
        except Exception as e:
            self.steplog()
            logging.getLogger().error(str(e))
            logger.error("\n%s"%(traceback.format_exc()))
            self.terminate(-1, False, "end error in actionprocessscript step %s" %
                           self.workingstep['step'])
            self.objectxmpp.xmpplog('[%s]-[%s]: Error in actionprocessscript step' % (self.data['name'], self.workingstep['step']),
                                    type='deploy',
                                    sessionname=self.sessionid,
                                    priority=self.workingstep['step'],
                                    action="xmpplog",
                                    who=self.objectxmpp.boundjid.bare,
                                    how="",
                                    why=self.data['name'],
                                    module="Deployment | Error | Execution",
                                    date=None,
                                    fromuser=self.data['login'],
                                    touser="")

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
            if self.__terminateifcompleted__(self.workingstep):
                return
            self.workingstep['command'] = self.replaceTEMPLATE(
                self.workingstep['command'])

            # self.objectxmpp.logtopulse("action_command_natif_shell")
            # todo si action deja faite return
            if "timeout" not in self.workingstep:
                self.workingstep['timeout'] = 15
                logging.getLogger().warn("timeout missing : default value 15s")
            re = shellcommandtimeout(
                self.workingstep['command'],
                self.workingstep['timeout']).run()
            self.__action_completed__(self.workingstep)
            self.workingstep['codereturn'] = re['codereturn']
            result = [x.strip('\n') for x in re['result'] if x != '']
            self.__resultinfo__(self.workingstep, result)
            self.objectxmpp.xmpplog('[%s] - [%s]: Error code %s for command : %s ' % (self.data['name'],
                                                                                      self.workingstep['step'],
                                                                                      self.workingstep['codereturn'],
                                                                                      self.workingstep['command']),
                                    type='deploy',
                                    sessionname=self.sessionid,
                                    priority=self.workingstep['step'],
                                    action="xmpplog",
                                    who=self.objectxmpp.boundjid.bare,
                                    how="",
                                    why=self.data['name'],
                                    module="Deployment | Error | Execution",
                                    date=None,
                                    fromuser=self.data['login'],
                                    touser="")
            self.steplog()
            if self.__Go_to_by_jump_succes_and_error__(re['codereturn']):
                return
            self.__Etape_Next_in__()
            return
        except Exception as e:
            logging.getLogger().error(str(e))
            logger.error("\n%s"%(traceback.format_exc()))
            if re['codereturn'] != 0 and 'error' in self.workingstep:
                self.__search_Next_step_int__(self.workingstep['succes'])
                self.__execstep__()
                return
            self.terminate(
                -1, False, "end error in action_command_natif_shell step %s" %
                self.workingstep['step'])
            self.objectxmpp.xmpplog('[%s]-[%s]: Error action_command_natif_shell : %s' % (self.data['name'], self.workingstep['step']),
                                    type='deploy',
                                    sessionname=self.sessionid,
                                    priority=self.workingstep['step'],
                                    action="xmpplog",
                                    who=self.objectxmpp.boundjid.bare,
                                    how="",
                                    why=self.data['name'],
                                    module="Deployment | Error | Execution",
                                    date=None,
                                    fromuser=self.data['login'],
                                    touser="")

    def actionprocessscriptfile(self):
        """
        {
                "step": intnb,
                "action": "actionprocessscriptfile",
                "typescript": "",
                "script" :  "",
                "suffix" : "",
                "bang" : "",
                "codereturn": "",
                "timeout": 900,
                "error": 5,
                "success": 3,
                "@resultcommand": "",
                "packageuuid" : ""
        }
        bang et suffix sont prioritaire sur ceux trouver depuis le typescript
        title action is Execute script
        script is copy in file in temp.
        execution of temp file

        typescript list python, tcl,

        """

        suffix = None
        shebang = None
        commandtype = ""

        if sys.platform.startswith('win'):
            # exec for power shell " powershell -executionpolicy bypass -File <ton_script_ps1>"
            extensionscriptfile = {
                                   "python": {
                                              "suffix" : 'py',
                                              "bang": "#!/usr/bin/python"
                                              },
                                   "visualbasicscript": {
                                                         "suffix": "vbs",
                                                         "bang": ""
                                                         },
                                   "Batch": {
                                             "suffix": "bat",
                                             "bang": ""
                                             },
                                   "powershell": {
                                                  "suffix": "ps1",
                                                  "bang": "",
                                                  "commandtype": "powershell -executionpolicy bypass -File "
                                                  }
                                   }
        elif sys.platform.startswith('linux'):
            extensionscriptfile = {
                                   "python": {
                                              "suffix": 'py',
                                              "bang": "#!/usr/bin/python",
                                              "commandtype": "python"
                                              },
                                   "Batch": {
                                             "suffix": "sh",
                                             "bang": "#!/bin/bash",
                                             "commandtype": "/bin/bash "
                                            },
                                   "unixKornshell": {
                                                     "suffix": "ksh",
                                                     "bang": "#!/bin/ksh",
                                                     "commandtype": "/bin/ksh"
                                                     },
                                   "unixCshell": {
                                                  "suffix": "csh",
                                                  "bang": "#!/bin/csh",
                                                  "commandtype": "/bin/csh "
                                                  }
                                   }
        elif sys.platform.startswith('darwin'):
            extensionscriptfile = {
                                   "python": {
                                              "suffix": 'py',
                                              "bang": "#!/usr/bin/python",
                                              "commandtype": "python"
                                              },
                                   "Batch": {
                                             "suffix": "sh",
                                             "bang": "#!/bin/bash",
                                             "commandtype": "/bin/bash"
                                             },
                                   "unixKornshell": {
                                                     "suffix": "ksh",
                                                     "bang": "#!/bin/ksh",
                                                     "commandtype": "/bin/ksh"
                                                     },
                                   "unixCshell": {
                                                  "suffix": "csh",
                                                  "bang": "#!/bin/csh",
                                                  "commandtype": "/bin/csh"
                                                  }
                                   }

        try:
            if self.__terminateifcompleted__(self.workingstep):
                return
            if (isBase64(self.workingstep['script'])):
                self.workingstep['script'] = base64.b64decode(self.workingstep['script'])
            self.workingstep['script'] = self.replaceTEMPLATE(
                self.workingstep['script'])
            if "timeout" not in self.workingstep:
                self.workingstep['timeout'] = 900
                logging.getLogger().warn("timeout missing : default value 900s")

            self.workingstep['pwd'] = ""
            if os.path.isdir(self.datasend['data']['pathpackageonmachine']):
                os.chdir(self.datasend['data']['pathpackageonmachine'])
                self.workingstep['pwd'] = os.getcwd()
            self.__alternatefolder()
            if self.workingstep['typescript'] in extensionscriptfile:
                suffix = extensionscriptfile[self.workingstep['typescript']]['suffix']
                shebang = extensionscriptfile[self.workingstep['typescript']]['bang']
                if 'commandtype' in extensionscriptfile[self.workingstep['typescript']]:
                    commandtype = extensionscriptfile[self.workingstep['typescript']]['commandtype']

            if 'suffix' in self.workingstep and self.workingstep['suffix'] != "":
                # Search sufix and extension for typescript.
                suffix = self.workingstep['suffix']


            if "bang" in self.workingstep and self.workingstep['bang'] != "":
                # Search sufix and extension for typescript.
                shebang = self.workingstep['bang']

            if suffix is not None:
                self.workingstep['suffix'] = suffix
            else:
                self.workingstep['suffix'] = ""

            if shebang is not None:
                self.workingstep['bang'] = shebang
                if shebang != "" and not self.workingstep['script'].startswith(self.workingstep['bang']):
                    self.workingstep['script'] = self.workingstep['bang'] + os.linesep + self.workingstep['script']
            else:
                self.workingstep['bang'] = ""

            self.workingstep['script'] = self.replaceTEMPLATE(
                self.workingstep['script'])

            fd, temp_path = mkstemp(suffix='.' + suffix)
            # TODO:  See how we deal with \
            st = self.workingstep['script']
            if (suffix == "bat") or (suffix == "ps1"):
                os.write(fd, st)
            else:
                os.write(fd, st.replace("\\","\\\\"))
            os.close(fd)
            self.workingstep['script'] = "script in temp file : %s" % temp_path
            # Create command
            if commandtype is not None:
                command = commandtype + temp_path

            # working Step recup from process et session
            if command != "":
                self.objectxmpp.process_on_end_send_message_xmpp.add_processcommand(command,
                                                                                    self.datasend,
                                                                                    self.objectxmpp.boundjid.bare,
                                                                                    self.objectxmpp.boundjid.bare,
                                                                                    self.workingstep['timeout'],
                                                                                    self.workingstep['step'])
        except Exception as e:
            self.steplog()
            logging.getLogger().error(str(e))
            logger.error("\n%s" % (traceback.format_exc()))
            self.terminate(-1, False, "end error in actionprocessscriptfile step %s" %
                           self.workingstep['step'])
            self.objectxmpp.xmpplog('[%s]-[%s]: Error in actionprocessscriptfile step' % (self.data['name'], self.workingstep['step']),
                                    type='deploy',
                                    sessionname=self.sessionid,
                                    priority=self.workingstep['step'],
                                    action="xmpplog",
                                    who=self.objectxmpp.boundjid.bare,
                                    how="",
                                    why=self.data['name'],
                                    module="Deployment | Error | Execution",
                                    date=None,
                                    fromuser=self.data['login'],
                                    touser="")

    def actionsuccescompletedend(self):
        """
        descriptor type
        {
            "step" : 11,
            "action" : "actionsuccescompletedend",
            "clear" : "True"
            "inventory" : "True"
        }
        clear optionnel option
        if clear is not defini then clear = True
        inventory optionnel option
        if inventory is not defini then inventory = True
        """
        inventory = True
        if 'inventory' in self.workingstep:
            boolstr = str(self.workingstep['inventory'])
            # status inventory "No inventory / Inventory on change / Forced inventory"
            if boolstr.lower() in ['true',
                                   '1',
                                   'y',
                                   'yes',
                                   'ok',
                                   'forced',
                                   'forced inventory',
                                   ]:
                inventory = True
                self.workingstep['actioninventory'] = 'forced'

            if boolstr.lower() in ['false',
                                   '0',
                                   'n',
                                   'no',
                                   'ko',
                                   'non',
                                   'not'
                                   'no inventory']:
                inventory = False
                self.workingstep['actioninventory'] = 'noforced'

            if boolstr.lower() in ['Inventory on change',
                                   'noforced']:
                inventory = True
                self.workingstep['actioninventory'] = 'noforced'


        if 'actioninventory' not in self.workingstep:
            logger.warning("inventory option is forced check option inventory")
            self.workingstep['actioninventory'] = 'forced'
        inventoryfile = ""
        if inventory:
            # genere inventaire et envoi inventaire
            # call plugin inventory pour master.
            self.objectxmpp.xmpplog('Starting inventory',
                                    type='deploy',
                                    sessionname=self.sessionid,
                                    priority=self.workingstep['step'],
                                    action="xmpplog",
                                    who=self.objectxmpp.boundjid.bare,
                                    how="",
                                    why=self.data['name'],
                                    module="Deployment | Execution | Inventory",
                                    date=None,
                                    fromuser=self.data['login'],
                                    touser="")
            try:
                self.objectxmpp.handleinventory(forced=self.workingstep['actioninventory'],
                                                sessionid=self.sessionid)
            except Exception as e:
                print str(e)
            #waitting active generated new inventory
            doinventory = False
            timeinventory = 0
            for indextime in range(48):  # waitting max 2 minutes
                if os.path.isfile(inventoryfile):
                    doinventory = True
                    timeinventory = (indextime + 1) * 5
                    break
                time.sleep(5)
            if doinventory:
                self.objectxmpp.xmpplog('Sending new inventory from %s : (generated in %s s)' % (self.objectxmpp.boundjid.bare, timeinventory),
                                        type='deploy',
                                        sessionname=self.sessionid,
                                        priority=self.workingstep['step'],
                                        action="xmpplog",
                                        who=self.objectxmpp.boundjid.bare,
                                        how="",
                                        why=self.data['name'],
                                        module="Deployment | Execution | Inventory",
                                        date=None,
                                        fromuser=self.data['login'],
                                        touser="")
            else:
                self.objectxmpp.xmpplog('[%s]-[%s] :<span class="log_err"> Deployment aborted: inventory execution error <span>' % (self.data['name'], self.workingstep['step']),
                                        type='deploy',
                                        sessionname=self.sessionid,
                                        priority=self.workingstep['step'],
                                        action="xmpplog",
                                        who=self.objectxmpp.boundjid.bare,
                                        how="",
                                        why=self.data['name'],
                                        module="Deployment | Execution | Inventory | Error",
                                        date=None,
                                        fromuser=self.data['login'],
                                        touser="")

        clear = True
        if 'clear' in self.workingstep:
            if isinstance(self.workingstep['clear'], bool):
                clear = self.workingstep['clear']
            else:
                self.workingstep['clear'] = str(self.workingstep['clear'])
                if self.workingstep['clear'] == "False":
                    clear = False
        self.objectxmpp.xmpplog('[%s]-[%s] :<span class="log_ok">Deployment successful<span>' % (self.data['name'], self.workingstep['step']),
                                type='deploy',
                                sessionname=self.sessionid,
                                priority=self.workingstep['step'],
                                action="xmpplog",
                                who=self.objectxmpp.boundjid.bare,
                                how="",
                                why=self.data['name'],
                                module="Deployment | Error | Execution",
                                date=None,
                                fromuser=self.data['login'],
                                touser="")
        if self.__terminateifcompleted__(self.workingstep):
            return
        self.terminate(0, clear, "end success")
        self.steplog()

    def actionerrorcompletedend(self):
        """
        descriptor type
        {
            "step" : 11,
            "action" : "actionerrorcompletedend",
            "clear" : true
        }
        clear optionnel option
        if clear is not defini then clear = True
        """
        clear = True
        if 'clear' in self.workingstep and isinstance(
                self.workingstep['clear'], bool):
            clear = self.workingstep['clear']
        self.objectxmpp.xmpplog('[%s]-[%s] :<span class="log_err"> Deployment aborted <span>' % (self.data['name'], self.workingstep['step']),
                                type='deploy',
                                sessionname=self.sessionid,
                                priority=self.workingstep['step'],
                                action="xmpplog",
                                who=self.objectxmpp.boundjid.bare,
                                how="",
                                why=self.data['name'],
                                module="Deployment | Error | Execution | Notify",
                                date=None,
                                fromuser=self.data['login'],
                                touser="")

        if self.__terminateifcompleted__(self.workingstep):
            return
        self.terminate(-1, clear, "end error")
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
        # composition command
        if 'title' not in self.workingstep:
            self.workingstep['title'] = "Confirmation"
        if 'icon' not in self.workingstep:
            self.workingstep['icon'] = "information"
        if 'query' not in self.workingstep:
            self.workingstep['query'] = "Yes or No"
        if 'boutontype' not in self.workingstep:
            self.workingstep['boutontype'] = ['yes', 'no']

        if sys.platform.startswith('linux'):
            logging.debug("machine linux")
            try:
                os.environ['DISPLAY']
                logging.debug(
                              "There is an X server  %s" %
                              os.environ['DISPLAY'])
                logging.debug("############################################")
                logging.debug("linux avec serveur X")
                linux_executable_dlg_confirm = "dlg_comfirm_pulse"
                command = linux_executable_dlg_confirm + \
                    " -T " + self.workingstep['title'] + \
                    " -I " + self.workingstep['icon'] + \
                    " -Q " + self.workingstep['query'] + \
                    " -B " + \
                    ",".join(self.workingstep['boutontype'])
                logging.debug(
                              "################LINUX  command ############################ %s" %
                              command)
            except KeyError:
                logging.debug("There is not X server")
                os.system(
                          "echo \"" +
                          self.workingstep['title'] +
                          "\n" +
                          self.workingstep['query'] +
                          "\n\" | wall")

                self.__Etape_Next_in__()
                return

        elif sys.platform.startswith('win'):
            logging.debug("command on windows")
            win_executable_dlg_confirm = "dlg_comfirm_pulse"
            command = win_executable_dlg_confirm + \
                " -T " + self.workingstep['title'] + \
                " -I " + self.workingstep['icon'] + \
                " -Q " + self.workingstep['query'] + \
                " -B " + \
                ",".join(self.workingstep['boutontype'])
        elif sys.platform.startswith('darwin'):
            logging.debug("command on darwin")
            Macos_executable_dlg_confirm = "dlg_comfirm_pulse"
            command = Macos_executable_dlg_confirm + \
                " -T " + self.workingstep['title'] + \
                " -I " + self.workingstep['icon'] + \
                " -Q " + self.workingstep['query'] + \
                " -B " + \
                ",".join(self.workingstep['boutontype'])
        # TODO: si action deja faite return

        # appelle boite de dialog

        re = shellcommandtimeout(command, 60).run()
        self.steplog()
        result = [x.strip('\n') for x in re['result'] if x != '']
        logging.getLogger().debug("result action actionconfirm:")
        self.objectxmpp.xmpplog('[%s]-[%s]: Dialog : Response %s' % (self.data['name'],self.workingstep['step'], result[-1]),
                                type='deploy',
                                sessionname=self.sessionid,
                                priority=self.workingstep['step'],
                                action="xmpplog",
                                who=self.objectxmpp.boundjid.bare,
                                how="",
                                why=self.data['name'],
                                module="Deployment | Error | Execution",
                                date=None,
                                fromuser=self.data['login'],
                                touser="")
        if self.__Go_to_by_jump__(result[0]):
            return
        if self.__Go_to_by_jump_succes_and_error__(re['codereturn']):
            return
        self.__Etape_Next_in__()
        return

        # self.objectxmpp.logtopulse('[%s]: Dialog : Reponse %s'%(self.workingstep['step'],result[0]),
        # type='deploy',
        # sessionname = self.sessionid ,
        # priority =self.workingstep['step'] )

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
        try:
            if self.__terminateifcompleted__(self.workingstep):
                return
            # todo si action deja faite return
            if "waiting" not in self.workingstep:
                self.workingstep['waiting'] = '10'
                logging.getLogger().warn("waiting missing : default value 180s")
            # timewaiting = int(self.workingstep['waiting']) + 180
            logging.getLogger().warn("timeout  waiting : %s" % self.workingstep['waiting'])
            self.objectxmpp.xmpplog('[%s]-[%s]: Waiting %s s before resuming deployment' % (self.data['name'],
                                                                                            self.workingstep['step'],
                                                                                            self.workingstep['waiting']),
                                    type='deploy',
                                    sessionname=self.sessionid,
                                    priority=self.workingstep['step'],
                                    action="xmpplog",
                                    who=self.objectxmpp.boundjid.bare,
                                    how="",
                                    why=self.data['name'],
                                    module="Deployment | Error | Execution",
                                    date=None,
                                    fromuser=self.data['login'],
                                    touser="")

            time.sleep(int(self.workingstep['waiting']))
            if 'goto' in self.workingstep:
                self.__search_Next_step_int__(self.workingstep['goto'])
                self.__execstep__()
                return True
            self.steplog()
            self.__Etape_Next_in__()
        except Exception:
            logger.error("\n%s"%(traceback.format_exc()))
            self.terminate(-1, False, "end error in actionwaitandgoto step %s" %
                           self.workingstep['step'])
            self.objectxmpp.xmpplog('[%s]-[%s]: Error in descriptor for action waitandgoto ' % (self.data['name'], self.workingstep['step']),
                                    type='deploy',
                                    sessionname=self.sessionid,
                                    priority=self.workingstep['step'],
                                    action="xmpplog",
                                    who=self.objectxmpp.boundjid.bare,
                                    how="",
                                    why=self.data['name'],
                                    module="Deployment | Error | Execution",
                                    date=None,
                                    fromuser=self.data['login'],
                                    touser="")

    def actionrestart(self):
        """
        descriptor type :
        {
            "step" : 9,
            "action": "actionrestart"
            "targetrestart" : "AM" or "MA"
        }
        """
        try:
            if self.__terminateifcompleted__(self.workingstep):
                return
            self.__next_current_step__()  # prepare action suivante # pointe maintenant sur l tape suivante
            self.__action_completed__(self.workingstep)
            # tag this session [reload session] and [execute etape] newly
            # currente step.
            self.__set_backtoworksession__()

            if not ('targetrestart' in self.workingstep and self.workingstep['targetrestart']=="AM"):
                self.workingstep['targetrestart'] = "MA"

            # rewrite session
            objsession = self.objectxmpp.session.sessionfromsessiondata(
                self.sessionid)
            objsession.setdatasession(self.datasend)
            # Restart machine based on OS
            self.steplog()

            if self.workingstep['targetrestart']=="AM":
                #restart Agent Machine
                self.objectxmpp.xmpplog('[%s]-[%s]: Restart machine agent' % (self.data['name'], self.workingstep['step']),
                                        type='deploy',
                                        sessionname=self.sessionid,
                                        priority=self.workingstep['step'],
                                        action="xmpplog",
                                        who=self.objectxmpp.boundjid.bare,
                                        how="",
                                        why=self.data['name'],
                                        module="Deployment | Error | Execution",
                                        date=None,
                                        fromuser=self.data['login'],
                                        touser="")
                self.objectxmpp.restartBot()
            else:
                #restart Machine
                self.objectxmpp.xmpplog('[%s]-[%s]: Restart machine' % (self.data['name'], self.workingstep['step']),
                                        type='deploy',
                                        sessionname=self.sessionid,
                                        priority=self.workingstep['step'],
                                        action="xmpplog",
                                        who=self.objectxmpp.boundjid.bare,
                                        how="",
                                        why=self.data['name'],
                                        module="Deployment | Error | Execution",
                                        date=None,
                                        fromuser=self.data['login'],
                                        touser="")
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
            logging.getLogger().error(str(e))
            logger.error("\n%s"%(traceback.format_exc()))
            self.terminate(-1, False, "end error in actionrestart %s step %s" %(self.workingstep['targetrestart'], self.workingstep['step']))
            self.objectxmpp.xmpplog('[%s]-[%s]: Error actionrestart : %s' % (self.data['name'], self.workingstep['step']),
                                    type = 'deploy',
                                    sessionname = self.sessionid,
                                    priority = self.workingstep['step'],
                                    action = "xmpplog",
                                    who = self.objectxmpp.boundjid.bare,
                                    how = "",
                                    why = self.data['name'],
                                    module = "Deployment | Error | Execution",
                                    date = None ,
                                    fromuser = self.data['login'],
                                    touser = "")

    def actioncleaning(self):
        self.objectxmpp.xmpplog('[%s] Cleaning package' % (self.data['name']),
                                type='deploy',
                                sessionname=self.sessionid,
                                priority=self.workingstep['step'],
                                action="xmpplog",
                                who=self.objectxmpp.boundjid.bare,
                                how="",
                                why=self.data['name'],
                                module="Deployment | Error | Execution",
                                date=None,
                                fromuser=self.data['login'],
                                touser="")
        try:
            if self.__terminateifcompleted__(self.workingstep):
                return
            self.__action_completed__(self.workingstep)
            if managepackage.packagedir(
            ) in self.datasend['data']['pathpackageonmachine']:
                os.chdir(managepackage.packagedir())
                if sys.platform.startswith('win'):
                    print "supprime file %s "
                    print "rmdir /s /q \"%s\"" % self.datasend['data']['pathpackageonmachine']
                    os.system("rmdir /s /q \"%s\"" %
                              self.datasend['data']['pathpackageonmachine'])
                else:
                    os.system("rm -Rf %s" %
                              self.datasend['data']['pathpackageonmachine'])
                self.objectxmpp.xmpplog('[%s]-[%s]: Deleting package file from machine' % (self.data['name'], self.workingstep['step']),
                                        type='deploy',
                                        sessionname=self.sessionid,
                                        priority=self.workingstep['step'],
                                        action="xmpplog",
                                        who=self.objectxmpp.boundjid.bare,
                                        how="",
                                        why=self.data['name'],
                                        module="Deployment | Error | Execution",
                                        date=None,
                                        fromuser=self.data['login'],
                                        touser="")
            self.steplog()
            self.__Etape_Next_in__()
        except Exception as e:
            logging.getLogger().error(str(e))
            logger.error("\n%s"%(traceback.format_exc()))
            self.terminate(-1, False, "end error in actioncleaning step %s" %
                           self.workingstep['step'])
            self.objectxmpp.xmpplog('[%s]-[%s]: Error in actioncleaning step' % (self.data['name'], self.workingstep['step']),
                                    type = 'deploy',
                                    sessionname=self.sessionid,
                                    priority=self.workingstep['step'],
                                    action="xmpplog",
                                    who=self.objectxmpp.boundjid.bare,
                                    how="",
                                    why=self.data['name'],
                                    module="Deployment | Error | Execution",
                                    date=None,
                                    fromuser=self.data['login'],
                                    touser="")
    # WIP
    def getpackagemanager(self):
        """
            This function helps to find the update manager
            depending on the linux distribution.
        """
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

    def __alternatefolder(self):
        if 'packageuuid' in self.workingstep:
            self.workingstep['packageuuid'] = self.replaceTEMPLATE(
                self.workingstep['packageuuid'])
            directoryworking = os.path.join(managepackage.packagedir(),
                                            self.workingstep['packageuuid'])
            if os.path.isdir(directoryworking):
                os.chdir(directoryworking)
                self.workingstep['pwd'] = os.getcwd()
                self.objectxmpp.xmpplog('[%s]-[%s]: Using package folder %s' % (self.data['name'],
                                                                                self.workingstep['step'],
                                                                                self.workingstep['packageuuid']),
                                        type='deploy',
                                        sessionname=self.sessionid,
                                        priority=self.workingstep['step'],
                                        action="xmpplog",
                                        who=self.objectxmpp.boundjid.bare,
                                        how="",
                                        why=self.data['name'],
                                        module="Deployment | Execution | Warning",
                                        date=None,
                                        fromuser=self.data['login'],
                                        touser="")
            else:
                self.objectxmpp.xmpplog('[%s]-[%s]: Warning : Requested package '\
                                        'directory missing!!!:  %s' % (self.data['name'],
                                                                       self.workingstep['step'],
                                                                       self.workingstep['packageuuid']),
                                        type='deploy',
                                        sessionname=self.sessionid,
                                        priority=self.workingstep['step'],
                                        action="xmpplog",
                                        who=self.objectxmpp.boundjid.bare,
                                        how="",
                                        why=self.data['name'],
                                        module="Deployment | Execution | Warning",
                                        date=None,
                                        fromuser=self.data['login'],
                                        touser="")
        self.workingstep['pwd'] = os.getcwd()
        self.objectxmpp.xmpplog('[%s]-[%s]: Current directory %s' % (self.data['name'],
                                                                     self.workingstep['step'],
                                                                     self.workingstep['pwd']),
                                type='deploy',
                                sessionname=self.sessionid,
                                priority=self.workingstep['step'],
                                action="xmpplog",
                                who=self.objectxmpp.boundjid.bare,
                                how="",
                                why=self.data['name'],
                                module="Deployment | Execution",
                                date=None,
                                fromuser=self.data['login'],
                                touser="")

    def action_download(self):
        """
        {
            "action": "action_download",
            "actionlabel": "74539906",
            "fullpath": "",
            "step": 0,
            "url": "https://github.com/notepad-plus-plus/notepad-plus-plus/releases/download/v7.8.9/npp.7.8.9.Installer.exe",
            "packageuuid" : ""
        }
        """
        try:
            if self.__terminateifcompleted__(self.workingstep):
                return
            self.__action_completed__(self.workingstep)
            self.workingstep['pwd'] = ""
            if os.path.isdir(self.datasend['data']['pathpackageonmachine']):
                os.chdir(self.datasend['data']['pathpackageonmachine'])
                self.workingstep['pwd'] = os.getcwd()
            self.__alternatefolder()

            msg = '[%s]-[%s]: Downloading file %s' % (self.data['name'],
                                                      self.workingstep['step'],
                                                      self.workingstep['url'])
            self.objectxmpp.xmpplog(msg,
                                    type='deploy',
                                    sessionname=self.sessionid,
                                    priority=self.workingstep['step'],
                                    action="xmpplog",
                                    who=self.objectxmpp.boundjid.bare,
                                    why=self.data['name'],
                                    module="Deployment | Error | Execution",
                                    date=None,
                                    fromuser=self.data['login'])
            result, txtmsg = downloadfile(self.workingstep['url']).downloadurl()

            if result:
                self.objectxmpp.xmpplog('[%s]-[%s] : %s %s' % (self.data['name'],
                                                               self.workingstep['step'],
                                                               txtmsg,
                                                               self.workingstep['url']),
                                        type='deploy',
                                        sessionname=self.sessionid,
                                        priority=self.workingstep['step'],
                                        action="xmpplog",
                                        who=self.objectxmpp.boundjid.bare,
                                        why=self.data['name'],
                                        module="Deployment | Execution",
                                        date=None,
                                        fromuser=self.data['login'])
                if 'succes' in self.workingstep:
                    # goto succes
                    self.__search_Next_step_int__(self.workingstep['succes'])
                    self.__execstep__()
                    return
            else:
                self.objectxmpp.xmpplog('[%s]-[%s] : %s %s' % (self.data['name'],
                                                               self.workingstep['step'],
                                                               txtmsg,
                                                               self.workingstep['url']),
                                        type='deploy',
                                        sessionname=self.sessionid,
                                        priority=self.workingstep['step'],
                                        action="xmpplog",
                                        who=self.objectxmpp.boundjid.bare,
                                        why=self.data['name'],
                                        module="Deployment | Execution",
                                        date=None,
                                        fromuser=self.data['login'])
                if 'error' in self.workingstep:
                    self.__search_Next_step_int__(self.workingstep['error'])
                    self.__execstep__()
                    return
                self.objectxmpp.xmpplog('[%s]-[%s] : Error downloading file but proceeding to next step %s' % (self.data['name'],
                                                                                               self.workingstep['step'],
                                                                                               txtmsg),
                                        type='deploy',
                                        sessionname=self.sessionid,
                                        priority=self.workingstep['step'],
                                        action="xmpplog",
                                        who=self.objectxmpp.boundjid.bare,
                                        why=self.data['name'],
                                        module="Deployment | Execution",
                                        date=None,
                                        fromuser=self.data['login'])
            self.steplog()
            self.__Etape_Next_in__()
        except Exception as e:
            logging.getLogger().error(str(e))
            logger.error("\n%s" % (traceback.format_exc()))
            self.terminate(-1, False, "Transfer error %s" %
                           self.workingstep['step'])
            self.objectxmpp.xmpplog('[%s]-[%s]: Transfer error' % (self.data['name'], self.workingstep['step']),
                                    type='deploy',
                                    sessionname=self.sessionid,
                                    priority=self.workingstep['step'],
                                    action="xmpplog",
                                    who=self.objectxmpp.boundjid.bare,
                                    why=self.data['name'],
                                    module="Deployment | Error | Execution",
                                    date=None,
                                    fromuser=self.data['login'])
