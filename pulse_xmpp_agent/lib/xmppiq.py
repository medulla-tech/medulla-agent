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
#
# file pulse_xmpp_agent/lib/xmppiq.py
#

import os, sys, platform
import json
import logging
from utils import   shellcommandtimeout, \
                    file_put_contents, \
                    file_get_contents, \
                    file_put_contents_w_a, \
                    decode_strconsole, \
                    encode_strconsole, \
                    keypub, \
                    showlinelog, \
                    simplecommand \
                    sshdup \
                    restartsshd

from  agentconffile import  directoryconffile
from shutil import copyfile, move
import datetime
import zlib
import re
import base64
import traceback
import uuid
import subprocess
from lib.managepackage import managepackage
from lib.update_remote_agent import Update_Remote_Agent
from utils_psutil import sensors_battery,\
                         winservices,\
                         clone_ps_aux,\
                         disk_usage,\
                         sensors_fans,\
                         mmemory,\
                         ifconfig,\
                         cpu_num,\
                         netstat,\
                         cputimes
from lib.update_remote_agent import agentinfoversion
if sys.platform.startswith('win'):
    import win32net
    import win32security
    import win32serviceutil

DEBUGPULSE = 25
logger = logging.getLogger()
def callXmppFunctionIq(functionname,  *args, **kwargs):
    logger.debug("**call function %s %s %s"%(functionname, args, kwargs))
    return getattr(functionsynchroxmpp,functionname)(*args, **kwargs)

def dispach_iq_command(xmppobject, jsonin):
    """
        this function doit retourner un json string
    """
    data = json.loads(jsonin)

    # functions synch list
    listactioncommand = ["xmppbrowsing",
                         "test",
                         "remotefile",
                         "remotecommandshell",
                         "listremotefileedit",
                         "remotefileeditaction",
                         "remotexmppmonitoring",
                         "keypub",
                         "information",
                         "keyinstall"]
    if data['action'] in listactioncommand:
        logging.log(DEBUGPULSE,"call function %s "%data['action'] )
        result = callXmppFunctionIq(data['action'],  xmppobject = xmppobject, data = data )
        if type(result) != str:
            logging.getLogger().warning("function %s not return str json"%data['action'])
        return result
    else:
        logging.log(DEBUGPULSE,"function %s missing in list listactioncommand"%data['action'] )
        return ""


class functionsynchroxmpp:
    """
        this function must return json string
    """
    @staticmethod
    def xmppbrowsing(xmppobject , data  ):
        logger.debug("iq xmppbrowsing")
        return json.dumps(data)

    @staticmethod
    def test( xmppobject, data):
        logger.debug("iq test")
        return json.dumps(data)

    @staticmethod
    def remotefilesimple( xmppobject, data ):
        logger.debug("iq remotefilesimple")
        datapath = data['data']
        if type(datapath) == unicode or type(datapath) == str:
            datapath = str(data['data'])
            filesystem = xmppobject.xmppbrowsingpath.listfileindir(datapath)
            data['data']=filesystem
        return json.dumps(data)

    @staticmethod
    def remotefile( xmppobject, data ):
        logger.debug("iq remotefile")
        datapath = data['data']
        if isinstance(datapath, basestring):
            datapath = str(data['data'])
            filesystem = xmppobject.xmppbrowsingpath.listfileindir(datapath)
            data['data']=filesystem
            try:
                datastr = json.dumps(data)
            except Exception as e:
                try:
                    datastr = json.dumps(data, encoding="latin1")
                except Exception as e:
                    logging.getLogger().error("synchro xmpp function remotefile : %s"%str(e))
                    return ""
        else:
            return ""
        try:
            result = base64.b64encode( zlib.compress(datastr, 9))
        except Exception as e:
            logging.getLogger().error("synchro xmpp function remotefile  encodage: %s"%str(e))
        return result

    @staticmethod
    def remotecommandshell( xmppobject, data ):
        logger.debug("iq remotecommandshell")
        result = shellcommandtimeout(encode_strconsole(data['data']), timeout=data['timeout']).run()
        re = [ decode_strconsole(x).strip(os.linesep)+"\n" for x in result['result'] ]
        result['result'] = re
        return json.dumps(result)

    @staticmethod
    def keypub( xmppobject, data ):
        logger.debug("iq keypub")
        # verify relayserver
        try:
            result =  { "result" : { "key" : keypub() }, "error" : False , 'numerror' : 0 }
        except Exception:
            result =  { "result" : { "key" : "" }, "error" : True , 'numerror' : 2 }
        return json.dumps(result)

    @staticmethod
    def keyinstall(xmppobject, data):
        restartsshd()
        try:
            msgaction=[]
            #logger.debug("error format message : %s"%(json.dumps(data, indent = 4)))
            if not 'keyinstall' in data["action"]:
                logger.error("error format message : %s"%(json.dumps(data, indent = 4)))
                data['action'] = "resultkeyinstall"
                data['ret'] = 20
                data['data']["msg_error"] = ["error format message"]
                return json.dumps(data, indent = 4)
            #install keypub on AM
            if sys.platform.startswith('linux'):
                import pwd
                import grp
                #verify compte pulse exist
                try:
                    uid = pwd.getpwnam("pulseuser").pw_uid
                    gid = grp.getgrnam("pulseuser").gr_gid
                    gidroot = grp.getgrnam("root").gr_gid
                    logger.debug("compte pulseuser  uuid %s\n gid %s\ngidroot %s"%(uid, gid, gidroot ))
                    msgaction.append("compte pulseuser  uuid %s\n gid %s\ngidroot %s"%(uid, gid, gidroot ))
                except Exception:
                    #le compte n'existe pas
                    logger.debug("Creation compte pulse user")
                    msgaction.append("Creation compte pulse user")
                    result = simplecommand(encode_strconsole("adduser --system --group --home /var/lib/pulse2 '\
                        '--shell /bin/rbash --disabled-password pulseuser"))
                uid = pwd.getpwnam("pulseuser").pw_uid
                gid = grp.getgrnam("pulseuser").gr_gid
                gidroot = grp.getgrnam("root").gr_gid

                authorized_keys_path = os.path.join(os.path.expanduser('~pulseuser'), '.ssh', 'authorized_keys')
                logger.debug("file authorized_keys is %s"%authorized_keys_path)
                msgaction.append("file authorized_keys is %s"%authorized_keys_path)
                if not os.path.isdir(os.path.dirname(authorized_keys_path)):
                    os.makedirs(os.path.dirname(authorized_keys_path), 0700)

                if not os.path.isfile(authorized_keys_path):
                    file_put_contents(authorized_keys_path,"")

                os.chown(os.path.dirname(authorized_keys_path), uid, gid)
                os.chown(authorized_keys_path, uid, gid)
                os.chown(authorized_keys_path, uid, gid)
                packagepath = os.path.join(os.path.expanduser('~pulseuser'), 'packages')
                pathuser = os.path.join(os.path.expanduser('~pulseuser'))
                if not os.path.isdir(pathuser):
                    os.chmod(pathuser, 751)
                if not os.path.isdir(packagepath):
                    os.makedirs(packagepath, 0764)
                os.chown(packagepath, uid, gidroot)
                os.chmod(os.path.dirname(authorized_keys_path), 0700)
                os.chmod(authorized_keys_path, 0644)
                os.chmod(packagepath, 0764)
                result = simplecommand(encode_strconsole("chown -R pulseuser: '/var/lib/pulse'"))
            elif sys.platform.startswith('win'):
                # check if pulse account exists
                try:
                    win32net.NetUserGetInfo('','pulse',0)
                    booluser = "pulse"
                except Exception:
                    booluser = "pulseuser"

                if booluser != "pulse":
                    # traitement si user pulseuser
                    try:
                        win32net.NetUserGetInfo('','pulseuser',0)
                    except Exception:
                        #user ni pulse, ni pulseuser il faut faire la creation du compte et du profile
                        # pulse account doesn't exist. Create it
                        logger.warning("Pulse user account does not exist. Creating it.")
                        msgaction.append("Pulse user account does not exist. Creating it.")
                        pulseuserpassword = uuid.uuid4().hex[:14]
                        result = simplecommand(encode_strconsole('net user "pulseuser" "%s" /ADD /COMMENT:"Pulse '\
                            'user with admin rights on the system"' % pulseuserpassword))
                        logger.info("Creation of pulse user: %s" %result)
                        msgaction.append("Creation of pulse user: %s" %result)
                        result = simplecommand(encode_strconsole('powershell -inputformat none -ExecutionPolicy RemoteSigned -Command'\
                            ' "Import-Module .\script\create-profile.ps1; New-Profile -Account pulseuser"'))
                        logger.info("Creation of pulseuser profile: %s" %result)
                        msgaction.append("Creation of pulseuser profile: %s" %result)
                        result = simplecommand(encode_strconsole('wmic useraccount where "Name=\'pulseuser\'" set PasswordExpires=False'))
                        adminsgrpsid = win32security.ConvertStringSidToSid('S-1-5-32-544')
                        adminsgroup = win32security.LookupAccountSid('',adminsgrpsid)[0]
                        result = simplecommand(encode_strconsole('net localgroup %s "pulseuser" /ADD' % adminsgroup))
                        logger.info("Adding pulseuser to administrators group: %s" %result)
                        msgaction.append("Adding pulseuser to administrators group: %s" %result)
                        # Reconfigure SSH server
                        logger.info("Reconfiguring ssh server for using keys in pulseuser account")
                        msgaction.append("Reconfiguring ssh server for using keys in pulseuser account")
                        sshdconfigfile = os.path.join(os.environ["ProgramFiles"], 'OpenSSH', 'sshd_config')
                        if os.path.isfile(sshdconfigfile):
                            with open(sshdconfigfile) as infile:
                                with open('sshd_config', 'w') as outfile:
                                    for line in infile:
                                        if line.startswith('AuthorizedKeysFile'):
                                            outfile.write('#' + line)
                                        else:
                                            outfile.write(line)
                            move('sshd_config', sshdconfigfile)
                            currentdir = os.getcwd()
                            os.chdir(os.path.join(os.environ["ProgramFiles"], 'OpenSSH'))
                            result = simplecommand(encode_strconsole('powershell '\
                                '-ExecutionPolicy Bypass -Command ". '\
                                '.\FixHostFilePermissions.ps1 -Confirm:$false"'))
                            os.chdir(currentdir)
                            win32serviceutil.StopService('sshd')
                            win32serviceutil.StopService('ssh-agent')
                            win32serviceutil.StartService('ssh-agent')
                            win32serviceutil.StartService('sshd')
                    # on configure le compte pulseuser
                    logger.info("Creating authorized_keys file in pulseuser account")
                    msgaction.append("Creating authorized_keys file in pulseuser account")
                    authorized_keys_path = os.path.join("c:\Users\pulseuser", '.ssh','authorized_keys' )
                    if not os.path.isdir(os.path.dirname(authorized_keys_path)):
                        os.makedirs(os.path.dirname(authorized_keys_path), 0700)
                    if not os.path.isfile(authorized_keys_path):
                        file_put_contents(authorized_keys_path,"")
                    currentdir = os.getcwd()
                    os.chdir(os.path.join(os.environ["ProgramFiles"], 'OpenSSH'))
                    result = simplecommand(encode_strconsole('powershell -ExecutionPolicy Bypass -Command ". '\
                        '.\FixHostFilePermissions.ps1 -Confirm:$false"'))
                    os.chdir(currentdir)
                    logger.info("Reset of permissions on ssh keys and folders: %s" %result)
                    msgaction.append("Reset of permissions on ssh keys and folders: %s" %result)
                else:
                    # user pulse sans profile user
                    # les informations sont dans "ProgramFiles"], "Pulse"
                    pathcompte = os.path.join(os.environ["ProgramFiles"], "Pulse")
                    process = subprocess.Popen( "wmic useraccount where name='pulse' get sid",
                                                shell=True,
                                                stdout=subprocess.PIPE,
                                                stderr=subprocess.STDOUT)
                    output = process.stdout.readlines()
                    sid = output[1].rstrip(' \t\n\r')
                    logger.info("SID compte Pulse : %s "%sid)
                    msgaction.append("path compte is  pathcompte : %s "%pathcompte)
                    logger.info("path compte is  pathcompte : %s "%pathcompte)
                    msgaction.append("path compte is  pathcompte : %s "%pathcompte)
                    cmd = 'REG ADD "HKLM\Software\Microsoft\Windows NT\CurrentVersion\ProfileList\%s" '\
                        '/v "ProfileImagePath" /t REG_SZ  /d "%s" /f'%(sid,
                                                                    pathcompte)
                    result = simplecommand(encode_strconsole(cmd))
                    logger.info("Creating authorized_keys file in pulse account")
                    msgaction.append("Creating authorized_keys file in pulse account")
                    authorized_keys_path = os.path.join(os.environ["ProgramFiles"],
                                                        "pulse",
                                                        '.ssh',
                                                        'authorized_keys' )
                    # creation if no exist
                    if not os.path.isdir(os.path.dirname(authorized_keys_path)):
                        os.makedirs(os.path.dirname(authorized_keys_path), 0700)
                    if not os.path.isfile(authorized_keys_path):
                        file_put_contents(authorized_keys_path,"")

                    currentdir = os.getcwd()
                    os.chdir(os.path.join(os.environ["ProgramFiles"], 'OpenSSH'))
                    result = simplecommand(encode_strconsole('powershell -ExecutionPolicy Bypass -Command ". '\
                        '.\FixHostFilePermissions.ps1 -Confirm:$false"'))
                    os.chdir(currentdir)
                    logger.info("Reset of permissions on ssh keys and folders: %s" %result)
                    msgaction.append("Reset of permissions on ssh keys and folders: %s" %result)
            elif sys.platform.startswith('darwin'):
                authorized_keys_path = os.path.join(os.path.join(os.path.expanduser('~pulseuser'),
                                                                '.ssh',
                                                                'authorized_keys') )
            else:
                return

            # instal key dans authorized_keys
            authorized_keys_content = file_get_contents(authorized_keys_path)
            if not data['data']['key'].strip(' \t\n\r') in authorized_keys_content:
                # add en append la key dans le fichier
                file_put_contents_w_a( authorized_keys_path, "\n"+ data['data']['key'], "a" )
                logger.debug("install key ARS [%s]"%data['data']['from'])
                msgaction.append('INSTALL key ARS %s on machine %s'%(data['data']['from'],
                                                                xmppobject.boundjid.bare))
                xmppobject.xmpplog( 'Installing ARS key %s on machine %s'%(data['data']['from'],
                                                                xmppobject.boundjid.bare),
                                    type = 'deploy',
                                    sessionname = data['data']["sessionid"],
                                    priority = -1,
                                    action = "xmpplog",
                                    who = xmppobject.boundjid.bare,
                                    how = "",
                                    why = "",
                                    module = "Deployment | Cluster | Notify",
                                    date = None ,
                                    fromuser = "",
                                    touser = "")
            else:
                xmppobject.xmpplog( 'Relay key %s is present on machine %s'%(data['data']['from'],
                                                        xmppobject.boundjid.bare),
                                    type = 'deploy',
                                    sessionname = data['data']["sessionid"],
                                    priority = -1,
                                    action = "xmpplog",
                                    who = xmppobject.boundjid.bare,
                                    how = "",
                                    why = "",
                                    module = "Deployment | Cluster | Notify",
                                    date = None ,
                                    fromuser = "",
                                    touser = "")
                logger.warning("key ARS [%s] : is already installed."%data['data']['from'])
                msgaction.append("key ARS [%s] : is already installed."%data['data']['from'])
            ####### jfkjfk
            data['action'] = "resultkeyinstall"
            data['ret'] = 0
            data['data'] = { "msg_action" : msgaction}
            return json.dumps(data, indent = 4)
        except Exception:
            data['action'] = "resultkeyinstall"
            data['ret'] = 255
            msgaction.append("%s"%(traceback.format_exc()))
            data['data']["msg_error"] = msgaction
            resltatreturn = json.dumps(data, indent = 4)
            logger.error("iq install key %s"%resltatreturn)
            return resltatreturn

    @staticmethod
    def information( xmppobject, data ):
        logger.debug("iq information")
        result =  { "result" : { "informationresult" : {} }, "error" : False , 'numerror' : 0 }
        for info_ask in data['data']['listinformation']:
            try:
                if info_ask == "keypub":
                    result['result']['informationresult'] [info_ask] = keypub()
                if info_ask == "os":
                    result['result']['informationresult'] [info_ask] = sys.platform
                if info_ask == "os_version":
                    result['result']['informationresult'] [info_ask] = platform.platform()
                if info_ask == "folders_packages":
                    result['result']['informationresult'] [info_ask] = managepackage.packagedir()
                if info_ask == "invent_xmpp":
                    result['result']['informationresult'] [info_ask] = xmppobject.seachInfoMachine()
                if info_ask == "battery":
                    result['result']['informationresult'] [info_ask] = decode_strconsole(sensors_battery())
                if info_ask == "winservices":
                    result['result']['informationresult'] [info_ask] = decode_strconsole(winservices())
                if info_ask == "clone_ps_aux":
                    result['result']['informationresult'] [info_ask] = decode_strconsole(clone_ps_aux())
                if info_ask == "disk_usage":
                    result['result']['informationresult'] [info_ask] = decode_strconsole(disk_usage())
                if info_ask == "sensors_fans":
                    result['result']['informationresult'] [info_ask] = decode_strconsole(sensors_fans())
                if info_ask == "mmemory":
                    result['result']['informationresult'] [info_ask] = decode_strconsole(mmemory())
                if info_ask == "ifconfig":
                    result['result']['informationresult'] [info_ask] = decode_strconsole(ifconfig())
                if info_ask == "cpu_num":
                    result['result']['informationresult'] [info_ask] = decode_strconsole(cpu_num())
                if info_ask == "netstat":
                    result['result']['informationresult'] [info_ask] = decode_strconsole(netstat())
                if info_ask == "profiluserpulse":
                    profilname='pulseuser'
                    if sys.platform.startswith('win'):
                        # check if pulse account exists
                        try:
                            win32net.NetUserGetInfo('','pulseuser', 0)
                            profilname='pulseuser'
                        except Exception:
                            profilname='pulse'
                    result['result']['informationresult'] [info_ask] = profilname
            except Exception:
                result['result']['informationresult'] [info_ask] = ""
        return json.dumps(result)

    @staticmethod
    def listremotefileedit( xmppobject, data ):
        logger.debug("iq listremotefileedit")
        listfileedit = [ x for x in os.listdir(directoryconffile()) if x.endswith(".ini")]
        data['data']={"result" : listfileedit}
        return json.dumps(data)

    @staticmethod
    def remotexmppmonitoring( xmppobject, data ):
        logger.debug("iq remotexmppmonitoring")
        result = ""
        if data['data'] == "battery":
            result = decode_strconsole(sensors_battery())
        elif data['data'] == "winservices":
            result = decode_strconsole(winservices())
        elif data['data'] == "clone_ps_aux":
            result = decode_strconsole(clone_ps_aux())
        elif data['data'] == "disk_usage":
            result = decode_strconsole(disk_usage())
        elif data['data'] == "sensors_fans":
            result = decode_strconsole(sensors_fans())
        elif data['data'] == "mmemory":
            result = decode_strconsole(mmemory())
        elif data['data'] == "ifconfig":
            result = decode_strconsole(ifconfig())
        elif data['data'] == "cpu_num":
            result = decode_strconsole(cpu_num())
        elif data['data'] == "agentinfos":
            # on doit verifie que l'image existe.
            descriptorimage = Update_Remote_Agent(xmppobject.img_agent)
            result = decode_strconsole(agentinfoversion(xmppobject))
        elif data['data'] == "netstat":
            result = decode_strconsole(netstat())
            result = re.sub("[ ]{2,}", "@", result)
        else:
            datastruct = json.loads(data['data'])
            if 'subaction' in datastruct:
                result = functionsynchroxmpp.__execfunctionmonitoringparameter(datastruct)
        result = base64.b64encode(zlib.compress(result, 9))
        data['result'] = result
        return json.dumps(data)

    @staticmethod
    def __execfunctionmonitoringparameter(data):
        result=""
        try:
            if  data['subaction'] == "cputimes":
                func = getattr(sys.modules[__name__], data['subaction'])
                result = decode_strconsole(json.dumps(func(*data['args'], **data['kwargs'])))
                return result
            elif data['subaction'] == "litlog":
                func = getattr(sys.modules[__name__], "showlinelog")
                result = decode_strconsole(json.dumps(func(*data['args'], **data['kwargs'])))
                return result
            else:
                return ""
        except Exception as e:
            print str(e)
            traceback.print_exc(file=sys.stdout)
            return ""

    @staticmethod
    def remotefileeditaction( xmppobject, data ):
        logger.debug("iq remotefileeditaction")
        if 'data' in data and 'action' in data['data']:
            if data['data']['action'] == 'loadfile':
                if 'file' in data['data']:
                    filename = os.path.join(directoryconffile(), data['data']['file'])
                    if os.path.isfile(filename):
                        filedata = file_get_contents(filename)
                        data['data'] = { "result" : filedata, "error" : False , 'numerror' : 0  }
                        return json.dumps(data)
                    else:
                        data['data'] = { "result" : "error file missing",  "error" : True , 'numerror' : 128}
                else:
                    data['data'] = { "result" : "error name file missing" }
            elif data['data']['action'] == 'create':
                if 'file' in data['data'] and data['data']['file'] != "" and 'content' in data['data']:
                    filename = os.path.join(directoryconffile(), data['data']['file'])
                    file_put_contents(filename,  data['data']['content'])
                    data['data'] = { "result" : "create file %s"%filename, "error" : False , 'numerror' : 0 }
                    return json.dumps(data)
                else:
                    data['data'] = { "result" : "error create file : name file missing", "error" : True , 'numerror' : 129 }
            elif data['data']['action'] == 'save':
                if 'file' in data['data'] and data['data']['file'] != "" \
                        and 'content' in data['data']:
                    filename = os.path.join(directoryconffile(), data['data']['file'])
                    if os.path.isfile(filename):
                        #datestr = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")+".ini"
                        #newfilename = filename[:-4] + "_" + datestr
                        #copyfile(filename, newfilename)
                        file_put_contents(filename,  data['data']['content'])
                        data['data'] = { "result" : "save file %s"%filename, "error" : False , 'numerror' : 0 }
                        return json.dumps(data)
                    else:
                        data['data'] = { "result" : "error save config file %s missing"%filename, "error" : True , 'numerror' : 130 }
            elif data['data']['action'] == 'listconfigfile':
                listfileedit = [ x for x in os.listdir(directoryconffile()) if (x.endswith(".ini") or x.endswith(".ini.local"))]
                data['data'] = { "result" : listfileedit, "error" : False , 'numerror' : 0 }
                return json.dumps(data)
            else:
                data['data'] = { "result" : "error the action parameter is not correct ", "error" : True , 'numerror' : 131 }
        else:
            data['data'] = { "result" : "error action remotefileeditaction parameter incorrect", "error" : True , 'numerror' : 132 }
        return json.dumps(data)
