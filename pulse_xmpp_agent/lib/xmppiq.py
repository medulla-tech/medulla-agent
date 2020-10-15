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
import time
import shlex
from utils import   shellcommandtimeout, \
                    file_put_contents, \
                    file_get_contents, \
                    file_put_contents_w_a, \
                    decode_strconsole, \
                    encode_strconsole, \
                    keypub, \
                    simplecommand, \
                    restartsshd, \
                    install_key_ssh_relayserver, \
                    showlinelog
import socket
from  agentconffile import  directoryconffile
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


def callXmppFunctionIq(functionname, *args, **kwargs):
    logger.debug("**call function %s %s %s" % (functionname, args, kwargs))
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
                         "keyinstall",
                         "packageslist",
                         "reversesshqa",
                         "get_id_rsa"]
    if data['action'] in listactioncommand:
        logging.log(DEBUGPULSE,"call function %s " % data['action'])
        result = callXmppFunctionIq(data['action'], xmppobject=xmppobject, data=data)
        if type(result) != str:
            logging.getLogger().warning("function %s not return str json" % data['action'])
        return result
    else:
        logging.log(DEBUGPULSE,"function %s missing in list listactioncommand" % data['action'])
        return ""


def logdeploymsg(xmppobject, msg, sessionid):
    xmppobject.xmpplog(msg,
                       type='deploy',
                       sessionname=sessionid,
                       priority=-1,
                       action="xmpplog",
                       who=xmppobject.boundjid.bare,
                       module="Deployment | Cluster | Notify",
                       date=None)

class functionsynchroxmpp:
    """
        this function must return json string
    """
    @staticmethod
    def xmppbrowsing(xmppobject, data):
        logger.debug("iq xmppbrowsing")
        return json.dumps(data)


    @staticmethod
    def test(xmppobject, data):
        logger.debug("iq test")
        return json.dumps(data)


    @staticmethod
    def get_id_rsa(xmppobject, data):
        result = {}
        private_key_ars = os.path.join(os.path.expanduser('~reversessh'),
                                       '.ssh',
                                       "id_rsa")
        result['private_key_ars'] = file_get_contents(private_key_ars)
        result['public_key_ars'] = file_get_contents("%s.pub" %
                                                     private_key_ars)
        return json.dumps(result)


    @staticmethod
    def reversesshqa(xmppobject, data):
        """
            call directement plugin reverse ssh
        """
        datareverse = data['data']
        portproxy = datareverse['portproxy']
        remoteport = datareverse['remoteport']
        if 'private_key_ars' in datareverse:
            private_key_ars = datareverse['private_key_ars'].strip(' \t\n\r')
            install_key_ssh_relayserver(private_key_ars, private=True)
        if 'public_key_ars' in datareverse:
            public_key_ars = datareverse['public_key_ars'].strip(' \t\n\r')
            install_key_ssh_relayserver(public_key_ars, private=False)
        if sys.platform.startswith('linux'):
            filekey = os.path.join(os.path.expanduser('~pulseuser'), ".ssh", "id_rsa")
            dd = """#!/bin/bash
            /usr/bin/ssh -t -t -%s 0.0.0.0:%s:localhost:%s -o StrictHostKeyChecking=no -i "%s" -l reversessh %s -p %s&
            """ % (datareverse['type_reverse'],
                   datareverse['portproxy'],
                   datareverse['remoteport'],
                   filekey,
                   datareverse['ipARS'],
                   datareverse['port_ssh_ars'])
            reversesshsh = os.path.join(os.path.expanduser('~pulseuser'),
                                        "reversessh.sh")
            file_put_contents(reversesshsh, dd)
            os.chmod(reversesshsh, 0o700)
            args = shlex.split(reversesshsh)
            result = subprocess.Popen(args)
            logger.debug("Command reversessh %s" % dd)
            #/usr/bin/ssh -t -t -R 36591:localhost:22 -o StrictHostKeyChecking=no -i /var/lib/pulse2/.ssh/id_rsa -l reversessh 212.83.136.107 -p 22
        elif sys.platform.startswith('win'):
            ################# win reverse #################
            try:
                win32net.NetUserGetInfo('', 'pulseuser', 0)
                filekey = os.path.join("C:\\",
                                       "Users",
                                       "pulseuser",
                                       ".ssh",
                                       "id_rsa")
            except Exception:
                filekey = os.path.join(os.environ["ProgramFiles"],
                                       'pulse',
                                       ".ssh",
                                       "id_rsa")

            sshexec = os.path.join(os.environ["ProgramFiles"],
                                   "OpenSSH",
                                   "ssh.exe")
            reversesshbat = os.path.join(os.environ["ProgramFiles"],
                                         "Pulse",
                                         "bin",
                                         "reversessh.bat")
            linecmd = []
            cmd = """\\"%s\\" -t -t -%s 0.0.0.0:%s:localhost:%s -o StrictHostKeyChecking=no -i \\"%s\\" -l reversessh %s -p %s""" % (sshexec,
                                                                                                                             datareverse['type_reverse'],
                                                                                                                             datareverse['portproxy'],
                                                                                                                             datareverse['remoteport'],
                                                                                                                             filekey,
                                                                                                                             datareverse['ipARS'],
                                                                                                                             datareverse['port_ssh_ars'])
            linecmd.append("""@echo off""")
            linecmd.append("""for /f "tokens=2 delims==; " %%%%a in (' wmic process call create "%s" ^| find "ProcessId" ') do set "$PID=%%%%a" """ % cmd)
            linecmd.append("""echo %$PID%""")
            linecmd.append("""echo %$PID% > C:\\"Program Files"\\Pulse\\bin\\%$PID%.pid""")
            cmd = '\r\n'.join(linecmd)

            if not os.path.exists(os.path.join(os.environ["ProgramFiles"],
                                               "Pulse",
                                               "bin")):
                os.makedirs(os.path.join(os.environ["ProgramFiles"],
                                         "Pulse",
                                         "bin"))
            file_put_contents(reversesshbat,  cmd)
            result = subprocess.Popen(reversesshbat)
            time.sleep(2)
        elif sys.platform.startswith('darwin'):
            filekey = os.path.join(os.path.expanduser('~pulseuser'),
                                   ".ssh",
                                   "id_rsa")
            cmd = """#!/bin/bash
            /usr/bin/ssh -t -t -%s 0.0.0.0:%s:localhost:%s -o StrictHostKeyChecking=no -i "%s" -l reversessh %s -p %s&
            """ % (datareverse['type_reverse'],
                   datareverse['portproxy'],
                   datareverse['remoteport'],
                   filekey,
                   datareverse['ipARS'],
                   datareverse['port_ssh_ars'])
            reversesshsh = os.path.join(os.path.expanduser('~pulseuser'),
                                        "reversessh.sh")
            file_put_contents(reversesshsh,  cmd)
            os.chmod(reversesshsh, 0o700)
            args = shlex.split(reversesshsh)
            result = subprocess.Popen(args)
        else:
            logger.warning("os not supported in plugin%s" % sys.platform)
        return json.dumps(data)


    @staticmethod
    def remotefilesimple(xmppobject, data):
        logger.debug("iq remotefilesimple")
        datapath = data['data']
        if type(datapath) == unicode or type(datapath) == str:
            datapath = str(data['data'])
            filesystem = xmppobject.xmppbrowsingpath.listfileindir(datapath)
            data['data'] = filesystem
        return json.dumps(data)


    @staticmethod
    def remotefile(xmppobject, data):
        logger.debug("iq remotefile")
        datapath = data['data']
        if isinstance(datapath, basestring):
            datapath = str(data['data'])
            filesystem = xmppobject.xmppbrowsingpath.listfileindir(datapath)
            data['data'] = filesystem
            try:
                datastr = json.dumps(data)
            except Exception as e:
                try:
                    datastr = json.dumps(data, encoding="latin1")
                except Exception as e:
                    logging.getLogger().error("synchro xmpp function remotefile : %s" % str(e))
                    return ""
        else:
            return ""
        try:
            result = base64.b64encode( zlib.compress(datastr, 9))
        except Exception as e:
            logging.getLogger().error("synchro xmpp function remotefile encoding: %s" % str(e))
        return result


    @staticmethod
    def remotecommandshell(xmppobject, data):
        logger.debug("iq remotecommandshell")
        result = shellcommandtimeout(encode_strconsole(data['data']), timeout=data['timeout']).run()
        re = [ decode_strconsole(x).strip(os.linesep)+"\n" for x in result['result'] ]
        result['result'] = re
        return json.dumps(result)


    @staticmethod
    def keypub(xmppobject, data):
        logger.debug("iq keypub")
        # verify relayserver
        try:
            result = {"result": {"key": keypub()}, "error": False, 'numerror': 0}
        except Exception:
            result = {"result": {"key": ""}, "error": True, 'numerror': 2}
        return json.dumps(result)


    @staticmethod
    def keyinstall(xmppobject, data):
        restartsshd()
        try:
            msgaction=[]
            if 'keyinstall' not in data["action"]:
                logger.error("error format message : %s" % (json.dumps(data, indent=4)))
                data['action'] = "resultkeyinstall"
                data['ret'] = 20
                data['data']["msg_error"] = ["error format message"]
                return json.dumps(data, indent=4)
            # Install keypub on AM
            if sys.platform.startswith('linux'):
                import pwd
                import grp
                reverse_ssh_key_privat_path = os.path.join(os.path.expanduser('~pulseuser'), '.ssh', 'id_rsa')
                # Check if pulseuser account exists
                try:
                    uid = pwd.getpwnam("pulseuser").pw_uid
                    gid = grp.getgrnam("pulseuser").gr_gid
                    gidroot = grp.getgrnam("root").gr_gid
                    logger.debug("compte pulseuser  uuid %s\n gid %s\ngidroot %s" % (uid, gid, gidroot))
                    msgaction.append("compte pulseuser  uuid %s\n gid %s\ngidroot %s" % (uid, gid, gidroot))
                except Exception:
                    # Account does not exist
                    logger.debug("Creation of the pulseuser account")
                    msgaction.append("Creation of the pulseuser account")
                    result = simplecommand(encode_strconsole("adduser --system --group --home /var/lib/pulse2 '\
                        '--shell /bin/rbash --disabled-password pulseuser"))
                uid = pwd.getpwnam("pulseuser").pw_uid
                gid = grp.getgrnam("pulseuser").gr_gid
                gidroot = grp.getgrnam("root").gr_gid

                authorized_keys_path = os.path.join(os.path.expanduser('~pulseuser'), '.ssh', 'authorized_keys')
                logger.debug("file authorized_keys is %s" % authorized_keys_path)
                msgaction.append("file authorized_keys is %s" % authorized_keys_path)
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
                # Check if pulse account exists
                try:
                    win32net.NetUserGetInfo('', 'pulse', 0)
                    booluser = "pulse"
                except Exception:
                    booluser = "pulseuser"

                if booluser != "pulse":
                    # If account is pulseuser
                    try:
                        win32net.NetUserGetInfo('', 'pulseuser', 0)
                    except Exception:
                        #user ni pulse, ni pulseuser il faut faire la creation du compte et du profile
                        # pulse account doesn't exist. Create it
                        logger.warning("Pulse user account does not exist. Creating it.")
                        msgaction.append("Pulse user account does not exist. Creating it.")
                        pulseuserpassword = uuid.uuid4().hex[:14]
                        result = simplecommand(encode_strconsole('net user "pulseuser" "%s" /ADD /COMMENT:"Pulse '\
                            'user with admin rights on the system"' % pulseuserpassword))
                        logger.info("Creation of pulse user: %s" % result)
                        msgaction.append("Creation of pulse user: %s" % result)
                        result = simplecommand(encode_strconsole('powershell -inputformat none -ExecutionPolicy RemoteSigned -Command'\
                            ' "Import-Module .\script\create-profile.ps1; New-Profile -Account pulseuser"'))
                        logger.info("Creation of pulseuser profile: %s" % result)
                        msgaction.append("Creation of pulseuser profile: %s" % result)
                        result = simplecommand(encode_strconsole('wmic useraccount where "Name=\'pulseuser\'" set PasswordExpires=False'))
                        adminsgrpsid = win32security.ConvertStringSidToSid('S-1-5-32-544')
                        adminsgroup = win32security.LookupAccountSid('', adminsgrpsid)[0]
                        result = simplecommand(encode_strconsole('net localgroup %s "pulseuser" /ADD' % adminsgroup))
                        logger.info("Adding pulseuser to administrators group: %s" % result)
                        msgaction.append("Adding pulseuser to administrators group: %s" % result)
                    # on configure le compte pulseuser
                    logger.info("Creating authorized_keys file in pulseuser account")
                    msgaction.append("Creating authorized_keys file in pulseuser account")
                    authorized_keys_path = os.path.join("C:", "Users", "pulseuser", '.ssh', 'authorized_keys')
                    reverse_ssh_key_privat_path = os.path.join("C:", "Users", "pulseuser", '.ssh', 'id_rsa')
                    if not os.path.isdir(os.path.dirname(authorized_keys_path)):
                        os.makedirs(os.path.dirname(authorized_keys_path), 0700)
                    if not os.path.isfile(authorized_keys_path):
                        file_put_contents(authorized_keys_path,"")
                    currentdir = os.getcwd()
                    os.chdir(os.path.join(os.environ["ProgramFiles"], 'OpenSSH'))
                    result = simplecommand(encode_strconsole('powershell -ExecutionPolicy Bypass -Command ". '\
                        '.\FixHostFilePermissions.ps1 -Confirm:$false"'))
                    os.chdir(currentdir)
                    logger.info("Reset of permissions on ssh keys and folders: %s" % result)
                    msgaction.append("Reset of permissions on ssh keys and folders: %s" % result)
                else:
                    # user pulse sans profile user
                    # les informations sont dans "ProgramFiles"], "Pulse"
                    pathcompte = os.path.join(os.environ["ProgramFiles"], "Pulse")
                    process = subprocess.Popen("wmic useraccount where name='pulse' get sid",
                                               shell=True,
                                               stdout=subprocess.PIPE,
                                               stderr=subprocess.STDOUT)
                    output = process.stdout.readlines()
                    sid = output[1].rstrip(' \t\n\r')
                    logger.info("SID compte Pulse : %s " % sid)
                    msgaction.append("path compte is  pathcompte : %s " % pathcompte)
                    logger.info("path compte is  pathcompte : %s " % pathcompte)
                    msgaction.append("path compte is  pathcompte : %s " % pathcompte)
                    cmd = 'REG ADD "HKLM\Software\Microsoft\Windows NT\CurrentVersion\ProfileList\%s" '\
                        '/v "ProfileImagePath" /t REG_SZ  /d "%s" /f' % (sid,
                                                                         pathcompte)
                    result = simplecommand(encode_strconsole(cmd))
                    logger.info("Creating authorized_keys file in pulse account")
                    msgaction.append("Creating authorized_keys file in pulse account")
                    authorized_keys_path = os.path.join(os.environ["ProgramFiles"],
                                                        "pulse",
                                                        '.ssh',
                                                        'authorized_keys')
                    reverse_ssh_key_privat_path = os.path.join(os.environ["ProgramFiles"],
                                                               "pulse",
                                                               '.ssh',
                                                               'id_rsa')

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
                    logger.info("Reset of permissions on ssh keys and folders: %s" % result)
                    msgaction.append("Reset of permissions on ssh keys and folders: %s" % result)
            elif sys.platform.startswith('darwin'):
                authorized_keys_path = os.path.join(os.path.join(os.path.expanduser('~pulseuser'),
                                                                 '.ssh',
                                                                 'authorized_keys'))
                reverse_ssh_key_privat_path = os.path.join(os.path.join(os.path.expanduser('~pulseuser'),
                                                                        '.ssh',
                                                                        'id_rsa'))
            else:
                return
            # Install private reverse ssh key if needed.
            if 'keyreverseprivatssh' in data['data']:
                install_key_ssh_relayserver(data['data']['keyreverseprivatssh'].strip(' \t\n\r'),
                                            private=True)
            # Install key in authorized_keys
            authorized_keys_content = file_get_contents(authorized_keys_path)
            if not data['data']['key'].strip(' \t\n\r') in authorized_keys_content:
                # add en append la key dans le fichier
                file_put_contents_w_a( authorized_keys_path, "\n"+ data['data']['key'], "a" )
                logger.debug("install key ARS [%s]"%data['data']['from'])
                msgaction.append('INSTALL key ARS %s on machine %s' % (data['data']['from'],
                                                                       xmppobject.boundjid.bare))
                xmppobject.xmpplog('Installing ARS key %s on machine %s' % (data['data']['from'],
                                                                            xmppobject.boundjid.bare),
                                   type='deploy',
                                   sessionname=data['data']["sessionid"],
                                   priority=-1,
                                   action="xmpplog",
                                   who=xmppobject.boundjid.bare,
                                   how="",
                                   why="",
                                   module="Deployment | Cluster | Notify",
                                   date=None,
                                   fromuser="",
                                   touser="")
            else:
                xmppobject.xmpplog('Relay key %s is present on machine %s' % (data['data']['from'],
                                                                              xmppobject.boundjid.bare),
                                   type='deploy',
                                   sessionname=data['data']["sessionid"],
                                   priority=-1,
                                   action="xmpplog",
                                   who=xmppobject.boundjid.bare,
                                   how="",
                                   why="",
                                   module="Deployment | Cluster | Notify",
                                   date=None,
                                   fromuser="",
                                   touser="")
                logger.warning("key ARS [%s] : is already installed." % data['data']['from'])
                msgaction.append("key ARS [%s] : is already installed." % data['data']['from'])
            data['action'] = "resultkeyinstall"
            data['ret'] = 0
            data['data'] = {"msg_action": msgaction}
            return json.dumps(data, indent=4)
        except Exception:
            data['action'] = "resultkeyinstall"
            data['ret'] = 255
            msgaction.append("%s" % (traceback.format_exc()))
            data['data']["msg_error"] = msgaction
            resltatreturn = json.dumps(data, indent=4)
            logger.error("iq install key %s" % resltatreturn)
            return resltatreturn

    @staticmethod
    def information( xmppobject, data ):
        logger.debug("iq information")
        result = {"result": {"informationresult": {}}, "error": False, 'numerror': 0}
        for info_ask in data['data']['listinformation']:
            try:
                if info_ask == "force_reconf":  # force reconfiguration immedialy
                    filedata=["BOOLCONNECTOR", "action_force_reconfiguration"]
                    for filename in  filedata:
                        file = open(os.path.join(os.path.dirname(os.path.realpath(__file__)),
                                                 "..", filename), "w")
                        file.close()
                        xmppobject.networkMonitor()
                    result['result']['informationresult'][info_ask] = "action force " \
                                                    "reconfiguration for"%xmppobject.boundjid.bare
                if info_ask == "keypub":
                    result['result']['informationresult'][info_ask] = keypub()
                if info_ask == "os":
                    result['result']['informationresult'][info_ask] = sys.platform
                if info_ask == "os_version":
                    result['result']['informationresult'][info_ask] = platform.platform()
                if info_ask == "folders_packages":
                    result['result']['informationresult'][info_ask] = managepackage.packagedir()
                if info_ask == "invent_xmpp":
                    result['result']['informationresult'][info_ask] = xmppobject.seachInfoMachine()
                if info_ask == "battery":
                    result['result']['informationresult'][info_ask] = decode_strconsole(sensors_battery())
                if info_ask == "winservices":
                    result['result']['informationresult'][info_ask] = decode_strconsole(winservices())
                if info_ask == "clone_ps_aux":
                    result['result']['informationresult'][info_ask] = decode_strconsole(clone_ps_aux())
                if info_ask == "disk_usage":
                    result['result']['informationresult'][info_ask] = decode_strconsole(disk_usage())
                if info_ask == "sensors_fans":
                    result['result']['informationresult'][info_ask] = decode_strconsole(sensors_fans())
                if info_ask == "mmemory":
                    result['result']['informationresult'][info_ask] = decode_strconsole(mmemory())
                if info_ask == "ifconfig":
                    result['result']['informationresult'][info_ask] = decode_strconsole(ifconfig())
                if info_ask == "cpu_num":
                    result['result']['informationresult'][info_ask] = decode_strconsole(cpu_num())
                if info_ask == "clean_reverse_ssh":
                    if xmppobject.config.agenttype in ['relayserver']:
                        #on clean les reverse ssh non utiliser
                        xmppobject.manage_persistence_reverse_ssh.terminate_reverse_ssh_not_using()
                if info_ask == "add_proxy_port_reverse":
                    if xmppobject.config.agenttype in ['relayserver']:
                        if 'param' in data['data'] and 'proxyport' in data['data']['param']:
                            xmppobject.manage_persistence_reverse_ssh.add_port(data['data']['param']['proxyport'])
                if info_ask == "get_ars_key_id_rsa":
                    private_key_ars = os.path.join(os.path.expanduser('~reversessh'),
                                                   '.ssh',
                                                   "id_rsa")
                    result['result']['informationresult'][info_ask] = file_get_contents(private_key_ars)
                if info_ask == "get_ars_key_id_rsa_pub":
                    public_key_ars = os.path.join(os.path.expanduser('~reversessh'),
                                                  '.ssh',
                                                  "id_rsa.pub")
                    result['result']['informationresult'][info_ask] = file_get_contents(public_key_ars)
                if info_ask == "get_free_tcp_port":
                    tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    tcp.bind(('', 0))
                    addr, port = tcp.getsockname()
                    tcp.close()
                    result['result']['informationresult'][info_ask] = port
                if info_ask == "netstat":
                    result['result']['informationresult'][info_ask] = decode_strconsole(netstat())
                if info_ask == "profiluserpulse":
                    profilname = 'pulseuser'
                    if sys.platform.startswith('win'):
                        # check if pulse account exists
                        try:
                            win32net.NetUserGetInfo('', 'pulseuser', 0)
                            profilname = 'pulseuser'
                        except Exception:
                            profilname = 'pulse'
                    result['result']['informationresult'][info_ask] = profilname
            except Exception:
                result['result']['informationresult'][info_ask] = ""
        return json.dumps(result)

    @staticmethod
    def listremotefileedit(xmppobject, data):
        logger.debug("iq listremotefileedit")
        listfileedit = [ x for x in os.listdir(directoryconffile()) if x.endswith(".ini")]
        data['data'] = {"result": listfileedit}
        return json.dumps(data)

    @staticmethod
    def remotexmppmonitoring(xmppobject, data):
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
                result = functionsynchroxmpp.__execfunctionmonitoringparameter(datastruct,
                                                                               xmppobject)
        result = base64.b64encode(zlib.compress(result, 9))
        data['result'] = result
        return json.dumps(data)

    @staticmethod
    def __execfunctionmonitoringparameter(data, xmppobject):
        result=""
        try:
            if  data['subaction'] == "cputimes":
                func = getattr(sys.modules[__name__], data['subaction'])
                result = decode_strconsole(json.dumps(func(*data['args'], **data['kwargs'])))
                return result
            elif data['subaction'] == "litlog":
                func = getattr(sys.modules[__name__], "showlinelog") # call showlinelog from util
                data['kwargs']['logfile'] = xmppobject.config.logfile
                result = decode_strconsole(json.dumps(func(*data['args'], **data['kwargs'])))
                return result
            else:
                return ""
        except Exception as e:
            logger.error("%s" % str(e))
            logger.error("%s" % (traceback.format_exc()))
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
                        data['data'] = {"result": filedata, "error": False, 'numerror': 0}
                        return json.dumps(data)
                    else:
                        data['data'] = {"result": "error file missing", "error": True, 'numerror': 128}
                else:
                    data['data'] = {"result": "error name file missing"}
            elif data['data']['action'] == 'create':
                if 'file' in data['data'] and data['data']['file'] != "" and 'content' in data['data']:
                    filename = os.path.join(directoryconffile(), data['data']['file'])
                    file_put_contents(filename, data['data']['content'])
                    data['data'] = {"result": "create file %s" % filename, "error": False, 'numerror': 0}
                    return json.dumps(data)
                else:
                    data['data'] = {"result": "error create file : name file missing", "error": True, 'numerror': 129}
            elif data['data']['action'] == 'save':
                if 'file' in data['data'] and data['data']['file'] != "" \
                        and 'content' in data['data']:
                    filename = os.path.join(directoryconffile(), data['data']['file'])
                    if os.path.isfile(filename):
                        file_put_contents(filename,  data['data']['content'])
                        data['data'] = {"result": "save file %s" % filename, "error": False, 'numerror': 0}
                        return json.dumps(data)
                    else:
                        data['data'] = {"result": "error save config file %s missing" % filename, "error": True, 'numerror': 130}
            elif data['data']['action'] == 'listconfigfile':
                listfileedit = [ x for x in os.listdir(directoryconffile()) if (x.endswith(".ini") or x.endswith(".ini.local"))]
                data['data'] = {"result": listfileedit, "error": False, 'numerror': 0}
                return json.dumps(data)
            else:
                data['data'] = {"result": "error the action parameter is not correct ", "error": True, 'numerror': 131}
        else:
            data['data'] = {"result": "error action remotefileeditaction parameter incorrect", "error": True, 'numerror': 132}
        return json.dumps(data)

    @staticmethod
    def packageslist(xmppobject, data):

        packages_path = os.path.join('/', 'var', 'lib', 'pulse2', 'packages')
        packages_list = {'total': 0, 'datas': []}
        total = 0
        for folder, sub_folders, files in os.walk(packages_path):
            size_bytes = 0
            _files = []
            count_files = 0
            if files and os.path.isfile(os.path.join(folder, 'conf.json')) or os.path.isfile(os.path.join(folder, 'xmppdeploy.json')):
                total += 1
                for f in files:
                    count_files += 1
                    path = os.path.join(folder, f)
                    size_bytes += os.stat(path).st_size
                    _files.append((f, os.stat(path).st_size))

                name = folder.split("/")[-1]
                licenses = ""
                metagenerator = ""
                description = ""
                version = ""
                targetos = ""
                methodtransfer = ""
                try:
                    with open(os.path.join(folder, 'conf.json'), 'r') as conf_file:
                        conf_json = json.load(conf_file)
                        if 'licenses' in conf_json:
                            licenses = conf_json['licenses']
                except:
                    pass

                try:
                    with open(os.path.join(folder, 'xmppdeploy.json'), 'r') as deploy_file:
                        deploy_json = json.load(deploy_file)
                        if 'metagenerator' in deploy_json['info']:
                            metagenerator = deploy_json['info']['metagenerator']
                        if 'name' in deploy_json['info']:
                            name = deploy_json['info']['name']
                        if 'description' in deploy_json['info']:
                            description = deploy_json['info']['description']
                        if 'version' in deploy_json['info']:
                            version = deploy_json['info']['version']
                        if 'methodtransfer' in deploy_json['info']:
                            methodtransfer = deploy_json['info']['methodetransfert']
                        if 'os' in deploy_json['metaparameter']:
                            targetos = ", ".join(deploy_json['metaparameter']['os'])
                except:
                    pass
                packages_list['datas'].append({'uuid': folder,
                                               'size': size_bytes,
                                               'targetos': targetos,
                                               'version': version,
                                               'description': description,
                                               'metagenerator': metagenerator,
                                               'licenses': licenses,
                                               'name': name,
                                               'methodtransfer': methodtransfer,
                                               'files': _files,
                                               'count_files': count_files,
                                               })

        packages_list['total'] = total
        return json.dumps(packages_list, indent=4)
