# -*- coding: utf-8 -*-
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
# file : pluginsrelay/plugin_downloadfile.py

import logging

from lib import utils
import os
import json
import time
import socket
import traceback

logger = logging.getLogger()
DEBUGPULSEPLUGIN = 25
plugin = { "VERSION" : "3.0", "NAME" : "downloadfile", "TYPE" : "relayserver" }
paramglobal = {"timeupreverssh" : 20 , "portsshmaster" : 22, "filetmpconfigssh" : "/tmp/tmpsshconf", "remoteport" : 22, "server_ssh_user" : "pulsetransfert"}

def get_free_tcp_port():
    tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp.bind(('', 0))
    addr, port = tcp.getsockname()
    tcp.close()
    return port

def create_path(type ="windows", host="", ipordomain="", path=""):
    """
        warning you must enter a raw string for parameter path
        eg ( a= create_path(host="pulse", ipordomain="192.168.56.103", path=r"C:\Program Files (x86)\Pulse\var\tmp\packages\a170890e-d060-11e7-ade3-0800278dc04d")
    """
    if path == "":
        return ""
    if type == "windows":
        if host != "" and ipordomain != "":
            print host,ipordomain,path
            return "%s@%s:\"\\\"%s\\\"\""%( host,
                                            ipordomain,
                                            path)
        else:
            return "\"\\\"%s\\\"\""%(path)
    elif type == "linux":
        if host != "" and ipordomain != "":
            return "%s@%s:\"%s\""%( host,
                                            ipordomain,
                                            path)
        else:
            return "\"%s\""%(path)

def scpfile(scr, dest,  objectxmpp, sessionid, reverbool=False):
    if reverbool:
        # version fichier de configuration.
        cmdpre = "scp -C -rp3 -F %s "\
                    "-o IdentityFile=/root/.ssh/id_rsa "\
                    "-o StrictHostKeyChecking=no "\
                    "-o LogLevel=ERROR "\
                    "-o UserKnownHostsFile=/dev/null "\
                    "-o Batchmode=yes "\
                    "-o PasswordAuthentication=no "\
                    "-o ServerAliveInterval=10 "\
                    "-o CheckHostIP=no "\
                    "-o ConnectTimeout=10 "%paramglobal['filetmpconfigssh']
    else :
        cmdpre = "scp -C -rp3 "\
                    "-o IdentityFile=/root/.ssh/id_rsa "\
                    "-o StrictHostKeyChecking=no "\
                    "-o LogLevel=ERROR "\
                    "-o UserKnownHostsFile=/dev/null "\
                    "-o Batchmode=yes "\
                    "-o PasswordAuthentication=no "\
                    "-o ServerAliveInterval=10 "\
                    "-o CheckHostIP=no "\
                    "-o ConnectTimeout=10 "
    cmdpre =  "%s %s %s"%(cmdpre, scr, dest)
    objectxmpp.xmpplog( 'Transfer command : ' + cmdpre,
                               type = 'noset',
                               sessionname = sessionid,
                               priority = -1,
                               action = "xmpplog",
                               who = objectxmpp.boundjid.bare,
                               how = "",
                               why = "",
                               module = "Notify | Download | Transferfile",
                               date = None ,
                               fromuser = "",
                               touser = "")
    return cmdpre

def action( objectxmpp, action, sessionid, data, message, dataerreur):
    logging.getLogger().debug("###################################################")
    logging.getLogger().debug("call %s from %s"%(plugin,message['from']))
    logging.getLogger().debug("###################################################")
    # print json.dumps(data,indent=4)
    profiluserpulse = "pulseuser"

    if hasattr(objectxmpp.config, 'clients_ssh_port'):
        paramglobal['remoteport'] = int(objectxmpp.config.clients_ssh_port)
        logger.debug("Clients SSH port %s"%paramglobal['remoteport'])
    logger.debug("Install key ARS in authorized_keys on agent machine")
    body = {'action': 'installkey',
            'sessionid': sessionid,
            'data': { 'jidAM': data['jidmachine']
            }
    }
    objectxmpp.send_message( mto = objectxmpp.boundjid.bare,
                             mbody = json.dumps(body),
                             mtype = 'chat')
    reversessh = False
    if hasattr(objectxmpp.config, 'clients_ssh_port'):
        localport = int(objectxmpp.config.clients_ssh_port)
    else:
        localport = 22
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(5.0)
    try:
        sock.connect((data['ipmachine'], localport))
    except socket.error:
        localport = get_free_tcp_port()
        reversessh = True
        #send create reverse ssh to machine
    finally:
        sock.close()
    #print json.dumps(data,indent=4)
    ##scp file from 2 hosts

    if reversessh is True:
        objectxmpp.xmpplog( 'Reverse ssh tunnel needed for machine %s behind nat'% data['hostname'],
                            type = 'noset',
                            sessionname = sessionid,
                            priority = -1,
                            action = "xmpplog",
                            who = objectxmpp.boundjid.bare,
                            how = "",
                            why = "",
                            module = "Notify | Download | Transferfile",
                            date = None ,
                            fromuser = "",
                            touser = "")

    if reversessh is False:
        if str(data['osmachine']).startswith('Linux'):
            source = create_path(type = "linux", host = profiluserpulse, ipordomain=data['ipmachine'], path = r'%s'%data['path_src_machine'])
        elif str(data['osmachine']).startswith('darwin'):
            source = create_path(type = "linux", host = profiluserpulse, ipordomain=data['ipmachine'], path = r'%s'%data['path_src_machine'])
        else:
            source = create_path(type = "windows", host = profiluserpulse, ipordomain = data['ipmachine'], path = r'%s'%data['path_src_machine'])


        cretefileconfigrescp = "Host %s\nPort %s\nHost %s\nPort %s\n"%(data['ipmaster'], paramglobal['portsshmaster'], data['ipmachine'], localport)
        utils.file_put_contents(paramglobal['filetmpconfigssh'],  cretefileconfigrescp)
    else:
        if str(data['osmachine']).startswith('Linux'):
            source = create_path(type = "linux", host = profiluserpulse, ipordomain="localhost", path = r'%s'%data['path_src_machine'])
        elif str(data['osmachine']).startswith('darwin'):
            source = create_path(type = "linux", host = profiluserpulse, ipordomain="localhost", path = r'%s'%data['path_src_machine'])
        else:
            source = create_path(type = "windows", host = profiluserpulse, ipordomain = "localhost", path = r'%s'%data['path_src_machine'])


        cretefileconfigrescp = "Host %s\nPort %s\nHost %s\nPort %s\n"%(data['ipmaster'], paramglobal['portsshmaster'], "localhost", localport)
        utils.file_put_contents(paramglobal['filetmpconfigssh'],  cretefileconfigrescp)

    if hasattr(objectxmpp.config, 'server_ssh_user'):
        paramglobal['server_ssh_user'] = objectxmpp.config.server_ssh_user
    else:
        logger.debug("We are using default pulsetransfert user.")

        if hasattr(objectxmpp.config, 'server_ssh_user'):
            paramglobal['server_ssh_user'] = objectxmpp.config.server_ssh_user
        else:
            logger.debug("We are using default pulsetransfert user.")

    dest = create_path(type ="linux",
                       host=paramglobal['server_ssh_user'],
                       ipordomain=data['ipmaster'],
                       path=data['path_dest_master'])
    if reversessh is False:
        command = scpfile(source, dest, objectxmpp, sessionid)
    else:
        datareversessh = {
            'action': 'reverse_ssh_on',
            'sessionid': sessionid,
            'data': {
                    'request': 'askinfo',
                    'port': localport,
                    'host': data['host'],
                    'remoteport': paramglobal['remoteport'],
                    'reversetype': 'R',
                    'options': 'createreversessh',
                    'persistence': 'Downloadfile'
            },
            'ret': 0,
            'base64': False }

        objectxmpp.send_message(mto = message['to'],
                    mbody = json.dumps(datareversessh),
                    mtype = 'chat')

        # initialise se cp
        command = scpfile(source,
                          dest,
                          objectxmpp,
                          sessionid,
                          reverbool = True)

        time.sleep(paramglobal['timeupreverssh'])
    print json.dumps(data,indent=4)
    print "----------------------------"
    print "exec command\n %s"%command
    print "----------------------------"
    print "----------------------------"
    objectxmpp.xmpplog( 'Copying file %s from machine %s to Master'%( os.path.basename(data['path_src_machine']), data['hostname']),
                                type = 'noset',
                                sessionname = sessionid,
                                priority = -1,
                                action = "xmpplog",
                                who = objectxmpp.boundjid.bare,
                                how = "",
                                why = "",
                                module = "Notify | Download | Transferfile",
                                date = None ,
                                fromuser = "",
                                touser = "")


    z = utils.simplecommand(command)
    print z['result']
    print z['code']
    print "----------------------------"

    if z['code'] != 0:
        objectxmpp.xmpplog( 'Error copying file %s from machine %s to Master'%( os.path.basename(data['path_src_machine']), data['hostname']),
                                type = 'noset',
                                sessionname = sessionid,
                                priority = -1,
                                action = "xmpplog",
                                who = objectxmpp.boundjid.bare,
                                how = "",
                                why = "",
                                module = "Notify | Download",
                                date = None ,
                                fromuser = "",
                                touser = "")
        objectxmpp.xmpplog( 'Transfer error : %s'% z['result'],
                                type = 'noset',
                                sessionname = sessionid,
                                priority = -1,
                                action = "xmpplog",
                                who = objectxmpp.boundjid.bare,
                                how = "",
                                why = "",
                                module = "Notify | Download | Transferfile",
                                date = None ,
                                fromuser = "",
                                touser = "")
    else:
        objectxmpp.xmpplog( 'Copying file %s from machine %s to Master successful'%( os.path.basename(data['path_src_machine']), data['hostname']),
                                type = 'noset',
                                sessionname = sessionid,
                                priority = -1,
                                action = "xmpplog",
                                who = objectxmpp.boundjid.bare,
                                how = "",
                                why = "",
                                module = "Notify | Download | Transferfile",
                                date = None ,
                                fromuser = "",
                                touser = "")
        # chang mod file dest
        tabdest = str(dest).split('"')
        cmd = "ssh %s -o IdentityFile=/root/.ssh/id_rsa "\
                    "-o StrictHostKeyChecking=no "\
                    "-o UserKnownHostsFile=/dev/null "\
                    "-o Batchmode=yes "\
                    "-o PasswordAuthentication=no "\
                    "-o ServerAliveInterval=10 "\
                    "-o CheckHostIP=no "\
                    "-o ConnectTimeout=10 'chmod 777 -R %s'"%(str(tabdest[0][:-1]),os.path.dirname(tabdest[1]))
        objectxmpp.xmpplog( 'Transfer command : ' + cmd,
                            type = 'noset',
                            sessionname = sessionid,
                            priority = -1,
                            action = "xmpplog",
                            who = objectxmpp.boundjid.bare,
                            how = "",
                            why = "",
                            module = "Notify | Download | Transferfile",
                            date = None ,
                            fromuser = "",
                            touser = "")
        z = utils.simplecommand(cmd)
        if z['code'] == 0:
            objectxmpp.xmpplog( 'Transfer result : ' + '\n'.join(z['result']),
                                type = 'noset',
                                sessionname = sessionid,
                                priority = -1,
                                action = "xmpplog",
                                who = objectxmpp.boundjid.bare,
                                how = "",
                                why = "",
                                module = "Notify | Download | Transferfile",
                                date = None ,
                                fromuser = "",
                                touser = "")
            objectxmpp.xmpplog( 'Setting mode 777 to file %s '%( os.path.basename(data['path_src_machine'])),
                                type = 'noset',
                                sessionname = sessionid,
                                priority = -1,
                                action = "xmpplog",
                                who = objectxmpp.boundjid.bare,
                                how = "",
                                why = "",
                                module = "Notify | Download | Transferfile",
                                date = None ,
                                fromuser = "",
                                touser = "")
        else:
            objectxmpp.xmpplog( 'Error setting mode 777 to file %s : %s'%( os.path.basename(data['path_src_machine']), z['result']),
                                type = 'noset',
                                sessionname = sessionid,
                                priority = -1,
                                action = "xmpplog",
                                who = objectxmpp.boundjid.bare,
                                how = "",
                                why = "",
                                module = "Notify | Download | Transferfile",
                                date = None ,
                                fromuser = "",
                                touser = "")
