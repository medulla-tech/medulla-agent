# -*- coding: utf-8 -*-
#
# (c) 2016-2018 siveo, http://www.siveo.net
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

# file : xmpp_baseplugin/plugin_guacamole.py

import json
import traceback
import sys
import time
import logging
import os

plugin = {"VERSION" : "1.12", "NAME" : "guacamole",  "TYPE" : "all"}


logger = logging.getLogger()
def action( xmppobject, action, sessionid, data, message, dataerreur ):
    #print json.dumps(data, indent=4)

    if xmppobject.config.agenttype in ['relayserver']:

        import MySQLdb

        # Get reversessh remote port and run reverse_ssh_on
        try:
            db = MySQLdb.connect(host=xmppobject.config.guacamole_dbhost,
                                 user=xmppobject.config.guacamole_dbuser,
                                 passwd=xmppobject.config.guacamole_dbpasswd,
                                 db=xmppobject.config.guacamole_dbname)
            cursor = db.cursor()
            # First find out if we need to run a reversessh connection
            sql = """ SELECT parameter_value FROM guacamole_connection_parameter WHERE connection_id = %s AND parameter_name = 'hostname';"""%(data['cux_id'])
            cursor.execute(sql)
            results = cursor.fetchall()
            hostname = results[0][0]
            if hostname != 'localhost':
                # We won't need a reversessh connection. We can safely quit and let guacamole connect directly to machine
                return
            else:
                # We need to run a reversessh connection
                sql = """ SELECT parameter_value FROM guacamole_connection_parameter WHERE connection_id = %s AND parameter_name = 'port';"""%(data['cux_id'])
                cursor.execute(sql)
                results = cursor.fetchall()
                localport = results[0][0]
                if data['cux_type'] == 'SSH':
                    if hasattr(xmppobject.config, 'clients_ssh_port'):
                        remoteport = int(xmppobject.config.clients_ssh_port)
                    else:
                        remoteport = 22
                    reversetype = 'R'
                elif data['cux_type'] == 'RDP':
                    remoteport = 3389
                    reversetype = 'R'
                elif data['cux_type'] == 'VNC':
                    # Specific VNC case. We will use a listener
                    remoteport = localport
                    if hasattr(xmppobject.config, 'clients_vnc_port'):
                        localport = int(xmppobject.config.clients_vnc_port)
                    else:
                        localport = 5900
                    reversetype = 'L'

        except Exception as e:
            db.close()
            dataerreur['data']['msg'] = "MySQL Error: %s" % str(e)
            logger.error("\n%s"%(traceback.format_exc()))
            raise

        datareversessh = {
                'action': 'reverse_ssh_on',
                'sessionid': sessionid,
                'data' : {
                        'request' : 'askinfo',
                        'port' : localport,
                        'host' : data['uuid'],
                        'remoteport' : remoteport,
                        'reversetype' : reversetype,
                        'options' : 'createreversessh',
                        'persistance' : data['cux_type']
                },
                'ret' : 0,
                'base64' : False }
        xmppobject.send_message(mto = message['to'],
                    mbody = json.dumps(datareversessh),
                    mtype = 'chat')

        if data['cux_type'] == 'VNC' and hostname == 'localhost':
            # Wait x seconds until tunnel is established and guacamole is ready
            # 5 seconds for the reversessh connection + 2 seconds for the guacamole connection
            time.sleep(10)

            # Ask machine plugin to start VNC connection
            datavnc = {
                'action': 'guacamole',
                'sessionid': sessionid,
                'data' : {
                    'options' : 'vnclistenmode'
                },
                'ret' : 0,
                'base64' : False
            }
            xmppobject.send_message(mto = data['jidmachine'],
                mbody = json.dumps(datavnc),
                mtype = 'chat')

        return

    else:
        # Machine plugin

        from  lib.utils import simplecommand

        if data['options'] == "vnclistenmode":
            if sys.platform.startswith('win'):
                try:
                    logger.info("start VNC listener")
                    program = os.path.join(os.environ["ProgramFiles"], 'TightVNC', 'tvnserver.exe')
                    #select display for vnc
                    cmd = """\"%s\" -controlservice -disconnectall"""%(program)
                    simplecommand(cmd)
                    cmd = """\"%s\" -controlservice -shareprimary"""%(program)
                    simplecommand(cmd)
                    cmd = """\"%s\" -controlservice -connect localhost"""%(program)
                    simplecommand(cmd)
                except Exception, e:
                    logger.error( "Error start VNC listener TightVNC: %s" % str(e))
                    logger.error("\n%s"%(traceback.format_exc()))
                    raise
            if sys.platform.startswith('darwin'):
                try:
                    simplecommand("pkill OSXvnc-server -connecthost localhost")
                    simplecommand("\"/Applications/Vine Server.app/Contents/MacOS/OSXvnc-server\" -connectHost localhost")
                except Exception, e:
                    logger.error( "Error start VNC listener OSXvnc-server: %s" % str(e))
                    logger.error("\n%s"%(traceback.format_exc()))
                    raise
            else:
                try:
                    simplecommand("vncconfig -nowin -connect localhost")
                except Exception, e:
                    logging.getLogger().error( "Error start VNC listener vncconfig: %s" % str(e))
                    logger.error("\n%s"%(traceback.format_exc()))
                    raise

        returnmessage = dataerreur
        returnmessage['data'] = data
        returnmessage['ret'] = 0

        #print json.dumps(returnmessage, indent = 4)
