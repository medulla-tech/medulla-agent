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
# file : pluginsrelay/plugin_guacamoleconf.py
import sys
from lib import utils
import MySQLdb
import traceback
import socket

import json
import logging

plugin = {"VERSION": "2.0", "NAME" :"guacamoleconf", "TYPE":"relayserver"}
logger = logging.getLogger()

def get_free_tcp_port():
    tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp.bind(('', 0))
    addr, port = tcp.getsockname()
    tcp.close()
    return port

def insertprotocole(protocole, hostname):
    return """INSERT INTO guacamole_connection (connection_name, protocol) VALUES ( '%s_%s', '%s');"""%(protocole.upper(), hostname, protocole.lower())

def deleteprotocole(protocole, hostname):
    return """DELETE FROM `guacamole_connection` WHERE connection_name = '%s_%s';"""%(protocole.upper(), hostname)

def insertparameter(index, parameter, value):
    return """INSERT INTO guacamole_connection_parameter (connection_id, parameter_name, parameter_value) VALUES (%s, '%s', '%s');"""%(index, parameter, value)

@utils.pluginprocess
def action(objetxmpp, action, sessionid, data, message, dataerreur, result):
    logger.debug("###################################################")
    logger.debug("call %s from %s"%(plugin, message['from']))
    logger.debug("###################################################")
    logger.debug(json.dumps(data, indent=4))
    logger.debug("###################################################")
    try:
        db = MySQLdb.connect(host=objetxmpp.config.guacamole_dbhost,
                             user=objetxmpp.config.guacamole_dbuser,
                             passwd=objetxmpp.config.guacamole_dbpasswd,
                             db=objetxmpp.config.guacamole_dbname)
    except Exception as e:
        dataerreur['data']['msg'] = "MySQL Error: %s" % str(e)
        logger.error("\n%s"%(traceback.format_exc()))
        raise
    cursor = db.cursor()
    result['data']['uuid'] = data['uuid']
    result['data']['machine_id'] = data['machine_id']
    result['data']['connection'] = {}

    # Add only detected protocols
    if hasattr(objetxmpp.config, 'guacamole_protocols'):
        protos = list(set(objetxmpp.config.guacamole_protocols.split()) \
                      & set(data['remoteservice'].keys()))
    else:
        protos = list(data['remoteservice'].keys())

    try:
        # delete connection
        for proto in protos:
            cursor.execute(deleteprotocole(proto, data['hostname']))
            db.commit()
        # create connection
        for proto in protos:
            result['data']['connection'][proto.upper()] = -1
            cursor.execute(insertprotocole(proto, data['hostname']))
            db.commit()
            result['data']['connection'][proto.upper()] = cursor.lastrowid
    except MySQLdb.Error as e:
        db.close()
        dataerreur['data']['msg'] = "MySQL Error: %s" % str(e)
        logger.error("\n%s"%(traceback.format_exc()))
        raise
    except Exception as e:
        dataerreur['data']['msg'] = "MySQL Error: %s" % str(e)
        logger.error("\n%s"%(traceback.format_exc()))
        db.close()
        raise
    ###################################
    ## configure parameters
    ###################################
    try:
        for proto in protos:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5.0)
            try:
                sock.connect((data['machine_ip'], int(data['remoteservice'][proto])))
                # Machine is directly reachable. We will not need a reversessh connection
                hostname = data['machine_ip']
                cursor.execute(insertparameter(result['data']['connection'][proto.upper()], 'hostname', hostname))
                port = data['remoteservice'][proto]
                cursor.execute(insertparameter(result['data']['connection'][proto.upper()], 'port', port))
            except socket.error:
                # Machine is not reachable. We will need a reversessh connection
                hostname = 'localhost'
                cursor.execute(insertparameter(result['data']['connection'][proto.upper()], 'hostname', hostname))
                port = get_free_tcp_port()
                cursor.execute(insertparameter(result['data']['connection'][proto.upper()], 'port', port))
                if proto.upper() == 'VNC':
                    # We need additional options for reverse VNC
                    listen_timeout = 50000
                    cursor.execute(insertparameter(result['data']['connection'][proto.upper()], 'listen-timeout', listen_timeout))
                    reverse_connect = 'true'
                    cursor.execute(insertparameter(result['data']['connection'][proto.upper()], 'reverse-connect', reverse_connect))
            sock.close()

            # Options specific to a protocol
            for option in list(objetxmpp.config.__dict__.keys()):
                if option.startswith(proto.lower()):
                    if option == 'ssh_keyfile':
                        # specific processing for ssh key
                        with open(objetxmpp.config.ssh_keyfile, 'r') as keyfile:
                            keydata=keyfile.read()

                        cursor.execute(insertparameter(\
                            result['data']['connection'][proto.upper()],
                           'private-key', keydata))
                    else:
                        # Update account for the os
                        if option[4:] == "username":
                            username = "pulseuser"

                            cursor.execute(insertparameter(\
                               result['data']['connection'][proto.upper()],
                               "username", username))
                        else:

                            cursor.execute(insertparameter(\
                               result['data']['connection'][proto.upper()],
                               option[4:],
                               getattr(objetxmpp.config, option)))
            # Commit our queries
            db.commit()

    except MySQLdb.Error as e:
        db.close()
        dataerreur['data']['msg'] = "MySQL Error: %s" % str(e)
        logger.error("\n%s"%(traceback.format_exc()))
        raise
    except Exception as e:
        dataerreur['data']['msg'] = "MySQL Error: %s" % str(e)
        logger.error("\n%s"%(traceback.format_exc()))
        db.close()
        raise
    db.close()
