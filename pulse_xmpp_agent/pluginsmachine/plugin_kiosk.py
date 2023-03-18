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
# file pulse_xmpp_agent/pluginsmachine/plugin_kiosk.py

import logging
import json
import traceback
import sys
import socket
from lib.managedbkiosk import manageskioskdb

plugin = {"VERSION": "1.31", "NAME" : "kiosk", "TYPE" : "machine"}

def action(objectxmpp, action, sessionid, data, message, dataerreur):
    logging.getLogger().debug("=====================================================")
    logging.getLogger().debug(plugin)
    logging.getLogger().debug("=====================================================")

    datasend = {'action' : "result%s"%plugin['NAME'],
                'data' :{'subaction' : 'test'},
                'sessionid' : sessionid
               }
    try:
        if data['subaction'] == 'test':
            datasend['data']['msg'] = "test success"
            objectxmpp.send_message(mto=message['from'],
                                    mbody=json.dumps(datasend, sort_keys=True, indent=4),
                                    mtype='chat')
        elif data['subaction'] == 'listpackage':
            # todo
            pass
        elif data['subaction'] == 'initialisation_kiosk':
            logging.getLogger().info("send initialization datas to kiosk")

            # When the data are initialized for the kiosk, the launchers founded
            # are added for each package. If the package has no launcher, the
            # Lunch button is removed for this package
            data["data"] = associate_launchers_to_datas(data["data"])

            strjson = json.dumps(data['data'])
            send_kiosk_data(strjson, objectxmpp.config.kiosk_local_port, objectxmpp, dataerreur, message)
            pass
        elif data['subaction'] == "profiles_updated":
            logging.getLogger().info("send updated profiles to kiosk")
            data["data"] = associate_launchers_to_datas(data["data"])
            data["data"]["action"] = "update_profile"

            strjson = json.dumps(data['data'])
            send_kiosk_data(strjson, objectxmpp.config.kiosk_local_port, objectxmpp, dataerreur, message)
            pass
        elif data['subaction'] == "update_launcher":
            data["data"]["action"] = "update_launcher"
            if data["data"]["uuid"] != "" or data["data"]["launcher"] != "":
                logging.getLogger().info("Update the launcher %s" %data["data"]["launcher"])
                kioskdb = manageskioskdb()
                old_launcher = kioskdb.get_cmd_launch(data["data"]["uuid"])
                if old_launcher != data["data"]["launcher"]:

                    kioskdb.set_cmd_launch(data["data"]["uuid"], data["data"]["launcher"])
                    strjson = json.dumps(data["data"])
                    send_kiosk_data(strjson, objectxmpp.config.kiosk_local_port, objectxmpp, dataerreur, message)
            else:
                pass
            pass
    except Exception as e:
        traceback.print_exc(file=sys.stdout)
        dataerreur['ret'] = -255
        dataerreur['data']['msg'] = "plugin kiosk error on machine %s [%s]"%(objectxmpp.boundjid.bare, str(e))
        objectxmpp.send_message(mto=message['from'],
                                mbody=json.dumps(dataerreur),
                                mtype='chat')

def send_kiosk_data(datastrdata, port = 8766, objectxmpp= None, dataerror = None, message = None):
    """send_kiosk_data generates a socket to the specified host and send the datas if the host is listening.
    Params:
        datastrdata: json stringified. This param contains the elements sent through the socket.
        port: int is the port used to send the datas.
        objectxmpp: is the xmppobject used to send response to the master
        dataerror: contains the dataerror of the initial action
        message: contains the message of the initial message

    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_address = ('localhost', port)
    try:
        sock.connect(server_address)
        try:
            sock.sendall(datastrdata.encode('ascii'))
            data = sock.recv(2048)
            print ('received "%s"' % data)
            objectxmpp.kiosk_presence == "True"
        except Exception as e:
            dataerror['ret'] = -255
            if not "Errno 111" in str(e):
                traceback.print_exc(file=sys.stdout)
                logging.getLogger().error("Kiosk [%s]"%str(e))
                dataerror['data']['msg'] = "plugin kiosk error on machine %s : [%s]"%(objectxmpp.boundjid.bare, str(e))
                objectxmpp.send_message(mto=message['from'],
                                        mbody=json.dumps(dataerror),
                                        mtype='chat')
                objectxmpp.kiosk_presence == "False"

            else :
                logging.getLogger().warning("Kiosk is not listen: verify presence kiosk")
                msg = "Kiosk is not listen on machine %s : [%s]\nverrify presence kiosk"%(objectxmpp.boundjid.bare, str(e))
                if objectxmpp is not None and dataerror is not None and message is not None:
                    dataerror['ret'] = -255
                    dataerror['data']['msg'] = msg
                    objectxmpp.send_message(mto=message['from'],
                                            mbody=json.dumps(dataerror),
                                            mtype='chat')
                    objectxmpp.kiosk_presence == "False"
    except Exception as e:
        logging.getLogger().error("Socket to kiosk can't be established")
        if objectxmpp is not None:
            objectxmpp.kiosk_presence == "False"

    finally:
        sock.close()


def associate_launchers_to_datas(data):
    """ This function associates the launchers stored in the db with
    the packages contained in the data variable.
    Param:
        data dict which contains the packages info
    Returns:
        data dict
    """

    kioskdb = manageskioskdb()
    if "packages_list" in data:
        for package in data["packages_list"]:
            launcher = kioskdb.get_cmd_launch(package['uuid'])

            if "Launch" in package['action']:
                # If no launcher in database
                if launcher is None or launcher == "":
                    # Remove the Launch button
                    package['action'].remove("Launch")
                else:
                    package['launcher'] = launcher
            else:
                pass

    return data
