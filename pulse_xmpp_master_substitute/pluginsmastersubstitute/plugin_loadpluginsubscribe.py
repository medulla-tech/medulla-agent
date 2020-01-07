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
# file pluginsmastersubstitute/plugin_loadpluginsubscribe.py

import base64
import json
import sys, os
import logging
import platform
from lib.utils import file_get_contents, getRandomName, data_struct_message
import traceback
from sleekxmpp import jid
import types
import ConfigParser
from lib.plugins.xmpp import XmppMasterDatabase


logger = logging.getLogger()
DEBUGPULSEPLUGIN = 25

# this plugin calling to starting agent

plugin = {"VERSION" : "1.0", "NAME" : "loadpluginsubscribe", "TYPE" : "substitute"}

def action( objectxmpp, action, sessionid, data, msg, dataerreur):
    logger.debug("=====================================================")
    logger.debug("call %s from %s"%(plugin, msg['from']))
    logger.debug("=====================================================")

    compteurcallplugin = getattr(objectxmpp, "num_call%s"%action)
    if compteurcallplugin == 0:
        read_conf_load_plugin_subscribe(objectxmpp)
        objectxmpp.add_event_handler('changed_status', objectxmpp.changed_status)
        #self.add_event_handler('presence_unavailable', objectxmpp.presence_unavailable)
        #self.add_event_handler('presence_available', objectxmpp.presence_available)

        #self.add_event_handler('presence_subscribe', objectxmpp.presence_subscribe)
        #self.add_event_handler('presence_subscribed', objectxmpp.presence_subscribed)

        #self.add_event_handler('presence_unsubscribe', objectxmpp.presence_unsubscribe)
        #self.add_event_handler('presence_unsubscribed', objectxmpp.presence_unsubscribed)

        #self.add_event_handler('changed_subscription', objectxmpp.changed_subscription)


def read_conf_load_plugin_subscribe(objectxmpp):
    """
        lit la configuration du plugin
        le repertoire ou doit se trouver le fichier de configuration est dans la variable objectxmpp.config.pathdirconffile
    """
    #namefichierconf = plugin['NAME'] + ".ini"
    #pathfileconf = os.path.join( objectxmpp.config.pathdirconffile, namefichierconf )
    #if not os.path.isfile(pathfileconf):
        #pass
    #else:
        #Config = ConfigParser.ConfigParser()
        #Config.read(pathfileconf)
        #if os.path.exists(pathfileconf + ".local"):
            #Config.read(pathfileconf + ".local")
    objectxmpp.changed_status = types.MethodType(changed_status, objectxmpp)
    #objectxmpp.presence_subscribe = types.MethodType(presence_subscribe, objectxmpp)
    #objectxmpp.presence_subscribed = types.MethodType(presence_subscribed, objectxmpp)
    #objectxmpp.changed_subscription = types.MethodType(changed_subscription, objectxmpp)
    #objectxmpp.presence_unavailable = types.MethodType(presence_unavailable, objectxmpp)
    #objectxmpp.presence_available = types.MethodType(presence_available, objectxmpp)
    #objectxmpp.presence_unsubscribe = types.MethodType(presence_unsubscribe, objectxmpp)
    #objectxmpp.presence_unsubscribed = types.MethodType(presence_unsubscribed, objectxmpp)


def changed_status(self, presence):
    frommsg = jid.JID(presence['from'])
    try:
        if frommsg.bare == self.boundjid.bare:
            logger.debug( "Message self calling not processed")
            return
    except Exception:
        logger.error("\n%s"%(traceback.format_exc()))
        pass

    if presence['type'] == 'unavailable':
        try:
            logger.debug("update offline for %s" % (presence['from']))
            result = XmppMasterDatabase().initialisePresenceMachine(presence['from'])
            if result is None:
                return
            if "type" in result and result['type'] == "relayserver":
                # recover list of cluster ARS
                listrelayserver = XmppMasterDatabase().getRelayServerofclusterFromjidars(
                    str(presence['from']))
                cluster = {'action': "cluster",
                            'sessionid': name_random(5, "cluster"),
                            'data': {'subaction': 'initclusterlist',
                                        'data': listrelayserver
                                    }
                            }
                # all Relays server in the cluster are notified.
                logger.debug( "Notify to all ARS, offline ARS %s"%presence['from'])
                for ARScluster in listrelayserver:
                    self.send_message(mto=ARScluster,
                                        mbody=json.dumps(cluster),
                                        mtype='chat')
            else:
                obj = XmppMasterDatabase().getcluster_resources(presence['from'])
                arscluster = []
                for t in obj['resource']:
                    if t['jidmachine'] == presence['from']:
                        logger.debug("*** resource recovery on ARS %s for deploy"\
                            "sessionid %s on machine  (connection loss) %s " % (t['jidrelay'],
                                                                                t['sessionid'],
                                                                                t['hostname']))
                        arscluster.append([ t['jidrelay'],
                                            t['sessionid'],
                                            t['hostname'],
                                            t['jidmachine'] ])
                        #logger.debug("*** %s"%t)
                        logger.debug("Update deploy Status for Machine OffLine %s"%t['jidmachine'])
                        XmppMasterDatabase().updatedeploystate(t['sessionid'], "DEPLOYMENT START (REBOOT)")
                        self.xmpplog("resource recovery on ARS %s for deploy"\
                            "sessionid %s on machine  (connection loss) %s " % (t['jidrelay'],
                                                                                t['sessionid'],
                                                                                t['hostname']),
                            type = 'deploy',
                            sessionname = t['sessionid'],
                            priority = -1,
                            action = "",
                            who = "",
                            how = "",
                            why =  t['jidmachine'],
                            module = "Deployment| Notify | Cluster",
                            date = None,
                            fromuser = "",
                            touser = "")
                        self.xmpplog('<span style="font-weight: bold;color : Orange;">WAITING REBOOT</span>',
                            type = 'deploy',
                            sessionname = t['sessionid'],
                            priority = -1,
                            action = "",
                            who =  t['jidmachine'],
                            how = "",
                            why = "",
                            module = "Deployment | Error | Terminate | Notify",
                            date = None ,
                            fromuser = "master",
                            touser = "")
                #arscluster = list(set(arscluster))
                if len(arscluster) > 0:
                    #logger.debug("*** START SEND MSG ARS")
                    listrelayserver = XmppMasterDatabase().getRelayServer(enable = True)
                    cluster = { 'action': "cluster",
                                'sessionid': name_random(5, "cluster"),
                                'data': {'subaction': 'removeresource',
                                            'data': { "jidmachine" :str(presence['from'])
                                            }
                                }
                        }
                    #logger.debug("*** list relayserver")
                    for ars in listrelayserver:
                        logger.debug("Remove Resource on ARS %s for MACH %s "%(ars,str(presence['from'])))
                        self.send_message(mto=ars['jid'],
                                            mbody=json.dumps(cluster),
                                            mtype='chat')
        except Exception:
            logger.error("%s"%(traceback.format_exc()))
    elif presence['type'] == "available":
        logger.info("update MACH or ARS %s Online"%presence['from'])
        result = XmppMasterDatabase().initialisePresenceMachine(presence['from'],
                                                                presence=1)

#def presence_subscribe(self, presence):
    #logger.info("**********   presence_subscribe %s %s"%(presence['from'],presence['type'] ))

#def presence_subscribed(self, presence):
    #logger.info("**********   presence_subscribed %s %s"%(presence['from'],presence['type'] ))

#def changed_subscription(self, presence):
    #logger.info("**********   changed_subscription %s %s"%(presence['from'],presence['type'] ))

#def presence_unavailable(self, presence):
    #logger.info("**********   presence_unavailable %s %s"%(presence['from'],presence['type'] ))

#def presence_available(self, presence):
    #logger.info("**********   presence_available %s %s"%(presence['from'],presence['type'] ))

#def presence_unsubscribe(self, presence):
    #logger.info("**********   presence_unsubscribe %s %s"%(presence['from'],presence['type'] ))

#def presence_unsubscribed(self, presence):
    #logger.info("**********   presence_unsubscribed %s %s"%(presence['from'],presence['type'] ))
