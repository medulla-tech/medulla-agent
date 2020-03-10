# -*- coding: utf-8 -*-
# (c) 2016 siveo, http://www.siveo.net
# plugin register machine dans presence table xmpp.
# file : pulse_xmpp_master_substitute/pluginsmastersubstitute/plugin_xmpplog.py
#
import zlib
import base64
import traceback
import os
import sys
import urllib2
import time
import json
import logging
from lib.plugins.xmpp import XmppMasterDatabase
from lib.plugins.glpi import Glpi
from lib.plugins.kiosk import KioskDatabase
from lib.localisation import Localisation
from lib.manageRSAsigned import MsgsignedRSA
from sleekxmpp import jid
from lib.utils import getRandomName
import re
from distutils.version import LooseVersion, StrictVersion
import ConfigParser

# this import will be used later
# import types

logger = logging.getLogger()

plugin = {"VERSION": "1.01", "NAME": "xmpplog", "TYPE": "substitute"}

def action(xmppobject, action, sessionid, data, msg, ret, dataobj):
    logger.debug("=====================================================")
    logger.debug("call %s from %s"%(plugin, msg['from']))
    logger.debug("=====================================================")
    compteurcallplugin = getattr(xmppobject, "num_call%s"%action)
    if compteurcallplugin == 0:
        #load regle of satus
        xmppobject.reglestatus = []
        loggerliststatus = XmppMasterDatabase().get_log_status()
        try:
            for t in XmppMasterDatabase().get_log_status():
                t['compile_re'] = re.compile(t['regexplog'])
                xmppobject.reglestatus.append(t)
            logger.debug("regle status initialise%s"% xmppobject.reglestatus)
        except:
            logger.error("\n%s"%(traceback.format_exc()))
        read_conf_log_agent(xmppobject)
    try :
        dataobj = data
        if "type" in dataobj and dataobj['type'] == "deploy" and  'text' in dataobj:
            re_status = searchstatus(xmppobject, dataobj['text'])
            if re_status['status'] != "":
                XmppMasterDatabase().updatedeploytosessionid(re_status['status'],
                                                             dataobj['sessionid'])
                logging.debug("applique status %s for sessionid %s"%(re_status['status'], dataobj['sessionid']))
            else:
                logging.debug("applique pas de status for sessionid %s"%(dataobj['sessionid']))
        if data["action"] == 'xmpplog':
            createlog(xmppobject, data)
        elif data["action"] == 'resultapplicationdeploymentjson':
            logger.debug("log result deployement")
            data['sessionid'] = sessionid
            xmpplogdeploy(xmppobject, data)
        else:
            logger.warning("message bad formated: msg log from %s" %(msg['from']))
            logger.warning("data msg is \n%s" %( json.dumps(data, indent = 4)))
    except Exception as e:
        logging.error("structure Message from %s %s " %(msg['from'], str(e)))
        logger.error("\n%s"%(traceback.format_exc()))

def createlog(xmppobject, dataobj):
    """
        this function creating log in base from body message xmpp
    """
    try:
        if 'text' in dataobj :
            text = dataobj['text']
        else:
            return
        type = dataobj['type'] if 'type' in dataobj else ""
        sessionname = dataobj['sessionid'] if 'sessionid' in dataobj else ""
        priority = dataobj['priority'] if 'priority' in dataobj else ""
        who = dataobj['who'] if 'who' in dataobj else  ""
        how = dataobj['how'] if 'how' in dataobj else ""
        why = dataobj['why'] if 'why' in dataobj else ""
        module = dataobj['module'] if 'module' in dataobj else ""
        action = dataobj['action'] if 'action' in dataobj else ""
        fromuser = dataobj['fromuser'] if 'fromuser' in dataobj else ""
        touser = dataobj['touser'] if 'touser' in dataobj else ""
        XmppMasterDatabase().setlogxmpp(text,
                                        type = type,
                                        sessionname = sessionname,
                                        priority = priority,
                                        who = who ,
                                        how  =how,
                                        why  =why,
                                        module = module,
                                        fromuser  = fromuser,
                                        touser  = touser,
                                        action = action)
    except Exception as e:
        logger.error("Message deploy error  %s %s" %(dataobj, str(e)))
        logger.error("\n%s"%(traceback.format_exc()))
            
        
def registerlogxmpp(xmppobject,
                    text,
                    type = 'noset',
                    sessionname = '',
                    priority = 0,
                    who = '' ,
                    how  = '',
                    why  = '',
                    module = '',
                    fromuser  = '',
                    touser  = '',
                    action = ''
                    ):
    """
        this function for creating log in base
    """
    XmppMasterDatabase().setlogxmpp(text,
                                    type = 'noset',
                                    sessionname = sessionname,
                                    priority = priority,
                                    who = who ,
                                    how  =how,
                                    why  =why,
                                    module = module,
                                    fromuser  = fromuser,
                                    touser  = touser,
                                    action = action)
        
def xmpplogdeploy(xmppobject, data):
    """
        this function manage msg deploy log
    """
    try:
        if 'text' in data and \
            'type' in data and \
                'sessionid' in data and \
                    'priority' in data and \
                        'who' in data:
            registerlogxmpp(xmppobject,
                            data['text'],
                            type = data['type'],
                            sessionname = data['sessionid'],
                            priority = data['priority'],
                            who = data['who'])
        elif 'action' in data :
            if data['action'] == 'resultapplicationdeploymentjson':
                #log dans base resultat
                if data['ret'] == 0:
                    XmppMasterDatabase().updatedeployresultandstate( data['sessionid'],
                                                                    "DEPLOYMENT SUCCESS",
                                                                    json.dumps(data,
                                                                               indent=4,
                                                                               sort_keys=True) )
                else:
                    XmppMasterDatabase().updatedeployresultandstate(data['sessionid'],
                                                                    "ABORT PACKAGE EXECUTION ERROR", 
                                                                    json.dumps(data,
                                                                               indent=4,
                                                                               sort_keys=True) )
    except Exception as e:
        logging.error("obj Message deploy error  %s\nerror text : %s" %(data, str(e)))
        logger.error("\n%s"%(traceback.format_exc()))

def read_conf_log_agent(xmppobject):
    # logger.debug("Initialisation plugin :% s "%plugin["NAME"])
    namefichierconf = plugin['NAME'] + ".ini"
    pathfileconf = os.path.join( xmppobject.config.pathdirconffile, namefichierconf )
    if not os.path.isfile(pathfileconf):
        pass

def searchstatus(xmppobject, chaine):
    for t in xmppobject.reglestatus:
        if  t['compile_re'].match(chaine):
            logger.debug("la chaine \"%s\"  matche pour [%s] et renvoi le status suivant \"%s\""%(chaine,t['regexplog'],t['status']))
            return { "status" : t['status'] , "logmessage" : chaine}
    return { "status" : "" , "logmessage" : chaine}
