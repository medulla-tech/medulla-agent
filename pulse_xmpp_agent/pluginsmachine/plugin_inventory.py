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
# file : plugin_inventory.py

from  lib.utils import simplecommand, file_put_contents_w_a, file_get_contents
import os, sys, platform
import zlib
import base64
import traceback
import json
import logging
import subprocess
import lxml.etree as ET
import hashlib
logger = logging.getLogger()
if sys.platform.startswith('win'):
    from lib.registerwindows import constantregisterwindows
    import _winreg

DEBUGPULSEPLUGIN = 25
ERRORPULSEPLUGIN = 40
WARNINGPULSEPLUGIN = 30
plugin = {"VERSION": "1.231", "NAME" :"inventory", "TYPE":"machine"}

def action(xmppobject, action, sessionid, data, message, dataerreur):
    logger.debug("###################################################")
    logger.debug("call %s from %s"%(plugin,message['from']))
    logger.debug("###################################################")
    strjidagent = str(xmppobject.boundjid.bare)
    boolchang = True # initialisation de boolchang. True si inventory modifier
    try:
        compteurcallplugin = getattr(xmppobject, "num_call%s"%action)
        if compteurcallplugin == 0:
            logger.debug("configure plugin %s"%action)
    except:
        pass
    try:
        xmppobject.sub_inventory
    except :
        xmppobject.sub_inventory = xmppobject.agentmaster
    resultaction = "result%s" % action
    result = {}
    result['action'] = resultaction
    result['ret'] = 0
    result['sessionid'] = sessionid
    result['base64'] = False
    result['data'] = {}
    dataerreur['action'] = resultaction
    dataerreur['data']['msg'] = "ERROR : %s" % action
    dataerreur['sessionid'] = sessionid
    timeoutfusion = 120
    msg=[]
    if not 'forced' in data:
        data['forced'] = "forced"
    if data['forced'] == True:
        data['forced'] = "forced"
    if data['forced'] == False:
        data['forced'] = "noforced"
    
    if sys.platform.startswith('linux') or sys.platform.startswith('darwin'):
        inventoryfile = os.path.join("/","tmp","inventory.txt")
    elif sys.platform.startswith('win'): 
        inventoryfile = os.path.join(os.environ["ProgramFiles"],
                                    'Pulse',
                                    'tmp',
                                    'inventory.txt')
    else:
        logger.error("undefined OS")
        xmppobject.xmpplog( "undefined OS",
                            type = 'deploy',
                            sessionname = sessionid,
                            priority = -1,
                            action = "xmpplog",
                            who = strjidagent,
                            module = "Notify | Inventory | Error",
                            date = None )
        return
    if os.path.exists(inventoryfile):
        os.rename(inventoryfile, "%s.back"%inventoryfile)
    
    if sys.platform.startswith('linux'):
        try:
            for nbcmd in range(1, 4):
                logger.debug("process inventory %s timeout %s"%(nbcmd,
                                                                timeoutfusion))
                cmd = "fusioninventory-agent --backend-collect-timeout=%s --local=%s"%(timeoutfusion,
                                                                                       inventoryfile)
                msg.append(cmd)
                obj = simplecommand(cmd)
                msg.append("result code error %s result cmd %s"%(obj['code'],
                                                                 obj['result']))
                if obj['code'] == 0:
                    break
                timeoutfusion = timeoutfusion + 60
            for mesg in msg:
                logger.debug(mesg)
                xmppobject.xmpplog( mesg,
                                    type = 'deploy',
                                    sessionname = sessionid,
                                    priority = -1,
                                    action = "xmpplog",
                                    who = strjidagent,
                                    module = "Notify | Inventory | Error",
                                    date = None )
            msg=[]
            if os.path.exists(inventoryfile):
                try:
                    result['data']['inventory'], boolchang = compact_xml(inventoryfile)
                    result['data']['inventory'] = base64.b64encode(zlib.compress(result['data']['inventory'], 9))
                    if boolchang == False:
                        xmppobject.xmpplog("no significant change in inventory.",
                                            type = 'deploy',
                                            sessionname = sessionid,
                                            priority = -1,
                                            action = "xmpplog",
                                            who = strjidagent,
                                            module = "Notify | Inventory",
                                            date = None )
                    else:
                        xmppobject.xmpplog("inventory changed",
                                            type = 'deploy',
                                            sessionname = sessionid,
                                            priority = -1,
                                            action = "xmpplog",
                                            who = strjidagent,
                                            module = "Notify | Inventory",
                                            date = None )
                except Exception as e:
                    logger.error("\n%s"%(traceback.format_exc()))
                    xmppobject.xmpplog( "error inventory %s "%str(e),
                                        type = 'deploy',
                                        sessionname = sessionid,
                                        priority = -1,
                                        action = "xmpplog",
                                        who = strjidagent,
                                        module = "Notify | Inventory | Error",
                                        date = None )
                    raise Exception(str(e))
            else:
                raise Exception('file inventory no exits')
        except Exception as e:
            dataerreur['data']['msg'] = "pulgin inventory %s : [ %s]"%(dataerreur['data']['msg'],str(e))
            logger.error("\n%s"%(traceback.format_exc()))
            logger.error("Send error message\n%s" % dataerreur)
            xmppobject.send_message(mto=xmppobject.sub_inventory,
                                   mbody=json.dumps(dataerreur),
                                   mtype='chat')
            msg.append(dataerreur['data']['msg'] )
            for mesg in msg:
                logger.debug(mesg)
                xmppobject.xmpplog( mesg,
                                    type = 'deploy',
                                    sessionname = sessionid,
                                    priority = -1,
                                    action = "xmpplog",
                                    who = strjidagent,
                                    module = "Notify | Inventory | Error",
                                    date = None )
            return
    elif sys.platform.startswith('win'):
        try:
            bitness = platform.architecture()[0]
            if bitness == '32bit':
                other_view_flag = _winreg.KEY_WOW64_64KEY
            elif bitness == '64bit':
                other_view_flag = _winreg.KEY_WOW64_32KEY
            # run the inventory
            program = os.path.join(os.environ["ProgramFiles"],
                                   'FusionInventory-Agent',
                                   'fusioninventory-agent.bat')
            for nbcmd in range(3):
                cmd = """\"%s\" --config=none --scan-profiles """ \
                        """--backend-collect-timeout=%s --local=\"%s\""""%(program,
                                                                           timeoutfusion,
                                                                           inventoryfile)
                msg.append(cmd)
                logger.debug(cmd)
                obj = simplecommand(cmd)
                msg.append("result code error %s result cmd %s"%(obj['code'],
                                                                 obj['result']))
                if obj['code'] == 0:
                    break
                timeoutfusion = timeoutfusion + 60
            for mesg in msg:
                xmppobject.xmpplog( mesg,
                                    type = 'deploy',
                                    sessionname = sessionid,
                                    priority = -1,
                                    action = "xmpplog",
                                    who = strjidagent,
                                    module = "Notify | Inventory | Error",
                                    date = None )
            msg=[]
            if os.path.exists(inventoryfile):
                try:
                    # read max_key_index parameter to find out the number of keys
                    # Registry keys that need to be pushed in an inventory
                    graine =""
                    listfinger = []
                    if hasattr(xmppobject.config, 'max_key_index'):
                        result['data']['reginventory'] = {}
                        result['data']['reginventory']['info'] = {}
                        result['data']['reginventory']['info']['max_key_index'] = int(xmppobject.config.max_key_index)
                        nb_iter = int(xmppobject.config.max_key_index) + 1
                        # get the value of each key and create the json file
                        for num in range(1, nb_iter):
                            reg_key_num = 'reg_key_'+str(num)
                            result['data']['reginventory'][reg_key_num] = {}
                            registry_key = getattr(xmppobject.config, reg_key_num)
                            result['data']['reginventory'][reg_key_num]['key'] = registry_key
                            hive = registry_key.split('\\')[0].strip('"')
                            sub_key = registry_key.split('\\')[-1].strip('"')
                            path = registry_key.replace(hive+'\\', '').replace('\\'+sub_key, '').strip('"')
                            if hive == 'HKEY_CURRENT_USER':
                                if hasattr(xmppobject.config, 'current_user'):
                                    process = subprocess.Popen( "wmic useraccount where name='%s' " \
                                                                    "get sid"%xmppobject.config.current_user,
                                                                shell=True,
                                                                stdout=subprocess.PIPE,
                                                                stderr=subprocess.STDOUT)
                                    output = process.stdout.readlines()
                                    sid = output[1].rstrip(' \t\n\r')
                                    hive = 'HKEY_USERS'
                                    path = sid+'\\'+path
                                else:
                                    logging.log(DEBUGPULSEPLUGIN, "HKEY_CURRENT_USER hive defined but current_user config parameter is not")
                            logging.log(DEBUGPULSEPLUGIN, "hive: %s" % hive)
                            logging.log(DEBUGPULSEPLUGIN, "path: %s" % path)
                            logging.log(DEBUGPULSEPLUGIN, "sub_key: %s" % sub_key)
                            reg_constants = constantregisterwindows()
                            try:
                                key = _winreg.OpenKey(reg_constants.getkey(hive),
                                                    path,
                                                    0,
                                                    _winreg.KEY_READ | other_view_flag)
                                key_value = _winreg.QueryValueEx(key, sub_key)
                                logging.log(DEBUGPULSEPLUGIN,"key_value: %s" % str(key_value[0]))
                                result['data']['reginventory'][reg_key_num]['value'] = str(key_value[0])
                                listfinger.append(str(key_value[0]))
                                _winreg.CloseKey(key)
                            except Exception, e:
                                logging.log(ERRORPULSEPLUGIN,"Error getting key: %s" % str(e))
                                result['data']['reginventory'][reg_key_num]['value'] = ""
                                pass
                        # generate the json and encode
                        logging.log(DEBUGPULSEPLUGIN,"---------- Registry inventory Data ----------")
                        logging.log(DEBUGPULSEPLUGIN,json.dumps(result['data']['reginventory'],
                                                                indent=4,
                                                                separators=(',', ': ')))
                        logging.log(DEBUGPULSEPLUGIN,"---------- End Registry inventory Data ----------")
                        result['data']['reginventory'] = base64.b64encode(json.dumps(result['data']['reginventory'],
                                                                                     indent=4,
                                                                                     separators=(',', ': ')))
                        # dans le cas ou il y a des registres, ceux ci seront pris en compte pour le fingerprint.
                        # on est jamais certain de l'ordre d'un dict. donc on peut pas prendre directement celui-ci dans 1 finger print.
                        listfinger.sort()
                        graine = ''.join(listfinger)
                    result['data']['inventory'], boolchang = compact_xml(inventoryfile,graine=graine)
                    result['data']['inventory'] = base64.b64encode(zlib.compress(result['data']['inventory'], 9))
                    if boolchang == False:
                        xmppobject.xmpplog("no significant change in inventory.",
                                            type = 'deploy',
                                            sessionname = sessionid,
                                            priority = -1,
                                            action = "xmpplog",
                                            who = strjidagent,
                                            module = "Notify | Inventory",
                                            date = None )
                    else:
                        xmppobject.xmpplog("inventory changed",
                                            type = 'deploy',
                                            sessionname = sessionid,
                                            priority = -1,
                                            action = "xmpplog",
                                            who = strjidagent,
                                            module = "Notify | Inventory",
                                            date = None )
                except Exception as e:
                    logger.error("\n%s"%(traceback.format_exc()))
                    xmppobject.xmpplog( "error inventory %s "%str(e),
                                        type = 'deploy',
                                        sessionname = sessionid,
                                        priority = -1,
                                        action = "xmpplog",
                                        who = strjidagent,
                                        module = "Notify | Inventory | Error",
                                        date = None )
                    raise Exception(str(e))
            else:
                raise Exception('file inventory no exits')
        except Exception as e:
            dataerreur['data']['msg'] = "pulgin inventory %s : [ %s]"%(dataerreur['data']['msg'],str(e))
            logger.error("\n%s"%(traceback.format_exc()))
            logger.error("Send error message\n%s" % dataerreur)
            xmppobject.send_message(mto=xmppobject.sub_inventory,
                                   mbody=json.dumps(dataerreur),
                                   mtype='chat')
            msg.append(dataerreur['data']['msg'] )
            for mesg in msg:
                logger.debug(mesg)
                xmppobject.xmpplog( mesg,
                                    type = 'deploy',
                                    sessionname = sessionid,
                                    priority = -1,
                                    action = "xmpplog",
                                    who = strjidagent,
                                    module = "Notify | Inventory | Error",
                                    date = None )
            return
    elif sys.platform.startswith('darwin'):
        try:
            for nbcmd in range(3):
                ## attention this command has been tested on only 1 Mac
                cmd = "/opt/fusioninventory-agent/bin/fusioninventory-inventory " \
                      "--backend-collect-timeout=%s > %s"%(timeoutfusion,
                                                           inventoryfile)
                msg.append(cmd)
                logger.debug(cmd)
                obj = simplecommand(cmd)
                msg.append("result code error %s result cmd %s"%(obj['code'],
                                                                 obj['result']))
                if obj['code'] == 0:
                    break
                timeoutfusion = timeoutfusion + 60
            for mesg in msg:
                xmppobject.xmpplog( mesg,
                                    type = 'deploy',
                                    sessionname = sessionid,
                                    priority = -1,
                                    action = "xmpplog",
                                    who = strjidagent,
                                    module = "Notify | Inventory | Error",
                                    date = None )
            msg=[]
            if os.path.exists(inventoryfile):
                try:
                    result['data']['inventory'], boolchang = compact_xml(inventoryfile)
                    result['data']['inventory'] = base64.b64encode(zlib.compress(result['data']['inventory'], 9))
                    if boolchang == False:
                        xmppobject.xmpplog("no significant change in inventory.",
                                            type = 'deploy',
                                            sessionname = sessionid,
                                            priority = -1,
                                            action = "xmpplog",
                                            who = strjidagent,
                                            module = "Notify | Inventory",
                                            date = None )
                    else:
                        xmppobject.xmpplog("inventory changed",
                                            type = 'deploy',
                                            sessionname = sessionid,
                                            priority = -1,
                                            action = "xmpplog",
                                            who = strjidagent,
                                            module = "Notify | Inventory",
                                            date = None )
                except Exception as e:
                    logger.error("\n%s"%(traceback.format_exc()))
                    xmppobject.xmpplog( "error inventory %s "%str(e),
                                        type = 'deploy',
                                        sessionname = sessionid,
                                        priority = -1,
                                        action = "xmpplog",
                                        who = strjidagent,
                                        module = "Notify | Inventory | Error",
                                        date = None )
                    raise Exception(str(e))
            else:
                raise Exception('file inventory no exits')
        except Exception as e:
            dataerreur['data']['msg'] = "pulgin inventory %s : [ %s]"%(dataerreur['data']['msg'],str(e))
            logger.error("\n%s"%(traceback.format_exc()))
            logger.error("Send error message\n%s" % dataerreur)
            xmppobject.send_message(mto=xmppobject.sub_inventory,
                                   mbody=json.dumps(dataerreur),
                                   mtype='chat')
            msg.append(dataerreur['data']['msg'] )
            for mesg in msg:
                logger.debug(mesg)
                xmppobject.xmpplog( mesg,
                                    type = 'deploy',
                                    sessionname = sessionid,
                                    priority = -1,
                                    action = "xmpplog",
                                    who = strjidagent,
                                    module = "Notify | Inventory | Error",
                                    date = None )
            return

    if result['base64'] is True:
        result['data'] = base64.b64encode(json.dumps(result['data']))
    if data['forced']=='forced' or boolchang:
        xmppobject.send_message(mto=xmppobject.sub_inventory,
                                mbody=json.dumps(result),
                                mtype='chat')
        xmppobject.xmpplog("inventory is injected",
                            type = 'deploy',
                            sessionname = sessionid,
                            priority = -1,
                            action = "xmpplog",
                            who = strjidagent,
                            module = "Notify | Inventory",
                            date = None )
    else:
        logger.debug("inventory is not injected")
        xmppobject.xmpplog("inventory is not injected",
                            type = 'deploy',
                            sessionname = sessionid,
                            priority = -1,
                            action = "xmpplog",
                            who = strjidagent,
                            module = "Notify | Inventory",
                            date = None )

def Setdirectorytempinfo():
    """
    This functions create a temporary directory.

    Returns:
    path directory INFO Temporaly
    """
    dirtempinfo = os.path.abspath(os.path.join(os.path.dirname(os.path.realpath(__file__)),"..","lib","INFOSTMP"))
    if not os.path.exists(dirtempinfo):
        os.makedirs(dirtempinfo, mode=0o007)
    return dirtempinfo

def compact_xml(inputfile, graine=""):
    """ prepare xml a envoyer et genere 1 finger print"""
    parser = ET.XMLParser(remove_blank_text=True, remove_comments=True)
    xmlTree = ET.parse(inputfile, parser=parser)
    strinventorysave  =  '<?xml version="1.0" encoding="UTF-8" ?>' + \
                            ET.tostring(xmlTree, pretty_print=False)
    file_put_contents_w_a(inputfile, strinventorysave)
    # fingerprint
    listxpath=['/REQUEST/CONTENT/ACCESSLOG',
               '/REQUEST/CONTENT/BIOS',
               '/REQUEST/CONTENT/OPERATINGSYSTEM',
               '/REQUEST/CONTENT/ENVS',
               '/REQUEST/CONTENT/PROCESSES',
               '/REQUEST/CONTENT/DRIVES',
               '/REQUEST/CONTENT/HARDWARE',
               '/REQUEST/CONTENT/CONTROLLERS',
               '/REQUEST/CONTENT/CPUS',
               '/REQUEST/CONTENT/VERSIONPROVIDER',
               '/REQUEST/CONTENT/INPUTS',
               '/REQUEST/CONTENT/LOCAL_GROUPS',
               '/REQUEST/CONTENT/LOCAL_USERS',
               '/REQUEST/CONTENT/VERSIONCLIENT',
               '/REQUEST/CONTENT/FIREWALL',
               '/REQUEST/DEVICEID',
               '/REQUEST/QUERY']
    for searchtag in listxpath:
        p = xmlTree.xpath(searchtag)
        for t in p:
            t.getparent().remove(t);
    strinventory  =  ET.tostring(xmlTree, pretty_print=True)
    # -----debug file compare------
    #namefilecompare = "%s.xml1"%inputfile
    #if os.path.exists(namefilecompare):
        #os.rename(namefilecompare, "%s.back"%namefilecompare)
    #file_put_contents_w_a(namefilecompare, strinventory)
    # -----end debug file compare------
    fingerprintinventory = hashlib.md5(strinventory+graine).hexdigest()
    # on recupere ancienne fingerprint
    manefilefingerprintinventory = os.path.join(Setdirectorytempinfo(),
                                                'fingerprintinventory')
    oldfingerprintinventory = ""
    if os.path.exists(manefilefingerprintinventory):
        oldfingerprintinventory = file_get_contents(manefilefingerprintinventory)
    file_put_contents_w_a(manefilefingerprintinventory, fingerprintinventory)
    if fingerprintinventory == oldfingerprintinventory:
        logger.debug("no significant change in inventory.")
        
        return strinventorysave, False
    logger.debug("inventory is modify.")
    return strinventorysave, True
