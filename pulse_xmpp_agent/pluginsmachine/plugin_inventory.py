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

from  lib.utils import simplecommand, file_put_contents_w_a
import os, sys, platform
import zlib
import base64
import traceback
import json
import logging
import subprocess
import lxml.etree as ET

logger = logging.getLogger()
if sys.platform.startswith('win'):
    from lib.registerwindows import constantregisterwindows
    import _winreg

DEBUGPULSEPLUGIN = 25
ERRORPULSEPLUGIN = 40
WARNINGPULSEPLUGIN = 30
plugin = {"VERSION": "1.20", "NAME" :"inventory", "TYPE":"machine"}

def compact_xml(inputfile):
    parser = ET.XMLParser(remove_blank_text=True, remove_comments=True)
    xmlTree = ET.parse(inputfile, parser=parser)
    strinventory  =  ET.tostring(xmlTree, pretty_print=False)
    file_put_contents_w_a(inputfile, '<?xml version="1.0" encoding="UTF-8" ?>' + strinventory)


def action(xmppobject, action, sessionid, data, message, dataerreur):
    logging.getLogger().debug("###################################################")
    logging.getLogger().debug("call %s"%(plugin))
    logging.getLogger().debug("###################################################")
    strjidagent = str(xmppobject.boundjid.bare)
    try:
        compteurcallplugin = getattr(xmppobject, "num_call%s"%action)
        if compteurcallplugin == 0:
            logging.getLogger().debug("configure plugin %s"%action)
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
    if sys.platform.startswith('linux'):
        try:
            inventoryfile = os.path.join("/","tmp","inventory.txt")
            if os.path.exists(inventoryfile):
                os.remove(inventoryfile)
            for nbcmd in range(3):
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
                    compact_xml(inventoryfile)
                    Fichier = open(inventoryfile, 'r')
                    result['data']['inventory'] = Fichier.read()
                    Fichier.close()
                    result['data']['inventory'] = base64.b64encode(zlib.compress(result['data']['inventory'], 9))
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
            program = os.path.join(os.environ["ProgramFiles"], 'FusionInventory-Agent', 'fusioninventory-agent.bat')
            namefile = os.path.join(os.environ["ProgramFiles"], 'Pulse', 'tmp', 'inventory.txt')
            if os.path.exists(namefile):
                os.remove(namefile)
            for nbcmd in range(3):
                cmd = """\"%s\" --config=none --scan-profiles --backend-collect-timeout=%s --local=\"%s\""""%(program,
                                                                                                              timeoutfusion,
                                                                                                              namefile)
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
            if os.path.exists(namefile):
                try:
                    compact_xml(namefile)
                    Fichier = open(namefile, 'r')
                    result['data']['inventory'] = base64.b64encode(zlib.compress(Fichier.read(), 9))
                    Fichier.close()
                    # read max_key_index parameter to find out the number of keys
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
                                    process = subprocess.Popen("wmic useraccount where name='%s' get sid" % xmppobject.config.current_user,
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
                                _winreg.CloseKey(key)
                            except Exception, e:
                                logging.log(ERRORPULSEPLUGIN,"Error getting key: %s" % str(e))
                                result['data']['reginventory'][reg_key_num]['value'] = ""
                                pass
                        # generate the json and encode
                        logging.log(DEBUGPULSEPLUGIN,"---------- Registry inventory Data ----------")
                        logging.log(DEBUGPULSEPLUGIN,json.dumps(result['data']['reginventory'], indent=4, separators=(',', ': ')))
                        logging.log(DEBUGPULSEPLUGIN,"---------- End Registry inventory Data ----------")
                        result['data']['reginventory'] = base64.b64encode(json.dumps(result['data']['reginventory'], indent=4, separators=(',', ': ')))
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
            inventoryfile = os.path.join("/","tmp","inventory.txt")
            if os.path.exists(namefile):
                os.remove(inventoryfile)
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
                    compact_xml(inventoryfile)
                    Fichier = open(inventoryfile, 'r')
                    result['data']['inventory'] = Fichier.read()
                    Fichier.close()
                    result['data']['inventory'] = base64.b64encode(zlib.compress(result['data']['inventory'], 9))
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

    xmppobject.send_message(mto=xmppobject.sub_inventory,
                            mbody=json.dumps(result),
                            mtype='chat')
