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

import os, sys
import json
import logging
from utils import shellcommandtimeout, file_put_contents, file_get_contents, decode_strconsole, encode_strconsole, keypub
from  agentconffile import  directoryconffile
from shutil import copyfile
import datetime
import zlib
import re
import base64
import traceback
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
DEBUGPULSE = 25
logger = logging.getLogger()
def callXmppFunctionIq(functionname,  *args, **kwargs):
    logger.debug("**call function %s %s %s"%(functionname, args, kwargs))
    return getattr(functionsynchroxmpp,functionname)(*args, **kwargs)

def dispach_iq_command(xmppobject, jsonin):
    """
        this function doit retirner un json string
    """
    data = json.loads(jsonin)

    # functions synch list
    #listactioncommand = ["xmppbrowsing", 
                         #"test", 
                         #"remotefile", 
                         #"remotecommandshell", 
                         #"listremotefileedit", 
                         #"remotefileeditaction",
                         #"remotexmppmonitoring"]
    listactioncommand = ["xmppbrowsing", 
                         "test", 
                         "remotefile", 
                         "remotecommandshell", 
                         "listremotefileedit", 
                         "remotefileeditaction",
                         "remotexmppmonitoring",
                         "keypub"]

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
        except:
            result =  { "result" : { "key" : "" }, "error" : True , 'numerror' : 2 }
        return json.dumps(result)

    @staticmethod
    def information( xmppobject, data ):
        logger.debug("iq information")
        result =  { "result" : { "informationresult" : {} }, "error" : False , 'numerror' : 0 }
        for info_ask in data['listinformation']:
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
            except:
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
