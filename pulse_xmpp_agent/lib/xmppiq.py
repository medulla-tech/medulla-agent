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
from utils import shellcommandtimeout, file_put_contents, file_get_contents, decode_strconsole, encode_strconsole
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

def callXmppFunctionIq(functionname,  *args, **kwargs):
    logging.getLogger().debug("**call function %s %s %s"%(functionname, args, kwargs))
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
                         "remotexmppmonitoring"]

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
        return json.dumps(data)

    @staticmethod
    def test( xmppobject, data):
        return json.dumps(data)

    @staticmethod
    def remotefilesimple( xmppobject, data ):
        datapath = data['data']
        if type(datapath) == unicode or type(datapath) == str:
            datapath = str(data['data'])
            filesystem = xmppobject.xmppbrowsingpath.listfileindir(datapath)
            data['data']=filesystem
        return json.dumps(data)

    @staticmethod
    def remotefile( xmppobject, data ):
        print data
        datapath = data['data']
        if type(datapath) == unicode or type(datapath) == str:
            datapath = str(data['data'])
            filesystem = xmppobject.xmppbrowsingpath.listfileindir(datapath)
            data['data']=filesystem
        return json.dumps(data)

    @staticmethod
    def remotecommandshell( xmppobject, data ):
        result = shellcommandtimeout(encode_strconsole(data['data']), timeout=data['timeout']).run()
        re = [ decode_strconsole(x).strip(os.linesep)+"\n" for x in result['result'] ]
        result['result'] = re
        return json.dumps(result)

    @staticmethod
    def listremotefileedit( xmppobject, data ):
        listfileedit = [ x for x in os.listdir(directoryconffile()) if x.endswith(".ini")]
        data['data']={"result" : listfileedit}
        return json.dumps(data)

    @staticmethod
    def remotexmppmonitoring( xmppobject, data ):
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
