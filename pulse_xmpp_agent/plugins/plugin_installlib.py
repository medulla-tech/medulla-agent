/**
 * (c) 2016 Siveo, http://http://www.siveo.net
 *
 * $Id$
 *
 * This file is part of Pulse .
 *
 * Pulse is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * Pulse is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Pulse.  If not, see <http://www.gnu.org/licenses/>.
 */
 
import base64
import json
import subprocess

from lib.networkinfo import networkagentinfo
plugin={"VERSION": "1.0", "NAME" :"installlib"}

def action(jsonobj, msg, classxmpp ):
    
    
    result = { 'action': "result%s"%jsonobj['action'],
               'msg' : 'Error : plugin_getipinfo'}

    sessionid = ''
    try:
        if jsonobj['sessionid'] != "":
            sessionid= jsonobj['sessionid']
    except:
        sessionid = "result"
   
    try:
        if isinstance(jsonobj['param'],str) or isinstance(jsonobj['param'],unicode) :
            jsonobj['param']=[jsonobj['param']]

    except NameError:
        jsonobj['param']=[]
    
    try:
        er = networkagentinfo(sessionid,"result%s"%jsonobj['action'],jsonobj['param'])
    except:
        classxmpp.send_message( mto=msg['from'],
                            mbody=json.dumps(result),
                            mtype='groupchat')
    

    classxmpp.send_message( mto=msg['from'],
                            mbody=json.dumps(er.messagejson),
                            mtype='groupchat')

