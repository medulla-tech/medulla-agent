# -*- coding: utf-8 -*-
#
# (c) 2015 siveo, http://www.siveo.net
# $Id$
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
# along with Pulse 2. If not, see <http://www.gnu.org/licenses/>.
#
#"""
# 
#"""
 
import base64
import json
import subprocess


plugin={"VERSION": "1.0", "NAME" :"listplugins"}


def action(jsonobj, msg, classxmpp ):
    
    
    result = { 'action': "result%s"%jsonobj['action'],
               'msg' : 'Error : plugin_listplugins'}
             #'data' : 'resultat test plugin getipinfo'}
    sessionid = ''
    try:
        if jsonobj['sessionid'] != "":
            sessionid= jsonobj['sessionid']
    except:
        sessionid = "result"
    #print json.dumps(er.messagejson, indent=4, sort_keys=True)
    classxmpp.send_message( mto=msg['from'],
                            mbody=result,
                            mtype='groupchat')

    #print json.dumps(jsonobj, indent=4, sort_keys=True)
    
    #classxmpp.send_message( mto=msg['from'],
                            #mbody=json.dumps(result),
                            #mtype='groupchat')
