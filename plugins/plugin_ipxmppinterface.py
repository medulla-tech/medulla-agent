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
 
# -*- coding: utf-8 -*-
import json

from lib.utils import  simplecommandestr, simplecommande
import sys, os, platform
from  lib.utils import pulginprocess



plugin={"VERSION": "3.0", "NAME" :"ipxmppinterface"}
@pulginprocess
def action( objetxmpp, action, sessionid, data, message, dataerreur,result):
    if sys.platform.startswith('linux'):
        obj = simplecommande("netstat -paunt | grep 5222")
        for i in range(len(obj['result'])):
            obj['result'][i]=obj['result'][i].rstrip('\n')
        a = "\n".join(obj['result'])
        dataerreur['ret'] = obj['code']
        if obj['code'] == 0:
            result['data']['result'] = a
        else:
            dataerreur['data']['msg']="Command error\n %s"%a
            raise

    if obj['code'] == 0:
        result['data']['result'] = a
    elif sys.platform.startswith('win'):
        obj = simplecommande("netstat -an | findstr 5222")
        for i in range(len(obj['result'])):
            obj['result'][i]=obj['result'][i].rstrip('\n')
        a = "\n".join(obj['result'])
        dataerreur['ret'] = obj['code']
        if obj['code'] == 0:
            result['data']['result'] = a
        else:
            dataerreur['data']['msg']="Command error \n %s"%a
            raise
    else:
        pass

