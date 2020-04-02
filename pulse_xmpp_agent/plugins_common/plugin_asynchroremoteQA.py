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
# file : plugin_asynchroreremoteQA.py


from  lib.utils import decode_strconsole, encode_strconsole,shellcommandtimeout
import json
import traceback
import sys
import logging

plugin = {"VERSION": "1.0", "NAME" : "asynchroremoteQA", "TYPE" : "all"}


def action(objectxmpp, action, sessionid, data, message, dataerreur):
    logging.getLogger().info("###################################################")
    logging.getLogger().info("call %s from %s"%(plugin,message['from']))
    logging.getLogger().info("###################################################")
    result = {'action': "result%s"%action,
              'sessionid': sessionid,
              'data' : {},
              'ret' : 0,
              'base64' : False }
    try:
        resultcmd = shellcommandtimeout(encode_strconsole(data['data']['customcmd']), 15).run()
        resultcmd['result'] = [decode_strconsole( x )  for x in resultcmd['result']]
        result['data']['result'] = resultcmd
        result['data']['data'] = data
        result['ret'] = resultcmd['code']
        objectxmpp.send_message(mto=message['from'],
                                mbody=json.dumps(result),
                                mtype='chat')
    except Exception as e:
        logging.getLogger().error(str(e))
        traceback.print_exc(file=sys.stdout)
        dataerreur['ret'] = -255
        dataerreur['data']['msg'] = "Erreur commande\n %s"%data['data']['customcmd']
        objectxmpp.send_message(mto=message['from'],
                                mbody=json.dumps(dataerreur),
                                mtype='chat')
