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

