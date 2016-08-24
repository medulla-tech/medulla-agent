# -*- coding: utf-8 -*-
#"""
#This plugin return unsimple text for test
#"""

from  lib.utils import pulginprocess
plugin={"VERSION": "2.0", "NAME" :"test"}
@pulginprocess
def action( objetxmpp, action, sessionid, data, message, dataerreur,result):
    if data['afficherliste'] [0] !=   'I am a test':
        dataerreur['data']['msg'] = 'There is an error, ret will be different than 0'
        raise
    result['data']['showList'] = data['showList']
    result['base64'] = True
