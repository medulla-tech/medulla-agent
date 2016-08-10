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
#This module is dedicated to analyse inventories sent by a Pulse 2 Client.
#The original inventory is sent using one line per kind of
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
