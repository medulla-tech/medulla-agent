# -*- coding: utf-8 -*-
#
# (c) 2017 siveo, http://www.siveo.net
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

# file scheduling_inv.py

"""
this plugin process inventory from crontab descriptor time
"""
import logging
from  lib.utils import getRandomName, call_plugin
# nb  -1 infinie
#SCHEDULE = {"schedule" : "*/1 * * * *", "nb" : -1}
#SCHEDULE = {"schedule" : "30 22 * * 2", "nb" : -1}

plugin = { "VERSION" : "1.0", "NAME" : "inv", "descrition" : "pluging scheduled inventory", "TYPE" : "scheduled" }

crontabdescriptor = "15 13 * * 4"
SCHEDULE = { "schedule" : crontabdescriptor, "nb" : -1 }

def schedule_main(objectxmpp):
    # cycle inventory or scheduled inventory
    if objectxmpp.config.inventory_interval != 0:
        return
    logging.getLogger().debug("###################################################")
    logging.getLogger().debug("call : %s ",plugin )
    logging.getLogger().debug("###################################################")
    msg={ 'from' : "master@pulse/MASTER",
            'to': objectxmpp.boundjid.bare
            }
    sessionid = getRandomName(6, "inventory")
    dataerreur = {}
    dataerreur['action']= "resultinventory"
    dataerreur['data']={}
    dataerreur['data']['msg'] = "ERROR : inventory"
    dataerreur['sessionid'] = sessionid
    dataerreur['ret'] = 255
    dataerreur['base64'] = False
    print dataerreur
    call_plugin("inventory",
                    objectxmpp,
                    "inventory",
                    sessionid,
                    {},
                    msg,
                    dataerreur)
    objectxmpp.xmpplog(
                "Sent Inventory from agent %s (scheduler) %s"%(objectxmpp.boundjid.bare, crontabdescriptor),
                type = 'noset',
                sessionname = sessionid,
                priority = 0,
                action = "",
                who = objectxmpp.boundjid.bare,
                how = "Planned",
                why = "",
                module = "Inventory | Inventory reception | Planned",
                fromuser = "",
                touser = "")
