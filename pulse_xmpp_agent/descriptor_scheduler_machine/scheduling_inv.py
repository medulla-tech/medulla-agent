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
"""
this plugin process inventory from crontab descriptor time
"""
import logging
from lib import utils

plugin = {"VERSION": "2.0", "NAME": "scheduling_inv", "TYPE": "machine","SCHEDULED": True,}  # fmt: skip

SCHEDULE = {"schedule": "$[0,59] $[8,17] * * *", "nb": -1}  # nb  -1 infinie


def schedule_main(objectxmpp):
    if objectxmpp.config.inventory_interval != 0:
        return
    logging.getLogger().debug("###################################################")
    logging.getLogger().debug("call %s ", plugin)
    logging.getLogger().debug("###################################################")
    msg = {"from": "master@pulse/MASTER", "to": objectxmpp.boundjid.bare}
    sessionid = utils.getRandomName(6, "inventory")
    dataerreur = {}
    dataerreur["action"] = "resultinventory"
    dataerreur["data"] = {}
    dataerreur["data"]["msg"] = "ERROR : inventory"
    dataerreur["sessionid"] = sessionid
    dataerreur["ret"] = 255
    dataerreur["base64"] = False
    utils.call_plugin(
        "inventory",
        objectxmpp,
        "inventory",
        sessionid,
        {"forced": "noforced"},
        msg,
        dataerreur,
    )
    objectxmpp.xmpplog(
        "Sent Inventory from agent %s" % (objectxmpp.boundjid.bare),
        type="noset",
        sessionname=sessionid,
        priority=0,
        action="xmpplog",
        who=objectxmpp.boundjid.bare,
        how="Planned",
        why="",
        module="Inventory | Inventory reception | Planned",
        fromuser="",
        touser="",
    )
