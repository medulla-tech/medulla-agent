# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2017-2023 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-3.0-or-later

"""
This plugin processes inventory based on crontab descriptor time.
"""

import logging
from lib import utils

plugin = {"VERSION": "2.0", "NAME": "scheduling_inv", "TYPE": "machine", "SCHEDULED": True}  # fmt: skip

SCHEDULE = {"schedule": "$[0,59] $[8,17] * * *", "nb": -1}  # nb  -1 infinie


def schedule_main(objectxmpp):
    """
    Main function for the scheduling inventory plugin.

    Args:
        objectxmpp: An object representing the XMPP connection.

    Notes:
        This function is called at specific intervals based on the crontab descriptor.
        If the inventory_interval in the configuration is not 0, the function does nothing.
        Otherwise, it sends an inventory request and logs the action.

    """
    if objectxmpp.config.inventory_interval != 0:
        return
    logging.getLogger().debug("###################################################")
    logging.getLogger().debug("call %s ", plugin)
    logging.getLogger().debug("###################################################")
    msg = {"from": "master@pulse/MASTER", "to": objectxmpp.boundjid.bare}
    sessionid = utils.getRandomName(6, "inventory")
    dataerreur = {"action": "resultinventory", "data": {}}
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
        f"Sent Inventory from agent {objectxmpp.boundjid.bare}",
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
