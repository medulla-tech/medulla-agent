# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2016-2023 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-3.0-or-later

import json
import os
import logging
from lib.utils import getRandomName


logger = logging.getLogger()

DEBUGPULSEPLUGIN = 25
plugin = {"VERSION": "1.0", "NAME": "start", "TYPE": "substitute"}  # fmt: skip


def action(objectxmpp, action, sessionid, data, msg, dataerreur):
    logger.debug("=====================================================")
    logger.debug("call %s from %s" % (plugin, msg["from"]))
    logger.debug("=====================================================")
    Setdirectorytempinfo()  # create directory pour install key public master.
    # in starting agent ask public key of master.
    ask_key_master_public(objectxmpp)


def ask_key_master_public(self, objectxmpp):
    """
    ask public key on master
    """
    datasend = {
        "action": "ask_key_public_master",
        "data": {},
        "ret": 0,
        "sessionid": getRandomName(5, "ask_key_public_master"),
    }
    self.send_message(mto=self.agentmaster, mbody=json.dumps(datasend), mtype="chat")


def Setdirectorytempinfo():
    """
    create directory
    """
    dirtempinfo = os.path.join(
        os.path.dirname(os.path.realpath(__file__)), "..", "INFOSTMP"
    )
    if not os.path.exists(dirtempinfo):
        os.makedirs(dirtempinfo, mode=0o700)
    return dirtempinfo
