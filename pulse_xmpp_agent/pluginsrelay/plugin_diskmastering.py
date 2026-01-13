# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2022-2023 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-3.0-or-later

import logging
import json
from lib.utils import set_logging_level

plugin = {"VERSION": "0.1", "NAME": "diskmastering", "TYPE": "relayserver"}  # fmt: skip

logger = logging.getLogger()


@set_logging_level
def action(objectxmpp, action, sessionid, data, message, dataerreur):
    logging.getLogger().debug("###################################################")
    logging.getLogger().debug("call %s from %s session id %s" % (plugin, message["from"], sessionid))
    logging.getLogger().debug("###################################################")

    # To complete : for later uses