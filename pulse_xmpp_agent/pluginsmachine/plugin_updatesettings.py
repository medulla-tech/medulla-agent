# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2016-2023 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-3.0-or-later

import logging
from lib.configuration import setconfigfile
from lib.utils import set_logging_level

logger = logging.getLogger()
plugin = {"VERSION": "1.5", "NAME": "updatesettings", "TYPE": "machine"}  # fmt: skip

# Examples
# param_1 = 'add@__@agentconf.ini@__@global@__@loglevel@__@DEBUG'
# param_2 = 'del@__@agentconf.ini@__@global@__@loglevel'
# nb_params = 2

# ---START-PARAMS---
# Add parameters here
param_1 = 'add@__@startupdate.ini@__@plugins@__@liststartplugin@__@all'
nb_params = 1
# ---END-PARAMS---


@set_logging_level
def action(xmppobject, action, sessionid, data, message, dataerreur):
    logger.debug("###################################################")
    logger.debug("call %s from %s" % (plugin, message["from"]))
    logger.debug("###################################################")
    msg = []
    # get the value of each parameter and update the config files

    try:
        nb_iter = int(nb_params) + 1
        for num in range(1, nb_iter):
            param_num = "param_" + str(num)
            msglog = "Processing parameter %s" % eval(param_num)
            msg.append(msglog)
            datasetting = eval(param_num).split("@__@")
            if len(datasetting) > 0 and (
                datasetting[0].lower() == "add" or datasetting[0].lower() == "del"
            ):
                if not setconfigfile(datasetting):
                    msglog = "Error setting parameter %s" % eval(param_num)
                    logger.error(msglog)
                    msg.append(msglog)
                else:
                    msglog = "Parameter %s successfully processed" % eval(param_num)
                    msg.append(msglog)
    except NameError:
        msglog = "Parameters not defined at start of plugin. Nothing to do"
        msg.append(msglog)

    # Write message to logger
    for line in msg:
        logger.debug(line)
