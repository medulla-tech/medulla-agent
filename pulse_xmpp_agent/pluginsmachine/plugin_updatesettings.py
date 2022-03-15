# -*- coding: utf-8 -*-
#
# (c) 2020 siveo, http://www.siveo.net
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

import logging
from lib.configuration import setconfigfile

logger = logging.getLogger()

plugin = {"VERSION": "1.3", "NAME": "updatesettings", "TYPE": "machine"} # fmt: skip

# Examples
# param_1 = 'add@__@agentconf.ini@__@global@__@loglevel@__@DEBUG'
# param_2 = 'del@__@agentconf.ini@__@global@__@loglevel'
# nb_params = 2

# ---START-PARAMS---
# Add parameters here
# param_1 = 'add@__@agentconf.ini@__@global@__@loglevel@__@DEBUG'
# param_2 = 'del@__@agentconf.ini@__@global@__@loglevel'
# nb_params = 2
# ---END-PARAMS---


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
