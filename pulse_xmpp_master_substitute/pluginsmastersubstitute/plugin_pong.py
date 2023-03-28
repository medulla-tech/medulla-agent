# -*- coding: utf-8 -*-
<<<<<<< HEAD
#
# (c) 2021 siveo, http://www.siveo.net
#
# $Id$
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

=======
# SPDX-FileCopyrightText: 2021-2023 Siveo <support@siveo.net> 
# SPDX-License-Identifier: GPL-2.0-or-later 
>>>>>>> integration

"""
    Plugin used to check if the presence machine call asynchome.
"""

import traceback
import os
import logging
from lib.plugins.xmpp import XmppMasterDatabase

logger = logging.getLogger()

plugin = {"VERSION": "1.0", "NAME": "pong", "TYPE": "substitute"}
def action(xmppobject, action, sessionid, data, msg, ret, dataobj):
    """
        Used to verify machine on
    """
    try:
        logger.debug("=====================================================")
        logger.debug("call %s from %s" % (plugin, msg['from']))
        logger.debug("=====================================================")
        result = XmppMasterDatabase().SetPresenceMachine(str(msg['from']), presence=1)
    except Exception as e:
        logger.error("Plugin pong %s from %s" % (str(e), str(msg['from'])))
        logger.error("We obtained the backtrace %s" % traceback.format_exc())
