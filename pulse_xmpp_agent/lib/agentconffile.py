#!/usr/bin/env python
# -*- coding: utf-8; -*-
#
# (c) 2016 siveo, http://www.siveo.net
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

import sys,os
import os.path

def conffilename( type ):
    """
        Function defining where the configuration file is located.
        configuration file for the type of machine and the Operating System
    """
    if type in ["machine"]:
        conffilenameparamter = "agentconf.ini"
    else:
        conffilenameparamter = "relayconf.ini"
    if sys.platform.startswith('linux'):
        fileconf = os.path.join("/", "etc" ,"pulse-xmpp-agent", conffilenameparamter)
    elif sys.platform.startswith('win'):
        fileconf = os.path.join(os.environ["ProgramFiles"], "Pulse", "etc", conffilenameparamter)
    elif sys.platform.startswith('darwin'):
        fileconf = os.path.join("/", "Library", "Application Support", "Pulse", "etc", conffilenameparamter)
    else:
        fileconf = conffilenameparamter

    if os.path.isfile(fileconf): 
        return fileconf
    else:
        return conffilenameparamter


