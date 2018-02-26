#!/usr/bin/env python
# -*- coding: utf-8; -*-
#
# (c) 2016 - 2018 siveo, http://www.siveo.net
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

import sys
import os

def directoryconffile():
    if sys.platform.startswith('linux'):
        fileconf = os.path.join(
            "/",
            "etc",
            "pulse-xmpp-agent")
    elif sys.platform.startswith('win'):
        fileconf = os.path.join(
            os.environ["ProgramFiles"],
            "Pulse",
            "etc")
    elif sys.platform.startswith('darwin'):
        fileconf = os.path.join(
            "/",
            "Library",
            "Application Support",
            "Pulse",
            "etc")
    if os.path.isdir(fileconf):
        return fileconf
    else:
        return None

def conffilename(agenttype):
    """
        Function defining where the configuration file is located.
        configuration file for the type of machine and the Operating System

        Args:
        agenttype: type of the agent, relay or machine or (cluster for ARS)

        Returns:
        Return the config file path

    """
    if agenttype in ["machine"]:
        conffilenameparameter = "agentconf.ini"
    elif agenttype in ["cluster"]:
        conffilenameparameter = "cluster.ini"
    else:
        conffilenameparameter = "relayconf.ini"
    if sys.platform.startswith('linux'):
        fileconf = os.path.join(
            "/",
            "etc",
            "pulse-xmpp-agent",
            conffilenameparameter)
    elif sys.platform.startswith('win'):
        fileconf = os.path.join(
            os.environ["ProgramFiles"],
            "Pulse",
            "etc",
            conffilenameparameter)
    elif sys.platform.startswith('darwin'):
        fileconf = os.path.join(
            "/",
            "Library",
            "Application Support",
            "Pulse",
            "etc",
            conffilenameparameter)
    else:
        fileconf = conffilenameparameter
    if conffilenameparameter == "cluster.ini":
        return fileconf
    if os.path.isfile(fileconf):
        return fileconf
    else:
        return conffilenameparameter

