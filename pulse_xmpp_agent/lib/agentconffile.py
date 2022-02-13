#!/usr/bin/python3
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
import shutil
import logging
logger = logging.getLogger()


def directoryconffile():
    """
        This function provide the path to the configuration files of pulse-xmpp-agent.

        Return:
            it returns the path to the configuration files if it exists
            it returns None if the path does not exist
    """
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
            "/opt",
            "Pulse",
            "etc")
    if os.path.isdir(fileconf):
        return fileconf
    else:
        return None


def pulseTempDir():
    """
    This function permits to obtain the temporary folder.

    Returns:
        It returns the path of pulse temporary folder
    """
    if sys.platform.startswith('linux'):
        tempdir = os.path.join(
            "/",
            "tmp")
    elif sys.platform.startswith('win'):
        tempdir = os.path.join(
            os.environ["ProgramFiles"],
            "Pulse",
            "tmp")
    elif sys.platform.startswith('darwin'):
        tempdir = os.path.join(
            "/opt",
            "Pulse",
            "tmp")

    return tempdir


def conffilename(agenttype):
    """
        This function define where the configuration file is located.

        Args:
            agenttype: type of the agent, relay or machine or cluster for RelayServer

        Returns:
            Return the config file path

    """
    if agenttype in ["machine"]:
        conffilenameparameter = "agentconf.ini"
    elif agenttype in ["cluster"]:
        conffilenameparameter = "cluster.ini"
    else:
        conffilenameparameter = "relayconf.ini"

    if directoryconffile() is not None:
        fileconf = os.path.join(directoryconffile(), conffilenameparameter)
    else:
        fileconf = conffilenameparameter

    if conffilenameparameter == "cluster.ini":
        return fileconf

    if os.path.isfile(fileconf):
        return fileconf
    else:
        return conffilenameparameter


def conffilenametmp(agenttype):
    """
        This function define where the configuration file tmp is located.

        Args:
            agenttype: type of the agent, relay or machine or cluster for RelayServer

        Returns:
            Return the config file path

    """
    if agenttype in ["machine"]:
        conffilenameparameter = "agentconftmp.ini"
    elif agenttype in ["cluster"]:
        conffilenameparameter = "clustertmp.ini"
    else:
        conffilenameparameter = "relayconftmp.ini"

    if directoryconffile() is not None:
        fileconf = os.path.join(directoryconffile(), conffilenameparameter)
    else:
        fileconf = conffilenameparameter

    if conffilenameparameter == "clustertmp.ini":
        return fileconf

    return fileconf


def rotation_file(namefile, suffixe=""):
    """
    This function exec rotation file.

        Args:
            namefile: name file rotation

    """
    if suffixe != "":
        suffixe = "_" + suffixe
    for x in range(5, 0, -1):
        src = "%s%s_%s" % (namefile, suffixe, x)
        dest = "%s%s_%s" % (namefile, suffixe, x + 1)
        if os.path.isfile(src):
            shutil.copyfile(src, dest)
        if x == 1:
            shutil.copyfile(namefile, dest)
