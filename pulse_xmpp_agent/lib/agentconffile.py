#!/usr/bin/python3
# -*- coding: utf-8; -*-
# SPDX-FileCopyrightText: 2016-2023 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-3.0-or-later

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
    if sys.platform.startswith("linux"):
        fileconf = os.path.join("/", "etc", "pulse-xmpp-agent")
    elif sys.platform.startswith("win"):
        fileconf = os.path.join("c:", "progra~1", "Pulse", "etc")
    elif sys.platform.startswith("darwin"):
        fileconf = os.path.join("/opt", "Pulse", "etc")
    return fileconf if os.path.isdir(fileconf) else None


def pulseTempDir():
    """
    This function permits to obtain the temporary folder.

    Returns:
        It returns the path of pulse temporary folder
    """
    if sys.platform.startswith("linux"):
        tempdir = os.path.join("/", "tmp")
    elif sys.platform.startswith("win"):
        tempdir = os.path.join("c:", "progra~1", "Pulse", "tmp")
    elif sys.platform.startswith("darwin"):
        tempdir = os.path.join("/opt", "Pulse", "tmp")

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

    return fileconf if os.path.isfile(fileconf) else conffilenameparameter


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

    return (
        os.path.join(pulseTempDir(), conffilenameparameter)
        if directoryconffile() is not None
        else conffilenameparameter
    )


def rotation_file(namefile, suffixe=""):
    """
    This function exec rotation file.

        Args:
            namefile: name file rotation

    """
    if suffixe != "":
        suffixe = f"_{suffixe}"
    for x in range(5, 0, -1):
        src = f"{namefile}{suffixe}_{x}"
        dest = f"{namefile}{suffixe}_{x + 1}"
        if os.path.isfile(src):
            shutil.copyfile(src, dest)
        if x == 1:
            shutil.copyfile(namefile, dest)
