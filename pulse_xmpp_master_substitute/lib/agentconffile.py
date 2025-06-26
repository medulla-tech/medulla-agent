#!/usr/bin/python3
# -*- coding: utf-8; -*-
# SPDX-FileCopyrightText: 2016-2023 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-3.0-or-later

import sys
import os
import shutil
import logging

logger = logging.getLogger()


def medullaPath():
    """
    Provides the path to the medulla install

    Returns:
        str: The path to the medulla install
    """
    if sys.platform.startswith("linux"):
        medullapath = os.path.join("/")
    elif sys.platform.startswith("win"):
        medullapath = os.path.join("c:\\", "progra~1", "Medulla")
    elif sys.platform.startswith("darwin"):
        medullapath = os.path.join("/opt", "Medulla")
    return medullapath if os.path.isdir(medullapath) else None


def directoryconffile():
    """
    Provides the path to the configuration files of pulse-xmpp-agent.

    Returns:
        str: The path to the configuration files if it exists, None otherwise.
    """
    if sys.platform.startswith("linux"):
        fileconf = os.path.join("/", "etc", "pulse-xmpp-agent")
    else:
        fileconf = os.path.join(medullaPath(), "etc")

    return fileconf if os.path.isdir(fileconf) else None


def pulseTempDir():
    """
    Obtains the temporary folder used by Pulse.

    Returns:
        str: The path of the pulse temporary folder.
    """
    tempdir = os.path.join(medullaPath(), "tmp")
    return tempdir


def conffilename(agenttype):
    """
    Defines the location of the configuration file.

    Args:
        agenttype (str): Type of the agent, relay or machine or cluster for RelayServer.

    Returns:
        str: The config file path.
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
    Defines the location of the temporary configuration file.

    Args:
        agenttype (str): Type of the agent, relay or machine or cluster for RelayServer.

    Returns:
        str: The temporary config file path.
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
    Executes file rotation.

    Args:
        namefile (str): Name of the file to rotate.
        suffixe (str): Suffix to be added to the rotated file names.
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
