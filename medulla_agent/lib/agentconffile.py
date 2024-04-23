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
        fileconf = os.path.join("/", "etc", "medulla-agent")
    elif sys.platform.startswith("win"):
        fileconf = os.path.join("c:\\", "progra~1", "Medulla")
    elif sys.platform.startswith("darwin"):
        fileconf = os.path.join("/opt", "Medulla")
    return fileconf if os.path.isdir(fileconf) else None


def directoryconffile():
    """
    Provides the path to the configuration files of medulla-agent.

    Returns:
        str: The path to the configuration files if it exists, None otherwise.
    """
    if sys.platform.startswith("linux"):
        fileconf = os.path.join("/", "etc", "medulla-agent")
    elif sys.platform.startswith("win"):
        fileconf = os.path.join("c:\\", "progra~1", "Medulla", "etc")
    elif sys.platform.startswith("darwin"):
        fileconf = os.path.join("/opt", "Medulla", "etc")
    return fileconf if os.path.isdir(fileconf) else None


def medullaTempDir():
    """
    Obtains the temporary folder used by Medulla.

    Returns:
        str: The path of the medulla temporary folder.
    """
    if sys.platform.startswith("linux"):
        tempdir = os.path.join("/", "tmp")
    elif sys.platform.startswith("win"):
        tempdir = os.path.join("c:\\", "progra~1", "Medulla", "tmp")
    elif sys.platform.startswith("darwin"):
        tempdir = os.path.join("/opt", "Medulla", "tmp")
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
        os.path.join(medullaTempDir(), conffilenameparameter)
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
