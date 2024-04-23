#!/usr/bin/python3
# -*- coding: utf-8; -*-
# SPDX-FileCopyrightText: 2016-2023 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-3.0-or-later

import sys
import os


def directoryconffile():
    """
    This function permits to obtain the configuration folder.

    Returns:
        It returns the path of medulla configuration folder
    """
    if sys.platform.startswith("linux"):
        fileconf = os.path.join("/", "etc", "medulla-agent")
    elif sys.platform.startswith("win"):
        fileconf = os.path.join("c:\\", "progra~1", "Medulla", "etc")
    elif sys.platform.startswith("darwin"):
        fileconf = os.path.join("/opt", "Medulla", "etc")
    if os.path.isdir(fileconf):
        return fileconf
    else:
        return None


def medullaTempDir():
    """
    This function permits to obtain the temporary folder.

    Returns:
        It returns the path of medulla temporary folder
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
    if sys.platform.startswith("linux"):
        fileconf = os.path.join("/", "etc", "medulla-agent", conffilenameparameter)
    elif sys.platform.startswith("win"):
        fileconf = os.path.join(
            "c:\\", "progra~1", "Medulla", "etc", conffilenameparameter
        )
    elif sys.platform.startswith("darwin"):
        fileconf = os.path.join(
            "/", "Library", "Application Support", "Medulla", "etc", conffilenameparameter
        )
    else:
        fileconf = conffilenameparameter
    if conffilenameparameter == "cluster.ini":
        return fileconf
    if os.path.isfile(fileconf):
        return fileconf
    else:
        return conffilenameparameter
