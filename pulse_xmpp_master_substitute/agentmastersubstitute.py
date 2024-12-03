#!/usr/bin/python3
# coding: utf-8
# SPDX-FileCopyrightText: 2016-2023 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-3.0-or-later
"""
    Launcher for agentsubstitute
"""

import sys
import os
import logging
from lib.configuration import confParameter
from lib.utils import ipfromdns
from lib.logcolor import add_coloring_to_emit_ansi
import time
import traceback
from optparse import OptionParser
from lib.plugins.xmpp import XmppMasterDatabase
from lib.plugins.glpi import Glpi
from lib.plugins.kiosk import KioskDatabase
from lib.plugins.msc import MscDatabase
from lib.plugins.pkgs import PkgsDatabase
from bin.agent import MUCBot

# import signal
from lib import manageRSAsigned

sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), "lib"))
sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), "bin"))
sys.path.append(
    os.path.join(os.path.dirname(os.path.realpath(__file__)), "pluginsmastersubstitute")
)

logger = logging.getLogger()


def Setdirectorytempinfo():
    """
    Create directory for temporary information.
    """
    dirtempinfo = os.path.join(os.path.dirname(os.path.realpath(__file__)), "INFOSTMP")
    if not os.path.exists(dirtempinfo):
        os.makedirs(dirtempinfo, mode=0o700)
    return dirtempinfo


def createDaemon(optsconsoledebug, optsdeamon, optfileconf):
    """
    This function creates a service/Daemon that will execute a det. task.
    """
    try:
        # Store the Fork PID
        pid = os.fork()
        if pid > 0:
            print("PID: %d" % pid)
            os._exit(0)
        doTask(optsconsoledebug, optsdeamon, optfileconf)
    except OSError as error:
        logging.error("Unable to fork. Error: %d (%s)" % (error.errno, error.strerror))
        logging.error("\n%s" % (traceback.format_exc()))
        os._exit(1)


def doTask(optsconsoledebug, optsdeamon, optfileconf):
    """
    Main function that performs the agent substitute task.

    Args:
        optsconsoledebug (bool): True if console debug is enabled, False otherwise.
        optsdeamon (bool): True if the process should be daemonized, False otherwise.
        optfileconf (str): Path to the configuration file.
    """

    tg = confParameter(optfileconf)
    logdir = os.path.dirname(tg.logfile)
    if not os.path.exists(logdir):
        os.makedirs(logdir)

    # all non-Windows platforms are supporting ANSI escapes so we use them
    logging.StreamHandler.emit = add_coloring_to_emit_ansi(logging.StreamHandler.emit)
    # format log more informations
    format = "%(asctime)s - %(levelname)s - %(message)s"
    # more information log
    # format ='[%(name)s : %(funcName)s : %(lineno)d] - %(levelname)s - %(message)s'
    if not optsdeamon:
        if optsconsoledebug:
            logging.basicConfig(level=logging.DEBUG, format=format)
        else:
            logging.basicConfig(
                level=tg.levellog, format=format, filename=tg.logfile, filemode="a+"
            )
    else:
        logging.basicConfig(
            level=tg.levellog, format=format, filename=tg.logfile, filemode="a+"
        )
    # Setup the command line arguments.
    tg = confParameter(optfileconf)

    configuration_file = (
        "/etc/pulse-xmpp-agent-substitute/agent_master_substitute_reg.ini.local"
    )

    # activate modules
    modules = {
        "glpi": (Glpi, "GLPI"),
        "xmpp": (XmppMasterDatabase, "XMPP"),
        "kiosk": (KioskDatabase, "KIOSK"),
        "msc": (MscDatabase, "MSC"),
        "pkgs": (PkgsDatabase, "PKGS"),
    }

    for module, (cls, name) in modules.items():
        if module in tg.plugins_list:
            logger.info(f"activate {name}")
            if not cls().activate():
                logger.error(f"We failed to connect the {name} database.")
                logger.error(f"Please verify your configuration in {optfileconf}")
                return
    xmpp = MUCBot(optfileconf)
    xmpp.shutdown = False

    xmpp.register_plugin("xep_0030")  # Service Discovery
    xmpp.register_plugin("xep_0045")  # Multi-User Chat
    xmpp.register_plugin("xep_0060")  # PubSub
    xmpp.register_plugin("xep_0004")  # Data Forms
    xmpp.register_plugin("xep_0050")  # Adhoc Commands
    xmpp.register_plugin(
        "xep_0199",
        {"keepalive": True, "frequency": 600, "interval": 600, "timeout": 500},
    )
    xmpp.register_plugin("xep_0077")  # In-band Registration
    xmpp["xep_0077"].force_registration = True

    # Calculer la longueur totale de la ligne centrale
    total_length = (
        (2 + 5) * 2 + len("CONNECTION SUBSTITUT") + len(str(xmpp.boundjid.bare))
    )
    logger.info("/" + "-" * 4 + "-" * total_length + "\\")
    logger.info("|----- CONNECTION XMPP SUBSTITUT %s -----|" % str(xmpp.boundjid.bare))
    logger.info("\\" + "-" * 4 + "-" * total_length + "/")

    xmpp.config = confParameter(optfileconf)
    xmpp.address = (ipfromdns(xmpp.config.Server), int(xmpp.config.Port))
    try:
        xmpp.connect(address=xmpp.address, force_starttls=None)
    except Exception as e:
        logging.error("Connection failed: %s. Retrying..." % e)
    try:
        xmpp.loop.run_forever()
    except RuntimeError:
        logging.error("RuntimeError during connection")
    finally:
        xmpp.loop.close()


# def handler_CTRL(signum, frame):
#     global xmpp
#     logger.error("CTRL + C")
#     if xmpp and xmpp.loop:
#         xmpp.loop.stop()

if __name__ == "__main__":
    if sys.platform.startswith("linux") and os.getuid() != 0:
        # logger.error("Agent must be running as root")
        sys.exit(0)

    # Check if the master keys are installed
    dirkey = Setdirectorytempinfo()
    filekeypublic = os.path.join(Setdirectorytempinfo(), "master-public-RSA.key")
    fileprivatekey = os.path.join(Setdirectorytempinfo(), "master-private-RSA.key")
    msgkey = manageRSAsigned.MsgsignedRSA("master")
    if not (os.path.isfile(filekeypublic) and os.path.isfile(fileprivatekey)):
        logger.error("The security keys are missing.")
        logger.error(
            "To work correctly we need the following keys: \n - %s \n - %s"
            % (filekeypublic, fileprivatekey)
        )
        sys.exit(0)

    namefileconfigdefault = os.path.join(
        "/", "etc", "pulse-xmpp-agent_substitute", "agent_master_substitute.ini"
    )

    optp = OptionParser()
    optp.add_option(
        "-d",
        "--deamon",
        action="store_true",
        dest="deamon",
        default=False,
        help="deamonize process",
    )
    optp.add_option(
        "-c",
        "--consoledebug",
        action="store_true",
        dest="consoledebug",
        default=False,
        help="console debug",
    )
    optp.add_option(
        "-f",
        "--configfile",
        dest="namefileconfig",
        default=namefileconfigdefault,
        help="configuration file",
    )

    # signal.signal(signal.SIGINT, handler_CTRL)
    opts, args = optp.parse_args()

    if not opts.deamon:
        doTask(opts.consoledebug, opts.deamon, opts.namefileconfig)
    else:
        createDaemon(opts.consoledebug, opts.deamon, opts.namefileconfig)
