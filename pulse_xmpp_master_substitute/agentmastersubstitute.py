#!/usr/bin/env python
# -*- coding: utf-8; -*-
# SPDX-FileCopyrightText: 2016-2023 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-2.0-or-later

import sys
import os
import logging
from lib.configuration import confParameter
from lib.utils import DEBUGPULSE, ipfromdns
from lib.logcolor import add_coloring_to_emit_ansi

import traceback
from optparse import OptionParser
from lib.plugins.xmpp import XmppMasterDatabase
from lib.plugins.glpi import Glpi
from lib.plugins.kiosk import KioskDatabase
from lib.plugins.msc import MscDatabase
from lib.plugins.pkgs import PkgsDatabase
from bin.agent import MUCBot



sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), "lib"))
sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), "bin"))
sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), "pluginsmastersubstitute"))

logger = logging.getLogger()

def Setdirectorytempinfo():
    """
        create directory
    """
    dirtempinfo = os.path.join(os.path.dirname(os.path.realpath(__file__)), "INFOSTMP")
    if not os.path.exists(dirtempinfo):
        os.makedirs(dirtempinfo, mode=0700)
    return dirtempinfo

def createDaemon(optsconsoledebug, optsdeamon, optfileconf):
    """
        This function create a service/Daemon that will execute a det. task
    """
    try:
        # Store the Fork PID
        pid = os.fork()
        if pid > 0:
            print 'PID: %d' % pid
            os._exit(0)
        doTask(optsconsoledebug, optsdeamon, optfileconf)
    except OSError, error:
        logging.error("Unable to fork. Error: %d (%s)" % (error.errno, error.strerror))
        traceback.print_exc(file=sys.stdout)
        os._exit(1)

def doTask( optsconsoledebug, optsdeamon, optfileconf):
    tg = confParameter( optfileconf )
    # all non-Windows platforms are supporting ANSI escapes so we use them
    logging.StreamHandler.emit = add_coloring_to_emit_ansi(logging.StreamHandler.emit)
    # format log more informations
    format = '%(asctime)s - %(levelname)s - %(message)s'
    # more information log
    # format ='[%(name)s : %(funcName)s : %(lineno)d] - %(levelname)s - %(message)s'
    if not optsdeamon :
        if optsconsoledebug :
            logging.basicConfig(level = logging.DEBUG, format=format)
        else:
            logging.basicConfig( level = tg.levellog,
                                 format = format,
                                 filename = tg.logfile,
                                 filemode = 'a')
    else:
        logging.basicConfig( level = tg.levellog,
                             format = format,
                             filename = tg.logfile,
                             filemode = 'a')

    # Setup the command line arguments.
    tg = confParameter( optfileconf )

    configuration_file = "/etc/pulse-xmpp-agent-substitute/agent_master_substitute_reg.ini.local"
    # activate module.
    if "glpi" in tg.plugins_list:
        logger.info("activate GLPI")
        if not Glpi().activate():
            logger.error("We failed to connect the Glpi database.")
            logger.error("Please verify your configuration in %s" % configuration_file)
            return

    if "xmpp" in tg.plugins_list:
        logger.info("activate XMPP")
        if not XmppMasterDatabase().activate():
            logger.error("We failed to connect the Xmpp database.")
            logger.error("Please verify your configuration in %s" % configuration_file)
            return

    if "kiosk" in tg.plugins_list:
        logger.info("activate KIOSK")
        if not KioskDatabase().activate():
            logger.error("We failed to connect the Kiok database.")
            logger.error("Please verify your configuration in %s" % configuration_file)
            return

    if "msc" in tg.plugins_list:
        logger.info("activate MSC")
        if not MscDatabase().activate():
            logger.error("We failed to connect the Msc database.")
            logger.error("Please verify your configuration in %s" % configuration_file)
            return

    if "pkgs" in tg.plugins_list:
        logger.info("activate PKGS")
        if not PkgsDatabase().activate():
            logger.error("We failed to connect the Pkgs database.")
            logger.error("Please verify your configuration in %s" % configuration_file)
            return

    xmpp = MUCBot( )
    xmpp.register_plugin('xep_0030') # Service Discovery
    xmpp.register_plugin('xep_0045') # Multi-User Chat
    xmpp.register_plugin('xep_0004') # Data Forms
    xmpp.register_plugin('xep_0050') # Adhoc Commands
    xmpp.register_plugin('xep_0199', {'keepalive': True,
                                      'frequency': 600,
                                      'interval': 600,
                                      'timeout'  : 500  })
    xmpp.register_plugin('xep_0077') # In-band Registration
    xmpp['xep_0077'].force_registration = True

    while True:
        tg = confParameter(optfileconf)
        xmpp.config = tg
        # Connect to the XMPP server and start processing XMPP stanzas.address=(args.host, args.port)
        if xmpp.connect(address=(ipfromdns(tg.Server),tg.Port)):
            xmpp.process(block=True)
            logging.log(DEBUGPULSE,"terminate infocommand")
            #event for quit loop server tcpserver for kiosk
        if xmpp.shutdown:
            break

if __name__ == '__main__':
    if sys.platform.startswith('linux') and  os.getuid() != 0:
        print "Agent must be running as root"
        sys.exit(0)
    #controle si les key de master sont installer
    dirkey = Setdirectorytempinfo()
    filekeypublic = os.path.join(
            Setdirectorytempinfo(),
            "master-public-RSA.key" )
    fileallkey = os.path.join(
            Setdirectorytempinfo(),
            "master-all-RSA.key" )
    if not (os.path.isfile(filekeypublic) and os.path.isfile(fileallkey)):
        print "key missing"
        print ("install key of master in \n\t%s\n\t%s\n\n"%(filekeypublic, fileallkey) )
        print("find files key on master in file \n\t- /usr/lib/python2.7/dist-packages/mmc/plugins/xmppmaster/master/INFOSTMP/master-public-RSA.key\n\t- /usr/lib/python2.7/dist-packages/mmc/plugins/xmppmaster/master/INFOSTMP/master-all-RSA.key ")
        sys.exit(0)
    namefileconfigdefault = os.path.join('/',
                                         'etc',
                                         'pulse-xmpp-agent_substitute',
                                         'agent_master_substitute.ini')
    optp = OptionParser()
    optp.add_option("-d", "--deamon",action="store_true",
                 dest="deamon", default=False,
                  help="deamonize process")

    optp.add_option("-c", "--consoledebug",action="store_true",
                dest="consoledebug", default = False,
                  help="console debug")

    optp.add_option("-f", "--configfile",
                dest="namefileconfig", default = namefileconfigdefault,
                  help = "configuration file")

    opts, args = optp.parse_args()
    if not opts.deamon :
        doTask(opts.consoledebug, opts.deamon,opts.namefileconfig)
    else:
        createDaemon(opts.consoledebug, opts.deamon,opts.namefileconfig)
