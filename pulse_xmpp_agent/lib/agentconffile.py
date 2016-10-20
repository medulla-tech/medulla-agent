#!/usr/bin/env python
# -*- coding: utf-8 -*-

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


