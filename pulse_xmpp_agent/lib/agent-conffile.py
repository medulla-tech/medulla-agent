#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys,os,platform

conffilename = agentconf.ini

if sys.platform.startswith('linux'):
    fileconf = os.path.join("/", "var", "lib" ,"pulse2", "clients" ,"config", conffilename)
elif sys.platform.startswith('win'):
    fileconf = os.path.join(os.environ["ProgramFiles"], "Pulse", "etc", conffilename)
elif sys.platform.startswith('darwin'):
    fileconf = os.path.join("/", "Library", "Application Support", "Pulse", "etc", conffilename)
else:
    fileconf = conffilename

