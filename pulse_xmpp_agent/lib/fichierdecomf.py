#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys,os,platform

fileconf="agentconf.ini"

if sys.platform.startswith('linux'):
    fileconf="agentconf.ini"
elif sys.platform.startswith('win'):
    fileconf="agentconf.ini"
elif sys.platform.startswith('darwin'):
    fileconf="agentconf.ini"
    
   