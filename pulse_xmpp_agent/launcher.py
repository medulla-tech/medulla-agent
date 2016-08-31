#!/usr/bin/env python
# -*- coding: utf-8 -*-

from lib.networkinfo import networkagentinfo
from lib.configuration import  parametreconf
from optparse import OptionParser
import os, sys, platform

if __name__ == '__main__':
    optp = OptionParser()
    optp.add_option("-t", "--type",
                dest="typemachine", default=False,
                help="Type machine : machine or relayserver")
    opts, args = optp.parse_args()
    if not opts.typemachine.lower() in ["machine",'relayserver']:
        print "Parameter error"
        sys.exit(1)
    if opts.typemachine.lower() in ["machine"]:
        if sys.platform.startswith('win'):
            print "Running", 'connectionagent.py -t %s'%opts.typemachine
            os.system('connectionagent.py -t %s'%opts.typemachine)
        else:
            print "Running", './connectionagent.py -t %s'%opts.typemachine
            os.system('./connectionagent.py -t %s'%opts.typemachine)
    if sys.platform.startswith('win'):
        print "Running", 'agentxmpp.py -t %s'%opts.typemachine
        os.system('agentxmpp.py -t %s'%opts.typemachine)
    else:
        print "Running", './agentxmpp.py -t %s'%opts.typemachine
        os.system('./agentxmpp.py -t %s'%opts.typemachine)
