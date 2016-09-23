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

    optp.add_option("-c", "--consoledebug",action="store_true", 
                dest="consoledebug", default = False,
                  help="console debug")

    opts, args = optp.parse_args()
    if not opts.typemachine.lower() in ["machine",'relayserver']:
        print "Parameter error"
        sys.exit(1)

    os.chdir(os.path.dirname(sys.argv[0]))

    if not opts.consoledebug:
        if opts.typemachine.lower() in ["machine"]:
            if sys.platform.startswith('win'):
                print "Running", 'connectionagent.py -t %s'%opts.typemachine
                os.system('connectionagent.py -t %s'%opts.typemachine)
            else:
                print "Running", 'python connectionagent.py -t %s'%opts.typemachine
                os.system('python connectionagent.py -t %s'%opts.typemachine)

        if sys.platform.startswith('win'):
            print "Running", 'agentxmpp.py -d -t %s'%opts.typemachine
            os.system('agentxmpp.py -d -t %s'%opts.typemachine)
        else:
            print "Running", 'python agentxmpp.py -d -t %s'%opts.typemachine
            os.system('python agentxmpp.py -d -t %s'%opts.typemachine)
    else:
        if opts.typemachine.lower() in ["machine"]:
            if sys.platform.startswith('win'):
                print "Running", 'connectionagent.py -c -t %s'%opts.typemachine
                os.system('connectionagent.py -c -t %s'%opts.typemachine)
            else:
                print "Running", 'python connectionagent.py -c -t %s'%opts.typemachine
                os.system('python connectionagent.py -c -t %s'%opts.typemachine)
        if sys.platform.startswith('win'):
            print "Running", 'agentxmpp.py -c -t %s'%opts.typemachine
            os.system('agentxmpp.py -c -t %s'%opts.typemachine)
        else:
            print "Running", 'python agentxmpp.py -c -t %s'%opts.typemachine
            os.system('python agentxmpp.py -c -t %s'%opts.typemachine)

