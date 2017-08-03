#!/usr/bin/env python
# -*- coding: utf-8; -*-
#
# (c) 2016 siveo, http://www.siveo.net
#
# This file is part of Pulse 2, http://www.siveo.net
#
# Pulse 2 is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# Pulse 2 is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Pulse 2; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
# MA 02110-1301, USA.

from optparse import OptionParser
import os, sys

from lib.utils import testagentconf, networkchanged, confchanged, refreshfingerprintconf, refreshfingerprint

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
    if not testagentconf(opts.typemachine):
        print "warning configuration  option missing \neg:   guacamole_baseurl  , connection/port/server' , global/relayserver_agent"
        print "reconfiguration"

    nchanged = networkchanged()
    if nchanged:
        print "network changed reconfiguration"
        refreshfingerprint()

    cchanged = confchanged(opts.typemachine)
    if cchanged:
        print "conf changed reconfiguration"
        refreshfingerprintconf(opts.typemachine)

    #test if agent conf is configured one
    testagenttype = testagentconf(opts.typemachine)

    testspeedagent = nchanged or cchanged or not testagenttype

    if  testspeedagent:
        print "search configuration from master"

    os.chdir(os.path.dirname(sys.argv[0]))
    if not opts.consoledebug:
        if opts.typemachine.lower() in ["machine"]:
            if  testspeedagent:
                if sys.platform.startswith('win'):
                    print "Running", 'connectionagent.py -t %s'%opts.typemachine
                    os.system('connectionagent.py -t %s'%opts.typemachine)
                else:
                    print "Running", 'python connectionagent.py -t %s'%opts.typemachine
                    os.system('python connectionagent.py -t %s'%opts.typemachine)

        if sys.platform.startswith('win'):
            print "Running", 'agentxmpp.py -t %s'%opts.typemachine
            os.system('agentxmpp.py -t %s'%opts.typemachine)
        else:
            print "Running", 'python agentxmpp.py -d -t %s'%opts.typemachine
            os.system('python agentxmpp.py -d -t %s'%opts.typemachine)
    else:
        if opts.typemachine.lower() in ["machine"]:
            if  testspeedagent:
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

