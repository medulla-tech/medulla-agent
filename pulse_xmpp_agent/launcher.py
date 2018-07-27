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
        print ("Parameter error")
        sys.exit(1)
    if not testagentconf(opts.typemachine):
        print ("warning configuration  option missing \neg:   guacamole_baseurl  , connection/port/server' , global/relayserver_agent")
        print ("reconfiguration")

    networkchanged = networkchanged()
    if networkchanged:
        print ("The network changed. We need to reconfigure")
        refreshfingerprint()

    configchanged = confchanged(opts.typemachine)
    if configchanged:
        print ("The configuration changed. We need to reconfigure")
        refreshfingerprintconf(opts.typemachine)

    testagenttype = testagentconf(opts.typemachine)

    testspeedagent = networkchanged or configchanged or not testagenttype

    if  testspeedagent:
        print ("search configuration from master")

    pathagent = os.path.join(os.path.dirname(os.path.realpath(__file__)))

    #from windows
    #########################################
    launcher      = os.path.join(pathagent,"launcher.py")
    connectionagent  = os.path.join(pathagent,"connectionagent.py")
    agentxmpp = os.path.join(pathagent,"agentxmpp.py")

    pythonexec = "C:\\python27\\python.exe"
    #########################################
    os.chdir(os.path.dirname(pathagent))
    if not opts.consoledebug:
        if opts.typemachine.lower() in ["machine"]:
            if  testspeedagent:
                if sys.platform.startswith('win'):
                    print ('cmd Running : %s %s -t %s'%(pythonexec, connectionagent, opts.typemachine))
                    os.system('%s %s -t %s'%(pythonexec, connectionagent, opts.typemachine))
                elif sys.platform.startswith('darwin'):
                    print ("Running", '/usr/local/bin/python2 connectionagent.py -t %s'%opts.typemachine)
                    os.system('/usr/local/bin/python2 connectionagent.py -t %s'%opts.typemachine)
                else:
                    print ("Running", 'python connectionagent.py -t %s'%opts.typemachine)
                    os.system('python connectionagent.py -t %s'%opts.typemachine)

        if sys.platform.startswith('win'):
            print ('cmd Running : %s %s -t %s'%(pythonexec, agentxmpp, opts.typemachine))
            os.system('%s %s -t %s'%(pythonexec, agentxmpp, opts.typemachine))
        elif sys.platform.startswith('darwin'):
            print ("Running", '/usr/local/bin/python2 agentxmpp.py -t %s'%opts.typemachine)
            os.system('/usr/local/bin/python2 agentxmpp.py -t %s'%opts.typemachine)
        else:
            print ("Running", 'python agentxmpp.py -d -t %s'%opts.typemachine)
            os.system('python agentxmpp.py -d -t %s'%opts.typemachine)
    else:
        if opts.typemachine.lower() in ["machine"]:
            if  testspeedagent:
                if sys.platform.startswith('win'):
                    print ('cmd Running : %s %s -c -t %s'%(pythonexec, connectionagent, opts.typemachine))
                    os.system('%s %s -c -t %s'%(pythonexec, connectionagent, opts.typemachine))
                elif sys.platform.startswith('darwin'):
                    print ("Running", '/usr/local/bin/python2 connectionagent.py -c -t %s'%opts.typemachine)
                    os.system('/usr/local/bin/python2 connectionagent.py -c -t %s'%opts.typemachine)
                else:
                    print ("Running", 'python connectionagent.py -c -t %s'%opts.typemachine)
                    os.system('python connectionagent.py -c -t %s'%opts.typemachine)
        if sys.platform.startswith('win'):
            print ('cmd Running : %s %s -c -t %s'%(pythonexec, agentxmpp, opts.typemachine))
            os.system('%s %s -c -t %s'%(pythonexec, agentxmpp, opts.typemachine))
        elif sys.platform.startswith('darwin'):
            print ("Running", '/usr/local/bin/python2 agentxmpp.py -c -t %s'%opts.typemachine)
            os.system('/usr/local/bin/python2 agentxmpp.py -c -t %s'%opts.typemachine)
        else:
            print ("Running", 'python agentxmpp.py -c -t %s'%opts.typemachine)
            os.system('python agentxmpp.py -c -t %s'%opts.typemachine)
