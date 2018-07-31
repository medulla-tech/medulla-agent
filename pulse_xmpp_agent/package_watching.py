#! /usr/bin/python
# -*- coding: utf-8 -*-
#
# (c) 2018 siveo, http://www.siveo.net
# $Id$
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
# along with Pulse 2. If not, see <http://www.gnu.org/licenses/>.
#
#"""
#This module is dedicated to analyse inventories sent by a Pulse 2 Client.
#The original inventory is sent using one line per kind of
#"""

# API information http://seb.dbzteam.org/pyinotify/
import select
import socket
import pyinotify
import time
import gzip
import os
import re
import json
import datetime
import random
import sys
import ConfigParser
import logging
import getopt
import xml.etree.cElementTree as ET
import traceback
import base64
import signal

conf ={}



logging.basicConfig(level=logging.DEBUG,
                    format='%(asctime)s %(levelname)s %(message)s',
                    filename='/var/log/mmc/waychingfile.log',
                    filemode='a')


class configerror(Exception):
    """Exception raised for errors in the file configuration.

    Attributes:
        expr -- input expression in which the error occurred
        msg  -- explanation of the error
    """
    def __init__(self, expr = "Error Config", msg = ""):
        self.expr = expr
        self.msg = msg

def conf_information(conffile):
    Config = ConfigParser.ConfigParser()
    Config.read(conffile)
    Config.read(conffile + '.local')
    configdata = {}
    #[network_agent]\nip_ars=???\nport_ars=
    if Config.has_option("network_agent", "ip_ars"):
        configdata['ip_ars'] = Config.get('network_agent', 'ip_ars')
    else:
        configdata['ip_ars'] = "localhost"     
    if Config.has_option("network_agent", "ip_ars"):
        configdata['port_ars'] = Config.getint('network_agent', 'port_ars')
    else:
        configdata['port_ars'] = "8765"

    if Config.has_option("watchingfile", "filelist"):
        filelist = Config.get('watchingfile', 'filelist')
    else:
        raise configerror(msg='filelist parameter is missing')

    if filelist =='':
        raise configerror(msg='filelist is empty')

    configdata['filelist'] = filelist.split(',')

    if Config.has_option("watchingfile", "excludelist"):
        excludelist = Config.get('watchingfile', 'excludelist')
    else:
        excludelist = None

    if excludelist is not None and len (excludelist) != 0: 
        configdata['excludelist'] = excludelist.split(',')
    else:
        configdata['excludelist'] = None

    configdata['filelist'] = filelist.split(',')

    return configdata

def getRandomName(nb, pref=""):
    a = "abcdefghijklnmopqrstuvwxyz0123456789"
    d = pref
    for t in range(nb):
        d = d + a[random.randint(0, 35)]
    return d

def send_agent_data(datastrdata, conf):
    EncodedString= base64.b64encode(datastrdata)
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_address = (conf['ip_ars'], int(conf['port_ars']) )
    try:
        sock.connect(server_address)
        sock.sendall(EncodedString.encode('ascii'))
        data = sock.recv(4096)
    except Exception as e:
        print str(e)
        traceback.print_exc(file=sys.stdout)
    finally:
        sock.close()

def pathlist(watch):
    pathlistrep = []
    for z in watch:
        pathlistrep.append(watch[z].path)
    return pathlistrep


def listdirfile(rootdir):
    file_paths=[]
    for folder, subs, files in os.walk(rootdir):
        dd = [os.path.join(folder, x) for x in subs]
        file_paths = file_paths + dd
    return file_paths

class MyEventHandler(pyinotify.ProcessEvent):
    def __init__(self, config, wm, mask):
        self.config = config
        self.wm = wm
        self.mask = mask

    def msg_structure(self):
        return { "action" : "notifysyncthing",
                 #"sessionid" : getRandomName(6, "syncthing"),
                 "data" : ""
        }

    def process_IN_ACCESS(self, event):
        pass

    def process_IN_ATTRIB(self, event):
        pass

    def process_IN_CLOSE_NOWRITE(self, event):
        pass

    def process_IN_CLOSE_WRITE(self, event):
        pass

    def process_IN_OPEN(self, event):
        pass

    def process_IN_MOVED_TO(self, event):
        if event.dir:
            print "Copie de répertoire :", event.pathname
        else:
            print "Copie de fichier :", event.pathname
            send_agent_data("Copie de fichier :", self.config)

    def process_IN_MODIFY(self, event):
        difffile = []
        datasend = self.msg_structure()
        difffile.append(os.path.dirname(event.pathname))
        datasend['data'] = { "difffile"  : event.pathname,
                             "notifydir" : difffile }
        datasendstr = json.dumps(datasend, indent=4)
        logging.getLogger().debug("Msg : %s"% datasendstr)
        send_agent_data(datasendstr, self.config)

    def process_IN_DELETE(self, event):
        disupp = []
        datasend = self.msg_structure()
        if event.dir:
            disupp.append(os.path.dirname(event.pathname))
            datasend['data'] = { "suppdir" : event.pathname,
                                 "notifydir" : disupp }
            datasendstr = json.dumps(datasend, indent=4)
        else:
            disupp.append(os.path.dirname(event.pathname))
            datasend['data'] = { "suppfile" : event.pathname,
                                 "notifydir" : disupp }
            datasendstr = json.dumps(datasend, indent=4)
        logging.getLogger().debug("Msg : %s"% datasendstr)
        send_agent_data(datasendstr, self.config)

    def process_IN_CREATE(self, event):
        diadd = []
        datasend = self.msg_structure()
        listdirectory = [ x for x in self.config['filelist'] if os.path.isdir(x)]
        startlistdirectory = [ x for x in self.config['filelist'] if os.path.isdir(x)]
        for t in startlistdirectory:
            listdirectory = listdirectory + listdirfile(t)
        listdirectory = list(set(listdirectory))
        if event.dir:
            listexistwatch = pathlist(self.wm.watches)
            for z in listdirectory:
                if not z in listexistwatch:
                    wdd = self.wm.add_watch(z, self.mask, rec=True)
                    diadd.append(z)
            datasend['data'] = { "adddir"    : diadd,
                                 "notifydir" : diadd }
            datasendstr = json.dumps(datasend, indent=4)
        else:
            diadd.append(os.path.dirname(event.pathname))
            datasend['data'] = { "addfile"    : event.pathname,
                                 "notifydir" : diadd }
            datasendstr = json.dumps(datasend, indent=4)
        logging.getLogger().debug("Msg : %s"% datasendstr)
        send_agent_data(datasendstr, self.config)

class watchingfilepartage:
    def __init__(self, config):
        self.config = config
        logging.getLogger().info("install inotify")
        listdirectory = [ x for x in config['filelist'] if os.path.isdir(x)]
        startlistdirectory = [ x for x in config['filelist'] if os.path.isdir(x)]
        for t in startlistdirectory:
            listdirectory = listdirectory + listdirfile(t)
        listdirectory = list(set(listdirectory))
        self.wm = pyinotify.WatchManager() # Watch Manager
        self.mask = pyinotify.IN_CREATE | \
                        pyinotify.IN_MODIFY | \
                            pyinotify.IN_DELETE #|  pyinotify.IN_MOVED_TO

        self.handler = MyEventHandler(self.config, self.wm, self.mask)
        if config['excludelist'] != None:
            excl = pyinotify.ExcludeFilter(config['excludelist'])
            wdd = self.wm.add_watch(listdirectory, self.mask, rec=True, exclude_filter=excl)
        else:
            wdd = self.wm.add_watch(listdirectory, self.mask, rec=True)

    def run(self):
        self.notifier = pyinotify.ThreadedNotifier(self.wm, self.handler)
        self.notifier.start()

    def stop(self):
        self.notifier.stop()

if __name__ == '__main__':
    logging.getLogger().info("Start package watching server")
    inifile = "/etc/pulse-xmpp-agent/package_watching.ini"
    pidfile ="/var/run/package_watching.pid"
    cp = None
    try:
        opts, suivarg = getopt.getopt(sys.argv[1:], "f:dh")
    except getopt.GetoptError:
        sys.exit(2)
    daemonize = True
    for option, argument in opts:
        if option == "-f":
            inifile = argument
        elif option == "-d":
            logging.getLogger().info("logger mode debug")
            daemonize = False
            logging.getLogger().setLevel(logging.DEBUG)
            print "pid file: %d\n"%os.getpid()
            print "kill -9 %s"%os.getpid()
        elif option == "-h":
            print "Configure in file '%s' \n[network_agent]\nip_ars=???\nport_ars=???"%inifile
            print "\t[-d <mode debug>]\n\t[-d] debug mode no daemonized"
            sys.exit(0)

    if not os.path.exists(inifile):
        print "configuration File missing '%s' does not exist." % inifile
        sys.exit(3)
    conf = conf_information(inifile)

    if daemonize:
        logging.getLogger().setLevel(logging.WARNING)
        try:
            pid = os.fork()
            if pid > 0:
                # exit first parent
                sys.exit(0)
        except OSError, e:
            print >>sys.stderr, "Fork #1 failed: %d (%s)" % (e.errno, e.strerror)
            sys.exit(1)
        # dissociate from parent environment
        os.close(sys.stdin.fileno())
        os.close(sys.stdout.fileno())
        os.close(sys.stderr.fileno())
        os.chdir("/")
        os.setsid()
        # do second fork
        try:
            pid = os.fork()
            if pid > 0:
                # exit from second parent, print eventual PID before
                print "Daemon PID %d" % pid
                print "kill -9 $(cat %s"%pidfile
                logging.getLogger().info("Daemon PID %d" % pid)
                os.seteuid(0)
                os.setegid(0)
                logging.getLogger().info("PID file" + str(pid) + " > " + pidfile)
                logging.getLogger().info("kill -9 $(cat %s)"%pidfile)
                os.system("echo " + str(pid) + " > " + pidfile)
                sys.exit(0)
        except OSError, e:
            print >>sys.stderr, "fork #2 failed: %d (%s)" % (e.errno, e.strerror)
            sys.exit(1)
    else:
        logging.getLogger().setLevel(logging.DEBUG)

    try:
        print "----------------------------------------------------------------"
        print conf
        print "----------------------------------------------------------------"
        a = watchingfilepartage(conf)
        a.run()
    except KeyboardInterrupt:
        print "interruption"
        a.stop()
        sys.exit(3)

