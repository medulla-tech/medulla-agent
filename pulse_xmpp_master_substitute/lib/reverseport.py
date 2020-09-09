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
#
# file : pulse_xmpp_agent/lib/reverseport.py
#

import os
import logging
import utils

from lib.utils import simplecommand

logger = logging.getLogger()

class reverse_port_ssh:

    def __init__(self):
        #creation d'un repertoire dans /var/run si non exist.
        self.directoryreverseport = "/var/run/revese_port_pulse"
        if not os.path.exists(self.directoryreverseport):
            os.makedirs(self.directoryreverseport)

    def add_port(self, number_port):
        logger.debug("lllllllllllllllllllllllllllllllllllllllllllll")
        filenumberport = os.path.join(self.directoryreverseport, "%s"%number_port)
        logger.debug("%s" % filenumberport)
        if not os.path.exists(filenumberport):
            try:
                logger.debug("lllllllllllllllllllll1111")
                os.mknod(filenumberport)
                logger.debug("llllllllllllllll2222222222")
            except OSError:
                logger.warning("the %s file exist"%filenumberport)
                logger.debug("llllllllllllllll22444444444")
            except Exception as  e:
                logger.debug("llllllllllllllll223333333333")
                logger.error("creation port id %s : [%s]" % (filenumberport, str(e)))

    def reverse_exist(self, number_port):
        cmd = 'netstat -an | egrep "tcp.*:%s.*LISTEN"' % number_port
        res = simplecommand(cmd)
        if res['code'] == 0 and res['result'] :
            return True
        return False

    def reverse_using(self, number_port):
        cmd = 'netstat -an | egrep "tcp.*:%s.*ESTABLISHED"' % number_port
        res = simplecommand(cmd)
        if res['code'] == 0 and res['result'] :
            return True
        return False

    def pid_reverse(self, number_port):
        cmd = 'lsof -t -i :%s -s tcp:LISTEN' % number_port
        es = simplecommand(cmd)
        if res['code'] == 0 and res['result'] :
            return int(res['result'][0].strip(" \n\r\t"))
        return 0

    def clean_reverse_if_no_user(self, number_port):
        # verify_ port user.
        cmd = 'lsof -t -i :%s' % number_port
        res = simplecommand(cmd)
        if res['code'] == 0 and len(res['result']) < 2 :
            # clean result
            if len(res['result']) == 1:
                self.stop_reverse(res['result'][0].strip(" \n\r\t"))
            try:
                logger.debug("rm %s"%os.path.join(self.directoryreverseport,
                                              "%s"%number_port))
                os.remove(os.path.join( self.directoryreverseport,
                                        "%s"%number_port))
            except:
                pass
            return True
        return False

    def stop_reverse(self, number_process):
        cmd = 'kill -9 %s' % number_process
        res = simplecommand(cmd)
        if res['code'] == 0:
            return True
        return False
    
    def list_port_reverse_ssh(self):
        return [ x for x in os.listdir(self.directoryreverseport)
            if os.path.isfile("%s/%s" % (self.directoryreverseport, x))]
           
    def terminate_reverse_ssh_not_using(self):
        for numberport in self.list_port_reverse_ssh():
            self.clean_reverse_if_no_user(numberport)
            
            
            
            
            
