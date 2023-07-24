#!/usr/bin/python3
# -*- coding: utf-8; -*-
# SPDX-FileCopyrightText: 2020-2023 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-3.0-or-later

import os
import logging

from lib.utils import simplecommand

logger = logging.getLogger()


class reverse_port_ssh:
    def __init__(self):
        # Create folder in /var/run if non existing
        self.directoryreverseport = "/var/run/reverse_port_pulse"
        if not os.path.exists(self.directoryreverseport):
            os.makedirs(self.directoryreverseport)

    def add_port(self, number_port):
        filenumberport = os.path.join(self.directoryreverseport, "%s" % number_port)
        logger.debug("%s" % filenumberport)
        if not os.path.exists(filenumberport):
            try:
                os.mknod(filenumberport)
            except OSError:
                logger.warning("the %s file exist" % filenumberport)
            except Exception as e:
                logger.error("creation port id %s : [%s]" % (filenumberport, str(e)))

    def reverse_exist(self, number_port):
        cmd = 'netstat -an | egrep "tcp.*:%s.*LISTEN"' % number_port
        res = simplecommand(cmd)
        if res["code"] == 0 and res["result"]:
            return True
        return False

    def reverse_using(self, number_port):
        cmd = 'netstat -an | egrep "tcp.*:%s.*ESTABLISHED"' % number_port
        res = simplecommand(cmd)
        if res["code"] == 0 and res["result"]:
            return True
        return False

    def pid_reverse(self, number_port):
        cmd = "lsof -t -i :%s -s tcp:LISTEN" % number_port
        res = simplecommand(cmd)
        if res["code"] == 0 and res["result"]:
            return int(res["result"][0].strip(" \n\r\t"))
        return 0

    def clean_reverse_if_no_user(self, number_port):
        # verify_ port user.
        cmd = "lsof -t -i :%s" % number_port
        res = simplecommand(cmd)
        if res["code"] == 0 and len(res["result"]) < 2:
            # clean result
            if len(res["result"]) == 1:
                self.stop_reverse(res["result"][0].strip(" \n\r\t"))
            try:
                logger.debug(
                    "rm %s"
                    % os.path.join(self.directoryreverseport, "%s" % number_port)
                )
                os.remove(os.path.join(self.directoryreverseport, "%s" % number_port))
            except Exception:
                pass
            return True
        return False

    def stop_reverse(self, number_process):
        cmd = "kill -9 %s" % number_process
        res = simplecommand(cmd)
        if res["code"] == 0:
            return True
        return False

    def list_port_reverse_ssh(self):
        return [
            x
            for x in os.listdir(self.directoryreverseport)
            if os.path.isfile("%s/%s" % (self.directoryreverseport, x))
        ]

    def terminate_reverse_ssh_not_using(self):
        for numberport in self.list_port_reverse_ssh():
            self.clean_reverse_if_no_user(numberport)
