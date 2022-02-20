#!/usr/bin/env python
# -*- coding: utf-8; -*-
#
# (c) 2016 - 2021 siveo, http://www.siveo.net
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
# file /pulse_xmpp_master_substitute/lib/stat.py


import sys
import os
import time
import logging
import datetime
import traceback

logger = logging.getLogger()


class statcallplugin:
    def __init__(self, objectxmpp, name, laps_time=60):
        self.obj = objectxmpp
        self.name = name
        start = time.time()
        self.param = {
            "old_time_%s" % name: start,
            "count_%s_in_time" % name: 1,
            "count_%s_up_time" % name: 1,
            "time_between_checks_%s" % name: laps_time,
            "star_time_%s" % name: start,
        }

    def statutility(self):
        try:
            currenttime = time.time()
            timeseconde = currenttime - self.param["old_time_%s" % self.name]
            timesecondeall = currenttime - self.param["star_time_%s" % self.name]
            self.param["count_%s_in_time" % self.name] += 1
            self.param["count_%s_up_time" % self.name] += 1
            if timeseconde > self.param["time_between_checks_%s" % self.name]:
                logger.debug(
                    "The plugin %s has called by %s "
                    "%s times in %s seconds (rate = %s)"
                    % (
                        self.name,
                        self.obj.boundjid.bare,
                        self.param["count_%s_in_time" % self.name],
                        timeseconde,
                        self.param["count_%s_in_time" % self.name] / timeseconde,
                    )
                )
                logger.debug(
                    "uptime call : %s times in %s seconds (rate = %s)"
                    % (
                        self.param["count_%s_up_time" % self.name],
                        timesecondeall,
                        self.param["count_%s_up_time" % self.name] / timesecondeall,
                    )
                )
                self.param["old_time_%s" % self.name] = currenttime
                self.param["count_%s_in_time" % self.name] = 0
        except Exception as e:
            logger.error("\n%s" % (traceback.format_exc()))

    def display_param_config(self, msg=""):
        logger.debug(
            "--------------------- PARAM %s STATS %s ---------------------------"
            % (msg, self.obj.boundjid.bare)
        )
        logger.debug("Parametter stat call plugin %s" % (self.name))
        logger.debug(
            "Parametter time_between_checks =  %s"
            % (self.param["time_between_checks_%s" % self.name])
        )
        timestamp = datetime.datetime.fromtimestamp(
            self.param["star_time_%s" % self.name]
        )
        logger.debug("first call to %s" % timestamp.strftime("%Y-%m-%d %H:%M:%S"))
        logger.debug("--------------------- PARAM STATS ---------------------------")

    def load_param_lap_time_stat_(self, Config):
        if Config.has_option("parameters", "time_between_checks"):
            self.param["time_between_checks_%s" % self.name] = Config.getint(
                "parameters", "time_between_checks"
            )
