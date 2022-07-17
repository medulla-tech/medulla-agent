#!/usr/bin/python3
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

import socket

import win32serviceutil

import servicemanager
import win32event
import win32service
import os
import logging
import logging.handlers
import urllib.request

# to had event log, do not remove
# https://stackoverflow.com/questions/51385195/writing-to-windows-event-log-using-win32evtlog-from-pywin32-library

# DUMMY_EVT_APP_NAME = "Dummy Application"
# >>> DUMMY_EVT_ID = 7040  # Got this from another event
# >>> DUMMY_EVT_CATEG = 9876
# >>> DUMMY_EVT_STRS = ["Dummy event string {:d}".format(item) for item in range(5)]
# >>> DUMMY_EVT_DATA = b"Dummy event data"
# >>>
# >>> "Current time: {:s}".format(time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()))
# 'Current time: 2018-07-18 20:03:08'
# >>>
# >>> win32evtlogutil.ReportEvent(
# ...     DUMMY_EVT_APP_NAME, DUMMY_EVT_ID, eventCategory=DUMMY_EVT_CATEG,
# ...     eventType=win32evtlog.EVENTLOG_WARNING_TYPE, strings=DUMMY_EVT_STRS,
# ...     data=DUMMY_EVT_DATA)

# GLOBAL DATA

log_file = os.path.join(
    os.environ["ProgramFiles"], "Pulse", "var", "log", "service.log"
)

program_dir = os.path.join(os.environ["ProgramFiles"], "Pulse", "bin")

logger = logging.getLogger("pulseagentservice")

logger.setLevel(logging.DEBUG)

handler = logging.handlers.RotatingFileHandler(
    log_file, maxBytes=10485760, backupCount=2
)
formatter = logging.Formatter(
    "%(asctime)s - %(module)-10s - %(levelname)-8s %(message)s", "%d-%m-%Y %H:%M:%S"
)
handler.setFormatter(formatter)
logger.addHandler(handler)


def file_get_contents(filename, use_include_path=0, context=None, offset=-1, maxlen=-1):
    if filename.find("://") > 0:
        ret = urllib.request.urlopen(filename).read()
        if offset > 0:
            ret = ret[offset:]
        if maxlen > 0:
            ret = ret[:maxlen]
        return ret
    else:
        fp = open(filename, "rb")
        try:
            if offset > 0:
                fp.seek(offset)
            ret = fp.read(maxlen)
            return ret
        finally:
            fp.close()


class SMWinservice(win32serviceutil.ServiceFramework):
    """Base class to create winservice in Python"""

    _svc_name_ = "pythonService"
    _svc_display_name_ = "pythonservice"
    _svc_description_ = "Python Service Description"

    @classmethod
    def parse_command_line(cls):
        """
        ClassMethod to parse the command line
        """
        win32serviceutil.HandleCommandLine(cls)

    def __init__(self, args):
        """
        Constructor of the winservice
        """
        win32serviceutil.ServiceFramework.__init__(self, args)
        self.hWaitStop = win32event.CreateEvent(None, 0, 0, None)
        socket.setdefaulttimeout(60)

    def SvcStop(self):
        """
        Called when the service is asked to stop
        """
        self.stop()
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        win32event.SetEvent(self.hWaitStop)

    def SvcDoRun(self):
        """
        Called when the service is asked to start
        """
        self.start()
        servicemanager.LogMsg(
            servicemanager.EVENTLOG_INFORMATION_TYPE,
            servicemanager.PYS_SERVICE_STARTED,
            (self._svc_name_, ""),
        )
        self.main()

    def start(self):
        """
        Override to add logic before the start
        eg. running condition
        """
        pass

    def stop(self):
        """
        Override to add logic before the stop
        eg. invalidating running condition
        """
        pass

    def main(self):
        """
        Main class to be ovverridden to add logic
        """
        pass


class PulseAgentService(SMWinservice):
    _svc_name_ = "pulsenetworknotify"
    _svc_display_name_ = "Pulse network notify"
    _svc_description_ = "Network events monitoring for Pulse Agent"
    isrunning = False
    isdebug = False
    listnamefilepid = [".PID_NETWORKS_ENVENTS"]

    def start(self):
        logger.info("Service %s launched " % self._svc_display_name_)
        self.isrunning = True

    def stop(self):
        self.isrunning = False
        logger.info("Service %s stopped" % self._svc_display_name_)
        cmd = ""
        for pidprog in self.listnamefilepid:
            pidfile = os.path.join(program_dir, pidprog)
            if os.path.isfile(pidfile):
                pid = file_get_contents(pidfile)
                cmd = "taskkill /PID %s /F" % pid
                try:
                    os.system(cmd)
                    continue
                except BaseException:
                    pass

    def main(self):
        i = 0
        while self.isrunning:
            print(
                (
                    "lancement de : %s" % "python.exe "
                    + os.path.join(program_dir, "networkevents.py")
                )
            )
            os.system(
                'python.exe "' + os.path.join(program_dir, "networkevents.py") + '"'
            )


if __name__ == "__main__":
    PulseAgentService.parse_command_line()
