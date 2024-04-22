#!/usr/bin/python3
# -*- coding: utf-8; -*-
# SPDX-FileCopyrightText: 2016-2023 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-3.0-or-later

import socket

import win32serviceutil

import servicemanager
import win32event
import win32service
import os
import logging
import logging.handlers
import urllib.request
from pulse_xmpp_agent.lib import utils


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

log_file = os.path.join("c:\\", "progra~1", "Pulse", "var", "log", "service.log")

program_dir = os.path.join("c:\\", "progra~1", "Pulse", "bin")

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
    _svc_name_ = "medullanetnotify"
    _svc_display_name_ = "Medulla network notify"
    _svc_description_ = "Network events monitoring for Medulla Agent"
    _exe_name_ = "C:\PROGRA~1\Python3\medullanetnotify.exe"

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
                pid = utils.file_get_contents(pidfile)
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
                    os.path.join("c:\\", "progra~1", "Python3", "python.exe") + os.path.join(program_dir, "networkevents.py") + '"'
            )


if __name__ == "__main__":
    PulseAgentService.parse_command_line()
