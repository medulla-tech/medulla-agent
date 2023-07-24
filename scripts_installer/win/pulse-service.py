#!/usr/bin/python3
# -*- coding: utf-8; -*-
# SPDX-FileCopyrightText: 2016-2023 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-3.0-or-later

import socket

import win32serviceutil

import servicemanager
import win32event
import win32service
import time
import re
import subprocess
import os
import sys
import logging
import logging.handlers
import urllib.request


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


log_file = os.path.join("c:\\", "Program Files", "Pulse", "var", "log", "service.log")
agent_dir = os.path.join(
    "C:\\", "Program Files", "Python311", "Lib", "site-packages", "pulse_xmpp_agent"
)

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


class PulseAgentService(SMWinservice):
    _svc_name_ = "medullaagent"
    _svc_display_name_ = "Medulla agent"
    _svc_description_ = "Workstation management agent"
    isrunning = False
    isdebug = False
    listnamefilepid = ["pidlauncher", "pidconnection", "pidagent"]

    def start(self):
        if "-debug" in sys.argv:
            self.isdebug = True
            logger.info("Service %s launched in debug mode" % self._svc_display_name_)
        else:
            logger.info("Service %s launched in normal mode" % self._svc_display_name_)
        self.isrunning = True

    def stop(self):
        self.isrunning = False
        logger.info("Service %s stopped" % self._svc_display_name_)
        cmd = ""
        for pidprog in self.listnamefilepid:
            pidfile = os.path.join(agent_dir, "INFOSTMP", pidprog)
            if os.path.isfile(pidfile):
                pid = file_get_contents(pidfile)
                cmd = "taskkill /PID %s /F /T" % pid
                try:
                    os.system(cmd)
                    continue
                except BaseException:
                    pass

    def main(self):
        i = 0
        while self.isrunning:
            batcmd = "NET START"
            result = subprocess.check_output(batcmd, shell=True)
            filter = "medullaagent"
            if not re.search(filter, result):
                if not self.isdebug:
                    os.system(
                        os.path.join("c:\\", "Program Files", "Python311", "python.exe")
                        + " "
                        + os.path.join(agent_dir, "launcher.py")
                        + " -t machine"
                    )
                else:
                    os.system(
                        os.path.join("c:\\", "Program Files", "Python311", "python.exe")
                        + " "
                        + os.path.join(agent_dir, "launcher.py")
                        + " -c -t machine"
                    )
            else:
                time.sleep(5)


if __name__ == "__main__":
    PulseAgentService.parse_command_line()
