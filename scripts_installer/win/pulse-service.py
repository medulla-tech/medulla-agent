#!/usr/bin/python3
# -*- coding: utf-8; -*-
# SPDX-FileCopyrightText: 2016-2023 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-3.0-or-later
import win32serviceutil
import win32service
import win32event
import servicemanager
import subprocess
import sys
import win32evtlogutil
import os
import socket

import time
import re
import urllib.request


def file_get_contents(
    filename, use_include_path=0, context=None, offset=-1, maxlen=-1, mode="b"
):
    if filename.find("://") > 0:
        ret = urllib.request.urlopen(filename).read()
        if offset > 0:
            ret = ret[offset:]
        if maxlen > 0:
            ret = ret[:maxlen]
        return ret
    else:
        if mode == "b":
            fp = open(filename, "rb")
        else:
            fp = open(filename, "r")
        try:
            if offset > 0:
                fp.seek(offset)
            ret = fp.read(maxlen)
            return ret
        finally:
            fp.close()


def log_message_info(message, event_type=servicemanager.EVENTLOG_INFORMATION_TYPE):
    servicemanager.LogInfoMsg(message)
    win32evtlogutil.ReportEvent(
        servicemanager.LogEventSourceName,
        event_type,
        event_category=0,
        event_id=0,
        strings=[message],
    )


agent_dir = os.path.join(
    "C:\\", "Progra~1", "Python3", "Lib", "site-packages", "pulse_xmpp_agent"
)

agent_launcher = os.path.join(
    "C:\\",
    "Progra~1",
    "Python3",
    "Lib",
    "site-packages",
    "pulse_xmpp_agent",
    "launcher.py",
)


class medullaagent(win32serviceutil.ServiceFramework):
    _svc_name_ = "medullaagent"
    _svc_display_name_ = "Medulla agent"
    _svc_description_ = "Workstation management agent"
    listnamefilepid = ["pidlauncher", "pidconnection", "pidagent"]

    def __init__(self, args):
        self.pid = 0
        win32serviceutil.ServiceFramework.__init__(self, args)
        self.hWaitStop = win32event.CreateEvent(None, 0, 0, None)

    def log_message(self, message, event_type=servicemanager.EVENTLOG_INFORMATION_TYPE):
        servicemanager.LogMsg(
            event_type, servicemanager.PYS_SERVICE_STARTED, (self._svc_name_, message)
        )

    def log_message_error(self, message):
        self.log_message(message, servicemanager.EVENTLOG_ERROR_TYPE)

    def log_message_warning(self, message):
        self.log_message(message, servicemanager.EVENTLOG_WARNING_TYPE)

    def SvcStop(self):
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        self.log_message("Arrêt du service en cours...")
        # Stop your service
        cmd = "taskkill /PID %s /F /T" % self.pid
        os.system(cmd)
        if hasattr(self, "process") and self.process.poll() is None:
            # Check if the process is running
            self.log_message(f"command Service stopped")
            self.process.terminate()  # Terminate the process
            self.process.wait()  # Wait for the process to finish

        self.log_message(f"Service {self._svc_display_name_} stopped")
        cmd = ""
        for pidprog in self.listnamefilepid:
            pidfile = os.path.join(agent_dir, "INFOSTMP", pidprog)
            self.log_message(f"pid file {pidfile}")
            if os.path.isfile(pidfile):
                pid = file_get_contents(pidfile, mode="t")
                cmd = "taskkill /PID %s /F /T" % pid
                self.log_message(f"command pid {cmd}")
                try:
                    self.log_message_warning(
                        f"Service {self._svc_display_name_} Termine PID {pid}"
                    )
                    os.system(cmd)
                    continue
                except BaseException:
                    pass
        servicemanager.LogMsg(
            servicemanager.EVENTLOG_INFORMATION_TYPE,
            servicemanager.PYS_SERVICE_STOPPED,
            (self._svc_name_, ""),
        )
        self.ReportServiceStatus(win32service.SERVICE_STOPPED)
        self.is_running = False

    def SvcDoRun(self):
        servicemanager.LogMsg(
            servicemanager.EVENTLOG_INFORMATION_TYPE,
            servicemanager.PYS_SERVICE_STARTED,
            (self._svc_name_, ""),
        )

        # Get the absolute path to the Python interpreter
        python_executable = sys.executable

        self.log_message(f"Python executable path: {python_executable}")
        self.log_message(f"Python agent_dir program :  {agent_launcher}")
        try:
            # Start your external process here
            self.process = subprocess.Popen(
                [
                    'C:\\"Progra~1"\\Python3\\python.exe',
                    agent_launcher,
                    "-t",
                    "machine",
                ],
                shell=True,
            )
            self.log_message("lance process %s" % self.process.pid)
            self.pid = self.process.pid
            # Wait for the process to complete (or for the service to be stopped)
            while True:
                rc = win32event.WaitForSingleObject(self.hWaitStop, 1000)
                if rc == win32event.WAIT_OBJECT_0:
                    # The service was stopped; exit the loop and service
                    break
            # Optionally, you can stop the external process here
            # self.process.terminate()
        except Exception as e:
            self.log_message_error(f"An error occurred: {str(e)}")
        servicemanager.LogMsg(
            servicemanager.EVENTLOG_INFORMATION_TYPE,
            servicemanager.PYS_SERVICE_STOPPED,
            (self._svc_name_, ""),
        )


if __name__ == "__main__":
    if len(sys.argv) == 1:
        servicemanager.Initialize()
        servicemanager.PrepareToHostSingle(medullaagent)
        servicemanager.StartServiceCtrlDispatcher()
    else:
        win32serviceutil.HandleCommandLine(medullaagent)
