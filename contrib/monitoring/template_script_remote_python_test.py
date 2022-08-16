#!/usr/bin/python
# -*- coding: utf-8; -*-
#
# (c) 2022 Siveo, http://www.siveo.net/
#
# $Id$
#
# This file is part of Pulse 2, http://pulse2.mandriva.org
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
# MA 02110-1301, USA

import json
import subprocess
import sys
from .utils import encode_strconsole

if sys.platform.startswith("win"):
    import wmi
    import pythoncom
    import _winreg as wr
    import win32api
    import win32security
    import ntsecuritycon
    import win32net
    import ctypes
    import win32com.client
    from win32com.client import GetObject
    from ctypes.wintypes import LPCWSTR, LPCSTR

# To define a log file uncomment the last 2 line of this block.
# The LOGFILE global variable depend of the OS.
# LOGFILE ="/var/lib/pulse2/script_monitoring/log_file_script_remote_python.log"
# logger = logging.getLogger()


def listservice():
    """
    This function lists the available services
    """
    if sys.platform.startswith("win"):
        pythoncom.CoInitialize()
        try:
            wmi_obj = wmi.WMI()
            wmi_sql = "select * from Win32_Service"  # Where Name ='Alerter'"
            wmi_out = wmi_obj.query(wmi_sql)
        finally:
            pythoncom.CoUninitialize()
        for dev in wmi_out:
            print(dev.Caption)
            print(dev.DisplayName)
    else:
        obj = simplecommandstr("systemctl list-units --type=service")
        print(obj["result"])


def simplecommandstr(cmd):
    obj = {}
    p = subprocess.Popen(
        cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT
    )
    result = p.stdout.readlines()
    obj["code"] = p.wait()
    obj["result"] = [x.strip() for x in result if x.strip() != ""]
    obj["result"] = "\n".join(obj["result"])
    return obj


def simplecommand(cmd):
    obj = {}
    p = subprocess.Popen(
        cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT
    )
    result = p.stdout.readlines()
    obj["code"] = p.wait()
    obj["result"] = result
    return obj


def loads_alert():
    # The metadata we need to add on the python script
    serialisationpickleevent = """@@@@@event@@@@@"""

    eventstruct = json.loads(serialisationpickleevent)
    if "general_status" in eventstruct["mon_devices_doc"]:
        eventstruct["general_status"] = eventstruct["mon_devices_doc"]["general_status"]
    return eventstruct


def windowspath(namescript):
    if sys.platform.startswith("win"):
        return '"' + namescript + '"'
    else:
        return namescript


def powerschellscriptps1(namescript):
    namescript = windowspath(namescript)
    print("powershell -ExecutionPolicy Bypass -File  %s" % namescript)
    obj = simplecommandstr(
        encode_strconsole("powershell -ExecutionPolicy Bypass -File %s" % namescript)
    )
    return obj


def main():
    # Personal Code below exec on remote machine
    # In the example code.
    # we recover the list of services on the remote machine
    print("CECI EST LE RESULTAT DU SCRIPT DISTANT 'EXECUTION SCRIPT REMOTE PYTHON'")
    print("les sorties de print sont directs renvoyes")
    print("exemple liste des services")
    listservice()

    # END Personal Code
    # Please modify the code before ( in the Personal code part ), if you know what you are doing.


if __name__ == "__main__":
    # logging.basicConfig(level=logging.DEBUG,
    # format='%(asctime)s %(message)s',
    # filename = LOGFILE,
    # filemode = 'a')
    # logger.debug("Program started")
    eventstruct = loads_alert()
    main()
