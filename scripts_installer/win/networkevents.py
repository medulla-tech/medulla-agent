#!/usr/bin/python3
# -*- coding: utf-8; -*-
# SPDX-FileCopyrightText: 2022-2023 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-3.0-or-later

"""Implementation of ISesNework in Python."""

from collections import deque
import logging
from threading import Thread
import pythoncom
import win32file
import time
import ctypes
import json
from win32com.server.policy import DesignatedWrapPolicy
from win32com.client import Dispatch
import win32api
import socket
import struct
from ctypes import windll
import os

# from EventSys.h
PROGID_EventSystem = "EventSystem.EventSystem"
PROGID_EventSubscription = "EventSystem.EventSubscription"

iplist = ""
# sens values for the events, this events contain the uuid of the
# event, the name of the event to be used as well as the method name
# of the method in the ISesNetwork interface that will be executed for
# the event.

WM_QUIT = 0x12
service_logger = logging.getLogger()

SUBSCRIPTION_NETALIVE = (
    "{cd1dcbd6-a14d-4823-a0d2-8473afde360f}",
    "pulse Network Alive",
    "ConnectionMade",
)

SUBSCRIPTION_NETALIVE_NOQOC = (
    "{a82f0e80-1305-400c-ba56-375ae04264a1}",
    "pulse Net Alive No Info",
    "ConnectionMadeNoQOCInfo",
)

SUBSCRIPTION_NETLOST = (
    "{45233130-b6c3-44fb-a6af-487c47cee611}",
    "pulse Network Lost",
    "ConnectionLost",
)

SUBSCRIPTION_REACH = (
    "{4c6b2afa-3235-4185-8558-57a7a922ac7b}",
    "pulse Network Reach",
    "ConnectionMade",
)

SUBSCRIPTION_REACH_NOQOC = (
    "{db62fa23-4c3e-47a3-aef2-b843016177cf}",
    "pulse Network Reach No Info",
    "ConnectionMadeNoQOCInfo",
)

SUBSCRIPTION_REACH_NOQOC2 = (
    "{d4d8097a-60c6-440d-a6da-918b619ae4b7}",
    "pulse Network Reach No Info 2",
    "ConnectionMadeNoQOCInfo",
)

SUBSCRIPTIONS = [
    SUBSCRIPTION_NETALIVE,
    SUBSCRIPTION_NETALIVE_NOQOC,
    SUBSCRIPTION_NETLOST,
    SUBSCRIPTION_REACH,
    SUBSCRIPTION_REACH_NOQOC,
    SUBSCRIPTION_REACH_NOQOC2,
]

SENSGUID_EVENTCLASS_NETWORK = "{d5978620-5b9f-11d1-8dd2-00aa004abd5e}"
SENSGUID_PUBLISHER = "{5fee1bd6-5b9b-11d1-8dd2-00aa004abd5e}"

# uuid of the implemented com interface
IID_ISesNetwork = "{d597bab1-5b9f-11d1-8dd2-00aa004abd5e}"


def GetIpAddrTable():
    """Returns the interface-to-IP address mapping table.

    It can be used, for example, to find out the IP addresses
    assigned to all network interfaces on this computer.

    The value returned is a list of dictionaries, each with
    the following entries:
        ip_raw:     IP address, in raw format (long integer)
        ip_str:     IP address, represented as a dot-separated
                    quartet string (e.g. "123.0.100.78")
        mask:       Subnet mask
        bcast_addr: Broadcast address
        reasm_size: Maximum reassembly size
        type:       Address type or state

    Raises WindowsError if there's some a accessing the
    system DLL.

    Note: The is basically a wrapper around GetIpAddrTable()
    from the Platform SDK. Read the documentation of that
    function for more information.
    """
    DWORD = ctypes.c_ulong
    USHORT = ctypes.c_ushort
    NULL = ""

    dwSize = DWORD(0)

    # First call to receive the correct dwSize back.
    #
    windll.iphlpapi.GetIpAddrTable(NULL, ctypes.byref(dwSize), 0)

    class MIB_IPADDRROW(ctypes.Structure):
        _fields_ = [
            ("dwAddr", DWORD),
            ("dwIndex", DWORD),
            ("dwMask", DWORD),
            ("dwBCastAddr", DWORD),
            ("dwReasmSize", DWORD),
            ("unused1", USHORT),
            ("wType", USHORT),
        ]

    class MIB_IPADDRTABLE(ctypes.Structure):
        _fields_ = [("dwNumEntries", DWORD), ("table", MIB_IPADDRROW * dwSize.value)]

    ipTable = MIB_IPADDRTABLE()
    rc = windll.iphlpapi.GetIpAddrTable(ctypes.byref(ipTable), ctypes.byref(dwSize), 0)
    if rc != 0:
        raise WindowsError("GetIpAddrTable returned %d" % rc)  # skipcq: PYL-E0602

    table = []

    for i in range(ipTable.dwNumEntries):
        entry = socket.inet_ntoa(struct.pack("L", ipTable.table[i].dwAddr))
        table.append(str(entry))
    table.sort()
    return ",".join(table)


def diff_interface(oldinterface, newinterface):
    add_interface = []
    del_interface = []
    commun_interface = set()
    for t in oldinterface:
        if t not in newinterface:
            del_interface.append(t)
        else:
            commun_interface.add(t)
    for t in newinterface:
        if t not in oldinterface:
            add_interface.append(t)
        else:
            commun_interface.add(t)
    commun_interface = sorted(commun_interface)
    add_interface.sort()
    del_interface.sort()
    return {
        "interface": commun_interface,
        "additionalinterface": add_interface,
        "removedinterface": del_interface,
    }


class NetworkManager(DesignatedWrapPolicy):
    """Implement ISesNetwork to know about the network status."""

    _com_interfaces_ = [IID_ISesNetwork]
    # event on interface
    # _public_methods_ = ['ConnectionMade',
    # 'ConnectionMadeNoQOCInfo',
    # 'ConnectionLost']
    _public_methods_ = ["ConnectionMadeNoQOCInfo"]
    _reg_clsid_ = "{41B032DA-86B5-4907-A7F7-958E59333010}"
    _reg_progid_ = "WaptService.NetworkManager"

    def __init__(self, connected_cb, disconnected_cb):
        self._wrap_(self)
        self.connected_cb = connected_cb
        self.disconnected_cb = disconnected_cb

        self.main_thread_id = win32api.GetCurrentThreadId()

    def ConnectionMade(self, *args):
        """Tell that the connection is up again."""
        service_logger.info("Connection was made.")
        self.connected_cb()

    def ConnectionMadeNoQOCInfo(self, *args):
        """Tell that the connection is up again."""
        service_logger.info("Connection was made no info.")
        self.connected_cb()

    def ConnectionLost(self, *args):
        """Tell the connection was lost."""
        service_logger.info("Connection was lost.")
        self.disconnected_cb()

    def register(self):
        """Register to listen to network events."""
        # call the CoInitialize to allow the registration to run in an other
        # thread
        pythoncom.CoInitialize()
        # interface to be used by com
        manager_interface = pythoncom.WrapObject(self)
        event_system = Dispatch(PROGID_EventSystem)
        # register to listent to each of the events to make sure that
        # the code will work on all platforms.
        for current_event in SUBSCRIPTIONS:
            # create an event subscription and add it to the event
            # service
            event_subscription = Dispatch(PROGID_EventSubscription)
            event_subscription.EventClassId = SENSGUID_EVENTCLASS_NETWORK
            event_subscription.PublisherID = SENSGUID_PUBLISHER
            event_subscription.SubscriptionID = current_event[0]
            event_subscription.SubscriptionName = current_event[1]
            event_subscription.MethodName = current_event[2]
            event_subscription.SubscriberInterface = manager_interface
            event_subscription.PerUser = True
            # store the event
            try:
                event_system.Store(PROGID_EventSubscription, event_subscription)
            except pythoncom.com_error as e:
                service_logger.error("Error registering to event %s", current_event[1])

    def poll_messages(self):
        """Pumps all waiting messages for the current thread.
        Returns 1 if a WM_QUIT message was received, else 0
        """
        return pythoncom.PumpWaitingMessages()

    def send_message(self, message):
        fileHandle = win32file.CreateFile(
            "\\\\.\\pipe\\interfacechang",
            win32file.GENERIC_READ | win32file.GENERIC_WRITE,
            0,
            None,
            win32file.OPEN_EXISTING,
            0,
            None,
        )
        win32file.WriteFile(fileHandle, message)
        win32file.CloseHandle(fileHandle)

    def run(self):
        """Thread run
        >>> manager = NetworkManager(connected, disconnected)
        >>> p = Thread(target=manager.run)
        >>> p.start()
        """
        global iplist
        pilemessage = deque()
        self.register()
        service_logger.info("start listen network interface")
        while True:
            ctypes.windll.iphlpapi.NotifyAddrChange(0, 0)
            try:
                iplistlocal = GetIpAddrTable()
            except Exception:
                service_logger.error("function get ip adress error")
                time.sleep(5)
                continue
            # service_logger.info(iplistlocal)
            if iplistlocal != iplist:
                oldinterface = [x.strip() for x in iplist.split(",")]
                newinterface = [x.strip() for x in iplistlocal.split(",")]
                datainterface = diff_interface(oldinterface, newinterface)
                try:
                    strchang = "Interface [%s] chang[" % (iplistlocal)
                    if len(datainterface["additionalinterface"]) > 0:
                        strchang = "%s+%s" % (
                            strchang,
                            datainterface["additionalinterface"],
                        )
                    if len(datainterface["removedinterface"]) > 0:
                        strchang = "%s-%s" % (
                            strchang,
                            datainterface["removedinterface"],
                        )
                    strchang = "%s]" % (strchang)
                    message = json.dumps(datainterface)
                    self.send_message(message)
                    service_logger.info("%s" % strchang)
                except Exception as e:
                    service_logger.error("%s" % str(e))
                    # pilemessage.append(message)
                    pass
                iplist = iplistlocal
                time.sleep(5)


if __name__ == "__main__":
    logfile = os.path.join("c:", "progra~1", "Pulse", "var", "log", "networkevents.log")

    program_dir = os.path.join("c:", "progra~1", "Pulse", "bin")
    pidfile = os.path.join(program_dir, ".PID_NETWORKS_ENVENTS")

    PID_PROGRAM = os.getpid()
    with open(pidfile, mode="w") as file:
        file.write("%s" % PID_PROGRAM)

    format = "%(asctime)s - %(levelname)s - %(message)s"
    logging.basicConfig(
        level=logging.DEBUG, format=format, filename=logfile, filemode="a"
    )
    service_logger.info("***************************")
    iplist = GetIpAddrTable()
    service_logger.info("START NETWORKEVENT [PID %s] %s" % (PID_PROGRAM, iplist))

    def connected():
        print("Connected")

    def disconnected():
        print("Disconnected")

    manager = NetworkManager(connected, disconnected)
    process = Thread(target=manager.run)
    process.start()
