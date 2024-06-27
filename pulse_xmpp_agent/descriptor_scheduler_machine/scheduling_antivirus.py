# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2016-2023 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-3.0-or-later

"""
This scheduling plugin checks all the installed antiviruses on the computer, checks if they're up to date and if they're active and sends a JSON object containing all of the informations.
"""

import json
from lib.utils import runcommand, name_random
import configparser

plugin = {"VERSION": "1.0", "NAME": "scheduling_antivirus", "TYPE": "machine", "SCHEDULED": True}  # fmt: skip

# specify the schedule execution delay 15 mins in this case
SCHEDULE = {"schedule": "*/1 * * * *", "nb": -1}

sessionid = name_random(8, "update_")

# parse the config file
config = configparser.ConfigParser()
config.read("C:/Program Files/Medulla/etc/agentconf.ini")

# get depl sub
mto_address = config.get("substitute", "deployment")


def get_status(product_state, product_name):
    # logic to determine update status and real-time protection based on prodstate
    defstatus = "[Disabled]"
    rtstatus = "[Disabled]"
    if product_name == "Windows Defender":
        if product_state == 397568:
            defstatus = "Up to date"
            rtstatus = "Enabled"
        elif product_state == 401664:
            defstatus = "Up to date"
            rtstatus = "Disabled"
    else:
        if product_state == 262144 or product_state == 393216:
            defstatus = "Up to date"
            rtstatus = "Disabled"
        elif (
            product_state == 262160
            or product_state == 393232
            or product_state == 393488
        ):
            defstatus = "Out of date"
            rtstatus = "Disabled"
        elif product_state == 266240 or product_state == 397312:
            defstatus = "Up to date"
            rtstatus = "Enabled"
        elif (
            product_state == 266256
            or product_state == 397328
            or product_state == 397584
        ):
            defstatus = "Out of date"
            rtstatus = "Enabled"
    return defstatus, rtstatus


def schedule_main(objectxmpp):
    # query to retrieve antviruses
    antivirus_products_output = runcommand(
        'Get-WmiObject -Namespace "root\SecurityCenter2" -Class AntiVirusProduct | Select-Object -Property DisplayName, ProductState'
    )
    antivirus_products = []

    firewall_bool = runcommand(
        'if ((Get-NetFirewallProfile | Where-Object { $_.Name -eq "Private" }).Enabled -eq $true -and (Get-NetFirewallProfile | Where-Object { $_.Name -eq "Public" }).Enabled -eq $true) { return 1 } else { return 0 }'
    )

    if antivirus_products_output:
        # split into lines
        antivirus_products_lines = antivirus_products_output.splitlines()

        # header
        antivirus_products_data = antivirus_products_lines[2:]

        # processing data
        for line in antivirus_products_data:
            parts = line.split()
            if len(parts) >= 2:
                # make full name if name contains spaces
                name = " ".join(parts[:-1])
                # prod state
                product_state_str = parts[-1]
                # check if not empty
                if product_state_str.isdigit():
                    product_state = int(product_state_str)
                    defstatus, rtstatus = get_status(product_state, name)
                    antivirus_products.append(
                        {
                            "Name": name,
                            "Product State": product_state,
                            "Definition Status": defstatus,
                            "Real-time Protection Status": rtstatus,
                            "Firewall": firewall_bool,
                        }
                    )

    antivirus_products_json = []

    for product in antivirus_products:
        last_scan = None

        if (
            product["Name"] == "AVG Antivirus"
            and product["Real-time Protection Status"] == "Enabled"
        ):
            last_scan = runcommand(
                '(Get-ItemProperty -Path "HKLM:\SOFTWARE\AVG\Antivirus\properties\settings\SmartScan" -Name "LastRun").LastRun'
            )

        if (
            product["Name"] == "Windows Defender"
            and product["Real-time Protection Status"] == "Enabled"
        ):
            last_scan = runcommand(
                "$mpStatus = Get-MpComputerStatus; $scanEndTime = $mpStatus.QuickScanEndTime; if ($mpStatus.FullScanEndTime -gt $scanEndTime) { $scanEndTime = $mpStatus.FullScanEndTime }; [int][double]::Parse((Get-Date $scanEndTime -UFormat %s))"
            )

        antivirus_product_json = {
            "Name": product["Name"],
            "Update Status": product["Definition Status"],
            "Real-time Protection Status": product["Real-time Protection Status"],
            "Last Scan": last_scan,
            "Firewall": product["Firewall"],
        }
        # append each antivirus product directly to the JSON array
        antivirus_products_json.append(antivirus_product_json)

    # data to send to server
    datasend = {
        "action": "checkantivirus",
        "sessionid": sessionid,
        "data": antivirus_products_json,
        "ret": 0,
        "base64": False,
    }

    # send message to master deploy
    objectxmpp.send_message(
        mto=mto_address,
        mbody=json.dumps(datasend),
        mtype="chat",
    )
