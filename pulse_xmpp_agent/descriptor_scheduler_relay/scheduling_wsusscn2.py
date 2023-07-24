# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2016-2023 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-3.0-or-later

"""
# download file Wsusscn2.cab
"""

import os
from lib import utils

plugin = {"VERSION": "1.1", "NAME": "scheduling_wsusscn2", "TYPE": "relayserver", "SCHEDULED": True}  # fmt: skip

# nb  -1 infinite
# all tuesday at 10h30PM
SCHEDULE = {"schedule": "30 22 * * 2", "nb": -1}


def schedule_main(objectxmpp):
    """
    Download Wsusscn2.cab file
    """
    print("*******************************************")
    print("*******************************************")
    print("*******************************************")
    try:
        os.makedirs("/var/lib/pulse2/Wsusscn2", 0o700)
    except OSError:
        pass
    re = utils.shellcommandtimeout(
        "wget -O /var/lib/pulse2/Wsusscn2/Wsusscn2.cab -P /var/lib/pulse2/Wsusscn2 http://go.microsoft.com/fwlink/p/?LinkID=74689",
        600,
    ).run()
    print(re["codereturn"])
    result = [x.strip("\n") for x in re["result"] if x != ""]
    print(result)
    print("*******************************************")
    print("*******************************************")
    print("*******************************************")


# http://go.microsoft.com/fwlink/p/?LinkID=74689
