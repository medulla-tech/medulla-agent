# -*- coding: utf-8 -*-
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
"""
# download file Wsusscn2.cab
"""
# pulse_xmpp_agent/descriptor_scheduler_relay/scheduling_wsusscn2.py

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
