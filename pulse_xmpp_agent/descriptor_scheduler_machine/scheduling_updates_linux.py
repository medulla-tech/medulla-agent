# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2026 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-3.0-or-later

"""
Every 30 minutes, asks updates_linux for a report when the machine changed
(restart, packages installed outside Medulla).
"""

import sys
from lib import utils

plugin = {"VERSION": "1.0", "NAME": "scheduling_updates_linux", "TYPE": "machine", "SCHEDULED": True}  # fmt: skip

# Random minute per machine, so that the fleet does not check at the same time
SCHEDULE = {"schedule": "$[0,29]/30 * * * *", "nb": -1}


def schedule_main(objectxmpp):
    if not sys.platform.startswith("linux"):
        return
    utils.call_plugin(
        "updates_linux",
        objectxmpp,
        "updates_linux",
        utils.getRandomName(6, "updates"),
        {"check": True},
        {"from": objectxmpp.boundjid.bare, "to": objectxmpp.boundjid.bare},
        {},
    )
