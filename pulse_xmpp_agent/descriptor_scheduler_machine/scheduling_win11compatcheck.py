# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2017-2023 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-3.0-or-later

"""
This plugin runs the Windows 11 compatibility check script based on crontab descriptor time.
"""

import logging
import os
import sys
import tempfile
from contextlib import redirect_stdout
from lib import medulla_windows11_compatibility
from lib.agentconffile import medullaPath


plugin = {"VERSION": "1.0", "NAME": "scheduling_win11compatcheck", "TYPE": "machine", "SCHEDULED": True}  # fmt: skip

SCHEDULE = {"schedule": "*/15 * * * *", "nb": 2}


def schedule_main(objectxmpp):
    """
    Main function for the scheduling Windows 11 compatibility check plugin.
    """
    logging.getLogger().debug("###################################################")
    logging.getLogger().debug("call %s ", plugin)
    logging.getLogger().debug("###################################################")
    try:
        if sys.platform.startswith("win"):
            json_output_file = os.path.join(medullaPath(), "var", "log", "windows11_compatibility_report.json")

            with open(json_output_file, "w", encoding="utf-8") as report_file:
                with redirect_stdout(report_file):
                    medulla_windows11_compatibility.main(["--json"])

            logging.getLogger().info(
                "scheduling_win11compatcheck - Windows 11 compatibility report saved to %s", json_output_file
            )
    except Exception as e:
        logging.getLogger().error(f"scheduling_win11compatcheck - An error occurred while running the Windows 11 compatibility check: {e}")
