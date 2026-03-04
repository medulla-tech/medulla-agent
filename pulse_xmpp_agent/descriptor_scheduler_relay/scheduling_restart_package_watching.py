# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2016-2023 Siveo <support@siveo.net>
# SPDX-FileCopyrightText: 2023-2025 Medulla <support@medulla-tech.io>
# SPDX-License-Identifier: GPL-3.0-or-later

"""
this plugin restart package-watching every day at 23h00 (11 pm)
"""
import logging
import os

plugin = {"VERSION": "0.1", "NAME": "scheduling_restart_package_watching", "TYPE": "relayserver", "SCHEDULED": True}  # fmt: skip

# nb  -1 infinie
SCHEDULE = {"schedule": "0 23 * * *", "nb": -1}


def schedule_main(objectxmpp):
    logging.getLogger().debug("==========Plugin scheduling_ars_synchro_package==========")
    logging.getLogger().debug(plugin)
    logging.getLogger().debug("=========================================================")


    try:
        os.system("systemctl restart pulse-package-watching.service")
    except:
        pass
