# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2016-2023 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-3.0-or-later

"""
this plugin charge tous les deploy scheduler, et envoi une demand d'execution a master
"""
import logging
from lib.managepackage import managepackage

plugin = {"VERSION": "1.3", "NAME": "scheduling_ars_synchro_package", "TYPE": "relayserver", "SCHEDULED": True, }  # fmt: skip

# nb  -1 infinie
SCHEDULE = {"schedule": "*/1 * * * *", "nb": -1}


def schedule_main(objectxmpp):
    logging.getLogger().debug(
        "==========Plugin scheduling_ars_synchro_package=========="
    )
    logging.getLogger().debug(plugin)
    logging.getLogger().debug(
        "========================================================="
    )

    managepackage.remove_symlinks()
    managepackage.package_for_deploy_from_share()
