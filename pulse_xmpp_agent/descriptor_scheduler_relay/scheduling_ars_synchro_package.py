# -*- coding: utf-8 -*-
#
# (c) 2016-2021 siveo, http://www.siveo.net
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
this plugin charge tous les deploy scheduler, et envoi une demand d'execution a master
"""
import json
import logging
import sys
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
