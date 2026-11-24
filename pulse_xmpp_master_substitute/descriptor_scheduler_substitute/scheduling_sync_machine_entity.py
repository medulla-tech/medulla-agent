#!/usr/bin/python3
# -*- coding: utf-8; -*-
# SPDX-FileCopyrightText: 2016-2023 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-3.0-or-later
"""
Realigne les entites GLPI des machines dans xmppmaster.

Un deplacement de machine dans GLPI ne declenche ni inventaire ni
consolidation : glpi_entity n'est pas complete et machines.glpi_entity_id
garde l'ancienne entite. Cette tache complete glpi_entity depuis
local_glpi_entities, aligne machines.glpi_entity_id et pose need_reconf=1
sur les machines corrigees.

Execute uniquement sur le substitut de reconfiguration (loadreconf).
"""
import logging
import traceback

from lib.plugins.xmpp import XmppMasterDatabase

plugin = {"VERSION": "1.0", "NAME": "scheduling_sync_machine_entity", "TYPE": "all", "SCHEDULED": True}  # fmt: skip

SCHEDULE = {"schedule": "*/15 * * * *", "nb": -1}

logger = logging.getLogger()


def schedule_main(objectxmpp):
    config = objectxmpp.config
    if "loadreconf" not in getattr(config, "pluginliststart", []):
        return
    if "xmpp" not in getattr(config, "plugins_list", []):
        return
    try:
        changes = XmppMasterDatabase().sync_machines_glpi_entity()
        logger.debug("%s: %s machine(s) realigned" % (plugin["NAME"], len(changes)))
    except Exception as error:
        logger.error("%s failed: %s" % (plugin["NAME"], error))
        logger.error(traceback.format_exc())
