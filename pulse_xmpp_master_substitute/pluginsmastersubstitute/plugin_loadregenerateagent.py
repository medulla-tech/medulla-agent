# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2016-2023 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-3.0-or-later

"""Charge le traitement periodique de la file reset_machine."""

import configparser
import logging
import os
import types

from lib.utils import call_plugin, getRandomName

logger = logging.getLogger()
plugin = {"VERSION": "1.0", "NAME": "loadregenerateagent", "TYPE": "substitute"}  # fmt: skip


def action(objectxmpp, action, sessionid, data, msg, dataerreur):
    """Configure le scheduler de regeneration lors du demarrage."""
    if getattr(objectxmpp, "num_call%s" % action) != 0:
        return
    _read_configuration(objectxmpp)
    if objectxmpp.regenerate_queue_scan_enabled:
        objectxmpp.schedule(
            "regenerateagent_queue_scan",
            objectxmpp.regenerate_queue_scan_interval,
            objectxmpp.regenerateagent_queue_scan,
            repeat=True,
        )


def regenerateagent_queue_scan(self):
    """Declenche plugin_regenerateagent en mode queue_process."""
    message = {"from": self.boundjid.bare, "to": self.boundjid.bare, "type": "chat"}
    call_plugin(
        "%s/plugin_regenerateagent.py" % self.modulepath,
        self,
        "regenerateagent",
        getRandomName(6, "regenerateq"),
        {"mode": "queue_process"},
        message,
        0,
        {},
    )


def _read_configuration(objectxmpp):
    """Lit la configuration et lie le scan a l'instance substitute."""
    path = os.path.join(objectxmpp.config.pathdirconffile, plugin["NAME"] + ".ini")
    configuration = configparser.ConfigParser()
    configuration.read([path, path + ".local"])
    objectxmpp.regenerate_queue_scan_enabled = configuration.getboolean(
        "parameters", "regenerate_queue_scan_enabled", fallback=True
    )
    objectxmpp.regenerate_queue_scan_interval = max(
        10, configuration.getint("parameters", "regenerate_queue_scan_interval", fallback=20)
    )
    objectxmpp.regenerate_queue_batch_size = max(
        1, configuration.getint("parameters", "regenerate_queue_batch_size", fallback=5)
    )
    objectxmpp.regenerateagent_queue_scan = types.MethodType(
        regenerateagent_queue_scan, objectxmpp
    )
