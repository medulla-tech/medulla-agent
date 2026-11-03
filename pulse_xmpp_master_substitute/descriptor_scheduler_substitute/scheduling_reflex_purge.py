#!/usr/bin/python3
# -*- coding: utf-8; -*-
# SPDX-FileCopyrightText: 2026 Medulla, http://www.medulla-tech.io
# SPDX-License-Identifier: GPL-3.0-or-later
"""
Nightly retention of the reflex data.

The horizons are the retention.* settings of the reflex database, set from the
console.
"""

import logging
import traceback

from lib.plugins.reflex import reflex_backend, is_reflex_substitute

plugin = {"VERSION": "1.0", "NAME": "scheduling_reflex_purge", "TYPE": "substitute", "SCHEDULED": True}  # fmt: skip

SCHEDULE = {"schedule": "35 2 * * *", "nb": -1}

logger = logging.getLogger()


def schedule_main(objectxmpp):
    """Apply the retention policy, once a night."""
    logger.debug("==============Plugin scheduled==============")
    logger.debug(plugin)
    logger.debug("============================================")
    if not is_reflex_substitute(objectxmpp):
        return
    try:
        backend = reflex_backend()
        if backend is None:
            return
        retention = backend.retention()
        logger.info("reflex: purge with measures=%dd alerts=%dd history=%dd"
                    % (retention["measures_days"],
                       retention["alerts_resolved_days"],
                       retention["notification_history_days"]))
        purged = backend.purge()
        logger.info("reflex: %d measure(s), %d alert(s), %d history line(s) "
                    "removed" % (purged.get("measures", 0),
                                 purged.get("alerts", 0),
                                 purged.get("notification_history", 0)))
    except Exception as error:
        logger.error("reflex: purge failed: %s" % error)
        logger.error("\n%s" % traceback.format_exc())
