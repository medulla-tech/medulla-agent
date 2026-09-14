#!/usr/bin/python3
# -*- coding: utf-8; -*-
# SPDX-FileCopyrightText: 2026 Medulla, http://www.medulla-tech.io
# SPDX-License-Identifier: GPL-3.0-or-later
"""
Immediate distribution of the probe configuration.

Reads the queue probe_config_changes written by the console and serves the
machines a change touches. The logic lives in
lib.plugins.reflex.process_config_changes.

The sixth field of the schedule is the seconds; the scheduler only wakes up
every 10 s, so a round runs 10 to 20 s after the previous one.
"""

import logging
import traceback

from lib.plugins.reflex import reflex_backend, is_reflex_substitute, \
    process_config_changes

plugin = {"VERSION": "1.0", "NAME": "scheduling_reflex_notify", "TYPE": "substitute", "SCHEDULED": True}  # fmt: skip

SCHEDULE = {"schedule": "* * * * * */15", "nb": -1}

logger = logging.getLogger()


def schedule_main(objectxmpp):
    """Serve the machines touched by the queued configuration changes."""
    logger.debug("==============Plugin scheduled==============")
    logger.debug(plugin)
    logger.debug("============================================")
    if not is_reflex_substitute(objectxmpp):
        return
    try:
        backend = reflex_backend()
        if backend is None:
            return
        backend.reset_target_cache()
        result = process_config_changes(objectxmpp, backend)
        if result and result["changes"]:
            logger.info("reflex: %d change(s) read, %d machine(s) served, "
                        "%d configuration(s) sent, %d failure(s), %d row(s) "
                        "queued again"
                        % (result["changes"], result["machines"],
                           result["sent"], result["failed"],
                           result["requeued"]))
    except Exception as error:
        logger.error("reflex: configuration changes failed: %s" % error)
        logger.error("\n%s" % traceback.format_exc())
