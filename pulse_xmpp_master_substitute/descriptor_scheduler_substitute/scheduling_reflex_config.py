#!/usr/bin/python3
# -*- coding: utf-8; -*-
# SPDX-FileCopyrightText: 2026 Medulla, http://www.medulla-tech.io
# SPDX-License-Identifier: GPL-3.0-or-later
"""
Distribution of the probe configuration to the agents.

Full sweep of the estate, behind the push of scheduling_reflex_notify and the
pull an agent makes on startup. The gap between sent_version and acked_version
of probe_agent_config designates an agent that did not take its configuration,
and it is served again.
"""

import logging
import traceback

from lib.plugins.reflex import reflex_backend, is_reflex_substitute, \
    active_machines, send_configuration, _to_int

plugin = {"VERSION": "1.1", "NAME": "scheduling_reflex_config", "TYPE": "substitute", "SCHEDULED": True}  # fmt: skip

SCHEDULE = {"schedule": "*/30 * * * *", "nb": -1}

logger = logging.getLogger()

# Machines served per round. A change applying to the whole estate is spread
# over several rounds rather than emitted in one burst.
MAX_PER_ROUND = 200


def schedule_main(objectxmpp):
    """Send its configuration to every agent whose version moved."""
    logger.debug("==============Plugin scheduled==============")
    logger.debug(plugin)
    logger.debug("============================================")
    if not is_reflex_substitute(objectxmpp):
        return
    try:
        backend = reflex_backend()
        if backend is None:
            return

        machines = active_machines()
        if not machines:
            logger.debug("reflex: no machine to configure")
            return

        sent = 0
        drifted = 0
        for machine in machines:
            if sent >= MAX_PER_ROUND:
                logger.info("reflex: %d configurations sent, the rest follows "
                            "on the next round" % sent)
                break
            state = backend.agent_config_state(_to_int(machine.get("id"), 0))
            if state and state.get("sent_version") \
                    and state.get("sent_version") != state.get("acked_version"):
                drifted += 1
            try:
                if send_configuration(objectxmpp, backend, machine):
                    sent += 1
            except Exception as error:
                logger.error("reflex: configuration of %s failed: %s"
                             % (machine.get("hostname"), error))

        if sent or drifted:
            logger.info("reflex: %d configuration(s) sent, %d agent(s) in "
                        "version drift" % (sent, drifted))
    except Exception as error:
        logger.error("reflex: configuration distribution failed: %s" % error)
        logger.error("\n%s" % traceback.format_exc())
