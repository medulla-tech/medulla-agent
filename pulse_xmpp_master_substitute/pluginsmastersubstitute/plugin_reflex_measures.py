#!/usr/bin/python3
# -*- coding: utf-8; -*-
# SPDX-FileCopyrightText: 2026 Medulla, http://www.medulla-tech.io
# SPDX-License-Identifier: GPL-3.0-or-later
"""
Reception of the reflex measures sent by the agents.

One report: resolve the JID into a machine, write the measures, evaluate the
conditions of the probes the batch carries. Nothing received here is executed.

The same action carries the two ends of the configuration distribution: the
request an agent makes on startup, and the acknowledgement it returns.
"""

import logging
import traceback

from lib.plugins.reflex import reflex_backend, machine_from_jid, \
    send_configuration, build_configuration, ReflexSourceUnavailable, \
    _to_int

plugin = {"VERSION": "1.1", "NAME": "reflex_measures", "TYPE": "substitute"}  # fmt: skip

logger = logging.getLogger()


def _acknowledge_version(backend, machines_id, version, error=None):
    """Record what the agent declares to apply."""
    if not version:
        return
    backend.database.set_agent_config_acked(machines_id, version,
                                            last_error=error)


def process_measures(xmppobject, backend, machine, data, sessionid):
    """Store a batch and evaluate what it says."""
    measures = data.get("measures")
    if not isinstance(measures, list) or not measures:
        logger.debug("reflex: empty report from %s" % machine.get("hostname"))
        return

    written, probe_ids = backend.store_measures(machine, measures)
    logger.info("reflex: %d measure(s) stored for %s"
                % (written, machine.get("hostname")))

    # Read before the count is judged: a report whose measures were all
    # discarded still says which configuration the agent holds.
    _acknowledge_version(backend, machine.get("id"),
                         data.get("config_version"))

    if not written:
        return

    # The measures are re-read with their probe identifier resolved, so the
    # evaluation judges the same values that were written.
    resolved = []
    by_key = backend.probe_index()
    for measure in measures:
        if not isinstance(measure, dict):
            continue
        probe_id = measure.get("probe_id")
        if not probe_id:
            definition = by_key.get(str(measure.get("probe_key") or ""))
            probe_id = definition.get("id") if definition else None
        if not probe_id:
            continue
        item = dict(measure)
        item["probe_id"] = probe_id
        resolved.append(item)

    opened = backend.evaluate(machine, probe_ids, resolved)
    for alert in opened:
        try:
            backend.notify_alert(alert)
        except Exception as error:
            logger.error("reflex: alert %s could not be notified: %s"
                         % (alert.get("id"), error))
            logger.error("\n%s" % traceback.format_exc())


def process_configrequest(xmppobject, backend, machine, data, sessionid):
    """Pull side: an agent asks for its configuration.

    An agent announcing the current version, which is also the last one sent
    to it, is only acknowledged. Any other request gets a configuration.
    """
    announced = str(data.get("config_version") or "")
    built = None
    if announced:
        try:
            built = build_configuration(backend, machine)
        except ReflexSourceUnavailable:
            built = None
    if built is not None and built[0] == announced:
        state = backend.agent_config_state(
            _to_int(machine.get("id"), 0)) or {}
        if state.get("sent_version") == announced:
            if state.get("acked_version") != announced:
                _acknowledge_version(backend, machine.get("id"),
                                     announced)
            logger.debug("reflex: %s already holds configuration %s"
                         % (machine.get("hostname"), announced))
            return
    version = send_configuration(xmppobject, backend, machine,
                                 sessionid=sessionid, force=True, built=built)
    if version:
        logger.info("reflex: configuration %s sent to %s on request"
                    % (version, machine.get("hostname")))


def process_configack(xmppobject, backend, machine, data, sessionid):
    """The agent declares the configuration it applies, errors included."""
    error = data.get("error")
    _acknowledge_version(backend, machine.get("id"),
                         data.get("config_version"), error=error)
    if error:
        logger.warning("reflex: %s applied its configuration with: %s"
                       % (machine.get("hostname"), error))


SUBACTIONS = {
    "measures": process_measures,
    "configrequest": process_configrequest,
    "configack": process_configack,
}


def action(xmppobject, action, sessionid, data, message, ret, dataobj):
    logger.debug("Start sessionid %s" % sessionid)
    logger.debug("call plugin %s from %s" % (plugin, message["from"]))

    try:
        backend = reflex_backend()
        if backend is None:
            logger.warning("reflex: backend unavailable, report dropped")
            return

        if not isinstance(data, dict):
            logger.warning("reflex: malformed message from %s" % message["from"])
            return

        subaction = str(data.get("subaction") or "").lower()
        handler = SUBACTIONS.get(subaction)
        if handler is None:
            logger.warning("reflex: subaction '%s' unknown, ignored" % subaction)
            return

        machine = machine_from_jid(message["from"])
        if not machine or not machine.get("id"):
            logger.warning("reflex: unknown machine behind %s"
                           % message["from"])
            return

        handler(xmppobject, backend, machine, data, sessionid)
    except Exception as error:
        logger.error("reflex: report from %s failed: %s"
                     % (message["from"], error))
        logger.error("\n%s" % traceback.format_exc())
    logger.debug("####end sessionid %s ####" % sessionid)
