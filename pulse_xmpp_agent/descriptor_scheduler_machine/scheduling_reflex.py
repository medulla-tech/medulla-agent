# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2026 Medulla, http://www.medulla-tech.io
# SPDX-License-Identifier: GPL-3.0-or-later
"""
Reflex machine scheduler.

Wakes up every minute, works out which probes are due from the cadence the
server gave them, runs their collectors and emits ONE message carrying
everything that was due. One message per probe would multiply the traffic of
the whole estate by the number of probes for no gain.

Two load properties matter here:

  - the phase of a probe is derived from the identifier of the machine, so
    that an estate does not measure it on the same cycle. The spreading is
    of a cycle, not of a second: every agent wakes up on the minute;
  - when the server cannot be reached the measures are kept locally, within a
    bounded spool, and replayed later with their original collected_at. The
    server tells a late report from a fresh one by comparing collected_at and
    received_at, which only works if the agent does not rewrite the date.

A probe records its result and not its intention: the slot is written as begun
before collecting and as achieved only once the measures are in the outgoing
batch. A cycle that fails is therefore taken up on the next one, within a
bounded number of tries, instead of being lost until the next cadence.

The agent measures nothing until the server has sent it a configuration.
Once per start it also announces the version it holds, so a change made while
it was down reaches it without waiting for the full sweep of the server.
"""

import json
import logging
import os
import time
import traceback
import zlib
from datetime import datetime

from lib.utils import getRandomName

plugin = {"VERSION": "1.1", "NAME": "scheduling_reflex", "TYPE": "machine", "SCHEDULED": True}  # fmt: skip

SCHEDULE = {"schedule": "*/1 * * * *", "nb": -1}

logger = logging.getLogger()

STATE_FILENAME = "reflex_schedule.json"
SPOOL_FILENAME = "reflex_spool.json"

# Bound of the local spool. Beyond it the oldest measures are dropped: an
# agent offline for a week must not fill its own disk to describe it.
MAX_SPOOL_MEASURES = 2000

# Cadence of the configuration request while the agent has none.
CONFIG_REQUEST_INTERVAL = 900

# Floor applied to any cadence, mirroring [scheduler] min_interval_seconds.
MIN_INTERVAL_SECONDS = 60

# Tries given to a probe inside one slot. Past that the slot is given up until
# the next one: a probe that keeps failing has to show as a hole on the server
# rather than be insisted on here.
MAX_PROBE_ATTEMPTS = 3


def _plugin_reflex():
    """The machine plugin holding the collector registry."""
    try:
        import plugin_reflex

        return plugin_reflex
    except ImportError:
        try:
            from pluginsmachine import plugin_reflex

            return plugin_reflex
        except ImportError:
            logger.error("reflex: plugin_reflex is not deployed on this machine")
            return None


def _state_path(reflex, filename):
    """Empty when the state directory cannot be trusted: nothing is then read
    from it, so a planted spool cannot be replayed to the server."""
    directory = reflex.usable_state_dir()
    return os.path.join(directory, filename) if directory else ""


def _read_json(path, default):
    if not path or not os.path.isfile(path):
        return default
    try:
        with open(path, "r") as handle:
            data = json.load(handle)
    except (IOError, OSError, ValueError) as error:
        logger.warning("reflex: %s unreadable (%s)" % (path, error))
        return default
    return data


def _write_json(path, data):
    if not path:
        return False
    try:
        with open(path, "w") as handle:
            json.dump(data, handle)
        return True
    except (IOError, OSError) as error:
        logger.error("reflex: %s not written (%s)" % (path, error))
        return False


def _machine_offset(objectxmpp, interval, probe_key=""):
    """Stable shift of one probe of one machine inside a cadence.

    Derived from the identifier of the machine, so it does not move from one
    restart to the next: an estate spread once stays spread. The probe takes
    part in the computation so that two probes of the same cadence on the same
    machine do not share a cycle, where a slow collector would hold back every
    probe measured behind it.
    """
    if interval <= 0:
        return 0
    try:
        identifier = str(objectxmpp.boundjid.bare)
    except Exception:
        identifier = ""
    if not identifier:
        identifier = str(os.uname()[1]) if hasattr(os, "uname") else "unknown"
    seed = "%s|%s" % (identifier, probe_key)
    return zlib.crc32(seed.encode("utf-8")) % interval


def _interval_of(probe):
    try:
        interval = int(probe.get("interval_seconds") or 0)
    except (TypeError, ValueError):
        interval = 0
    if interval < MIN_INTERVAL_SECONDS:
        interval = MIN_INTERVAL_SECONDS
    return interval


def _slot_entry(raw):
    """State of one probe, read whatever shape the file holds it in.

    Before this version a probe held its bare slot number, which recorded an
    attempt and not a result. It is read as an achieved slot: deploying this
    correction must not make every probe of the estate due at once.
    """
    if isinstance(raw, dict):
        try:
            slot = int(raw["slot"])
        except (KeyError, TypeError, ValueError):
            return None
        try:
            tries = int(raw.get("tries") or 0)
        except (TypeError, ValueError):
            tries = 0
        return {"slot": slot, "done": bool(raw.get("done")), "tries": tries}
    try:
        return {"slot": int(raw), "done": True, "tries": 0}
    except (TypeError, ValueError):
        return None


def _due_probes(objectxmpp, probes, slots, now):
    """Probes to measure on this cycle, with their slot marked as begun.

    A probe is due when its slot changed, and also when the current slot was
    begun without being achieved: a cycle where the collector failed, or where
    the agent stopped before the measures were in hand, is taken up on the
    next one. Past MAX_PROBE_ATTEMPTS the slot is given up.

    Working on slots rather than on an elapsed delay keeps the cadence
    anchored: a cycle that runs late does not push the following ones back.
    """
    due = []
    updated = dict(slots)
    for probe in probes:
        if not isinstance(probe, dict):
            continue
        probe_key = str(probe.get("probe_key") or "")
        if not probe_key:
            continue
        interval = _interval_of(probe)
        offset = _machine_offset(objectxmpp, interval, probe_key)
        slot = int((now + offset) // interval)
        entry = _slot_entry(slots.get(probe_key))
        tries = 1
        if entry is not None and entry["slot"] == slot:
            if entry["done"]:
                continue
            if entry["tries"] >= MAX_PROBE_ATTEMPTS:
                continue
            tries = entry["tries"] + 1
        updated[probe_key] = {"slot": slot, "done": False, "tries": tries}
        due.append(probe)
    return due, updated


def _mark_measured(slots, probe_keys):
    """Close the slot of the probes whose measures are in the outgoing batch."""
    for probe_key in probe_keys:
        entry = slots.get(probe_key)
        if isinstance(entry, dict):
            entry["done"] = True


def _monitoring_jid(objectxmpp):
    """JID of the substitute in charge of monitoring, master_mon@pulse."""
    target = getattr(objectxmpp, "sub_monitoring", None)
    if target is not None:
        target = str(target)
        if target:
            return target
    configured = getattr(objectxmpp.config, "sub_monitoring", None)
    if isinstance(configured, list) and configured:
        return str(configured[0])
    if configured:
        return str(configured)
    return "master_mon@pulse"


def _send(objectxmpp, payload):
    """Hand one message over. Returns True when it left the agent."""
    target = _monitoring_jid(objectxmpp)
    try:
        connected = objectxmpp.is_connected()
    except Exception:
        connected = True
    if not connected:
        logger.warning("reflex: agent not connected, message kept locally")
        return False
    try:
        objectxmpp.send_message(
            mto=target, mbody=json.dumps(payload), mtype="chat"
        )
        return True
    except Exception as error:
        logger.error("reflex: sending to %s failed: %s" % (target, error))
        return False


def _measures_message(reflex, config_version, measures, sessionid):
    return {
        "action": "reflex_measures",
        "sessionid": sessionid,
        "base64": False,
        "ret": 0,
        "data": {
            "subaction": "measures",
            "date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "config_version": config_version,
            "platform": reflex.current_os(),
            "agent_plugin_version": reflex.plugin["VERSION"],
            "measures": measures,
        },
    }


def _request_configuration(objectxmpp, reflex, config_version):
    """Pull side of the distribution: the agent asks for its configuration."""
    payload = {
        "action": "reflex_measures",
        "sessionid": getRandomName(6, "reflexcfg"),
        "base64": False,
        "ret": 0,
        "data": {
            "subaction": "configrequest",
            "date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "config_version": config_version,
            "platform": reflex.current_os(),
            "collectors": reflex.known_collectors(),
        },
    }
    return _send(objectxmpp, payload)


def _load_spool(reflex):
    data = _read_json(_state_path(reflex, SPOOL_FILENAME), {"measures": []})
    measures = data.get("measures") if isinstance(data, dict) else None
    return measures if isinstance(measures, list) else []


def _save_spool(reflex, measures):
    if len(measures) > MAX_SPOOL_MEASURES:
        dropped = len(measures) - MAX_SPOOL_MEASURES
        measures = measures[-MAX_SPOOL_MEASURES:]
        logger.warning("reflex: spool full, %d oldest measure(s) dropped"
                       % dropped)
    _write_json(_state_path(reflex, SPOOL_FILENAME), {"measures": measures})


def schedule_main(objectxmpp):
    """One reflex cycle: what is due, measured, and sent in a single message."""
    logger.debug("==============Plugin scheduled==============")
    logger.debug(plugin)
    logger.debug("============================================")
    try:
        reflex = _plugin_reflex()
        if reflex is None:
            return

        state_path = _state_path(reflex, STATE_FILENAME)
        state = _read_json(state_path, {})
        if not isinstance(state, dict):
            state = {}
        slots = state.get("slots") if isinstance(state.get("slots"), dict) else {}
        now = time.time()

        config = reflex.read_local_config()
        probes = config.get("probes") or []
        config_version = config.get("config_version") or ""

        announced = getattr(objectxmpp, "reflex_config_announced", False)
        if probes and not announced:
            if _request_configuration(objectxmpp, reflex, config_version):
                objectxmpp.reflex_config_announced = True
                state["last_config_request"] = now

        if not probes:
            # Nothing measured until the server has spoken. The request is
            # repeated on its own cadence so a machine that came up before
            # the substitute does not stay mute forever.
            last_request = float(state.get("last_config_request") or 0)
            if now - last_request >= CONFIG_REQUEST_INTERVAL \
                    or getattr(objectxmpp, "num_call_scheduling_reflex", 0) == 0:
                if _request_configuration(objectxmpp, reflex, config_version):
                    state["last_config_request"] = now
                    state["slots"] = slots
                    _write_json(state_path, state)
            logger.debug("reflex: no probe configured yet")
            return

        due, slots = _due_probes(objectxmpp, probes, slots, now)
        # The attempt is written before collecting: an agent that stops inside
        # a collector spends a try rather than start the same slot over for
        # ever.
        state["slots"] = slots
        _write_json(state_path, state)

        measures = []
        measured = []
        for probe in due:
            probe_key = str(probe.get("probe_key") or "")
            try:
                collected = reflex.collect_probe(probe)
            except Exception as error:
                # One failing collector never interrupts the others, and its
                # slot stays open: the probe comes back on the next cycle.
                logger.error("reflex: probe %s failed: %s"
                             % (probe_key, error))
                continue
            if not collected:
                logger.warning("reflex: probe %s produced no measure"
                               % probe_key)
                continue
            measures.extend(collected)
            measured.append(probe_key)

        if measured:
            # The slot is only achieved once the measures are in hand. What
            # follows can delay their sending, not lose them: an agent that
            # cannot talk spools them.
            _mark_measured(slots, measured)
            state["slots"] = slots
            _write_json(state_path, state)

        spooled = _load_spool(reflex)
        if not measures and not spooled:
            return

        # Late measures keep their original collected_at, so the server can
        # tell a replayed report from a fresh one.
        payload = _measures_message(
            reflex, config_version, spooled + measures,
            getRandomName(6, "reflexmea"))

        if _send(objectxmpp, payload):
            if spooled:
                logger.info("reflex: %d spooled measure(s) replayed"
                            % len(spooled))
                _save_spool(reflex, [])
            logger.info("reflex: %d measure(s) sent for %d probe(s)"
                        % (len(spooled) + len(measures), len(due)))
        else:
            _save_spool(reflex, spooled + measures)
            logger.warning("reflex: %d measure(s) kept locally"
                           % (len(spooled) + len(measures)))
    except Exception as error:
        logger.error("reflex: cycle failed with %s" % error)
        logger.error("reflex: backtrace\n%s" % traceback.format_exc())
