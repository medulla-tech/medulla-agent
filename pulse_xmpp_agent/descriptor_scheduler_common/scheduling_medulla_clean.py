# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2026 Medulla, http://www.medulla-tech.io
# SPDX-License-Identifier: GPL-3.0-or-later

"""
Removes the agent files Medulla no longer ships: the distribution never
deletes anything.

One _clean_<feature> function per removed feature; the name alone makes it
run. Raise VERSION when adding one, or it never reaches the machines.
"""

import logging
import os

plugin = {"VERSION": "1.0", "NAME": "scheduling_medulla_clean", "TYPE": "all", "SCHEDULED": True}  # fmt: skip

# Random time per machine, in working hours: desktops are off at night.
SCHEDULE = {"schedule": "$[0,59] $[8,17] * * *", "nb": -1}

logger = logging.getLogger()

# Plugin directories, relative to the agent root.
PLUGIN_DIRS = [
    "pluginsmachine",
    "pluginsrelay",
    os.path.join("agentrescue", "pluginsmachine"),
    "descriptor_scheduler_machine",
    "descriptor_scheduler_relay",
]

# Agent working directory.
STATE_DIR = "INFOSTMP"


def _root():
    """Agent root, deduced from this file."""
    return os.path.dirname(os.path.dirname(os.path.realpath(__file__)))


def _remove(path):
    """Delete one file and its compiled form. Never raises."""
    try:
        os.remove(path)
    except OSError as error:
        logger.warning("medulla_clean: %s not removed (%s)" % (path, error))
        return 0
    logger.info("medulla_clean: %s removed" % path)

    directory, name = os.path.split(path)
    cache = os.path.join(directory, "__pycache__")
    if not os.path.isdir(cache):
        return 1
    stem = os.path.splitext(name)[0] + "."
    for compiled in os.listdir(cache):
        if compiled.startswith(stem) and compiled.endswith(".pyc"):
            try:
                os.remove(os.path.join(cache, compiled))
            except OSError:
                pass
    return 1


def _remove_plugins(names):
    """Delete these plugins, by exact name, from every plugin directory."""
    root = _root()
    removed = 0
    for relative in PLUGIN_DIRS:
        directory = os.path.join(root, relative)
        if not os.path.isdir(directory):
            continue
        for name in names:
            path = os.path.join(directory, name)
            # Never follow a name out of the directory.
            if os.path.dirname(os.path.realpath(path)) != os.path.realpath(directory):
                continue
            if os.path.isfile(path):
                removed += _remove(path)
    return removed


def _remove_state_files(prefix, suffix):
    """Delete the working files named <prefix>...<suffix>. Both are required."""
    workdir = os.path.join(_root(), STATE_DIR)
    if not prefix or not suffix or not os.path.isdir(workdir):
        return 0
    removed = 0
    for name in os.listdir(workdir):
        if name.startswith(prefix) and name.endswith(suffix):
            removed += _remove(os.path.join(workdir, name))
    return removed


def _clean_old_monitoring():
    """Old monitoring, dropped in 2026: plugins and per-service state files."""
    removed = _remove_plugins(
        [
            "plugin_remote_script_monitoring.py",
            "plugin_installconfmonitoring.py",
        ]
    )
    removed += _remove_state_files("mon_", "_alert.json")
    return removed


def sweep():
    """Run every _clean_* function, return the number of files removed."""
    removed = 0
    for name, function in sorted(globals().items()):
        if not (name.startswith("_clean_") and callable(function)):
            continue
        try:
            removed += function()
        except Exception as error:
            logger.error("medulla_clean: %s failed (%s)" % (name, error))
    return removed


def schedule_main(objectxmpp):
    removed = sweep()
    if removed:
        logger.info("medulla_clean: %d obsolete file(s) removed" % removed)
