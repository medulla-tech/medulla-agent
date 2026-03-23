# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2024-2025 Medulla, http://www.medulla-tech.io
# SPDX-License-Identifier: GPL-3.0-or-later
"""
Scheduled plugin to run CVE security scans.

This plugin periodically triggers a CVE scan using the Medulla security module.
It scans software inventory from GLPI and checks for known vulnerabilities
via the CVE Central API.

Configuration file: scheduling_security_scan.ini
"""

import configparser
import logging
import os
import traceback
from datetime import datetime

logger = logging.getLogger()

plugin = {
    "VERSION": "1.0",
    "NAME": "scheduling_security_scan",
    "TYPE": "relayserver",
    "SCHEDULED": True
}

# Cron: tous les jours a 4h du matin, nb=-1 = repetition infinie
SCHEDULE = {"schedule": "0 4 * * *", "nb": -1}


def schedule_main(objectxmpp):
    """Fonction principale du scheduler. Lance un scan CVE global."""
    date = datetime.now()
    logger.info(f"=== {plugin['NAME']} started at {date} ===")

    # Initialize config on first run
    num_call = getattr(objectxmpp, f"num_call_{plugin['NAME']}", 0)
    if num_call == 0:
        read_config_plugin(objectxmpp)

    objectxmpp.__dict__[f"num_call_{plugin['NAME']}"] = num_call + 1

    # Check if properly configured
    config = getattr(objectxmpp, 'security_scan_config', None)
    if not config:
        logger.warning("Security scan not configured, skipping")
        return

    if not config.get('enabled', False):
        logger.debug("Security scan disabled in config")
        return

    try:
        # Try to import MMC security modules
        try:
            from mmc.plugins.security.scanner import run_cve_scan
        except ImportError as e:
            logger.error(f"Cannot import MMC security modules: {e}")
            logger.error("Make sure mmc-agent and security plugin are installed")
            logger.error("If relay is on a separate server, this plugin should run on the central server")
            return

        # Run the CVE scan
        logger.info("Starting CVE security scan (global)...")
        result = run_cve_scan()

        # Log results
        if result.get('status') == 'completed':
            logger.info(f"CVE scan completed successfully:")
            logger.info(f"  - Scan ID: {result.get('scan_id')}")
            logger.info(f"  - Software scanned: {result.get('softwares_sent', 0)}")
            logger.info(f"  - CVEs found: {result.get('cves_received', 0)}")
        else:
            logger.error(f"CVE scan failed: {result.get('error', 'Unknown error')}")
            if result.get('errors'):
                for err in result['errors']:
                    logger.error(f"  - {err}")

    except Exception as e:
        logger.error(f"Error running security scan: {e}")
        logger.debug(traceback.format_exc())


def read_config_plugin(objectxmpp):
    """
    Read plugin configuration from INI file (with .local override support)
    """
    # Find config directory
    try:
        from lib.agentconffile import directoryconffile
        confdir = directoryconffile()
    except:
        confdir = "/etc/pulse-xmpp-agent"

    configfile = os.path.join(confdir, f"{plugin['NAME']}.ini")
    configfile_local = os.path.join(confdir, f"{plugin['NAME']}.ini.local")

    config = {
        'enabled': False,
    }

    # Read config files
    config_files = [configfile]
    if os.path.isfile(configfile_local):
        config_files.append(configfile_local)

    if os.path.isfile(configfile):
        try:
            parser = configparser.ConfigParser()
            parser.read(config_files)

            if parser.has_section('security_scan'):
                config['enabled'] = parser.getboolean('security_scan', 'enabled', fallback=False)

            logger.info(f"Security scan config loaded: enabled={config['enabled']}")

        except Exception as e:
            logger.error(f"Error reading config: {e}")
    else:
        logger.warning(f"Config file not found: {configfile}")

    objectxmpp.security_scan_config = config
