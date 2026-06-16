# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2024-2025 Medulla, http://www.medulla-tech.io
# SPDX-License-Identifier: GPL-3.0-or-later
"""
Scheduled plugin to run CVE security scans.

This plugin periodically triggers a CVE scan using the Medulla security module.
It scans software inventory from GLPI and checks for known vulnerabilities
via the CVE Central API.
"""

import logging
import traceback
from datetime import datetime

logger = logging.getLogger()

plugin = { "VERSION": "1.2","NAME": "scheduling_security_scan","TYPE": "relayserver","SCHEDULED": True}

# Tous les jours a 4h du matin, nb=-1 = repetition infinie
SCHEDULE = {"schedule": "0 4 * * *", "nb": -1}


def schedule_main(objectxmpp):
    """Fonction principale du scheduler. Lance un scan CVE global."""
    date = datetime.now()
    logger.info(f"=== {plugin['NAME']} started at {date} ===")

    try:
        try:
            from mmc.plugins.security.scanner import run_cve_scan
        except ImportError as e:
            logger.error(f"Cannot import MMC security modules: {e}")
            logger.error("Make sure mmc-agent and security plugin are installed")
            logger.error("If relay is on a separate server, this plugin should run on the central server")
            return

        logger.info("Starting CVE security scan (global)...")
        result = run_cve_scan()

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
