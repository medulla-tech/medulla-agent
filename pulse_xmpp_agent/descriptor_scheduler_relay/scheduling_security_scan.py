# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2024-2025 Medulla, http://www.medulla-tech.io
# SPDX-License-Identifier: GPL-3.0-or-later
"""Scan CVE quotidien de tout le parc (module security de mmc, serveur central uniquement)."""

import logging
import threading
import time

logger = logging.getLogger()

plugin = {"VERSION": "1.4", "NAME": "scheduling_security_scan", "TYPE": "relayserver", "SCHEDULED": True}

# Tous les jours à une heure et des minutes aléatoires
SCHEDULE = {"schedule": "$[0,59] $[0,23] * * *", "nb": -1}

ATTEMPTS = 3
RETRY_DELAY = 900
running = threading.Lock()


def schedule_main(objectxmpp):
    try:
        from mmc.plugins.security.scanner import run_cve_scan
    except ImportError:
        logger.debug("Security scan skipped: no mmc security module on this relay")
        return
    if running.locked():
        logger.info("Security scan already running, skipped")
        return
    # Un scan peut durer : la boucle XMPP du relais ne doit pas l'attendre
    threading.Thread(target=_scan, args=(run_cve_scan,), name=plugin["NAME"], daemon=True).start()


def _scan(run_cve_scan):
    with running:
        for attempt in range(1, ATTEMPTS + 1):
            try:
                result = run_cve_scan()
            except Exception as e:
                result = {"error": str(e)}
            if result.get("status") == "completed":
                logger.info(f"Security scan completed: {result.get('softwares_sent', 0)} software, "
                            f"{result.get('cves_received', 0)} CVEs")
                return
            logger.error(f"Security scan failed ({attempt}/{ATTEMPTS}): {result.get('error')}")
            if attempt < ATTEMPTS:
                time.sleep(RETRY_DELAY)
