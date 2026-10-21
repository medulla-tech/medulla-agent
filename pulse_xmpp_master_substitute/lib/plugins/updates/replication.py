# -*- coding: utf-8; -*-
# SPDX-FileCopyrightText: 2026 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-3.0-or-later
# file : pulse_xmpp_master_substitute/lib/plugins/updates/replication.py

"""
Replication of the medulla-wsus mirror into the local updates database.
"""

from datetime import datetime, timezone
import hashlib
import hmac
import logging
import threading
import time
import traceback

import requests

logger = logging.getLogger()

TIMEOUT = 120

# Causes kept in replication.last_error and read by the interface;
# any other text is an internal error, detailed in the log
NOT_CONFIGURED = "not_configured"
DENIED = "denied"
CLOCK = "clock"
UNREACHABLE = "unreachable"

# Two replications never run at once
lock = threading.Lock()


class MirrorError(Exception):
    """Refusal by the mirror; the message is the cause kept for the interface."""


def cause(error):
    if isinstance(error, MirrorError):
        return str(error)
    if isinstance(error, requests.exceptions.RequestException):
        return UNREACHABLE
    return str(error)


def sign(key, server_id, method, path_url, timestamp):
    message = "%s\n%s\n%s\n%s" % (server_id, method, path_url, timestamp)
    return hmac.new(key.encode(), message.encode(), hashlib.sha256).hexdigest()


def to_datetime(value):
    """Convert an ISO 8601 date to a naive UTC datetime for MySQL."""
    if not value:
        return None
    date = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if date.tzinfo:
        date = date.astimezone(timezone.utc).replace(tzinfo=None)
    return date


def file_rows(update):
    """Return (file, language) for every file of every variant."""
    return [
        (file, file.get("language") or variant.get("language"))
        for variant in update.get("variants") or []
        for file in variant.get("files") or []
    ]


class MirrorClient(object):
    def __init__(self, url, server_id, key, proxy=""):
        self.url = url.rstrip("/")
        self.server_id = server_id
        self.key = key
        self.session = requests.Session()
        if proxy:
            self.session.proxies = {"http": proxy, "https": proxy}

    def get(self, path, params=None):
        request = requests.Request("GET", self.url + path, params=params).prepare()
        timestamp = str(int(time.time()))
        request.headers["X-Medulla-Server"] = self.server_id
        request.headers["X-Medulla-Timestamp"] = timestamp
        request.headers["X-Medulla-Signature"] = sign(
            self.key, self.server_id, "GET", request.path_url, timestamp
        )
        settings = self.session.merge_environment_settings(
            request.url, self.session.proxies, None, None, None
        )
        response = self.session.send(request, timeout=TIMEOUT, **settings)
        # 403: unknown, inactive or wrong key; 401: timestamp out of window
        if response.status_code == 403:
            raise MirrorError(DENIED)
        if response.status_code == 401:
            raise MirrorError(CLOCK)
        response.raise_for_status()
        data = response.json()
        if not data.get("success"):
            raise RuntimeError("mirror refused %s: %s" % (path, data))
        return data


def pages(client, path, params, upto=None):
    """Yield every page of a paginated mirror endpoint."""
    after = None
    while True:
        query = dict(params)
        if upto is not None:
            query["upto"] = upto
        if after is not None:
            query["after"] = after
        page = client.get(path, query)
        yield page
        upto = page["upto"]
        if not page.get("has_more"):
            return
        after = page["next_after"]


def copy_changes(client, store, generation, since, products, upto=None):
    params = {"since": since, "products": ",".join(sorted(products))}
    for page in pages(client, "/v1/changes", params, upto):
        if page["generation"] != generation:
            raise RuntimeError("mirror generation changed during replication")
        store.save_products(page.get("products") or [])
        store.save_releases(page.get("releases") or [])
        store.save_updates(page.get("updates") or [])
        upto = page["upto"]
    return upto


def copy_cves(client, store, since, upto):
    for page in pages(client, "/v1/cves", {"since": since}, upto):
        store.save_cves(page.get("cves") or [])


def copy_media(client, store):
    """Replace the media list when the mirror's version changed; return True when copied."""
    version = store.media_version()
    data = client.get("/v1/media", {"version": version} if version else None)
    if data.get("unchanged"):
        return False
    store.save_media(data.get("media") or [], data["version"])
    logger.info("Updates mirror: %d media" % len(data.get("media") or []))
    return True


def copy_linux_releases(client, store):
    """Replace the Linux versions when the mirror's version changed; return True when copied."""
    version = store.linux_releases_version()
    try:
        data = client.get("/v1/linux_releases", {"version": version} if version else None)
    except requests.exceptions.HTTPError as error:
        if error.response is None or error.response.status_code != 404:
            raise
        logger.warning("Updates mirror: no Linux versions on this mirror, list kept")
        return False
    if data.get("unchanged"):
        return False
    store.save_linux_releases(data.get("linux_releases") or [], data["version"])
    logger.info("Updates mirror: %d Linux versions" % len(data.get("linux_releases") or []))
    return True


def copy_updates(client, store):
    """Bring the updates of the store up to date with the mirror; the caller commits.

    Return True when updates were copied (media alone change no machine)."""
    generation, version = store.state()
    catalog = client.get("/v1/catalog")
    since = version or 0
    kept = None
    if catalog["generation"] != generation:
        logger.info("Updates mirror: full copy")
        since = 0
        # A rebuilt mirror numbers its updates again: an old id may now be another update
        kept = store.kept_references()
        store.clear_updates()
        store.reset_copied()
    elif catalog["version"] == version and not store.pending_products():
        store.save_success(generation, version)
        logger.debug("Updates mirror: unchanged")
        return False

    generation = catalog["generation"]
    upto = copy_changes(client, store, generation, since, store.copied_products())
    pending = store.pending_products()
    if pending:
        copy_changes(client, store, generation, 0, pending, upto)
        store.mark_copied(pending)
    copy_cves(client, store, since, upto)
    if kept:
        reattach(store, kept)
    store.save_success(generation, upto)
    logger.debug("Updates mirror: replicated")
    return True


def identity_index(rows):
    """Lookups by Microsoft identity: catalog id, WSUS id, then KB and exact title."""
    index = {}
    for row in rows:
        for key in identity_keys(row):
            index.setdefault(key, row["id"])
    return index


def identity_keys(row):
    keys = []
    if row.get("mucatalog_id"):
        keys.append(("mucatalog", row["mucatalog_id"]))
    if row.get("wsus_id"):
        keys.append(("wsus", row["wsus_id"]))
    if row.get("kb") and row.get("title"):
        keys.append(("kb_title", row["kb"], row["title"]))
    return keys


def new_update_id(index, row):
    for key in identity_keys(row):
        if key in index:
            return index[key]
    return None


def reattach(store, kept):
    """Put the admin approvals and the built packages back on the copied updates."""
    index = identity_index(store.update_identities())
    for table in ("approvals", "update_packages"):
        rows, lost = [], []
        for row in kept[table]:
            update_id = new_update_id(index, row)
            if update_id is None:
                lost.append(row)
            else:
                rows.append(dict(row, update_id=update_id))
        store.restore_references(table, rows)
        for row in lost:
            logger.error(
                "Updates mirror: %s of KB%s « %s » not found after the full copy"
                % (table, row.get("kb"), row.get("title"))
            )


def run(client, database):
    """Replicate the updates, the media and the Linux versions, each in its transaction; record the outcome.

    Return True when updates were copied and committed."""
    with database.store() as store:
        store.mark_attempt()
    copied = False
    try:
        with database.store() as store:
            copied = copy_updates(client, store)
        with database.store() as store:
            copy_media(client, store)
        with database.store() as store:
            copy_linux_releases(client, store)
    except Exception as error:
        logger.error("Updates mirror replication failed: %s" % error)
        with database.store() as store:
            store.save_error(cause(error))
    return copied


def refresh(client, database, entity_id=None, recompute=False):
    """Replicate, then recompute the machines of entity_id when given,
    or every machine when something was copied or recompute is set."""
    copied = run(client, database) if client else False
    if entity_id is None:
        database.purge_orphan_reports()
    if entity_id is not None:
        database.recompute_entity(entity_id)
    elif copied or recompute:
        database.recompute_all()


def refresh_locked(client, database, entity_id=None, then=None, recompute=False):
    """Refresh under the lock: the periodic refresh is skipped when one
    is running, a refresh for an entity waits for it.
    then is called after a refresh that ran."""
    if not lock.acquire(blocking=entity_id is not None):
        logger.info("Updates mirror replication still running, skipped")
        return
    try:
        refresh(client, database, entity_id, recompute)
        if entity_id is not None:
            logger.info(
                "Updates tracking of entity %s changed: machines recomputed" % entity_id
            )
    except Exception:
        logger.error("Updates refresh failed\n%s" % traceback.format_exc())
    finally:
        lock.release()
    if then is not None:
        then()


def start_refresh(client, database, entity_id=None, then=None, recompute=False):
    threading.Thread(
        target=refresh_locked,
        args=(client, database, entity_id, then, recompute),
        name="updates_replication",
        daemon=True,
    ).start()
