# -*- coding: utf-8; -*-
# SPDX-FileCopyrightText: 2026 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-3.0-or-later
# file : pulse_xmpp_master_substitute/lib/plugins/updates/compute.py

"""
Updates missing on a machine, from its report and the replicated catalog.

Inputs (loaded by UpdatesStore):
- report: machine_reports row (build, ubr, architecture, esu_licensed,
  search_status, search_server, searched_at) and dotnet, the .NET versions
  installed (None when the machine does not report them)
- tracked_products: products.id tracked by the machine entity, None without entity
- tracked_releases: (products.id, release name) tracked by the machine entity
- machine_releases: (products.id, release name) of the releases matching the
  machine build and architecture
- installed_kbs: set of installed KB numbers
- windows_missing: [{"kb", "title", "windows_update_id", "installed_on"}] from
  the last successful search of the machine, empty when there is none;
  installed_on the date this KB was installed, None when not known
- catalog: [{"id", "kb", "title", "build", "architecture", "published_at",
  "superseded", "removed", "classification", "target_version", "dotnet",
  "wsus_id", "products", "release"}], build and architecture being those of the update
  release (None without release), release its (products.id, name) (None
  without a named release), target_version the build.UBR it brings, dotnet
  the .NET versions it targets (None when not a .NET update), products a set
  of products.id

- supersedes: {superseded update id: [(superseding update id, its kb)]}

The catalog decides, the Windows list completes it, and has the last word
on older updates: after a successful search at Microsoft, an update of the
catalog Windows does not list is missing only when recent, Windows Update
possibly paused or deferred by policy. The cumulatives of the machine build
stay decided by its UBR, unless the restart is pending and they are installed and
no longer listed by a successful search: the UBR only moves at the restart.
Without such a search (WSUS, no access, failure),
the catalog alone decides.
A .NET cumulative replaces the older ones of its family (release,
architecture, .NET versions), whose supersedence the catalog does not know.
The catalog does not propose a .NET update of a family, or a servicing stack
update, published by the day of the .NET or system cumulative installed.

System cumulatives of the machine release, superseded or not, one entry per KB,
those its UBR already reached left out:
- main: the latest security one, not a preview; one row, the only one rules approve
- optional: previews and out of band ones more recent than main
- esu: Windows 10 without license, the main it would otherwise have, never deployable
Any other update is main.
"""

from datetime import date, datetime, timedelta
import re

TITLE_LENGTH = 500

# Windows 10 left support on 2025-10-14: later updates need an ESU license
WINDOWS10_BUILDS = (19044, 19045)
WINDOWS10_END_OF_SUPPORT = date(2025, 10, 14)
ESU_TITLE = "Extended Security Update"

UPGRADES = "Upgrades"
SECURITY = "Security Updates"

# machine_updates.offer
MAIN = "main"
OPTIONAL = "optional"
ESU = "esu"
ARCHITECTURE_IN_TITLE = re.compile(r"\b(x64|arm64|x86)\b", re.IGNORECASE)

DOTNET_CUMULATIVE = "cumulative update"
# Recent cumulatives embed the servicing stack
SERVICING_STACK = "servicing stack update"
# The monthly cumulative of Windows, its optional preview included
# (« 2026-10 Cumulative Update Preview for Windows 11 … »), not the .NET one
SYSTEM_CUMULATIVE = re.compile(r"cumulative update (preview )?for windows", re.IGNORECASE)


def is_system_cumulative(title):
    title = title or ""
    return SYSTEM_CUMULATIVE.search(title) is not None and "dynamic" not in title.lower()


def is_preview(update):
    return "preview" in (update["title"] or "").lower()


def is_security_cumulative(update):
    return update.get("classification") == SECURITY and not is_preview(update)


# Searches made at Microsoft, not at a WSUS
MICROSOFT_SERVERS = ("windows_update", "microsoft_update")
# Quality updates can be deferred 30 days and paused 35: Windows may not list
# a more recent one yet
WINDOWS_LIST_DAYS = 35


def uses_windows_list(report):
    return report.get("search_status") == "ok"


def windows_decides(report):
    """Successful search at Microsoft: it has the last word on older updates."""
    return (
        uses_windows_list(report)
        and report.get("search_server") in MICROSOFT_SERVERS
        and report.get("searched_at") is not None
    )


def windows_keeps(update, report, listed_kbs):
    """False for an older update a search at Microsoft does not list."""
    if not windows_decides(report) or update["kb"] in listed_kbs:
        return True
    if cumulative_installed(update, report) is not None:
        return True
    published = update.get("published_at")
    return published is None or published >= report["searched_at"] - timedelta(
        days=WINDOWS_LIST_DAYS
    )


def predates_install(item, report, installed_kbs):
    """True when the Windows list may predate the install of this KB, which then stays out.

    A KB can come back with a new version under the same number: listed by a search
    of a later day than its install, it is missing again. The install date has no
    time, so the day of the search counts as after it; an unknown date as well."""
    if item.get("kb") not in installed_kbs:
        return False
    installed_on = item.get("installed_on")
    searched_at = report.get("searched_at")
    return installed_on is None or searched_at is None or installed_on >= searched_at.date()


def machine_updates(
    report,
    tracked_products,
    tracked_releases,
    machine_releases,
    installed_kbs,
    windows_missing,
    catalog,
    supersedes,
):
    """Rows {update_id, kb, title, origin, offer} of what the machine misses."""
    if tracked_products is None:
        return []
    if not is_version_tracked(machine_releases, tracked_releases):
        return []
    tracking = (tracked_products, tracked_releases)
    windows_missing = [
        item for item in windows_missing if not predates_install(item, report, installed_kbs)
    ]
    candidates = [update for update in catalog if is_candidate(update, report, tracking)]
    latest = latest_ubr(candidates, report)
    listed_kbs = {item.get("kb") for item in windows_missing if item.get("kb") is not None}
    families = dotnet_families(
        [update for update in candidates if windows_keeps(update, report, listed_kbs)],
        catalog,
        installed_kbs,
    )
    families["system"] = installed_cumulative_date(catalog, report, installed_kbs)
    others = [update for update in candidates if not is_system_cumulative(update["title"])]
    return merge(
        cumulative_rows(report, tracking, installed_kbs, catalog, supersedes, families, listed_kbs)
        + deduce(report, installed_kbs, others, supersedes, latest, families, listed_kbs),
        from_windows(report, tracking, windows_missing, catalog, latest, families),
    )


def missing_cumulatives(report, machine_releases, installed_kbs, windows_missing, catalog, supersedes):
    """Main system cumulative the machine misses, tracked or not: an upgrade needs it
    even when the admin only checked its target. The optional ones only for a release
    without any security cumulative. By the UBR alone: an upgrade waits for the restart."""
    products = {product for update in catalog for product in update["products"]}
    releases = {update["release"] for update in catalog if update["release"]} | set(machine_releases)
    rows = machine_updates(dict(report, reboot_pending=False), products, releases, machine_releases,
                           installed_kbs, windows_missing, catalog, supersedes)
    system = [row for row in rows if is_system_cumulative(row["title"])]
    main = [row for row in system if row["offer"] == MAIN]
    if main or any(
        is_system_cumulative(update["title"])
        and is_security_cumulative(update)
        and matches_release(update, report)
        and not update["removed"]
        for update in catalog
    ):
        return main
    return [row for row in system if row["offer"] == OPTIONAL]


def latest_cumulative_id(rows, catalog):
    """Most recent catalog update among rows of missing_cumulatives, None without any."""
    ids = {row["update_id"] for row in rows}
    updates = [update for update in catalog if update["id"] in ids]
    if not updates:
        return None
    return max(updates, key=lambda update: update.get("published_at") or datetime.min)["id"]


def merge(deduced, windows):
    """Catalog rows, confirmed or completed by the Windows rows."""
    rows = list(deduced)
    by_id = {row["update_id"]: row for row in rows}
    by_kb = {row["kb"]: row for row in rows if row["kb"] is not None}
    for item in windows:
        known = by_id.get(item["update_id"]) if item["update_id"] is not None else None
        known = known or by_kb.get(item["kb"])
        if known is not None:
            known["origin"] = "machine"
            continue
        rows.append(item)
        by_id[item["update_id"]] = item
        if item["kb"] is not None:
            by_kb[item["kb"]] = item
    return rows


def row(update_id, kb, title, origin, offer=MAIN):
    return {
        "update_id": update_id,
        "kb": kb,
        "title": (title or ("KB%s" % kb if kb else ""))[:TITLE_LENGTH],
        "origin": origin,
        "offer": offer,
    }


def is_named(release):
    return bool(release) and release[0] is not None and release[1] is not None


def own_releases(releases, system_type):
    """(products.id, name) of the machine release among (os_product_name, products.id, name).

    os_product_name starts with Client. or Server.: a shared build is
    narrowed to the machine system type when it is known."""
    if system_type:
        releases = [release for release in releases if of_system(release[0], system_type)]
    return [(product_id, name) for _, product_id, name in releases]


def of_system(os_product_name, system_type):
    return (os_product_name or "").lower().startswith(system_type.lower() + ".")


def is_version_tracked(machine_releases, tracked_releases):
    """False when the machine runs a known version the entity does not track."""
    known = [release for release in machine_releases or () if is_named(release)]
    return not known or any(release in tracked_releases for release in known)


def is_tracked(update, tracking):
    """A versioned update follows its version, any other its products."""
    tracked_products, tracked_releases = tracking
    release = update.get("release")
    if is_named(release):
        return release in tracked_releases
    return not update["products"].isdisjoint(tracked_products)


def matches_release(update, report):
    return (
        update["build"] is not None
        and update["build"] == report.get("build")
        and update["architecture"] == report.get("architecture")
    )


def title_architecture(title):
    found = ARCHITECTURE_IN_TITLE.search(title or "")
    return found.group(1).lower() if found else None


def pick_update(updates, report, title=None):
    """The catalog update matching the machine among those of one KB, or None if ambiguous.

    title: the one Windows reports for this update, when known."""
    # Upgrade media carry the KB of the cumulative they include
    candidates = [update for update in updates if update.get("classification") != UPGRADES] or updates
    released = [update for update in candidates if matches_release(update, report)]
    candidates = released or [update for update in candidates if update["build"] is None]
    narrowers = (
        lambda update: bool(title) and update["title"] == title,
        lambda update: not update["superseded"],
        lambda update: title_architecture(update["title"]) == report.get("architecture"),
        lambda update: bool(report.get("release")) and report["release"].lower() in (update["title"] or "").lower(),
    )
    for keep in narrowers:
        if len(candidates) <= 1:
            break
        candidates = [update for update in candidates if keep(update)] or candidates
    if len(candidates) == 1:
        return candidates[0]
    # Catalog duplicates: same title, the lowest id stays the same from one computation to the next
    title = candidates[0]["title"] if candidates else None
    if title and all(update["title"] == title for update in candidates):
        return min([update for update in candidates if not update["removed"]] or candidates,
                   key=lambda update: update["id"])
    return None


def target(update):
    """(build, UBR) of a cumulative update target_version, None otherwise."""
    parts = (update.get("target_version") or "").split(".")
    if len(parts) < 2:
        return None
    try:
        return int(parts[-2]), int(parts[-1])
    except ValueError:
        return None


def cumulative_installed(update, report):
    """True or False for a cumulative of the machine build, None otherwise."""
    reached = target(update)
    if reached is None or reached[0] != report.get("build") or report.get("ubr") is None:
        return None
    return report["ubr"] >= reached[1]


def dotnet_applies(update, report):
    """A .NET update needs one of its versions; unknown versions keep it."""
    versions = update.get("dotnet")
    installed = report.get("dotnet")
    if not versions or installed is None:
        return True
    return not set(versions).isdisjoint(installed)


def own_ubr(update, report):
    """Target UBR of a cumulative of the machine build, None otherwise."""
    reached = target(update)
    return reached[1] if reached and reached[0] == report.get("build") else None


def latest_ubr(candidates, report):
    """Highest target UBR among the cumulatives: it replaces the older ones."""
    ubrs = [own_ubr(update, report) for update in candidates]
    return max((ubr for ubr in ubrs if ubr is not None), default=None)


def is_older_cumulative(update, report, latest):
    ubr = own_ubr(update, report)
    return ubr is not None and latest is not None and ubr < latest


def dotnet_key(update):
    """(release, architecture, .NET versions) of a .NET update, None otherwise."""
    title = update["title"] or ""
    if not update.get("dotnet") or not is_named(update.get("release")):
        return None
    architecture = title_architecture(title) or update["architecture"]
    return update["release"], architecture, frozenset(update["dotnet"])


def dotnet_family(update):
    """Family of a .NET cumulative, None otherwise."""
    if DOTNET_CUMULATIVE not in (update["title"] or "").lower():
        return None
    return dotnet_key(update)


def installed_cumulative_date(catalog, report, installed_kbs=()):
    """Publication of the system cumulative installed, None if unknown: the
    one reached by the machine UBR, or an installed KB (Windows 10 titles do
    not give the build)."""
    installed = [
        update["published_at"]
        for update in catalog
        if update["kb"] in installed_kbs
        and is_system_cumulative(update["title"])
        and update.get("published_at") is not None
        and matches_release(update, report)
    ]
    reached_date = ubr_cumulative_date(catalog, report)
    if reached_date is not None:
        installed.append(reached_date)
    return max(installed, default=None)


def ubr_cumulative_date(catalog, report):
    """Publication of the cumulative reached by the machine UBR, None if unknown."""
    ubr = report.get("ubr")
    if ubr is None:
        return None
    reached = {}
    for update in catalog:
        own = own_ubr(update, report)
        if (
            own is None
            or own > ubr
            or update.get("published_at") is None
            or update.get("classification") == UPGRADES
            or not matches_release(update, report)
        ):
            continue
        reached.setdefault(own, []).append(update["published_at"])
    return max(reached[max(reached)]) if reached else None


def covered_by_cumulative(update, families):
    """A .NET non cumulative or a servicing stack update published by the day
    of the installed cumulative of its family or of the system."""
    published = update.get("published_at")
    if not families or published is None:
        return False
    title = (update["title"] or "").lower()
    if SERVICING_STACK in title:
        installed = families.get("system")
    elif DOTNET_CUMULATIVE not in title and dotnet_key(update) is not None:
        installed = families["installed"].get(dotnet_key(update))
    else:
        return False
    return installed is not None and published.date() <= installed.date()


def dotnet_families(candidates, catalog, installed_kbs):
    """Dates of the .NET cumulatives: {"kbs": {kb: date}, "newest": {family:
    date of its newest candidate}, "installed": {family: date of its newest
    installed member}}. A KB takes the date of its most recent catalog row."""
    families = {"kbs": {}, "newest": {}, "installed": {}}
    for update in catalog:
        if dotnet_family(update) is not None:
            when = update.get("published_at") or datetime.min
            families["kbs"][update["kb"]] = max(families["kbs"].get(update["kb"], when), when)
    for key, updates in (
        ("newest", candidates),
        ("installed", [update for update in catalog if update["kb"] in installed_kbs]),
    ):
        for update in updates:
            family = dotnet_family(update)
            if family is not None:
                when = families["kbs"][update["kb"]]
                families[key][family] = max(families[key].get(family, when), when)
    return families


def is_older_dotnet(update, families):
    """A .NET cumulative older than a candidate of its family, or than an installed one."""
    family = dotnet_family(update)
    if family is None or update["kb"] not in families["kbs"]:
        return False
    when = families["kbs"][update["kb"]]
    newest = families["newest"].get(family)
    installed = families["installed"].get(family)
    return (newest is not None and when < newest) or (
        installed is not None and when <= installed
    )


def dotnet_rows(candidates, report):
    """Ids of the rows kept among the catalog duplicates of the .NET cumulatives."""
    by_kb = {}
    for update in candidates:
        if dotnet_family(update) is not None:
            by_kb.setdefault(update["kb"], []).append(update)
    return {(pick_update(updates, report) or updates[0])["id"] for updates in by_kb.values()}


def reported_update(updates, item):
    """The update Windows identifies among those of one KB, None when its id is not in the catalog."""
    reported = (item.get("windows_update_id") or "").lower()
    matches = [
        update for update in updates
        if reported and (update.get("wsus_id") or "").lower() == reported
        and not update["removed"] and update.get("classification") != UPGRADES
    ]
    return min(matches, key=lambda update: update["id"], default=None)


def from_windows(report, tracking, windows_missing, catalog, latest=None, families=None):
    by_kb = {}
    for update in catalog:
        if update["kb"] is not None:
            by_kb.setdefault(update["kb"], []).append(update)
    rows = []
    seen = set()
    for item in windows_missing:
        kb = item.get("kb")
        known = by_kb.get(kb, []) if kb is not None else []
        # Outside the catalog or of an untracked product or version: not proposed
        tracked = [update for update in known if is_tracked(update, tracking)]
        if not tracked:
            continue
        # Offered by cumulative_rows, which keeps the origin
        if any(is_system_cumulative(update["title"]) and matches_release(update, report)
               for update in tracked):
            continue
        update = reported_update(tracked, item) or pick_update(tracked, report, item.get("title"))
        if update is None:
            rows.append(row(None, kb, item.get("title"), "machine"))
        elif cumulative_installed(update, report):
            continue
        elif is_older_cumulative(update, report, latest):
            continue
        elif families and is_older_dotnet(update, families):
            continue
        elif update["id"] not in seen:
            seen.add(update["id"])
            rows.append(row(update["id"], kb, update["title"], "machine"))
    return rows


def superseded_by_installed(update_id, supersedes, installed_kbs):
    """Walk the supersedence chain up from update_id."""
    pending = [update_id]
    visited = set()
    while pending:
        current = pending.pop()
        for superseding_id, kb in supersedes.get(current, ()):
            if kb in installed_kbs:
                return True
            if superseding_id not in visited:
                visited.add(superseding_id)
                pending.append(superseding_id)
    return False


def needs_esu(update, report):
    if report.get("build") not in WINDOWS10_BUILDS or report.get("esu_licensed"):
        return False
    published = update.get("published_at")
    return ESU_TITLE.lower() in (update["title"] or "").lower() or bool(
        published and published.date() > WINDOWS10_END_OF_SUPPORT
    )


def known_installed(update, report, installed_kbs, listed_kbs):
    """True or False when known, None otherwise. Restart pending, installed and no longer
    listed by a successful search: a cumulative only moves the UBR at the restart."""
    if (
        report.get("reboot_pending")
        and uses_windows_list(report)
        and update["kb"] in installed_kbs
        and update["kb"] not in listed_kbs
    ):
        return True
    return cumulative_installed(update, report)


def is_missing(update, report, installed_kbs, supersedes, listed_kbs=()):
    installed = known_installed(update, report, installed_kbs, listed_kbs)
    if installed is not None:
        return not installed
    return (
        update["kb"] is not None
        and update["kb"] not in installed_kbs
        and not superseded_by_installed(update["id"], supersedes, installed_kbs)
    )


def is_candidate(update, report, tracking):
    return (
        matches_release(update, report)
        and update.get("classification") != UPGRADES
        and is_tracked(update, tracking)
        and not update["superseded"]
        and not update["removed"]
        and dotnet_applies(update, report)
        and not needs_esu(update, report)
    )


def is_newer(update, other, report):
    """By target UBR, by publication when one of them has none."""
    ubrs = own_ubr(update, report), own_ubr(other, report)
    if None not in ubrs:
        return ubrs[0] > ubrs[1]
    return (update.get("published_at") or datetime.min) > (other.get("published_at") or datetime.min)


def latest_cumulative(updates, report):
    newest = None
    for update in sorted(updates, key=lambda item: (item.get("published_at") or datetime.min, item["id"])):
        if newest is None or not is_newer(newest, update, report):
            newest = update
    return newest


def system_cumulatives(catalog, report, tracking):
    """System cumulatives of the machine release, one entry per KB, none removed."""
    by_kb = {}
    for update in catalog:
        if (
            is_system_cumulative(update["title"])
            and matches_release(update, report)
            and update.get("classification") != UPGRADES
            and not update["removed"]
            and is_tracked(update, tracking)
        ):
            by_kb.setdefault(update["kb"] or ("id", update["id"]), []).append(update)
    picked = []
    for updates in by_kb.values():
        updates = [update for update in updates if target(update)] or updates
        picked.append(pick_update(updates, report) or updates[0])
    return picked


def cumulative_rows(report, tracking, installed_kbs, catalog, supersedes, families, listed_kbs):
    def missing(update):
        installed = known_installed(update, report, installed_kbs, listed_kbs)
        if installed is not None:
            return not installed
        if update["kb"] in listed_kbs:
            return True
        published = update.get("published_at")
        system = families["system"]
        if published is not None and system is not None and published.date() <= system.date():
            return False
        return (
            is_missing(update, report, installed_kbs, supersedes, listed_kbs)
            and windows_keeps(update, report, listed_kbs)
        )

    def offered(update, offer):
        origin = "machine" if update["kb"] in listed_kbs else "deduced"
        return row(update["id"], update["kb"], update["title"], origin, offer)

    cumulatives = system_cumulatives(catalog, report, tracking)
    available = [update for update in cumulatives if not needs_esu(update, report)]
    newest = latest_cumulative([u for u in cumulatives if is_security_cumulative(u)], report)
    main = latest_cumulative([u for u in available if is_security_cumulative(u)], report)
    others = [update for update in available if not is_security_cumulative(update)]

    rows = []
    if newest is not None and needs_esu(newest, report) and missing(newest):
        rows.append(offered(newest, ESU))
    if main is None:
        newest_other = latest_cumulative(others, report)
        optional = [newest_other] if newest_other else []
    else:
        optional = [update for update in others if is_newer(update, main, report)]
    if main is not None and missing(main):
        rows.append(offered(main, MAIN))
    rows.extend(offered(update, OPTIONAL) for update in optional if missing(update))
    return rows


def deduce(report, installed_kbs, candidates, supersedes, latest=None, families=None,
           listed_kbs=()):
    kept_dotnet = dotnet_rows(candidates, report)
    rows = []
    latest_kbs = set()
    for update in candidates:
        ubr = own_ubr(update, report)
        if ubr is not None:
            # Catalog duplicates (mucatalog / WSUS) are not always marked superseded
            if is_older_cumulative(update, report, latest) or update["kb"] in latest_kbs:
                continue
            latest_kbs.add(update["kb"])
        if dotnet_family(update) is not None and update["id"] not in kept_dotnet:
            continue
        if families and is_older_dotnet(update, families):
            continue
        if covered_by_cumulative(update, families):
            continue
        if not windows_keeps(update, report, listed_kbs):
            continue
        if is_missing(update, report, installed_kbs, supersedes, listed_kbs):
            rows.append(row(update["id"], update["kb"], update["title"], "deduced"))
    return rows
