#!/usr/bin/python3
# -*- coding: utf-8; -*-
# SPDX-FileCopyrightText: 2026 Medulla, http://www.medulla-tech.io
# SPDX-License-Identifier: GPL-3.0-or-later
"""
Reflex sweep, every minute.

Three jobs no incoming measure can trigger: the alerts whose condition moved,
was switched off or deleted, the retry queue of the notifications, and the
escalation of critical alerts nobody acknowledged.
"""

import logging
import traceback

from lib.plugins.reflex import reflex_backend, is_reflex_substitute, _to_int, \
    condition_moved_fields, BATCH_OPERATORS, THRESHOLDLESS_OPERATORS, \
    ALERT_RESOLVED_CONDITION_CHANGED, ALERT_RESOLVED_CONDITION_DISABLED, \
    ALERT_RESOLVED_CONDITION_REMOVED, ALERT_RESOLVED_PROBE_DISABLED, \
    SKIP_CHANNEL_TYPE_UNSUPPORTED, SKIP_RULE_NO_RECIPIENT, \
    SKIP_RETRY_ALERT_RESOLVED, SKIP_RETRY_ATTEMPTS_EXHAUSTED, \
    SKIP_RETRY_RULE_UNAVAILABLE, SKIP_RETRY_TARGET_NOT_MATCHED, \
    SKIP_RETRY_CHANNEL_ENTITY_MISMATCH

plugin = {"VERSION": "1.2", "NAME": "scheduling_reflex_tick", "TYPE": "substitute", "SCHEDULED": True}  # fmt: skip

SCHEDULE = {"schedule": "*/1 * * * *", "nb": -1}

logger = logging.getLogger()

MAX_RETRIES_PER_ROUND = 50
MAX_ATTEMPTS = 5

# machines_id and the uuid are carried for the language, read from the
# placement; the measure and its threshold so a second mail says what the
# first one said.
_ALERT_FIELDS = ("probe_id", "machines_id", "uuid_inventorymachine",
                "hostname", "severity", "message", "opened_at", "instance",
                "unit", "value_type", "value_at_trigger",
                "value_text_at_trigger", "detail_at_trigger",
                "threshold_value", "threshold_text",
                "probe_key", "probe_label")


def _alert_of(entry, alert_id):
    """The alert a queued row describes, as the senders read it."""
    alert = {"id": alert_id}
    alert.update((field, entry.get(field)) for field in _ALERT_FIELDS)
    return alert


def _sweep_stale_conditions(backend):
    """Close the alerts the rule behind them no longer accounts for.

    An alert closes when a measure fails its condition. Two things escape that:
    a condition that no longer evaluates -- switched off, deleted, or on a
    disabled probe -- and a condition that moved, whose alert stands against a
    threshold nobody would raise it on today.

    The moved ones are judged against the condition of today, never against the
    one frozen on the alert. Returns the number of alerts closed, per reason.
    """
    closed = {}
    judging = {}
    for alert in backend.stale_alerts():
        alert_id = _to_int(alert.get("id"), 0)
        operator = str(alert.get("operator") or "").lower()
        if not _to_int(alert.get("probe_enabled"), 0):
            closed.setdefault(ALERT_RESOLVED_PROBE_DISABLED,
                              []).append(alert_id)
        elif alert.get("current_condition_id") is None:
            closed.setdefault(ALERT_RESOLVED_CONDITION_REMOVED,
                              []).append(alert_id)
        elif not _to_int(alert.get("condition_enabled"), 0):
            closed.setdefault(ALERT_RESOLVED_CONDITION_DISABLED,
                              []).append(alert_id)
        # A moved condition is judged on measures, which an operator without
        # a threshold gives no verdict on: its alert stands on an event that
        # did happen, and a duration edited on the condition must not close
        # the whole estate at once. Same exemption as
        # pulse2.database.reflex._close_overridden_alerts.
        elif (operator in BATCH_OPERATORS
                and operator not in THRESHOLDLESS_OPERATORS):
            judging.setdefault(_to_int(alert.get("probe_id"), 0),
                               []).append(alert)

    for probe_id, alerts in judging.items():
        # One read per probe, sized on the widest window its alerts ask for,
        # and each alert judged over its own window inside it.
        spans = dict((_to_int(alert.get("id"), 0),
                      backend.judgement_span(alert, probe_id, {
                          "id": alert.get("machines_id"),
                          "uuid_inventorymachine":
                              alert.get("uuid_inventorymachine"),
                          "entity_id": alert.get("entity_id")}))
                     for alert in alerts)
        measures = backend.recent_measures(
            probe_id, [_to_int(alert.get("machines_id"), 0)
                       for alert in alerts], max(spans.values()))
        for alert in alerts:
            alert_id = _to_int(alert.get("id"), 0)
            window = measures.get(_to_int(alert.get("machines_id"), 0)) or []
            stands = backend.condition_still_stands(alert, window,
                                                    spans[alert_id])
            if stands is not False:
                continue
            closed.setdefault(ALERT_RESOLVED_CONDITION_CHANGED,
                              []).append(alert_id)
            logger.info("reflex: alert %s on %s closed, its condition "
                        "changed since it was raised (%s) and no longer "
                        "holds" % (alert_id, alert.get("hostname"),
                                   ", ".join(condition_moved_fields(alert))
                                   or "unknown field"))

    resolved = {}
    for reason, alert_ids in closed.items():
        moved = backend.resolve_alerts(alert_ids, reason)
        if moved:
            resolved[reason] = moved
            logger.info("reflex: %d alert(s) closed, reason %s"
                        % (moved, reason))
    return resolved


def _retry_notifications(backend):
    """Resend what a channel refused, until the attempts run out.

    Every way out of this loop gives its reason to drop_retry: it is the only
    thing that separates "we gave up" from "the resend is not due yet".
    """
    sent = 0
    for entry in backend.pending_retries(MAX_RETRIES_PER_ROUND):
        attempts = _to_int(entry.get("attempt_count"), 0) + 1
        if attempts > MAX_ATTEMPTS:
            backend.drop_retry(entry.get("id"), SKIP_RETRY_ATTEMPTS_EXHAUSTED,
                               entry)
            logger.warning("reflex: notification of alert %s abandoned after "
                           "%d attempts" % (entry.get("alert_id"), attempts - 1))
            continue
        if str(entry.get("alert_status") or "") == "resolved":
            backend.drop_retry(entry.get("id"), SKIP_RETRY_ALERT_RESOLVED,
                               entry)
            continue

        # The rule is looked up again at every round: it may have been deleted,
        # turned off, or had its minimum severity raised since.
        rules = [rule for rule in backend.rules_for(entry.get("probe_id"),
                                                    entry.get("severity"))
                 if _to_int(rule.get("id"), 0) == _to_int(entry.get("rule_id"), 0)]
        if not rules:
            backend.drop_retry(entry.get("id"), SKIP_RETRY_RULE_UNAVAILABLE,
                               entry)
            continue
        rule = rules[0]
        # The machine may have changed customer since the attempt that failed.
        # Judged before the restriction of the rule, as on the first notice.
        if not backend.channel_reaches(rule, entry):
            backend.drop_retry(entry.get("id"),
                               SKIP_RETRY_CHANNEL_ENTITY_MISMATCH, entry)
            continue
        if not backend.rule_applies(rule, entry):
            backend.drop_retry(entry.get("id"), SKIP_RETRY_TARGET_NOT_MATCHED,
                               entry)
            continue

        alert = _alert_of(entry, entry.get("alert_id"))
        settings = backend.channel_settings(rule.get("config_json"),
                                            rule.get("recipients"))
        if not settings["recipients"]:
            backend.drop_retry(entry.get("id"), SKIP_RULE_NO_RECIPIENT, entry)
            continue
        escalation = bool(_to_int(entry.get("is_escalation"), 0))
        language = backend.alert_language(alert)
        result = backend.send_email(
            _to_int(rule.get("channel_id"), 0), settings,
            backend.alert_subject(alert, language),
            backend.alert_body(alert, escalation, language),
            backend.alert_html_body(alert, escalation, language))
        backend.record_attempt(alert, rule, settings, result, escalation,
                               attempt_count=attempts)
        backend.drop_retry(entry.get("id"))
        if result.get("success"):
            sent += 1
    return sent


def _escalate(backend):
    """Second notice for a critical alert nobody acknowledged."""
    sent = 0
    for entry in backend.escalation_candidates():
        alert = _alert_of(entry, entry.get("id"))
        rule = {
            "id": entry.get("rule_id"),
            "channel_id": entry.get("channel_id"),
            "recipients": entry.get("recipients"),
            "config_json": entry.get("config_json"),
        }
        if str(entry.get("channel_type") or "email") != "email":
            # Traced with is_escalation, which is also what takes this
            # candidate out of the next sweeps.
            backend.record_skip(alert.get("id"), SKIP_CHANNEL_TYPE_UNSUPPORTED,
                                channel_id=_to_int(rule.get("channel_id"), 0),
                                rule_id=_to_int(rule.get("id"), 0),
                                escalation=True)
            continue
        settings = backend.channel_settings(rule.get("config_json"),
                                            rule.get("recipients"))
        if not settings["recipients"]:
            backend.record_skip(alert.get("id"), SKIP_RULE_NO_RECIPIENT,
                                channel_id=_to_int(rule.get("channel_id"), 0),
                                rule_id=_to_int(rule.get("id"), 0),
                                escalation=True)
            continue
        language = backend.alert_language(alert)
        result = backend.send_email(
            _to_int(rule.get("channel_id"), 0), settings,
            backend.alert_subject(alert, language),
            backend.alert_body(alert, True, language),
            backend.alert_html_body(alert, True, language))
        backend.record_attempt(alert, rule, settings, result, True,
                               attempt_count=1)
        if result.get("success"):
            sent += 1
    return sent


def schedule_main(objectxmpp):
    """One sweep: stale conditions, retries, escalations."""
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

        stale = _sweep_stale_conditions(backend)
        retried = _retry_notifications(backend)
        escalated = _escalate(backend)
        if retried or escalated or stale:
            logger.info("reflex: %d stale alert(s) closed, "
                        "%d retry(ies), %d escalation(s)"
                        % (sum(stale.values()), retried, escalated))
    except Exception as error:
        logger.error("reflex: sweep failed: %s" % error)
        logger.error("\n%s" % traceback.format_exc())
