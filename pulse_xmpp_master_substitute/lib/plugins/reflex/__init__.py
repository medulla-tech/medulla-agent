# -*- coding: utf-8; -*-
# SPDX-FileCopyrightText: 2026 Medulla, http://www.medulla-tech.io
# SPDX-License-Identifier: GPL-3.0-or-later
"""
Reflex backend of the master substitute.

The agent measures, this side evaluates and notifies. The schema belongs to
pulse2.database.reflex, which is called rather than rewritten: record_measures,
get_probe_config_for_machine, set_agent_config_sent, set_agent_config_acked,
add_notification_history and purge_old_data. Activation is lazy, so only the
substitute in charge of reflex opens a connection to that database.
"""

import calendar
import configparser
import errno
import gettext
import hashlib
import json
import logging
import os
import re
import smtplib
import socket
import ssl
from datetime import datetime, timedelta
from decimal import Decimal
from email.header import Header
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.utils import formataddr, formatdate, make_msgid
from html import escape as html_escape

from sqlalchemy import text

logger = logging.getLogger()

REFLEX_INI = "/etc/mmc/plugins/reflex.ini"

try:
    from pulse2.database.reflex import SEVERITY_RANK
except Exception:
    SEVERITY_RANK = {"info": 1, "medium": 2, "high": 3, "critical": 4}

try:
    from pulse2.database.reflex import TARGET_SPECIFICITY
except Exception:
    TARGET_SPECIFICITY = {"machine": 0, "group": 1, "entity": 2}

# The operators the server refuses a threshold on, taken from it so the two
# layers cannot hold different lists. They compare to nothing because they
# report an event and not a state, which is what this side reads them for.
try:
    from pulse2.database.reflex import THRESHOLDLESS_OPERATORS
except Exception:
    THRESHOLDLESS_OPERATORS = ("changed",)


# Cheapest target to resolve first: a machine row, then the entity the report
# carries, then dyngroup.
PLACEMENT_RESOLUTION_COST = {"machine": 0, "entity": 1, "group": 2}


# notification_history.skip_reason. Keys, worded by the console.
SKIP_COOLDOWN = "cooldown"
SKIP_SEVERITY_BELOW_MIN = "severity_below_min"
SKIP_RULE_DISABLED = "rule_disabled"
SKIP_CHANNEL_DISABLED = "channel_disabled"
SKIP_TARGET_NOT_MATCHED = "target_not_matched"
SKIP_CHANNEL_TYPE_UNSUPPORTED = "channel_type_unsupported"
SKIP_NO_RULE_MATCHES = "no_rule_matches"
SKIP_CHANNEL_ENTITY_MISMATCH = "channel_entity_mismatch"
SKIP_RULE_NO_RECIPIENT = "rule_no_recipient"
SKIP_RETRY_ATTEMPTS_EXHAUSTED = "retry_attempts_exhausted"
SKIP_RETRY_ALERT_RESOLVED = "retry_alert_resolved"
SKIP_RETRY_RULE_UNAVAILABLE = "retry_rule_unavailable"
SKIP_RETRY_TARGET_NOT_MATCHED = "retry_target_not_matched"
SKIP_RETRY_CHANNEL_ENTITY_MISMATCH = "retry_channel_entity_mismatch"

# Same column when a sending was attempted and failed, the detail going to
# error_message.
SEND_CHANNEL_NO_HOST = "channel_no_host"
SEND_CHANNEL_NO_SENDER = "channel_no_sender"
SEND_CHANNEL_NO_RECIPIENT = "channel_no_recipient"
SEND_CHANNEL_PASSWORD_UNREADABLE = "channel_password_unreadable"
SEND_SMTP_HOST_UNKNOWN = "smtp_host_unknown"
SEND_SMTP_CONNECT_REFUSED = "smtp_connect_refused"
SEND_SMTP_UNREACHABLE = "smtp_unreachable"
SEND_SMTP_TIMEOUT = "smtp_timeout"
SEND_SMTP_TLS_FAILED = "smtp_tls_failed"
SEND_SMTP_AUTH_REFUSED = "smtp_auth_refused"
SEND_SMTP_SENDER_REFUSED = "smtp_sender_refused"
SEND_SMTP_RECIPIENTS_REFUSED = "smtp_recipients_refused"
SEND_SMTP_CONNECTION_LOST = "smtp_connection_lost"
SEND_SMTP_SERVER_ERROR = "smtp_server_error"
SEND_SMTP_ERROR = "smtp_error"

# alerts.resolved_reason. A normal resolution leaves the column NULL.
ALERT_RESOLVED_CONDITION_CHANGED = "condition_changed"
ALERT_RESOLVED_CONDITION_DISABLED = "condition_disabled"
ALERT_RESOLVED_CONDITION_REMOVED = "condition_removed"
ALERT_RESOLVED_PROBE_DISABLED = "probe_disabled"
ALERT_RESOLVED_SUPERSEDED = "superseded"

SMTP_TIMEOUT_SECONDS = 15

# notification_history.error_message
MAX_ERROR_DETAIL = 512
# probe_measures.detail and alerts.detail_at_trigger, one copied onto the other
MAX_MEASURE_DETAIL = 512
MAX_REFUSED_LISTED = 4

# Operators of probe_conditions handled by the batch evaluation.
BATCH_OPERATORS = ("gt", "gte", "lt", "lte", "eq", "ne", "between", "outside",
                   "changed")

# Delay before an unacknowledged configuration is pushed again.
RESEND_AFTER_MINUTES = 30

# Consecutive reports that may be missing without breaking a streak.
MISSED_REPORTS_ALLOWED = 3

# Cadence assumed for a probe whose assignments declare none.
DEFAULT_INTERVAL_SECONDS = 300

# Identifiers bound into one IN list, max_allowed_packet being finite.
MAX_IDS_PER_STATEMENT = 500


class ReflexSourceUnavailable(Exception):
    """A source reflex depends on could not be read."""


# =============================================================================
# Small helpers, mirroring the ones of the shared layer
# =============================================================================
def _to_int(value, default=0):
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _to_float(value, default=None):
    if value is None or value == "":
        return default
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def entity_identifier(value):
    """A GLPI entity number, None when there is none to read.

    0 is the root entity of GLPI. _to_int() cannot read an entity number: it
    answers 0 for anything it fails to parse, which is a valid entity here.
    """
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    text_value = str(value).strip()
    if not text_value:
        return None
    try:
        return int(text_value)
    except (TypeError, ValueError):
        return None


def _serialise(value):
    if isinstance(value, datetime):
        # received_at is stored to the millisecond; the fraction is kept.
        return moment_text(value)
    if isinstance(value, Decimal):
        return float(value)
    return value


def _rows(result):
    keys = list(result.keys())
    return [dict((k, _serialise(v)) for k, v in zip(keys, row)) for row in result]


def _placeholders(prefix, values):
    names = []
    params = {}
    for index, value in enumerate(values):
        name = "%s%d" % (prefix, index)
        names.append(":" + name)
        params[name] = value
    return ", ".join(names), params

def _in_batches(values):
    """Slices of at most MAX_IDS_PER_STATEMENT, keeping one IN list bindable."""
    for start in range(0, len(values), MAX_IDS_PER_STATEMENT):
        yield values[start:start + MAX_IDS_PER_STATEMENT]


def _instance_clause(params, instance, column):
    """Narrow a statement to one instance, or leave it whole."""
    if instance is None:
        return ""
    params["instance"] = str(instance)
    return "   AND %s = :instance " % column


def _previous_text(older):
    """What the `changed` operator compares against, from the older measure.

    Taken outside the judged window on purpose: what a value changed from is
    not evidence, it is what the comparison needs to exist at all.
    """
    if older is None:
        return None
    return (older.get("value_text") if older.get("value_text") is not None
            else older.get("value_num"))


def severity_rank(severity):
    """Rank of a severity in SEVERITY_RANK, 0 when it is unknown."""
    return SEVERITY_RANK.get(str(severity or "").strip().lower(), 0)


def severity_reaches(severity, min_severity):
    """True when a severity is at least the required one."""
    return severity_rank(severity) >= severity_rank(min_severity)


def by_gravity(conditions):
    """Conditions from the most serious, display order kept otherwise."""
    return sorted(conditions or [],
                  key=lambda condition: -severity_rank(condition.get("severity")))


# Column an alert freezes at insert, against the name the condition of today
# carries for the same setting.
ALERT_FREEZE_FIELDS = (
    ("operator_at_trigger", "operator"),
    ("threshold_value_at_trigger", "threshold_value"),
    ("threshold_value2_at_trigger", "threshold_value2"),
    ("threshold_text_at_trigger", "threshold_text"),
    ("duration_seconds_at_trigger", "duration_seconds"),
)


def same_setting(left, right):
    """Whether two settings of a condition say the same thing.

    Compared as numbers when both read as numbers: 85, 85.0 and Decimal('85')
    are one threshold. NULL and the empty string are the same absence.
    """
    left_absent = left is None or str(left).strip() == ""
    right_absent = right is None or str(right).strip() == ""
    if left_absent or right_absent:
        return left_absent and right_absent
    left_num = _to_float(left)
    right_num = _to_float(right)
    if left_num is not None and right_num is not None:
        return left_num == right_num
    return str(left).strip().lower() == str(right).strip().lower()


def condition_moved_fields(alert):
    """Settings of an alert that read differently today than when it fired.

    Empty when the alert froze nothing: a missing freeze is not a change.
    """
    if not str(alert.get("operator_at_trigger") or "").strip():
        return []
    return [key for column, key in ALERT_FREEZE_FIELDS
            if not same_setting(alert.get(column), alert.get(key))]


# Restrictions already reported as unreadable, to log them once.
_UNREADABLE_TARGETS = set()


def parse_target_filter(target_filter):
    """Read the restriction a notification rule carries.

    Two forms only, group:<id> and entity:<id>; anything else concerns every
    machine. "entity:0" is the root entity of GLPI, so entity identifiers are
    not judged with the "> 0" a group number is judged with.

    Returns a ("group"|"entity", id) pair, or ("", 0) for no restriction.
    """
    raw = str(target_filter or "").strip()
    if not raw:
        return ("", 0)
    kind, separator, value = raw.partition(":")
    kind = kind.strip().lower()
    identifier = entity_identifier(value.strip())
    if separator and identifier is not None:
        if kind == "entity":
            return (kind, identifier)
        if kind == "group" and identifier > 0:
            return (kind, identifier)
    if raw not in _UNREADABLE_TARGETS:
        _UNREADABLE_TARGETS.add(raw)
        logger.warning("reflex: restriction '%s' not understood, the rules "
                       "carrying it apply to every machine" % raw)
    return ("", 0)


# Read rather than parsed with a format string: the agent sends the ISO form,
# the driver a datetime, the database the SQL form with a fraction of one to
# six digits or none. Anything trailing the seconds is left out of the match.
_MOMENT_PATTERN = re.compile(
    r"(\d{4})-(\d{2})-(\d{2})[ T](\d{2}):(\d{2}):(\d{2})(?:[.,](\d{1,6}))?")

# What may follow the seconds: an offset with or without the colon, or the Z
# of UTC.
_OFFSET_PATTERN = re.compile(r"(?:(Z)|([+-])(\d{2}):?(\d{2}))")


def moment_text(moment):
    """SQL text of an instant, milliseconds kept when it carries some."""
    if moment.microsecond:
        return "%s.%03d" % (moment.strftime("%Y-%m-%d %H:%M:%S"),
                            moment.microsecond // 1000)
    return moment.strftime("%Y-%m-%d %H:%M:%S")


def parse_moment(value):
    """Read a timestamp into a datetime, fraction included, None if unusable.

    The only reader a subtraction may use: probe_measures dates its rows to the
    millisecond, and a truncation to the second is of the order of what short
    durations measure.
    """
    if isinstance(value, datetime):
        return value
    match = _MOMENT_PATTERN.match(str(value or "").strip())
    if match is None:
        return None
    fraction = match.group(7) or ""
    try:
        return datetime(int(match.group(1)), int(match.group(2)),
                        int(match.group(3)), int(match.group(4)),
                        int(match.group(5)), int(match.group(6)),
                        int(fraction.ljust(6, "0")) if fraction else 0)
    except ValueError:
        return None


def moment_offset(value):
    """Offset a timestamp carries, in seconds, None when it carries none.

    Kept apart from parse_moment, which must keep answering a naive datetime:
    everything it reads is subtracted from datetime.now(), naive too.
    """
    if isinstance(value, datetime):
        offset = value.utcoffset()
        return None if offset is None else int(offset.total_seconds())
    raw = str(value or "").strip()
    match = _MOMENT_PATTERN.match(raw)
    if match is None:
        return None
    trailer = raw[match.end():].strip()
    offset = _OFFSET_PATTERN.fullmatch(trailer) if trailer else None
    if offset is None:
        return None
    if offset.group(1):
        return 0
    seconds = int(offset.group(3)) * 3600 + int(offset.group(4)) * 60
    return -seconds if offset.group(2) == "-" else seconds


def moment_utc_epoch(value):
    """Instant of an offset-carrying timestamp, in seconds since the epoch.

    None when the timestamp carries no offset, which is not the same as UTC: a
    date with no zone is a wall clock reading and nothing says whose.
    """
    offset = moment_offset(value)
    if offset is None:
        return None
    moment = parse_moment(value)
    if moment is None:
        return None
    # timegm and not mktime: the fields are read as they were written.
    return calendar.timegm(moment.timetuple()) - offset


def _host_moment(epoch):
    """An instant read on the clock of this host, None when it is unreadable.

    Last resort of local_moments: an unreadable date costs its own row, not the
    report it travelled with.
    """
    try:
        return datetime.fromtimestamp(epoch).strftime("%Y-%m-%d %H:%M:%S")
    except (OverflowError, OSError, ValueError):
        return None


def normalise_datetime(value):
    """SQL text of a timestamp, to the second, to be written or displayed.

    The zone is left as it came; only local_moments converts. Never the input
    of a subtraction, which reads parse_moment.
    """
    moment = parse_moment(value)
    return moment.strftime("%Y-%m-%d %H:%M:%S") if moment is not None else None


def observed_step(moments, declared):
    """Real cadence of a series of instants, newest first, in seconds.

    Read on the measures and not on the assignment: a slow collector adds its
    own time to every turn of the agent loop. The median of the gaps is taken,
    so a missing report does not stretch the cadence nor a duplicate shrink it.
    Below two gaps the declared cadence answers.
    """
    fallback = float(max(_to_int(declared, 0), 1))
    gaps = sorted((moments[index] - moments[index + 1]).total_seconds()
                  for index in range(len(moments) - 1))
    if len(gaps) < 2:
        return fallback
    middle = len(gaps) // 2
    median = (gaps[middle] if len(gaps) % 2
              else (gaps[middle - 1] + gaps[middle]) / 2.0)
    return median if median > 0 else fallback


def format_duration(seconds, language=None):
    """Render a measured duration with two units at most.

    "45 s", "12 min", "2 h 01", "3 d 04 h". A value empty, negative or not
    numeric reads "0 s". The units come from the catalogue, so they follow the
    language of the reader.
    """
    total = _to_float(seconds)
    if total is None or total < 0:
        total = 0.0
    total = int(total + 0.5)

    if total < 60:
        return translated_pattern("%d s", (total,), language)

    minutes = int(total / 60.0 + 0.5)
    if minutes < 60:
        return translated_pattern("%d min", (minutes,), language)

    hours, remainder = divmod(total, 3600)
    remainder_minutes = int(remainder / 60.0 + 0.5)
    if remainder_minutes == 60:
        hours += 1
        remainder_minutes = 0
    if hours < 24:
        return translated_pattern("%d h %02d", (hours, remainder_minutes),
                                  language)

    days, remainder = divmod(total, 86400)
    remainder_hours = int(remainder / 3600.0 + 0.5)
    if remainder_hours == 24:
        days += 1
        remainder_hours = 0
    return translated_pattern("%d d %02d h", (days, remainder_hours), language)


def decimal_separator(language):
    """The decimal mark of the language a notification is written in.

    ReflexHelper::decimalSeparator(): English, the C locale and no language at
    all keep the dot, every other language writes a comma. No catalogue is
    consulted, so a missing .mo still gets its numbers written right.
    """
    code = str(language or "").strip().lower()
    if not code or code == "c" or code.startswith("en"):
        return "."
    return ","


def format_number(value, language=None):
    """Render a measured number the way the console renders it beside it.

    Two decimals at most, trailing zeros dropped, then the decimal mark of the
    reader: ReflexHelper::plainNumber() then displayNumber(). A value that is
    not a number answers "", and the caller prints what it holds.
    """
    number = _to_float(value)
    if number is None:
        return ""
    rendered = ("%.2f" % number).rstrip("0").rstrip(".")
    # -0.004 rounds to "-0", which is a way of writing zero nobody writes.
    if rendered in ("", "-", "-0"):
        rendered = "0"
    separator = decimal_separator(language)
    return rendered if separator == "." else rendered.replace(".", separator)


def measure_instance(value_text, value_type=None):
    """What a measure was taken on, None when the probe reports one value.

    value_text names the volume or the port on a numeric or boolean probe, and
    IS the value on a text probe. Same rule as
    pulse2.database.reflex.measure_instance.
    """
    if str(value_type or "numeric").strip().lower() == "text":
        return None
    if value_text is None:
        return None
    value_text = str(value_text).strip()
    return value_text or None


def storable_detail(detail):
    """A measure detail as the column of 512 keeps it: whole or not at all.

    Kept whatever the status, and dropped whole when it does not fit: a cut
    detail is worse than no detail, and a cut JSON reads as nothing.
    """
    detail = str(detail or "").strip()
    if not detail or len(detail) > MAX_MEASURE_DETAIL:
        return None
    return detail


def detail_items(detail):
    """Entries a detail carries as {"items": [...]}, empty when it has none.

    ReflexHelper::detailItems(): the same column also holds the plain text
    reason of a reading that could not be taken, so anything that is not that
    object reads as no list at all.
    """
    detail = str(detail or "").strip()
    if not detail.startswith("{"):
        return []
    try:
        decoded = json.loads(detail)
    except Exception:
        return []
    items = decoded.get("items") if isinstance(decoded, dict) else None
    if not isinstance(items, list):
        return []
    return [item.strip() for item in items
            if isinstance(item, str) and item.strip()]


def is_boolean_type(value_type):
    """Whether a probe answers yes or no."""
    return str(value_type or "").strip().lower() == "boolean"


def boolean_text(value, language=None):
    """A yes/no measure in words, as the console words it.

    Empty when there is nothing to word, and the caller then prints nothing: a
    reading no rule recognises is not turned into a No.
    """
    if value is None or str(value).strip() == "":
        return ""
    number = _to_float(value)
    if number is None:
        word = str(value).strip().lower()
        if word in ("true", "yes", "on"):
            return translate("Yes", language)
        if word in ("false", "no", "off"):
            return translate("No", language)
        return ""
    return translate("Yes" if number != 0 else "No", language)


def unit_label(unit, language=None):
    """The unit of a probe as the console prints it beside a value.

    ReflexHelper::unitLabel(): "count" is a type nobody writes after a number,
    and "d" is a day of the catalogue.
    """
    unit = str(unit or "").strip()
    if unit == "count":
        return ""
    if unit == "d":
        return translate("d", language)
    return unit


def clip_detail(detail):
    """Keep a technical detail within the column that stores it."""
    detail = str(detail or "").strip()
    if len(detail) <= MAX_ERROR_DETAIL:
        return detail
    return detail[:MAX_ERROR_DETAIL - 3] + "..."


def transport_failure_key(error):
    """Key of a transport failure, None when the exception is not one.

    Read from the exception and not from its text: a name that does not resolve
    and a port that refuses send the reader to two different places.
    """
    if isinstance(error, socket.gaierror):
        return SEND_SMTP_HOST_UNKNOWN
    if isinstance(error, ssl.SSLError):
        return SEND_SMTP_TLS_FAILED
    if isinstance(error, (socket.timeout, TimeoutError)):
        return SEND_SMTP_TIMEOUT
    if isinstance(error, ConnectionRefusedError):
        return SEND_SMTP_CONNECT_REFUSED
    if isinstance(error, (ConnectionResetError, ConnectionAbortedError,
                          BrokenPipeError)):
        return SEND_SMTP_CONNECTION_LOST
    number = getattr(error, "errno", None)
    if number == errno.ETIMEDOUT:
        return SEND_SMTP_TIMEOUT
    if number == errno.ECONNREFUSED:
        return SEND_SMTP_CONNECT_REFUSED
    if number in (errno.ENETUNREACH, errno.EHOSTUNREACH, errno.ENETDOWN):
        return SEND_SMTP_UNREACHABLE
    return None


def smtp_failure_key(error, phase):
    """Family of a failed sending, as a key the console words.

    The phase cannot be recovered from the exception: SMTPNotSupportedError is
    what a server without STARTTLS answers, and also one without AUTH.
    """
    key = transport_failure_key(error)
    if key is not None:
        return key
    if isinstance(error, smtplib.SMTPServerDisconnected):
        return SEND_SMTP_CONNECTION_LOST
    if phase == "auth":
        # Whatever code it carries, an answer to AUTH refuses the account.
        return SEND_SMTP_AUTH_REFUSED
    if phase == "tls":
        return SEND_SMTP_TLS_FAILED
    if isinstance(error, smtplib.SMTPRecipientsRefused):
        return SEND_SMTP_RECIPIENTS_REFUSED
    if isinstance(error, smtplib.SMTPSenderRefused):
        return SEND_SMTP_SENDER_REFUSED
    if isinstance(error, smtplib.SMTPConnectError):
        return SEND_SMTP_CONNECT_REFUSED
    if isinstance(error, smtplib.SMTPResponseException):
        return SEND_SMTP_SERVER_ERROR
    return SEND_SMTP_ERROR


def refused_recipients_text(refused):
    """What a server answered per recipient, bounded to what fits."""
    entries = list((refused or {}).items())
    parts = []
    for recipient, answer in entries[:MAX_REFUSED_LISTED]:
        try:
            code, detail = answer
        except (TypeError, ValueError):
            code, detail = "", answer
        if isinstance(detail, bytes):
            detail = detail.decode("utf-8", "replace")
        parts.append("%s: %s %s" % (recipient, code, detail))
    remaining = len(entries) - MAX_REFUSED_LISTED
    if remaining > 0:
        parts.append("and %d other recipient(s)" % remaining)
    return "; ".join(parts)


# What was being done when the sending failed, said in the detail.
SMTP_PHASE_LABELS = {
    "connect": "connecting to",
    "tls": "starting TLS with",
    "auth": "authenticating on",
    "send": "sending through",
}


def smtp_failure(error, phase, settings):
    """One failed sending, as the key of its family and its detail."""
    settings = settings or {}
    host = str(settings.get("host") or "")
    port = _to_int(settings.get("port"), 0)
    if isinstance(error, smtplib.SMTPRecipientsRefused):
        raw = "every recipient refused: %s" % refused_recipients_text(
            getattr(error, "recipients", None))
    elif isinstance(error, smtplib.SMTPResponseException):
        detail = error.smtp_error
        if isinstance(detail, bytes):
            detail = detail.decode("utf-8", "replace")
        raw = "SMTP %s: %s" % (error.smtp_code, detail)
    else:
        # The class name is the detail, not what the console shows.
        raw = "%s: %s" % (type(error).__name__, error)
    return {
        "success": False,
        "error_key": smtp_failure_key(error, phase),
        "error": clip_detail("%s %s:%d: %s" % (
            SMTP_PHASE_LABELS.get(phase, "sending through"), host, port, raw)),
    }


# =============================================================================
# Alert mail
#
# Outlook renders mail with the engine of Word: no <style> block, no flexbox,
# no positioning, no image. Hence tables, inline styles and bgcolor attributes.
# =============================================================================

# .reflex-badge-* of web/modules/reflex/graph/css/index.css, restated inline.
SEVERITY_BADGE_COLORS = {
    "critical": ("#dc3545", "#ffffff"),
    "high": ("#fd7e14", "#ffffff"),
    "medium": ("#ffc107", "#333333"),
    "info": ("#3b82f6", "#ffffff"),
}
SEVERITY_BADGE_UNKNOWN = ("#adb5bd", "#333333")

ALERT_MAIL_FACT = (
    '<tr>'
    '<td width="140" valign="top" style="width:140px; padding:10px 10px 0 0;'
    ' font-family:Arial,Helvetica,sans-serif; font-size:13px; line-height:18px;'
    ' color:#64748b;">{label}</td>'
    '<td valign="top" style="padding:10px 0 0 0;'
    ' font-family:Arial,Helvetica,sans-serif; font-size:14px; line-height:19px;'
    ' font-weight:bold; color:#1e293b;">{value}</td>'
    '</tr>\n')

ALERT_MAIL_BANNER = (
    '<tr><td bgcolor="#fef3c7" style="padding:10px 20px;'
    ' background-color:#fef3c7; border-bottom:1px solid #e2e8f0;'
    ' font-family:Arial,Helvetica,sans-serif; font-size:13px;'
    ' font-weight:bold; color:#856404;">{text}</td></tr>\n')

ALERT_MAIL_SUBTITLE = (
    '<tr><td style="padding:0 20px 16px 20px;'
    ' font-family:Arial,Helvetica,sans-serif; font-size:14px; line-height:20px;'
    ' color:#64748b;">{text}</td></tr>\n')

# The rail on the left of the message is a table cell and not a border: Outlook
# drops border-left on a block, and a coloured cell it cannot drop.
ALERT_MAIL_MESSAGE = (
    '<tr><td style="padding:0 20px 18px 20px;">\n'
    '<table role="presentation" border="0" cellpadding="0" cellspacing="0"'
    ' width="100%" style="border-collapse:collapse;">\n'
    '<tr>\n'
    '<td width="4" bgcolor="{severity_bg}" style="width:4px;'
    ' background-color:{severity_bg}; font-size:0; line-height:0;">&nbsp;</td>\n'
    '<td bgcolor="#f1f5f9" style="padding:12px 14px; background-color:#f1f5f9;'
    ' font-family:Arial,Helvetica,sans-serif; font-size:15px; line-height:22px;'
    ' color:#1e293b;">{text}</td>\n'
    '</tr>\n</table>\n</td></tr>\n')

# Nested table with the padding on the cell, not an inline-block: Word draws
# no padding on one.
ALERT_MAIL_ACTION = (
    '<tr><td style="padding:0 20px 20px 20px;">\n'
    '<table role="presentation" border="0" cellpadding="0" cellspacing="0"'
    ' style="border-collapse:collapse;">\n'
    '<tr><td bgcolor="#25607d" align="center" style="padding:11px 22px;'
    ' background-color:#25607d; border-radius:3px;">'
    '<a href="{url}" style="font-family:Arial,Helvetica,sans-serif;'
    ' font-size:14px; font-weight:bold; color:#ffffff;'
    ' text-decoration:none;">{label}</a>'
    '</td></tr>\n'
    '</table>\n</td></tr>\n')

ALERT_MAIL_FOOTER = ("Automatic message from Medulla Reflex. Do not reply: "
                     "notification channels and rules are set in the Medulla "
                     "console.")

ALERT_MAIL_FACTS = (
    '<tr><td style="padding:4px 20px 18px 20px;">\n'
    '<table role="presentation" border="0" cellpadding="0" cellspacing="0"'
    ' width="100%" style="border-collapse:collapse;'
    ' border-top:1px solid #e2e8f0;">\n'
    '{rows}'
    '</table>\n</td></tr>\n')

ALERT_MAIL_HTML = """<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
<meta http-equiv="Content-Type" content="text/html; charset=UTF-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>{title}</title>
</head>
<body style="margin:0; padding:0; background-color:#f8fafc;">
<div style="display:none; font-size:1px; color:#f8fafc; line-height:1px; max-height:0; max-width:0; opacity:0; overflow:hidden;">{preheader}</div>
<table role="presentation" border="0" cellpadding="0" cellspacing="0" width="100%" style="border-collapse:collapse; background-color:#f8fafc;">
<tr>
<td align="center" style="padding:16px 10px;">
<table role="presentation" border="0" cellpadding="0" cellspacing="0" width="600" style="width:100%; max-width:600px; border-collapse:collapse; background-color:#ffffff; border:1px solid #e2e8f0;">
<tr>
<td bgcolor="#25607d" style="padding:14px 20px; background-color:#25607d; font-family:Arial,Helvetica,sans-serif; font-size:15px; font-weight:bold; color:#ffffff;">Medulla Reflex</td>
</tr>
{banner}<tr><td style="padding:20px 20px 2px 20px;">
<table role="presentation" border="0" cellpadding="0" cellspacing="0" width="100%" style="border-collapse:collapse;">
<tr>
<td align="left" style="font-family:Arial,Helvetica,sans-serif; font-size:21px; line-height:27px; font-weight:bold; color:#1e293b;">{hostname}</td>
<td align="right" valign="middle">
<table role="presentation" border="0" cellpadding="0" cellspacing="0" align="right" style="border-collapse:collapse;">
<tr><td bgcolor="{severity_bg}" style="padding:4px 10px; background-color:{severity_bg}; border-radius:3px; font-family:Arial,Helvetica,sans-serif; font-size:11px; font-weight:bold; color:{severity_fg}; white-space:nowrap;">{severity}</td></tr>
</table>
</td>
</tr>
</table>
</td></tr>
{subtitle}{message}{facts}{action}<tr>
<td bgcolor="#1f2937" style="padding:12px 20px; background-color:#1f2937; font-family:Arial,Helvetica,sans-serif; font-size:12px; line-height:18px; color:#94a3b8;">
{footer}
</td>
</tr>
</table>
</td>
</tr>
</table>
</body>
</html>
"""


def _html(value):
    """Escape one value before it enters the markup, attributes included."""
    return html_escape(str(value if value is not None else ""), quote=True)


def severity_badge_colors(severity):
    """Background and text colour of one severity, as the console draws it."""
    return SEVERITY_BADGE_COLORS.get(str(severity or "").strip().lower(),
                                     SEVERITY_BADGE_UNKNOWN)


def alert_value_display(alert, language=None):
    """The measure that raised an alert, rendered as the console renders it.

    The type of the probe decides which column holds the value and how it is
    written, never the number itself: 1 is a percentage on one probe and a
    state on the next.
    """
    if is_boolean_type(alert.get("value_type")):
        return boolean_text(alert.get("value_at_trigger"), language)
    text_value = alert.get("value_text_at_trigger")
    if (text_value is not None
            and measure_instance(text_value,
                                 alert.get("value_type")) is None
            and str(text_value).strip()):
        # Not the instance, so it is the value: a text probe.
        return str(text_value).strip()
    if _to_float(alert.get("value_at_trigger")) is None:
        return ""
    unit = str(alert.get("unit") or "").strip()
    if unit.lower() == "s":
        return format_duration(alert.get("value_at_trigger"), language)
    return ("%s %s" % (format_number(alert.get("value_at_trigger"), language),
                       unit_label(unit, language))).strip()


def alert_threshold_display(alert, language=None):
    """The threshold the measure was compared to, empty when there is none.

    Written like the measure above it, so both numbers carry the same decimal
    mark on the same line.
    """
    threshold = alert.get("threshold_value")
    if threshold is None:
        return str(alert.get("threshold_text") or "").strip()
    if is_boolean_type(alert.get("value_type")):
        return boolean_text(threshold, language)
    unit = str(alert.get("unit") or "").strip()
    if unit.lower() == "s":
        return format_duration(threshold, language)
    number = format_number(threshold, language)
    return (("%s %s" % (number, unit_label(unit, language))).strip()
            if number else "")


def alert_detail_display(alert):
    """What the measure that raised an alert carried besides its number.

    One line per entry of a detail listing them, the text itself when it is
    free text, nothing at all otherwise: an alert opened before the column
    existed carries NULL for good, and no mail invents what it held.
    """
    detail = (alert or {}).get("detail_at_trigger")
    items = detail_items(detail)
    if items:
        return items
    detail = str(detail or "").strip()
    return [detail] if detail else []


def alert_opened_display(alert, language=None):
    """When an alert opened, and for how long it has been open since.

    Day first outside English.
    """
    code = str(language or "").strip().lower()
    shape = ("%Y-%m-%d %H:%M" if not code or code.startswith("en")
             else "%d/%m/%Y %H:%M")
    moment = parse_moment(alert.get("opened_at"))
    if moment is None:
        return (datetime.now().strftime(shape), "")
    elapsed = (datetime.now() - moment).total_seconds()
    return (moment.strftime(shape),
            format_duration(elapsed, language) if elapsed > 0 else "")


def render_alert_html(alert, escalation=False, console_url="", language=None):
    """The HTML half of the mail one alert sends.

    Everything coming from the database or from a machine is escaped before it
    enters the markup. Every block but the machine name is optional, console
    button included: what is missing is left out and the mail leaves.
    """
    alert = alert or {}
    severity = str(alert.get("severity") or "").strip()
    severity_bg, severity_fg = severity_badge_colors(severity)
    severity_word = severity_label(severity, language)
    hostname = str(alert.get("hostname") or "").strip()
    message = str(alert.get("message") or "").strip()
    probe = translate(
        str(alert.get("probe_label") or alert.get("probe_key") or "").strip(),
        language)
    instance = str(alert.get("instance") or "").strip()

    subtitle = _html(probe)
    if instance:
        # The volume or the port the probe fanned out over, in the heading:
        # "a disk is full" has to say which one.
        marker = ('<span style="color:#1e293b; font-weight:bold;">%s</span>'
                  % _html(instance))
        subtitle = ("%s &#183; %s" % (subtitle, marker)) if subtitle else marker

    rows = []
    value = alert_value_display(alert, language)
    if value:
        rows.append(ALERT_MAIL_FACT.format(
            label=_html(translate("Measured value", language)),
            value=_html(value)))
    threshold = alert_threshold_display(alert, language)
    if threshold:
        rows.append(ALERT_MAIL_FACT.format(
            label=_html(translate("Threshold", language)),
            value=_html(threshold)))
    detail = alert_detail_display(alert)
    if detail:
        # What the number counts, which the number alone never says: "1" is a
        # service, and the mail names it.
        rows.append(ALERT_MAIL_FACT.format(
            label=_html(translate("Detail", language)),
            value="<br />".join(_html(line) for line in detail)))
    opened_at, elapsed = alert_opened_display(alert, language)
    opened = _html(opened_at)
    if elapsed:
        opened += ('<span style="font-weight:normal; color:#64748b;">'
                   ' &#183; %s</span>'
                   % _html(translate_format("open for %s", elapsed, language)))
    rows.append(ALERT_MAIL_FACT.format(
        label=_html(translate("Opened at", language)), value=opened))

    banner = ""
    if escalation:
        banner = ALERT_MAIL_BANNER.format(
            text=_html(translate("Alert not acknowledged, second notice.",
                                 language)))

    return ALERT_MAIL_HTML.format(
        title=_html("Medulla Reflex - %s - %s" % (severity_word, hostname)),
        preheader=_html((message or probe)[:160]),
        severity=_html(severity_word.upper() or translate("Alert", language)
                       .upper()),
        severity_bg=severity_bg,
        severity_fg=severity_fg,
        banner=banner,
        hostname=_html(hostname) or "&#8212;",
        subtitle=(ALERT_MAIL_SUBTITLE.format(text=subtitle)
                  if subtitle else ""),
        message=(ALERT_MAIL_MESSAGE.format(text=_html(message),
                                           severity_bg=severity_bg)
                 if message else ""),
        facts=ALERT_MAIL_FACTS.format(rows="".join(rows)),
        action=(ALERT_MAIL_ACTION.format(
            url=_html(console_url),
            label=_html(translate("Open in the Medulla console", language)))
            if console_url else ""),
        footer=_html(translate(ALERT_MAIL_FOOTER, language)))


DEFAULT_MAX_LOOKBACK = 3600


# =============================================================================
# Backend
# =============================================================================
class ReflexBackend(object):
    """Singleton holding the reflex connection and the evaluation logic."""

    _instance = None
    is_activated = False

    def __new__(cls, *args, **kwargs):
        if cls._instance is None:
            cls._instance = super(ReflexBackend, cls).__new__(cls)
        return cls._instance

    def __init__(self):
        if not hasattr(self, "_initialised"):
            self.database = None
            self.config = None
            self.settings = {}
            self._target_machines = {}
            self._target_groups = {}
            self._probe_intervals = {}
            self._probe_placements = {}
            # One line for a base that will not date the measures, not one per
            # report.
            self._local_time_warned = False
            self._max_lookback = None
            self._lookback_warned = False
            self._initialised = True

    # -------------------------------------------------------------------
    # Activation
    # -------------------------------------------------------------------
    def activate(self):
        """Open the reflex database, once, on first need."""
        if ReflexBackend.is_activated:
            return True
        try:
            from mmc.plugins.reflex.config import ReflexConfig
            from pulse2.database.reflex import ReflexDatabase
        except ImportError as error:
            logger.error(
                "reflex: the server side module is not installed here (%s). "
                "The reflex substitute stays idle." % error
            )
            return False

        try:
            self.config = ReflexConfig("reflex")
        except Exception as error:
            logger.error("reflex: %s unreadable (%s)" % (REFLEX_INI, error))
            return False

        if getattr(self.config, "disable", True):
            logger.info("reflex: module disabled by %s" % REFLEX_INI)
            return False

        self.database = ReflexDatabase()
        if not self.database.activate(self.config):
            logger.error("reflex: connection to the reflex database failed")
            return False

        ReflexBackend.is_activated = True
        logger.info("reflex: substitute backend connected")
        return True

    @property
    def engine(self):
        return self.database.db if self.database is not None else None

    def execute(self, sql, params=None):
        """Run a statement on the engine opened by the shared layer."""
        return self.engine.execute(text(sql), params or {})

    def select(self, sql, params=None):
        return _rows(self.execute(sql, params))

    def select_one(self, sql, params=None):
        rows = self.select(sql, params)
        return rows[0] if rows else None

    # -------------------------------------------------------------------
    # Retention and evaluation settings
    # -------------------------------------------------------------------
    def retention(self):
        """Horizons of the settings table, as purge_old_data applies them."""
        return {
            name: _to_int(self.database.setting("retention." + name), 0)
            for name in ("measures_days", "alerts_resolved_days",
                         "notification_history_days")
        }

    def max_lookback(self):
        """evaluation.max_lookback_seconds, read once per cycle."""
        if self._max_lookback is None:
            try:
                seconds = _to_int(self.database.setting(
                    "evaluation.max_lookback_seconds"), 0)
                if seconds <= 0:
                    raise ValueError("%r is not a duration" % seconds)
                self._max_lookback = seconds
                self._lookback_warned = False
            except Exception as error:
                if not self._lookback_warned:
                    self._lookback_warned = True
                    logger.warning(
                        "reflex: evaluation.max_lookback_seconds unreadable "
                        "(%s), %ds applied" % (error, DEFAULT_MAX_LOOKBACK))
                return DEFAULT_MAX_LOOKBACK
        return self._max_lookback

    def bounded_window(self, seconds):
        """A window of history, never wider than max_lookback_seconds."""
        return min(max(_to_int(seconds, 0), 0), self.max_lookback())

    def aes_key(self):
        return str(getattr(self.config, "keyAES32", "") or "")

    def console_alerts_url(self):
        """Address of the alert page of the console, "" when there is none.

        Never raises: the mail leaves without its link rather than not leaving.
        """
        reader = getattr(self.database, "console_alerts_url", None)
        if reader is None:
            return ""
        try:
            return str(reader() or "")
        except Exception as error:
            logger.debug(
                "reflex: console address unreadable (%s), the notification "
                "leaves without a link" % error)
            return ""

    # =====================================================================
    # Configuration distribution
    # =====================================================================
    def machine_config(self, machines_id, group_ids=None, entity_ids=None):
        """Probe configuration of a machine, with its version.

        The version is the fingerprint of what is sent, compared to
        sent_version.
        """
        probes = self.database.get_probe_config_for_machine(
            machines_id, group_ids=group_ids, entity_ids=entity_ids)
        payload = []
        for probe in probes or []:
            collectors = {}
            for collector in probe.get("collectors") or []:
                os_key = str(collector.get("os") or "")
                if not os_key:
                    continue
                collectors[os_key] = {
                    "collector": collector.get("collector"),
                    "params_json": collector.get("params_json"),
                    "requires": collector.get("requires"),
                }
            payload.append({
                "probe_id": _to_int(probe.get("probe_id"), 0),
                "probe_key": probe.get("probe_key"),
                "metric_key": probe.get("metric_key"),
                "unit": probe.get("unit"),
                "value_type": probe.get("value_type"),
                "os_support": probe.get("os_support"),
                "interval_seconds": _to_int(probe.get("interval_seconds"), 300),
                "collectors": collectors,
            })
        payload.sort(key=lambda item: str(item.get("probe_key") or ""))
        return (self.config_version(payload), payload)

    @staticmethod
    def config_version(payload):
        """Fingerprint of a configuration, stable for an unchanged content."""
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        return hashlib.sha1(canonical.encode("utf-8")).hexdigest()[:32]

    def agent_config_state(self, machines_id):
        return self.select_one(
            "SELECT machines_id, hostname, sent_version, sent_at, "
            "       acked_version, acked_at, probe_count, last_error "
            "  FROM probe_agent_config WHERE machines_id = :machines_id",
            {"machines_id": _to_int(machines_id, 0)})

    # =====================================================================
    # Measures
    # =====================================================================
    def probe_index(self):
        """probe_key and metric definition of every enabled probe."""
        rows = self.select(
            "SELECT id, probe_key, metric_key, unit, value_type "
            "  FROM probes WHERE enabled = 1")
        return dict((row["probe_key"], row) for row in rows)

    def probe_interval(self, probe_id, machine=None):
        """Cadence declared for a probe on one machine, in seconds.

        What was asked, not what happens: it sizes the first window read and
        the silence tolerated when the history is too short to show a cadence.
        The widest placement reaching the machine wins, an undecidable one
        counting as reaching it, so the window widens and never narrows. Cached
        for the cycle, per machine.
        """
        probe_id = _to_int(probe_id, 0)
        if isinstance(machine, dict):
            machine = dict(machine)
        else:
            machine = {"id": machine}
        machines_id = _to_int(machine.get("id"), 0)
        key = (probe_id, machines_id)
        if key not in self._probe_intervals:
            uuid = str(machine.get("uuid_inventorymachine") or "").strip() \
                or None
            entity_id = machine.get("entity_id")
            interval = 0
            placements = sorted(
                self.probe_placements(probe_id),
                key=lambda row: -_to_int(row.get("interval_seconds"), 0))
            for placement in placements:
                asked = _to_int(placement.get("interval_seconds"), 0)
                if asked <= 0:
                    break
                if machines_id <= 0 \
                        or self.placement_reaches(placement, machines_id,
                                                  uuid, entity_id) \
                        or self.placement_undecided(placement, machines_id,
                                                    uuid, entity_id):
                    interval = asked
                    break
            if interval <= 0:
                interval = self.declared_interval(probe_id)
            self._probe_intervals[key] = (
                interval if interval > 0 else DEFAULT_INTERVAL_SECONDS)
        return self._probe_intervals[key]

    def declared_interval(self, probe_id):
        """default_interval_seconds of a probe, 0 when there is none."""
        key = (probe_id, None)
        if key not in self._probe_intervals:
            interval = 0
            try:
                row = self.select_one(
                    "SELECT default_interval_seconds AS declared "
                    "  FROM probes WHERE id = :probe_id",
                    {"probe_id": probe_id}) or {}
                interval = _to_int(row.get("declared"), 0)
            except Exception as error:
                logger.warning("reflex: cadence of probe %s unreadable (%s)"
                               % (probe_id, error))
            self._probe_intervals[key] = interval
        return self._probe_intervals[key]

    def local_moments(self, epochs):
        """SQL text of instants, in the zone the database dates rows in.

        received_at is stamped by NOW(3), so the zone that matters is the one
        of the MySQL session, not of this process: FROM_UNIXTIME is asked to do
        the conversion. On failure the clock of this host answers, and says so.
        """
        wanted = sorted({int(epoch) for epoch in epochs if epoch is not None})
        resolved = {}
        for batch in _in_batches(wanted):
            columns = []
            params = {}
            for rank, epoch in enumerate(batch):
                columns.append("FROM_UNIXTIME(:epoch%d) AS m%d"
                               % (rank, rank))
                params["epoch%d" % rank] = epoch
            row = None
            try:
                row = self.select_one("SELECT " + ", ".join(columns), params)
            except Exception as error:
                if not self._local_time_warned:
                    self._local_time_warned = True
                    logger.warning(
                        "reflex: the database could not date the measures "
                        "received (%s). They are dated with the clock of this "
                        "server instead, which is only right if it shares the "
                        "time zone of the database." % error)
            for rank, epoch in enumerate(batch):
                resolved[epoch] = (normalise_datetime((row or {}).get(
                    "m%d" % rank)) or _host_moment(epoch))
        return resolved

    def collected_moments(self, measures):
        """What to write in collected_at, per distinct value of a batch.

        An agent declaring an offset dates an instant, converted into the zone
        of the base. One declaring none has its date taken as it comes. A date
        nobody can read stays unreadable and the base dates the row itself.
        """
        per_value = {}
        per_epoch = {}
        for measure in measures or []:
            if not isinstance(measure, dict):
                continue
            value = measure.get("collected_at")
            key = str(value)
            if key in per_value:
                continue
            epoch = moment_utc_epoch(value)
            if epoch is None:
                per_value[key] = normalise_datetime(value)
            else:
                per_value[key] = None
                per_epoch.setdefault(epoch, []).append(key)
        if per_epoch:
            local = self.local_moments(per_epoch.keys())
            for epoch, keys in per_epoch.items():
                for key in keys:
                    per_value[key] = local.get(epoch)
        return per_value

    def placed_probe_ids(self, machine, probe_ids):
        """Among these probes, those measured on this machine right now.

        Placed and not lifted by probe_exclusions. Nothing is cached: a probe
        placed a second ago must be measured a second later. A source that
        could not be read keeps the measure.
        """
        machine = machine or {}
        machines_id = _to_int(machine.get("id"), 0)
        wanted = sorted(set(_to_int(value, 0) for value in probe_ids or []
                            if _to_int(value, 0) > 0))
        if not wanted:
            return set()
        if machines_id <= 0:
            # No machine to judge the placements against.
            return set(wanted)

        fragment, probe_params = _placeholders("pid", wanted)
        try:
            placements = self.select(
                "SELECT probe_id, target_type, target_id "
                "  FROM probe_assignments "
                " WHERE probe_id IN (" + fragment + ")", dict(probe_params))
            lifted = set(
                _to_int(row.get("probe_id"), 0)
                for row in self.select(
                    "SELECT probe_id FROM probe_exclusions "
                    " WHERE machines_id = :machines_id "
                    "   AND probe_id IN (" + fragment + ")",
                    dict(probe_params, machines_id=machines_id)))
        except Exception as error:
            logger.warning(
                "reflex: the placements of %s could not be read (%s), its "
                "report is written as it arrived"
                % (machine.get("hostname") or machines_id, error))
            return set(wanted)

        uuid = str(machine.get("uuid_inventorymachine") or "").strip() or None
        entity_id = machine.get("entity_id")
        placed = set()
        for placement in sorted(placements, key=lambda row:
                                PLACEMENT_RESOLUTION_COST.get(
                                    str(row.get("target_type") or "").strip()
                                    .lower(), 9)):
            probe_id = _to_int(placement.get("probe_id"), 0)
            if probe_id in placed or probe_id in lifted:
                continue
            if self.placement_reaches(placement, machines_id, uuid,
                                      entity_id) \
                    or self.placement_undecided(placement, machines_id, uuid,
                                                entity_id):
                placed.add(probe_id)
        return placed

    def store_measures(self, machine, measures):
        """Write a batch of measures. Returns (written, probe ids touched).

        collected_at is declared by the machine, stored in the zone of the
        base; received_at is written on insert and is what freshness and
        duration are judged on. Only what the probe is placed to measure on
        this machine is written: an agent that has not been served its new
        configuration yet keeps reporting probes that were just removed.
        """
        collected = self.collected_moments(measures)
        index = self.probe_index()
        by_id = dict((_to_int(row["id"], 0), row) for row in index.values())
        candidates = []
        for measure in measures or []:
            if not isinstance(measure, dict):
                continue
            probe_id = _to_int(measure.get("probe_id"), 0)
            definition = by_id.get(probe_id)
            if definition is None:
                definition = index.get(str(measure.get("probe_key") or ""))
                probe_id = _to_int(definition.get("id"), 0) if definition else 0
            if probe_id <= 0 or definition is None:
                logger.warning(
                    "reflex: measure of an unknown probe ignored (%s)"
                    % measure.get("probe_key"))
                continue
            candidates.append((probe_id, definition, measure))

        if not candidates:
            return (0, [])

        # Resolved once for the whole report, then applied in memory.
        placed = self.placed_probe_ids(
            machine, set(probe_id for probe_id, _, _ in candidates))

        prepared = []
        touched = set()
        discarded = {}
        for probe_id, definition, measure in candidates:
            if probe_id not in placed:
                key = str(definition.get("probe_key") or probe_id)
                discarded[key] = discarded.get(key, 0) + 1
                continue

            value_type = str(definition.get("value_type") or "numeric").lower()
            value = measure.get("value")
            value_text = measure.get("value_text")
            if value_type == "text":
                if value_text is None:
                    value_text = None if value is None else str(value)
                value_num = None
            else:
                value_num = _to_float(value)
                if value_text is None and isinstance(value, str):
                    value_text = value

            status = str(measure.get("status") or "ok").lower()
            detail = storable_detail(measure.get("detail"))
            prepared.append({
                "machines_id": _to_int(machine.get("id"), 0),
                "uuid_inventorymachine": machine.get("uuid_inventorymachine"),
                "hostname": machine.get("hostname") or "",
                "probe_id": probe_id,
                "metric_key": (measure.get("metric_key")
                               or definition.get("metric_key")),
                "value_num": value_num,
                "value_text": value_text,
                "unit": measure.get("unit") or definition.get("unit"),
                "status": status,
                "detail": detail,
                "collected_at": collected.get(
                    str(measure.get("collected_at"))),
            })
            touched.add(probe_id)

        if discarded:
            # One line per report and not one per measure: a park catching up
            # on a configuration change would otherwise read as an incident.
            logger.info(
                "reflex: %d measure(s) from %s discarded, the probe is not "
                "placed on it: %s"
                % (sum(discarded.values()),
                   machine.get("hostname") or machine.get("id"),
                   ", ".join("%s x%d" % (key, count)
                             for key, count in sorted(discarded.items()))))

        if not prepared:
            return (0, [])
        written = self.database.record_measures(prepared)
        return (written, sorted(touched))

    # =====================================================================
    # Condition evaluation
    # =====================================================================
    def conditions_of(self, probe_ids, entity_id=None):
        """Conditions of these probes, as one estate applies them.

        Two levels, column by column: the setting the estate holds in
        probe_condition_overrides, else the value the product ships in
        default_<field>. Keyed by (probe_id, entity_id): one condition is two
        settings for two estates. An estate that could not be read falls back
        on the shipped values, never on the setting of another.
        """
        if not probe_ids:
            return {}
        fragment, params = _placeholders("probe", [_to_int(p, 0)
                                                   for p in probe_ids])
        entity = entity_identifier(entity_id)
        # entity_id is a varchar on both sides: 0 is the root entity of GLPI
        # and matches the row written against '0'.
        params["entity"] = None if entity is None else str(entity)
        rows = self.select(
            "SELECT c.id, c.probe_id, c.operator, "
            "       COALESCE(pco.threshold_value, c.default_threshold_value)"
            "              AS threshold_value, "
            "       COALESCE(pco.threshold_value2, c.default_threshold_value2)"
            "              AS threshold_value2, "
            "       COALESCE(pco.threshold_text, c.default_threshold_text)"
            "              AS threshold_text, "
            "       COALESCE(pco.duration_seconds, c.default_duration_seconds)"
            "              AS duration_seconds, "
            "       COALESCE(pco.severity, c.default_severity) AS severity, "
            "       COALESCE(pco.message_template, c.default_message_template)"
            "              AS message_template, "
            "       p.probe_key, p.label, p.value_type, p.unit "
            "  FROM probe_conditions c "
            "  JOIN probes p ON p.id = c.probe_id "
            "  LEFT JOIN probe_condition_overrides pco "
            "         ON pco.condition_id = c.id "
            "        AND pco.entity_id = :entity "
            " WHERE COALESCE(pco.enabled, c.default_enabled) = 1 "
            "   AND p.enabled = 1 "
            "   AND c.probe_id IN (" + fragment + ") "
            " ORDER BY c.probe_id ASC, c.display_order ASC", params)
        grouped = {}
        for row in rows:
            grouped.setdefault((_to_int(row["probe_id"], 0), entity),
                               []).append(row)
        return grouped

    @staticmethod
    def condition_holds(condition, value_num, value_text, previous_text=None):
        """Whether one measure satisfies one condition.

        Returns None when the comparison cannot be made, which is not the same
        as false: an unusable measure must not resolve an alert.
        """
        operator = str(condition.get("operator") or "").lower()
        threshold = _to_float(condition.get("threshold_value"))
        threshold2 = _to_float(condition.get("threshold_value2"))
        threshold_text = condition.get("threshold_text")

        if operator == "changed":
            if value_text is None and value_num is None:
                return None
            current = value_text if value_text is not None else str(value_num)
            if previous_text is None:
                return False
            return str(current) != str(previous_text)

        if operator in ("eq", "ne") and threshold_text not in (None, ""):
            if value_text is None:
                return None
            equal = str(value_text).strip() == str(threshold_text).strip()
            return equal if operator == "eq" else not equal

        if value_num is None:
            return None
        if operator == "gt":
            return threshold is not None and value_num > threshold
        if operator == "gte":
            return threshold is not None and value_num >= threshold
        if operator == "lt":
            return threshold is not None and value_num < threshold
        if operator == "lte":
            return threshold is not None and value_num <= threshold
        if operator == "eq":
            return threshold is not None and value_num == threshold
        if operator == "ne":
            return threshold is not None and value_num != threshold
        if operator == "between":
            if threshold is None or threshold2 is None:
                return None
            return threshold <= value_num <= threshold2
        if operator == "outside":
            if threshold is None or threshold2 is None:
                return None
            return value_num < threshold or value_num > threshold2
        return None

    def _window_measures(self, machines_id, probe_id, seconds, instance=None):
        """Measures of a probe on a machine over a window, newest first.

        The window is cut on received_at, written by the server, because :since
        comes from the server clock; collected_at carries the drift of the
        reporting machine. `instance` narrows it to one series, which
        _streak_coverage has to walk alone: interleaved, two volumes break each
        other's streak.
        """
        seconds = self.bounded_window(seconds)
        params = {"machines_id": _to_int(machines_id, 0),
                  "probe_id": _to_int(probe_id, 0),
                  "since": datetime.now() - timedelta(seconds=seconds + 1)}
        restriction = _instance_clause(params, instance, "value_text")
        return self.select(
            "SELECT value_num, value_text, status, received_at "
            "  FROM probe_measures "
            " WHERE machines_id = :machines_id AND probe_id = :probe_id "
            "   AND received_at >= :since " + restriction +
            " ORDER BY received_at DESC", params)

    def _streak_coverage(self, condition, measures, declared_interval):
        """What the unbroken streak of a condition proves, newest first.

        Walked back from the most recent measure, stopping at the first measure
        that breaks the condition, the first unusable one, and the first
        silence too long to be a missed report.

        Returns (covered, streak, exhausted, gap_limit).
        """
        moments = []
        for measure in measures:
            moment = parse_moment(measure.get("received_at"))
            if moment is None:
                break
            moments.append(moment)

        # The tolerated silence follows the cadence the measures show, not the
        # one the assignment declares: a slow collector would cut every streak.
        step = observed_step(moments, declared_interval)
        gap_limit = max(step,
                        float(max(_to_int(declared_interval, 0), 1))) \
            * MISSED_REPORTS_ALLOWED

        oldest = None
        streak = 0
        for index, measure in enumerate(measures):
            if index >= len(moments):
                break
            if str(measure.get("status") or "ok") == "unavailable":
                break
            if oldest is not None and \
                    (oldest - moments[index]).total_seconds() > gap_limit:
                break
            previous_text = _previous_text(
                measures[index + 1] if index + 1 < len(measures) else None)
            holds = self.condition_holds(
                condition, _to_float(measure.get("value_num")),
                measure.get("value_text"), previous_text)
            if not holds:
                break
            oldest = moments[index]
            streak += 1

        covered = ((datetime.now() - oldest).total_seconds()
                   if oldest is not None else 0.0)
        exhausted = streak > 0 and streak == len(measures)
        return (covered, streak, exhausted, gap_limit)

    def judgement_span(self, condition, probe_id, machine=None):
        """Seconds of history a condition is judged over, in one place.

        The duration asked plus one declared cadence, capped by
        max_lookback_seconds. The opening proves itself over it and the sweep
        of the stale alerts re-judges over it.
        """
        return min(_to_int(condition.get("duration_seconds"), 0)
                   + self.probe_interval(probe_id, machine) + 1,
                   self.max_lookback())

    def _held_continuously(self, condition, machine, probe_id,
                           detail=None, instance=None):
        """Whether a condition held without interruption over its duration.

        The size of the read must not decide the verdict: when the streak runs
        to the edge of the first window, the question is asked again as far back
        as max_lookback_seconds allows.
        """
        if detail is None:
            detail = {}
        if not isinstance(machine, dict):
            machine = {"id": machine}
        machines_id = machine.get("id")
        duration = _to_int(condition.get("duration_seconds"), 0)
        interval = self.probe_interval(probe_id, machine)
        detail.update({"window": 0, "streak": 0, "covered": 0.0,
                       "interval": interval, "required": 0.0,
                       "widened": False})
        if duration <= 0:
            return True

        # The coverage required is the duration, exactly: received_at is dated
        # to the millisecond, so there is no storage imprecision to forgive.
        required = float(duration)
        detail["required"] = required

        ceiling = self.max_lookback()
        span = self.judgement_span(condition, probe_id, machine)
        measures = self._window_measures(machines_id, probe_id, span, instance)
        covered, streak, exhausted, gap = self._streak_coverage(
            condition, measures, interval)
        if covered < required and exhausted and span < ceiling:
            measures = self._window_measures(machines_id, probe_id, ceiling,
                                             instance)
            covered, streak, exhausted, gap = self._streak_coverage(
                condition, measures, interval)
            detail["widened"] = True

        detail.update({"window": len(measures), "streak": streak,
                       "covered": covered, "gap_limit": gap})
        return covered >= required

    @staticmethod
    def _representative(condition, measures):
        """The measure of one series a condition is judged on.

        When a batch carries one instance twice, the measure kept is the one
        that would raise the alert: the highest for an upper bound, the lowest
        for a lower one.
        """
        operator = str(condition.get("operator") or "").lower()
        numeric = [m for m in measures if _to_float(m.get("value")) is not None]
        if not numeric:
            return measures[0] if measures else None
        if operator in ("lt", "lte"):
            return min(numeric, key=lambda m: _to_float(m.get("value")))
        return max(numeric, key=lambda m: _to_float(m.get("value")))

    @staticmethod
    def _measure_text(measure):
        """value_text of a batch measure, the way store_measures writes it."""
        value_text = measure.get("value_text")
        if value_text is None and isinstance(measure.get("value"), str):
            value_text = measure.get("value")
        return value_text

    @classmethod
    def _series_of(cls, condition, measures):
        """Split a batch into the series a condition has to be judged on.

        A probe reporting several mount points sends one measure per volume,
        and each is a series of its own. Pairs (instance, measures), in a
        stable order; instance is None on a probe reporting a single value and
        on a text probe, measure_instance deciding that here as everywhere
        else.
        """
        value_type = condition.get("value_type")
        series = {}
        for measure in measures:
            instance = measure_instance(cls._measure_text(measure), value_type)
            series.setdefault(instance, []).append(measure)
        return sorted(series.items(), key=lambda item: item[0] or "")

    def evaluate(self, machine, probe_ids, batch):
        """Evaluate every condition of the probes carried by a batch.

        One verdict per condition and per instance, judged on the conditions of
        the estate of this machine. Returns the alerts opened, so the caller
        can notify them once.
        """
        self.reset_target_cache()
        opened = []
        grouped = {}
        for measure in batch or []:
            probe_id = _to_int(measure.get("probe_id"), 0)
            grouped.setdefault(probe_id, []).append(measure)

        entity_id = self.machine_entity(machine)
        for (probe_id, _), conditions in self.conditions_of(
                probe_ids, entity_id).items():
            measures = grouped.get(probe_id) or []
            usable = [m for m in measures
                      if str(m.get("status") or "ok") not in ("unavailable",
                                                              "error")]
            for condition in by_gravity(conditions):
                operator = str(condition.get("operator") or "").lower()
                if operator not in BATCH_OPERATORS:
                    continue
                if not usable:
                    # An unavailable measure decides nothing.
                    continue
                # Grouped over every measure and not over the usable ones: an
                # instance whose measure failed this turn still exists.
                series = self._series_of(condition, measures)
                reported = set(instance for instance, _ in series)

                for instance, rows in series:
                    fit = [m for m in rows
                           if str(m.get("status") or "ok")
                           not in ("unavailable", "error")]
                    if not fit:
                        continue
                    representative = self._representative(condition, fit)
                    if representative is None:
                        continue
                    value_num = _to_float(representative.get("value"))
                    value_text = self._measure_text(representative)

                    previous = None
                    if operator == "changed":
                        previous = self._previous_value(machine, probe_id,
                                                        instance)
                    holds = self.condition_holds(condition, value_num,
                                                 value_text, previous)
                    if holds is None:
                        continue
                    detail = {"window": 0, "streak": 0, "covered": 0.0,
                              "required": 0.0, "widened": False,
                              "interval": self.probe_interval(probe_id,
                                                              machine)}
                    if holds:
                        holds = self._held_continuously(
                            condition, machine, probe_id,
                            detail=detail, instance=instance)

                    # Without this line, a condition that never reaches its
                    # coverage looks like a condition nobody evaluated.
                    logger.debug(
                        "reflex: %s cond=%s instance=%s %s value=%s "
                        "threshold=%s duration=%ss interval=%ss holds=%s "
                        "window=%d measure(s) streak=%d covered=%.1fs "
                        "required=%.1fs widened=%s on %s"
                        % (condition.get("probe_key"), condition.get("id"),
                           instance or "-", operator,
                           value_num if value_num is not None else value_text,
                           condition.get("threshold_value"),
                           _to_int(condition.get("duration_seconds"), 0),
                           detail.get("interval"), bool(holds),
                           _to_int(detail.get("window"), 0),
                           _to_int(detail.get("streak"), 0),
                           detail.get("covered") or 0.0,
                           detail.get("required") or 0.0,
                           bool(detail.get("widened")),
                           machine.get("hostname")))

                    alert = self.apply_condition(
                        machine, condition, holds, value_num, value_text,
                        detail=representative.get("detail"))
                    if alert:
                        opened.append(alert)

                self._resolve_unreported_instances(machine, condition,
                                                   reported)
        superseded = set()
        for alert in opened:
            superseded.update(alert.get("superseded") or [])
        return [alert for alert in opened
                if _to_int(alert.get("id"), 0) not in superseded]

    def _resolve_unreported_instances(self, machine, condition, reported):
        """Close the alerts of the instances a probe no longer reports.

        A volume that was unmounted stops being measured, and the resolution
        runs on incoming measures: nothing else would ever close its alert.
        Closed without a reason, like a return under the threshold.
        """
        if not any(instance is not None for instance in reported):
            return
        probe_id = _to_int(condition.get("probe_id"), 0)
        condition_id = _to_int(condition.get("id"), 0)
        machines_id = _to_int(machine.get("id"), 0)
        rows = self.select(
            "SELECT id, value_text_at_trigger FROM alerts "
            " WHERE probe_id = :probe_id AND condition_id = :condition_id "
            "   AND machines_id = :machines_id AND status IN ('open','ack')",
            {"probe_id": probe_id, "condition_id": condition_id,
             "machines_id": machines_id})
        for row in rows:
            instance = measure_instance(row.get("value_text_at_trigger"),
                                        condition.get("value_type"))
            if instance in reported:
                continue
            self.resolve_alert(row.get("id"))
            logger.info("reflex: alert %s resolved on %s, %s is no longer "
                        "reported" % (row.get("id"), machine.get("hostname"),
                                      instance))

    def _previous_value(self, machine, probe_id, instance=None):
        """Value before the last one, for the changed operator.

        Read on the series of the instance when the probe names one, or the
        measure before the last one would be another volume.
        """
        params = {"machines_id": _to_int(machine.get("id"), 0),
                  "probe_id": _to_int(probe_id, 0)}
        restriction = _instance_clause(params, instance, "value_text")
        rows = self.select(
            "SELECT value_num, value_text FROM probe_measures "
            " WHERE machines_id = :machines_id AND probe_id = :probe_id "
            + restriction +
            " ORDER BY id DESC LIMIT 1 OFFSET 1", params)
        if not rows:
            return None
        row = rows[0]
        if row.get("value_text") is not None:
            return str(row["value_text"])
        if row.get("value_num") is not None:
            return str(row["value_num"])
        return None

    # =====================================================================
    # Alert lifecycle
    # =====================================================================
    def open_alert_of(self, probe_id, condition_id, machines_id,
                      instance=None):
        """The alert this condition already stands on, None when there is none.

        The instance is part of the identity and is stored in
        value_text_at_trigger, the column measure_instance reads on an alert. A
        probe reporting a single value passes None and the clause is left out.
        """
        params = {"probe_id": _to_int(probe_id, 0),
                  "condition_id": _to_int(condition_id, 0),
                  "machines_id": _to_int(machines_id, 0)}
        restriction = _instance_clause(params, instance,
                                       "value_text_at_trigger")
        return self.select_one(
            "SELECT id, severity, status, occurrence_count, opened_at, "
            "       message, hostname "
            "  FROM alerts "
            " WHERE probe_id = :probe_id AND machines_id = :machines_id "
            "   AND condition_id = :condition_id AND status IN ('open','ack') "
            + restriction +
            " ORDER BY id DESC LIMIT 1", params)

    def standing_alerts_on(self, probe_id, machines_id, instance=None):
        """Every alert standing on one machine, probe and instance.

        The watched object, whatever condition raised the alert: this is what
        keeps one alert per object, the most serious.
        """
        params = {"probe_id": _to_int(probe_id, 0),
                  "machines_id": _to_int(machines_id, 0)}
        restriction = _instance_clause(params, instance,
                                       "value_text_at_trigger")
        return self.select(
            "SELECT id, condition_id, severity, status "
            "  FROM alerts "
            " WHERE probe_id = :probe_id AND machines_id = :machines_id "
            "   AND status IN ('open','ack') " + restriction, params)

    @staticmethod
    def render_message(condition, machine, value_num, value_text,
                       language=None):
        """Fill the template of a condition. Variables only, never code.

        The template is translated BEFORE its variables are substituted: once
        @@value@@ has become 100 the string is in no catalogue.
        """
        template = condition.get("message_template")
        if template:
            template = translate(template, language)
        else:
            # A pattern and not a concatenation, so that a language free to put
            # the machine first can.
            template = translate_format(
                "%s on @@machine@@",
                translate(condition.get("label") or "Alert", language),
                language)
        unit = str(condition.get("unit") or "").strip().lower()
        value_type = condition.get("value_type")
        instance = measure_instance(value_text, value_type)
        if (instance is None and value_text is not None
                and str(value_text).strip()):
            value = str(value_text)
        elif is_boolean_type(value_type):
            # A yes/no probe, worded as the console words it.
            value = boolean_text(value_num, language)
        elif value_num is not None:
            value = (format_duration(value_num, language) if unit == "s"
                     else format_number(value_num, language))
        else:
            # A numeric probe with no number: the instance is not a fallback.
            value = ""
        threshold = condition.get("threshold_value")
        if threshold is None:
            threshold = condition.get("threshold_text") or ""
        elif is_boolean_type(value_type):
            threshold = boolean_text(threshold, language)
        elif unit == "s":
            threshold = format_duration(threshold, language)
        else:
            threshold = format_number(threshold, language)
        rendered = str(template)
        rendered = rendered.replace("@@machine@@",
                                    str(machine.get("hostname") or ""))
        rendered = rendered.replace("@@value@@", value)
        rendered = rendered.replace("@@threshold@@", str(threshold))
        rendered = rendered.replace("@@instance@@", str(instance or ""))
        # A variable resolving to nothing leaves the spaces that framed it.
        # Horizontal runs only: a template is free to carry a line break.
        rendered = re.sub(r"[ \t]{2,}", " ", rendered).strip()
        return rendered[:512]

    def apply_condition(self, machine, condition, holds, value_num, value_text,
                        detail=None):
        """Turn the verdict of a condition into an alert movement.

        Four cases: nothing, opening, confirmation, resolution. One alert stands
        per machine, probe and instance, the most serious; equal severities
        leave each other alone.
        """
        machines_id = _to_int(machine.get("id"), 0)
        probe_id = _to_int(condition.get("probe_id"), 0)
        condition_id = _to_int(condition.get("id"), 0)
        operator = str(condition.get("operator") or "").strip().lower()
        instance = measure_instance(value_text, condition.get("value_type"))
        existing = self.open_alert_of(probe_id, condition_id, machines_id,
                                      instance)

        if not holds:
            # A thresholdless operator states an event, not a state: it is
            # false again at the very next measure, and closing on that would
            # take the alert off the console before anyone read it. Such an
            # alert waits for a hand, here or on another resolution reason.
            if existing and operator not in THRESHOLDLESS_OPERATORS:
                self.resolve_alert(existing["id"])
                logger.info("reflex: alert %s resolved on %s"
                            % (existing["id"], machine.get("hostname")))
            return None

        severity = str(condition.get("severity") or "medium").lower()
        rank = severity_rank(existing["severity"] if existing else severity)
        others = [row for row in self.standing_alerts_on(probe_id, machines_id,
                                                         instance)
                  if _to_int(row.get("condition_id"), 0) != condition_id]
        graver = [row for row in others
                  if severity_rank(row.get("severity")) > rank]
        if graver:
            if existing:
                self.resolve_alert(existing["id"], ALERT_RESOLVED_SUPERSEDED)
                logger.info("reflex: alert %s on %s superseded by alert %s"
                            % (existing["id"], machine.get("hostname"),
                               graver[0].get("id")))
            return None

        if existing:
            self.execute(
                "UPDATE alerts SET last_seen_at = NOW(), "
                "       occurrence_count = occurrence_count + 1 "
                " WHERE id = :alert_id", {"alert_id": existing["id"]})
            return None

        # Composed once and kept, in the language of the placement that governs
        # this probe on this machine: the console displays this very message
        # and a second notice repeats it word for word.
        message = self.render_message(condition, machine, value_num,
                                      value_text,
                                      self.placement_language(probe_id,
                                                              machine))
        params = {
            "probe_id": probe_id,
            "condition_id": condition_id,
            "machines_id": machines_id,
            "uuid_inventorymachine": machine.get("uuid_inventorymachine"),
            "hostname": (machine.get("hostname") or "")[:255],
            "severity": severity,
            "value_at_trigger": value_num,
            "value_text_at_trigger": (str(value_text)[:512]
                                      if value_text is not None else None),
            # What the triggering measure carried, frozen like the rest of the
            # _at_trigger columns: the machine page tells what is true now.
            "detail_at_trigger": storable_detail(detail),
            "message": message,
            # The condition as it stands at this instant, copied onto the
            # alert: condition_id only points at the row of today.
            "operator_at_trigger": (str(condition.get("operator") or "").strip()
                                    or None),
            "threshold_value_at_trigger": condition.get("threshold_value"),
            "threshold_value2_at_trigger": condition.get("threshold_value2"),
            "threshold_text_at_trigger": condition.get("threshold_text"),
            "duration_seconds_at_trigger": condition.get("duration_seconds"),
        }
        try:
            result = self.execute(
                "INSERT INTO alerts (probe_id, condition_id, machines_id, "
                "  uuid_inventorymachine, hostname, severity, status, "
                "  value_at_trigger, value_text_at_trigger, "
                "  detail_at_trigger, message, "
                "  operator_at_trigger, threshold_value_at_trigger, "
                "  threshold_value2_at_trigger, threshold_text_at_trigger, "
                "  duration_seconds_at_trigger, "
                "  opened_at, last_seen_at, occurrence_count) "
                "VALUES (:probe_id, :condition_id, :machines_id, "
                "  :uuid_inventorymachine, :hostname, :severity, 'open', "
                "  :value_at_trigger, :value_text_at_trigger, "
                "  :detail_at_trigger, :message, "
                "  :operator_at_trigger, :threshold_value_at_trigger, "
                "  :threshold_value2_at_trigger, :threshold_text_at_trigger, "
                "  :duration_seconds_at_trigger, "
                "  NOW(), NOW(), 1)", params)
        except Exception as error:
            logger.error("reflex: alert could not be opened: %s" % error)
            return None

        alert_id = _to_int(getattr(result, "lastrowid", 0), 0)
        logger.info("reflex: alert %s opened on %s: %s"
                    % (alert_id, machine.get("hostname"), message))

        milder = [_to_int(row.get("id"), 0) for row in others
                  if severity_rank(row.get("severity")) < rank]
        superseded = []
        if milder:
            # Closed without notification: nothing is sent on a resolution.
            if self.resolve_alerts(milder, ALERT_RESOLVED_SUPERSEDED):
                superseded = milder
                logger.info("reflex: alert(s) %s on %s superseded by alert %s"
                            % (", ".join(str(i) for i in milder),
                               machine.get("hostname"), alert_id))

        return {
            "id": alert_id,
            "probe_id": probe_id,
            "condition_id": condition_id,
            "machines_id": machines_id,
            "uuid_inventorymachine": machine.get("uuid_inventorymachine"),
            "entity_id": machine.get("entity_id"),
            "hostname": machine.get("hostname"),
            "severity": params["severity"],
            "message": message,
            "instance": instance,
            "probe_key": condition.get("probe_key"),
            "probe_label": condition.get("label"),
            # What the mail states beside the rendered message, carried raw: a
            # template is free never to quote either.
            "unit": condition.get("unit"),
            "value_type": condition.get("value_type"),
            "value_at_trigger": value_num,
            "value_text_at_trigger": params["value_text_at_trigger"],
            "detail_at_trigger": params["detail_at_trigger"],
            "threshold_value": condition.get("threshold_value"),
            "threshold_text": condition.get("threshold_text"),
            "superseded": superseded,
        }

    def resolve_alert(self, alert_id, reason=None):
        """Close one alert. reason stays NULL on a return under threshold."""
        self.execute(
            "UPDATE alerts SET status = 'resolved', resolved_at = NOW(), "
            "       resolved_reason = :reason "
            " WHERE id = :alert_id AND status IN ('open','ack')",
            {"alert_id": _to_int(alert_id, 0), "reason": reason})

    def resolve_alerts(self, alert_ids, reason):
        """Close a batch of alerts under one reason, returns how many moved.

        The status clause is kept even though the identifiers were just read
        open: a measure may have closed one in between, and re-closing it would
        overwrite the reason it closed for.
        """
        ids = sorted(set(_to_int(identifier, 0)
                         for identifier in alert_ids or []))
        ids = [identifier for identifier in ids if identifier > 0]
        moved = 0
        for batch in _in_batches(ids):
            fragment, params = _placeholders("alert", batch)
            params["reason"] = reason
            result = self.execute(
                "UPDATE alerts SET status = 'resolved', resolved_at = NOW(), "
                "       resolved_reason = :reason "
                " WHERE id IN (" + fragment + ") "
                "   AND status IN ('open','ack')", params)
            moved += _to_int(getattr(result, "rowcount", 0), 0)
        return moved

    # -------------------------------------------------------------------
    # Alerts their rule no longer accounts for
    # -------------------------------------------------------------------
    def stale_alerts(self):
        """Standing alerts whose condition is gone, switched off, or moved.

        <=> and not =: an operator with no second bound puts a NULL on one side,
        where = answers NULL and would hide the change. c.id IS NULL covers a
        deleted condition, alerts having no foreign key on condition_id.
        """
        return self.select(
            "SELECT a.id, a.probe_id, a.condition_id, a.machines_id, "
            "       a.hostname, a.severity, a.opened_at, "
            "       a.operator_at_trigger, a.threshold_value_at_trigger, "
            "       a.threshold_value2_at_trigger, "
            "       a.threshold_text_at_trigger, "
            "       a.duration_seconds_at_trigger, "
            "       c.id AS current_condition_id, c.operator, "
            "       COALESCE(pco.threshold_value, c.default_threshold_value)"
            "              AS threshold_value, "
            "       COALESCE(pco.threshold_value2, c.default_threshold_value2)"
            "              AS threshold_value2, "
            "       COALESCE(pco.threshold_text, c.default_threshold_text)"
            "              AS threshold_text, "
            "       COALESCE(pco.duration_seconds, c.default_duration_seconds)"
            "              AS duration_seconds, "
            "       COALESCE(pco.enabled, c.default_enabled) "
            "              AS condition_enabled, "
            "       COALESCE(p.enabled, 0) AS probe_enabled, p.probe_key, "
            "       xm.uuid_inventorymachine, xe.glpi_id AS entity_id "
            "  FROM alerts a "
            "  LEFT JOIN probe_conditions c ON c.id = a.condition_id "
            "  LEFT JOIN probes p ON p.id = a.probe_id "
            "  LEFT JOIN xmppmaster.machines xm ON xm.id = a.machines_id "
            "  LEFT JOIN xmppmaster.glpi_entity xe "
            "         ON xe.id = xm.glpi_entity_id "
            "  LEFT JOIN probe_condition_overrides pco "
            "         ON pco.condition_id = c.id "
            "        AND pco.entity_id = CAST(xe.glpi_id AS CHAR) "
            " WHERE a.status IN ('open','ack') "
            "   AND (c.id IS NULL "
            "        OR COALESCE(pco.enabled, c.default_enabled) = 0 "
            "        OR COALESCE(p.enabled, 0) = 0 "
            "        OR (a.operator_at_trigger IS NOT NULL "
            "            AND NOT (a.operator_at_trigger <=> c.operator "
            "                 AND a.threshold_value_at_trigger <=> "
            "                     COALESCE(pco.threshold_value, "
            "                              c.default_threshold_value) "
            "                 AND a.threshold_value2_at_trigger <=> "
            "                     COALESCE(pco.threshold_value2, "
            "                              c.default_threshold_value2) "
            "                 AND a.threshold_text_at_trigger <=> "
            "                     COALESCE(pco.threshold_text, "
            "                              c.default_threshold_text) "
            "                 AND a.duration_seconds_at_trigger <=> "
            "                     COALESCE(pco.duration_seconds, "
            "                              c.default_duration_seconds)))) "
            " ORDER BY a.probe_id ASC, a.machines_id ASC, a.id ASC")

    def recent_measures(self, probe_id, machines_ids, seconds):
        """Measures of one probe over a window, for several machines at once.

        Same window rule as _window_measures, read for a list of machines: the
        sweep judges every stale alert of a probe on one statement. Grouped by
        machine, newest first; a machine with nothing in the window gets no
        key.
        """
        probe_id = _to_int(probe_id, 0)
        seconds = self.bounded_window(seconds)
        wanted = sorted(set(_to_int(identifier, 0)
                            for identifier in machines_ids or []))
        wanted = [identifier for identifier in wanted if identifier > 0]
        grouped = {}
        since = datetime.now() - timedelta(seconds=seconds + 1)
        for batch in _in_batches(wanted):
            fragment, params = _placeholders("mid", batch)
            params.update({"probe_id": probe_id, "since": since})
            rows = self.select(
                "SELECT machines_id, value_num, value_text, status, "
                "       received_at "
                "  FROM probe_measures "
                " WHERE probe_id = :probe_id AND received_at >= :since "
                "   AND machines_id IN (" + fragment + ") "
                " ORDER BY machines_id ASC, received_at DESC", params)
            for row in rows:
                grouped.setdefault(
                    _to_int(row.get("machines_id"), 0), []).append(row)
        return grouped

    def condition_still_stands(self, condition, measures, seconds):
        """Whether a condition is still satisfied over the window it asks for.

        True, False, or None when nothing in the window can decide, which keeps
        the alert open. One measure satisfying the condition anywhere in the
        window answers True, so a dip does not close what the normal resolution
        would have closed on the next report.
        """
        measures = measures or []
        cutoff = datetime.now() - timedelta(
            seconds=self.bounded_window(seconds) + 1)
        decided = False
        for index, measure in enumerate(measures):
            moment = parse_moment(measure.get("received_at"))
            if moment is None or moment < cutoff:
                # Ordered newest first: past the cutoff nothing decides.
                break
            if str(measure.get("status") or "ok") == "unavailable":
                continue
            previous_text = _previous_text(
                measures[index + 1] if index + 1 < len(measures) else None)
            holds = self.condition_holds(
                condition, _to_float(measure.get("value_num")),
                measure.get("value_text"), previous_text)
            if holds:
                return True
            if holds is False:
                decided = True
        return False if decided else None

    # =====================================================================
    # Notifications
    # =====================================================================
    # -------------------------------------------------------------------
    # Rule targeting
    # -------------------------------------------------------------------
    def reset_target_cache(self):
        """Forget what the previous cycle resolved.

        The backend is a singleton: a membership read once would otherwise
        survive the machine leaving its group.
        """
        self._target_machines = {}
        self._target_groups = {}
        self._probe_intervals = {}
        self._probe_placements = {}
        self._max_lookback = None

    def machine_target(self, machines_id):
        """uuid and GLPI entity of a machine, read once per cycle at most.

        An empty answer means the machine could not be read, which is not the
        same as a machine attached to nothing.
        """
        machines_id = _to_int(machines_id, 0)
        if machines_id <= 0:
            return {}
        if machines_id not in self._target_machines:
            row = {}
            try:
                rows = _rows(_xmpp_engine().execute(text(
                    "SELECT m.uuid_inventorymachine, e.glpi_id AS entity_id "
                    "  FROM xmppmaster.machines m "
                    "  LEFT JOIN xmppmaster.glpi_entity e "
                    "         ON e.id = m.glpi_entity_id "
                    " WHERE m.id = :machines_id"),
                    {"machines_id": machines_id}))
                row = rows[0] if rows else {}
            except Exception as error:
                logger.warning("reflex: machine %s unreadable: %s"
                               % (machines_id, error))
            self._target_machines[machines_id] = row
        return self._target_machines[machines_id]

    def machine_entity(self, machine):
        """The GLPI entity of a machine, None when there is none to be read.

        None covers a machine attached to nothing and a machine nobody could
        read alike: both read the values the product ships.
        """
        machine = machine or {}
        entity_id = machine.get("entity_id")
        if entity_id is None:
            entity_id = self.machine_target(machine.get("id")).get("entity_id")
        return entity_identifier(entity_id)

    def machine_groups(self, machines_id, uuid_inventorymachine):
        """Groups of a machine, read once per cycle at most.

        None when dyngroup could not be read, so a rule is never dropped on an
        answer nobody obtained. The failure is cached like a result.
        """
        machines_id = _to_int(machines_id, 0)
        if machines_id not in self._target_groups:
            try:
                groups = machine_group_ids(uuid_inventorymachine)
            except ReflexSourceUnavailable:
                groups = None
            self._target_groups[machines_id] = groups
        return self._target_groups[machines_id]

    # -------------------------------------------------------------------
    # Which placement governs a machine
    # -------------------------------------------------------------------
    def probe_placements(self, probe_id):
        """Every placement of one probe, read once per cycle at most.

        Where the probe was placed, not which machines that reaches.
        """
        probe_id = _to_int(probe_id, 0)
        if probe_id not in self._probe_placements:
            rows = []
            try:
                rows = self.select(
                    "SELECT id, target_type, target_id, interval_seconds, "
                    "       language "
                    "  FROM probe_assignments WHERE probe_id = :probe_id",
                    {"probe_id": probe_id})
            except Exception as error:
                # The alert opens without a language, which is the English of
                # the database. Never a lost alert for a missing wording.
                logger.warning("reflex: placements of probe %s unreadable "
                               "(%s)" % (probe_id, error))
            self._probe_placements[probe_id] = rows
        return self._probe_placements[probe_id]

    def placement_reaches(self, placement, machines_id, uuid=None,
                          entity_id=None):
        """Whether one placement covers one machine.

        The three targets of probe_assignments, read the way
        pulse2.database.reflex.machine_target_clauses reads them the other way
        round: target_id is a varchar, so a machine target is its machines_id
        written as text. A membership nobody could resolve answers False.
        """
        target_type = str(placement.get("target_type") or "").strip().lower()
        target_id = str(placement.get("target_id") or "").strip()
        if target_type == "machine":
            return _to_int(target_id, 0) == _to_int(machines_id, 0)
        if target_type == "group":
            if not uuid:
                target = self.machine_target(machines_id)
                uuid = str(target.get("uuid_inventorymachine") or "").strip()
            if not uuid:
                return False
            groups = self.machine_groups(machines_id, uuid)
            if groups is None:
                return False
            return _to_int(target_id, 0) in groups
        if target_type == "entity":
            # Both sides through entity_identifier() and neither through
            # _to_int(): an empty target_id, a machine attached to no entity
            # and the root entity are all three spelled 0.
            target_entity = entity_identifier(target_id)
            if target_entity is None:
                return False
            if entity_id is None:
                target = self.machine_target(machines_id)
                entity_id = target.get("entity_id")
            machine_entity = entity_identifier(entity_id)
            if machine_entity is None:
                return False
            return target_entity == machine_entity
        return False

    def placement_undecided(self, placement, machines_id, uuid=None,
                            entity_id=None):
        """Whether a placement could not be judged against a machine.

        placement_reaches() answers False both to "does not cover" and to
        "nobody could resolve the membership". Told apart here, and only for
        the targets resolved elsewhere than in the row itself: a dyngroup that
        is down must not turn every measure of a group placement into a measure
        to throw away.
        """
        target_type = str(placement.get("target_type") or "").strip().lower()
        if target_type == "group":
            if not uuid:
                uuid = str(self.machine_target(machines_id)
                           .get("uuid_inventorymachine") or "").strip()
            if not uuid:
                # A machine with no inventory identity is in no dyngroup,
                # which is an answer; a machine nobody could read is not.
                return not self.machine_target(machines_id)
            return self.machine_groups(machines_id, uuid) is None
        if target_type == "entity":
            if entity_identifier(entity_id) is not None:
                return False
            # None is "attached to no entity" when the machine could be read,
            # and "nobody knows" when it could not.
            return not self.machine_target(machines_id)
        return False

    def governing_placement(self, probe_id, machines_id, uuid=None,
                            entity_id=None):
        """The placement that rules a probe on a machine, None when there is
        none.

        Same order as pulse2.database.reflex._governs: the shortest cadence,
        then the most specific target, then the oldest. Memberships are
        resolved only as far as needed.
        """
        machines_id = _to_int(machines_id, 0)
        if machines_id <= 0:
            return None
        best = None
        best_rank = None
        for placement in self.probe_placements(probe_id):
            rank = (_to_int(placement.get("interval_seconds"), 0) or 2 ** 31,
                    TARGET_SPECIFICITY.get(
                        str(placement.get("target_type") or "").strip()
                        .lower(), 9),
                    _to_int(placement.get("id"), 0))
            if best_rank is not None and rank >= best_rank:
                # Already beaten: a membership read is a statement.
                continue
            if not self.placement_reaches(placement, machines_id, uuid,
                                          entity_id):
                continue
            best, best_rank = placement, rank
        return best

    def placement_language(self, probe_id, machine):
        """Language of whoever placed the probe that rules this machine.

        Read from probe_assignments.language where it lives, rather than copied
        onto anything that would have to be kept in step. None means the
        English the database stores.
        """
        machine = machine or {}
        try:
            uuid = str(machine.get("uuid_inventorymachine") or "").strip()
            placement = self.governing_placement(probe_id, machine.get("id"),
                                                 uuid or None,
                                                 machine.get("entity_id"))
        except Exception as error:
            logger.debug("reflex: placement of probe %s on machine %s not "
                         "resolved (%s)"
                         % (probe_id, machine.get("id"), error))
            return None
        return placement.get("language") if placement else None

    def alert_language(self, alert):
        """The language one alert is notified in.

        Found from the machine and the probe the alert carries, so the first
        notice, a resend and a second notice cannot answer differently.
        """
        alert = alert or {}
        return self.placement_language(alert.get("probe_id"), {
            "id": alert.get("machines_id"),
            "uuid_inventorymachine": alert.get("uuid_inventorymachine"),
            "entity_id": alert.get("entity_id"),
        })

    def rule_applies(self, rule, alert):
        """Whether the restriction of a rule keeps the machine of an alert.

        Resolving a machine costs a read, so nothing is read while no rule
        carries a restriction, and never twice for one machine in a cycle.
        """
        kind, identifier = parse_target_filter(rule.get("target_filter"))
        if not kind:
            return True

        machines_id = _to_int(alert.get("machines_id"), 0)
        if machines_id <= 0:
            logger.debug("reflex: alert without a machine, restriction "
                         "'%s:%s' left aside" % (kind, identifier))
            return True

        if kind == "group":
            uuid = str(alert.get("uuid_inventorymachine") or "").strip()
            if not uuid:
                target = self.machine_target(machines_id)
                if not target:
                    return True
                uuid = str(target.get("uuid_inventorymachine") or "").strip()
            if not uuid:
                return True
            groups = self.machine_groups(machines_id, uuid)
            if groups is None:
                return True
            return identifier in groups

        entity_id = alert.get("entity_id")
        if entity_id is None:
            target = self.machine_target(machines_id)
            if not target:
                return True
            entity_id = target.get("entity_id")
        machine_entity = entity_identifier(entity_id)
        if machine_entity is None:
            # Attached to no entity is a fact about the machine, not a read
            # that failed: no entity restriction keeps it.
            return False
        return machine_entity == identifier

    def alert_entity(self, alert):
        """The GLPI entity of the machine an alert is about, None when there
        is none to be read.

        None covers a machine attached to nothing and one that could not be
        read: the caller refuses to send on either, and neither is a
        permission.
        """
        alert = alert or {}
        return self.machine_entity({"id": alert.get("machines_id"),
                                    "entity_id": alert.get("entity_id")})

    def channel_reaches(self, rule, alert):
        """Whether this channel may be told about the machine of this alert.

        The partition of a SaaS instance, checked at the moment of sending. Both
        sides go through entity_identifier(), the only reader that tells the
        root entity, 0, from an absence.
        """
        channel_entity = entity_identifier(rule.get("channel_entity_id"))
        if channel_entity is None:
            # An unknown owner is refused rather than served: sending would
            # mean picking a customer at random. 0 does not come through here,
            # entity_identifier() answering it as a number.
            return False
        return self.alert_entity(alert) == channel_entity

    # -------------------------------------------------------------------
    # Rules and sending
    # -------------------------------------------------------------------
    def classify_rules(self, probe_id, severity):
        """Split the rules that name a probe into senders and discards.

        The discarded ones come back with the key saying why: a rule left out
        is what the history has to show. The flags and the minimum severity are
        judged here rather than by the WHERE clause.
        """
        rows = self.select(
            "SELECT r.id, r.channel_id, r.probe_id, r.min_severity, "
            "       r.recipients, r.target_filter, r.cooldown_minutes, "
            "       r.escalation_minutes, r.enabled AS rule_enabled, "
            "       c.name AS channel_name, c.channel_type, c.config_json, "
            "       c.enabled AS channel_enabled, "
            # Aliased: the row this builds is matched against an alert that
            # carries an entity_id of its own, that of the machine.
            "       c.entity_id AS channel_entity_id "
            "  FROM notification_rules r "
            "  JOIN notification_channels c ON c.id = r.channel_id "
            " WHERE (r.probe_id IS NULL OR r.probe_id = :probe_id)",
            {"probe_id": _to_int(probe_id, 0)})

        kept = []
        discarded = []
        for row in rows:
            # Turned off first, severity second: naming the severity on a
            # disabled rule would read as "raise it and the mail leaves".
            if not _to_int(row.get("rule_enabled"), 0):
                discarded.append((row, SKIP_RULE_DISABLED))
            elif not _to_int(row.get("channel_enabled"), 0):
                discarded.append((row, SKIP_CHANNEL_DISABLED))
            elif not severity_reaches(severity, row.get("min_severity")):
                discarded.append((row, SKIP_SEVERITY_BELOW_MIN))
            else:
                kept.append(row)
        return kept, discarded

    def rules_for(self, probe_id, severity):
        """Enabled rules that concern a probe and reach a severity."""
        return self.classify_rules(probe_id, severity)[0]

    def in_cooldown(self, alert, channel_id, cooldown_minutes):
        """Whether this channel was told about this lately, and may keep quiet.

        "This" is the watched object -- machine, probe, instance -- never the
        alert, which is notified once and reopens under a new identifier every
        time a value oscillates around its threshold.
        """
        cooldown_minutes = _to_int(cooldown_minutes, 0)
        if cooldown_minutes <= 0:
            return False
        alert = alert or {}
        machines_id = _to_int(alert.get("machines_id"), 0)
        probe_id = _to_int(alert.get("probe_id"), 0)
        if machines_id <= 0 or probe_id <= 0:
            # Nothing to anchor the window on: silence is not guessed.
            return False

        instance = alert.get("instance")
        if instance is None:
            instance = measure_instance(alert.get("value_text_at_trigger"),
                                        alert.get("value_type"))
        params = {"channel_id": _to_int(channel_id, 0),
                  "machines_id": machines_id, "probe_id": probe_id,
                  "since": datetime.now() - timedelta(minutes=cooldown_minutes)}
        restriction = _instance_clause(params, instance,
                                       "a.value_text_at_trigger")
        rank = severity_rank(alert.get("severity"))
        if rank > 0:
            fragment, severity_params = _placeholders(
                "sev", sorted(name for name, value in SEVERITY_RANK.items()
                              if value >= rank))
            params.update(severity_params)
            restriction += "   AND a.severity IN (" + fragment + ") "
        row = self.select_one(
            "SELECT h.id FROM notification_history h "
            "  JOIN alerts a ON a.id = h.alert_id "
            " WHERE h.channel_id = :channel_id AND h.status = 'sent' "
            "   AND h.created_at >= :since "
            "   AND a.machines_id = :machines_id "
            "   AND a.probe_id = :probe_id " + restriction +
            " LIMIT 1", params)
        return row is not None

    @staticmethod
    def channel_settings(config_json, rule_recipients=None):
        """Sending parameters of a channel, read from its own config_json.

        Nothing falls back on the server configuration, and the recipients are
        those of the rule: a list left in the config_json of an older channel
        is ignored.
        """
        try:
            conf = json.loads(config_json or "{}")
        except ValueError:
            conf = {}
        if not isinstance(conf, dict):
            conf = {}

        recipients = rule_recipients or ""
        if isinstance(recipients, (list, tuple)):
            recipients = [str(r).strip() for r in recipients if str(r).strip()]
        else:
            recipients = [r.strip()
                          for r in str(recipients).replace(";", ",").split(",")
                          if r.strip()]

        use_tls = conf.get("use_tls", False)
        if isinstance(use_tls, str):
            use_tls = use_tls.strip().lower() in ("1", "true", "yes", "on")
        try:
            port = int(conf.get("port") or 25)
        except (TypeError, ValueError):
            port = 25

        return {
            "host": str(conf.get("host") or "").strip(),
            "port": port,
            "use_tls": bool(use_tls),
            "username": str(conf.get("username") or "").strip(),
            "from_address": str(conf.get("from_address") or "").strip(),
            "from_name": str(conf.get("from_name") or "Medulla Reflex").strip(),
            "recipients": recipients,
        }

    def send_email(self, channel_id, settings, subject, body,
                   html_body=None):
        """Hand one message over to the SMTP server of a channel.

        Acceptance by the relay is what is reported: it proves neither delivery
        nor reading. With html_body the mail leaves as multipart/alternative.
        A failure answers both error_key, which the console words, and error,
        the technical detail.
        """
        if not settings["host"]:
            return {"success": False, "error_key": SEND_CHANNEL_NO_HOST,
                    "error": "channel without an SMTP server"}
        if not settings["from_address"]:
            return {"success": False, "error_key": SEND_CHANNEL_NO_SENDER,
                    "error": "channel without a sender address"}
        if not settings["recipients"]:
            return {"success": False, "error_key": SEND_CHANNEL_NO_RECIPIENT,
                    "error": "rule without a recipient"}

        # The secret is read back for this sending only: it never travels with
        # the channel and never reaches a log line.
        password = ""
        if settings["username"]:
            try:
                password = self.database.get_channel_secret(channel_id,
                                                            self.aes_key())
            except Exception as error:
                return {"success": False,
                        "error_key": SEND_CHANNEL_PASSWORD_UNREADABLE,
                        "error": clip_detail("password of user '%s' could not "
                                             "be read: %s: %s"
                                             % (settings["username"],
                                                type(error).__name__, error))}
            if not password:
                return {"success": False,
                        "error_key": SEND_CHANNEL_PASSWORD_UNREADABLE,
                        "error": "channel declares user '%s' without a password"
                                 % settings["username"]}

        if html_body:
            # Plain part first, HTML second: a client renders the last part it
            # understands, so a text-only reader still gets the whole message.
            message = MIMEMultipart("alternative")
            message.attach(MIMEText(body, "plain", "utf-8"))
            message.attach(MIMEText(html_body, "html", "utf-8"))
        else:
            message = MIMEText(body, "plain", "utf-8")
        message["Subject"] = Header(subject, "utf-8")
        message["From"] = formataddr(
            (str(Header(settings["from_name"], "utf-8")),
             settings["from_address"]))
        message["To"] = ", ".join(settings["recipients"])
        message["Date"] = formatdate(localtime=True)
        message_id = make_msgid()
        message["Message-ID"] = message_id

        server = None
        try:
            # One catch per phase: the phase is what separates a host that does
            # not resolve from a port that refuses and an account refused, and
            # each of the three is fixed somewhere else.
            try:
                server = smtplib.SMTP(settings["host"], settings["port"],
                                      timeout=SMTP_TIMEOUT_SECONDS)
                server.ehlo()
            except Exception as error:
                return smtp_failure(error, "connect", settings)
            if settings["use_tls"]:
                try:
                    server.starttls()
                    server.ehlo()
                except Exception as error:
                    return smtp_failure(error, "tls", settings)
            if settings["username"]:
                try:
                    server.login(settings["username"], password)
                except Exception as error:
                    return smtp_failure(error, "auth", settings)
            try:
                refused = server.sendmail(settings["from_address"],
                                          settings["recipients"],
                                          message.as_string())
            except Exception as error:
                return smtp_failure(error, "send", settings)
        finally:
            # The password only ever lived in this frame.
            password = ""
            if server is not None:
                try:
                    server.quit()
                except Exception:
                    pass

        accepted = [r for r in settings["recipients"] if r not in (refused or {})]
        if not accepted:
            # sendmail only raises when every recipient was refused before the
            # data; refused one by one, they land here instead.
            return {"success": False,
                    "error_key": SEND_SMTP_RECIPIENTS_REFUSED,
                    "error": clip_detail(
                        "no recipient accepted by %s: %s"
                        % (settings["host"], refused_recipients_text(refused)))}
        return {"success": True, "accepted": accepted,
                "provider_message_id": message_id}

    def alert_body(self, alert, escalation=False, language=None):
        """The mail one alert sends.

        The plain half is never decoration: a terminal reader, an SMS gateway
        and a ticket queue get this one, so it states the instance, the measure
        and its threshold even when the template quotes none of them, and it
        spells the console address bare. Its labels go through the catalogue of
        the message they frame.
        """
        if language is None:
            language = self.alert_language(alert)
        head = ("%s\n\n" % translate("Alert not acknowledged, second notice.",
                                     language)) if escalation else ""
        instance = alert.get("instance")
        measured_on = ("%s: %s\n" % (translate("Measured on", language),
                                     instance)) if instance else ""
        value = alert_value_display(alert, language)
        measured = ("%s: %s\n" % (translate("Measured value", language),
                                  value)) if value else ""
        threshold = alert_threshold_display(alert, language)
        compared = ("%s: %s\n" % (translate("Threshold", language),
                                  threshold)) if threshold else ""
        lines = alert_detail_display(alert)
        detailed = ""
        if len(lines) == 1:
            detailed = "%s: %s\n" % (translate("Detail", language), lines[0])
        elif lines:
            detailed = "%s:\n%s\n" % (translate("Detail", language),
                                      "\n".join("- %s" % line
                                                for line in lines))
        console = self.console_alerts_url()
        link = ("\n%s\n%s\n" % (translate("Alerts in the Medulla console:",
                                          language), console)
                if console else "")
        return (
            "%s%s\n\n"
            "%s: %s\n"
            "%s: %s\n"
            "%s"
            "%s"
            "%s"
            "%s"
            "%s: %s\n"
            "%s: %s\n"
            "%s: %s\n"
            "%s"
            % (head,
               translate("Medulla Reflex raised an alert.", language),
               translate("Machine", language),
               alert.get("hostname") or "",
               translate("Probe", language),
               # The label of a shipped probe is a string of the catalogue.
               translate(alert.get("probe_label")
                         or alert.get("probe_key") or "", language),
               measured_on,
               measured,
               compared,
               detailed,
               translate("Severity", language),
               severity_label(alert.get("severity"), language),
               translate("Message", language),
               alert.get("message") or "",
               translate("Opened at", language),
               alert.get("opened_at")
               or datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
               link))

    def alert_html_body(self, alert, escalation=False, language=None):
        """The same alert, rendered for a mail client that displays HTML.

        None when it could not be rendered, and the sending then leaves as
        plain text.
        """
        try:
            if language is None:
                language = self.alert_language(alert)
            return render_alert_html(alert, escalation,
                                     self.console_alerts_url(), language)
        except Exception as error:
            logger.warning("reflex: HTML body of alert %s not rendered: %s"
                           % (alert.get("id") if alert else None, error))
            return None

    def alert_subject(self, alert, language=None):
        """The subject of the mail one alert sends.

        Composed here for the three senders, so none of them words it
        differently. Nothing of the estate, the gravity or the notice it is: a
        subject travels through every relay and shows on a locked phone.
        """
        if language is None:
            language = self.alert_language(alert or {})
        return "Medulla Reflex - %s" % translate("Alert", language)

    def record_skip(self, alert_id, reason, channel_id=None, rule_id=None,
                    escalation=False, attempt_count=0):
        """Write down one sending that did not happen.

        The only way out of the notification paths: a bare continue leaves the
        console with nothing to show the day somebody received no mail.
        """
        return self.database.add_notification_history(
            alert_id=alert_id, channel_id=channel_id, rule_id=rule_id,
            status="skipped", skip_reason=reason,
            attempt_count=_to_int(attempt_count, 0),
            is_escalation=1 if escalation else 0)

    def notify_alert(self, alert, escalation=False):
        """Send one alert through every rule that concerns it.

        Every attempt is traced, successful or not, and so is every rule that
        did not send. Called once per alert, when it opens, which bounds the
        rows written here to one per rule and per alert.
        """
        sent = 0
        # Resolved once for the whole alert: the language is that of the
        # placement, never of the channel.
        language = self.alert_language(alert)

        def skip(rule, reason):
            self.record_skip(alert.get("id"), reason,
                             channel_id=_to_int(rule.get("channel_id"), 0),
                             rule_id=_to_int(rule.get("id"), 0),
                             escalation=escalation)

        rules, discarded = self.classify_rules(alert.get("probe_id"),
                                               alert.get("severity"))
        for rule, reason in discarded:
            skip(rule, reason)
        if not rules and not discarded:
            # No rule names this probe at all. Without this row the page of the
            # alert is empty.
            self.record_skip(alert.get("id"), SKIP_NO_RULE_MATCHES,
                             escalation=escalation)

        for rule in rules:
            channel_id = _to_int(rule.get("channel_id"), 0)
            # Before the settings somebody chose: a restriction and a cooldown
            # are judged on a channel that may hear about this machine at all.
            if not self.channel_reaches(rule, alert):
                skip(rule, SKIP_CHANNEL_ENTITY_MISMATCH)
                continue
            if not self.rule_applies(rule, alert):
                skip(rule, SKIP_TARGET_NOT_MATCHED)
                continue
            if str(rule.get("channel_type") or "email") != "email":
                skip(rule, SKIP_CHANNEL_TYPE_UNSUPPORTED)
                continue
            if not escalation and self.in_cooldown(alert, channel_id,
                                                   rule.get("cooldown_minutes")):
                skip(rule, SKIP_COOLDOWN)
                continue

            settings = self.channel_settings(rule.get("config_json"),
                                             rule.get("recipients"))
            if not settings["recipients"]:
                skip(rule, SKIP_RULE_NO_RECIPIENT)
                continue
            result = self.send_email(
                channel_id, settings,
                self.alert_subject(alert, language),
                self.alert_body(alert, escalation, language),
                self.alert_html_body(alert, escalation, language))
            self.record_attempt(alert, rule, settings, result, escalation,
                                attempt_count=1)
            if result.get("success"):
                sent += 1
        return sent

    def record_attempt(self, alert, rule, settings, result, escalation,
                       attempt_count=1):
        """Trace one attempt, without the secret.

        A failure writes both: the key of its family in skip_reason, which the
        console words, and the technical detail in error_message.
        """
        success = bool(result.get("success"))
        next_retry = None
        if not success:
            # Backoff bounded to an hour.
            delay = min(5 * (2 ** max(attempt_count - 1, 0)), 60)
            next_retry = datetime.now() + timedelta(minutes=delay)
        history_id = self.database.add_notification_history(
            alert_id=alert.get("id"),
            channel_id=_to_int(rule.get("channel_id"), 0),
            rule_id=_to_int(rule.get("id"), 0),
            recipients=", ".join(settings.get("recipients") or []),
            status="sent" if success else "failed",
            skip_reason=None if success else result.get("error_key"),
            error_message=result.get("error"),
            attempt_count=attempt_count,
            accepted_at=datetime.now() if success else None,
            provider_message_id=result.get("provider_message_id"),
            is_escalation=1 if escalation else 0)
        if not success and next_retry is not None and history_id:
            self.execute(
                "UPDATE notification_history SET next_retry_at = :next_retry "
                " WHERE id = :history_id",
                {"next_retry": next_retry,
                 "history_id": _to_int(history_id, 0)})
        return history_id

    # -------------------------------------------------------------------
    # Retry queue and escalation
    # -------------------------------------------------------------------
    @staticmethod
    def _with_instance(rows):
        """Give every alert row the instance it was raised on.

        Resolved once here rather than by each caller building its mail.
        """
        for row in rows or []:
            row["instance"] = measure_instance(row.get("value_text_at_trigger"),
                                               row.get("value_type"))
        return rows

    def pending_retries(self, limit=50):
        rows = self.select(
            "SELECT h.id, h.alert_id, h.channel_id, h.rule_id, h.recipients, "
            "       h.attempt_count, h.is_escalation, a.hostname, a.severity, "
            "       a.machines_id, a.uuid_inventorymachine, "
            "       a.message, a.probe_id, a.opened_at, a.status AS alert_status,"
            "       a.value_at_trigger, a.value_text_at_trigger, "
            "       a.detail_at_trigger, "
            "       p.value_type, p.unit, "
            # The threshold as it was when the alert rose, read off the alert
            # and never off probe_conditions: a threshold lowered then restored
            # would make the resend quote a limit that triggered nothing.
            "       a.threshold_value_at_trigger AS threshold_value, "
            "       a.threshold_text_at_trigger AS threshold_text, "
            "       p.probe_key, p.label AS probe_label "
            "  FROM notification_history h "
            "  JOIN alerts a ON a.id = h.alert_id "
            "  JOIN probes p ON p.id = a.probe_id "
            " WHERE h.status = 'failed' AND h.next_retry_at IS NOT NULL "
            "   AND h.next_retry_at <= NOW() "
            " ORDER BY h.next_retry_at ASC LIMIT :limit",
            {"limit": _to_int(limit, 50)})
        return self._with_instance(rows)

    def drop_retry(self, history_id, reason=None, entry=None):
        """Take one row out of the retry queue.

        Without a reason this is bookkeeping. With one, the queue gives up and
        that is written down: clearing next_retry_at alone leaves a failed row
        indistinguishable from a resend not yet scheduled.
        """
        self.execute(
            "UPDATE notification_history SET next_retry_at = NULL "
            " WHERE id = :history_id", {"history_id": _to_int(history_id, 0)})
        if not reason:
            return
        entry = entry or {}
        self.record_skip(
            entry.get("alert_id"), reason,
            channel_id=_to_int(entry.get("channel_id"), 0),
            rule_id=_to_int(entry.get("rule_id"), 0),
            escalation=bool(_to_int(entry.get("is_escalation"), 0)),
            attempt_count=_to_int(entry.get("attempt_count"), 0))

    def escalation_candidates(self, limit=50):
        """Critical alerts still open past the escalation delay of a rule."""
        rows = self.select(
            "SELECT a.id, a.probe_id, a.machines_id, a.hostname, a.severity, "
            "       a.message, a.opened_at, a.uuid_inventorymachine, "
            "       a.value_at_trigger, a.value_text_at_trigger, "
            "       a.detail_at_trigger, "
            "       p.value_type, p.unit, "
            "       a.threshold_value_at_trigger AS threshold_value, "
            "       a.threshold_text_at_trigger AS threshold_text, "
            "       r.id AS rule_id, r.channel_id, r.target_filter, "
            "       r.recipients, r.min_severity, r.escalation_minutes, "
            "       c.channel_type, c.config_json, p.probe_key, "
            "       c.entity_id AS channel_entity_id, "
            "       p.label AS probe_label "
            "  FROM alerts a "
            "  JOIN probes p ON p.id = a.probe_id "
            "  JOIN notification_rules r "
            "       ON (r.probe_id IS NULL OR r.probe_id = a.probe_id) "
            "  JOIN notification_channels c ON c.id = r.channel_id "
            " WHERE a.status = 'open' AND a.severity = 'critical' "
            "   AND r.enabled = 1 AND c.enabled = 1 "
            "   AND r.escalation_minutes IS NOT NULL "
            "   AND a.opened_at <= NOW() - INTERVAL r.escalation_minutes MINUTE "
            "   AND NOT EXISTS (SELECT 1 FROM notification_history h "
            "                    WHERE h.alert_id = a.id AND h.rule_id = r.id "
            "                      AND h.is_escalation = 1) "
            " LIMIT :limit", {"limit": _to_int(limit, 50)})
        # A row carries the rule and the alert at once. Nothing is written for
        # the rows this drops: the sweep runs every minute and would write a
        # row a minute, and such a row carries is_escalation, which is what
        # takes the candidate out of the NOT EXISTS above.
        return self._with_instance(
            [row for row in rows
             if self.rule_applies(row, row) and self.channel_reaches(row, row)])

    def purge(self):
        return self.database.purge_old_data()


def reflex_backend():
    """The activated backend, or None when reflex is not usable here."""
    backend = ReflexBackend()
    if ReflexBackend.is_activated:
        return backend
    return backend if backend.activate() else None


# =============================================================================
# Bridge with the estate database and with XMPP
# =============================================================================
def _xmpp_database():
    from lib.plugins.xmpp import XmppMasterDatabase

    return XmppMasterDatabase()


def _xmpp_engine():
    return _xmpp_database().engine_xmppmmaster_base


def machine_from_jid(jid):
    """Machine behind a JID, as xmppmaster knows it.

    An empty answer means the JID belongs to no known machine; an xmppmaster
    that cannot be read raises.
    """
    try:
        return _xmpp_database().getMachinefromjid(str(jid)) or {}
    except Exception as error:
        logger.error("reflex: JID %s could not be resolved: %s" % (jid, error))
        raise ReflexSourceUnavailable("machine behind %s: %s" % (jid, error))


_ACTIVE_MACHINE_SQL = (
    "SELECT m.id, m.jid, m.hostname, m.platform, "
    "       m.uuid_inventorymachine, e.glpi_id AS entity_id "
    "  FROM xmppmaster.machines m "
    "  LEFT JOIN xmppmaster.glpi_entity e ON e.id = m.glpi_entity_id "
    " WHERE m.agenttype = 'machine' AND m.enabled = 1 "
    "   AND m.jid IS NOT NULL AND m.jid != ''")


def active_machines():
    """Machines an agent is expected to run on, [] when they cannot be read."""
    try:
        return _rows(_xmpp_engine().execute(text(_ACTIVE_MACHINE_SQL), {}))
    except Exception as error:
        logger.error("reflex: the machine list could not be read: %s" % error)
        return []


def machine_group_ids(uuid_inventorymachine):
    """Dyngroup groups a machine belongs to.

    An empty answer means the machine is in no group; a dyngroup that cannot
    be read raises rather than answering an empty list that passes for a fact.
    """
    uuid = str(uuid_inventorymachine or "").strip()
    if not uuid:
        return []
    try:
        rows = _rows(_xmpp_engine().execute(text(
            "SELECT DISTINCT r.FK_groups AS group_id "
            "  FROM dyngroup.Results r "
            "  JOIN dyngroup.Machines dm ON dm.id = r.FK_machines "
            " WHERE dm.uuid = :uuid"), {"uuid": uuid}))
    except Exception as error:
        logger.warning("reflex: groups of %s unreadable: %s" % (uuid, error))
        raise ReflexSourceUnavailable(
            "dyngroup membership of %s: %s" % (uuid, error))
    return [_to_int(row.get("group_id"), 0) for row in rows
            if _to_int(row.get("group_id"), 0) > 0]


def machines_in_groups(group_ids):
    """Machines belonging to dyngroup groups, as xmppmaster numbers them.

    The mirror image of machine_group_ids, so a sweep over a whole park does
    not resolve the groups of every machine one by one. DISTINCT because
    dyngroup.Machines carries the same machine twice after a group import.
    Raises rather than answering an empty list, which would pass for a fact.
    """
    ids = sorted(set(_to_int(value, 0) for value in group_ids or []))
    ids = [value for value in ids if value > 0]
    if not ids:
        return set()
    fragment, params = _placeholders("grp", ids)
    try:
        rows = _rows(_xmpp_engine().execute(text(
            "SELECT DISTINCT m.id "
            "  FROM dyngroup.Results r "
            "  JOIN dyngroup.Machines dm ON dm.id = r.FK_machines "
            "  JOIN xmppmaster.machines m "
            "         ON m.uuid_inventorymachine = dm.uuid "
            " WHERE r.FK_groups IN (" + fragment + ")"), params))
    except Exception as error:
        logger.warning("reflex: members of groups %s unreadable: %s"
                       % (ids, error))
        raise ReflexSourceUnavailable(
            "dyngroup members of %s: %s" % (ids, error))
    return set(_to_int(row.get("id"), 0) for row in rows
               if _to_int(row.get("id"), 0) > 0)


def machines_in_entities(entity_ids):
    """Machines attached to GLPI entities, as xmppmaster numbers them.

    entity_id is glpi_entity.glpi_id, not the local key of the table. 0 is
    kept: it is the root entity, where every machine of a park declaring one
    entity sits. What entity_identifier() cannot read at all is dropped.
    """
    ids = set()
    for value in entity_ids or []:
        identifier = entity_identifier(value)
        if identifier is None:
            logger.warning("reflex: entity target '%s' is not a number, the "
                           "placement carrying it reaches no machine" % value)
            continue
        ids.add(identifier)
    ids = sorted(ids)
    if not ids:
        return set()
    fragment, params = _placeholders("ent", ids)
    try:
        rows = _rows(_xmpp_engine().execute(text(
            "SELECT m.id "
            "  FROM xmppmaster.machines m "
            "  JOIN xmppmaster.glpi_entity e ON e.id = m.glpi_entity_id "
            " WHERE e.glpi_id IN (" + fragment + ")"), params))
    except Exception as error:
        logger.warning("reflex: machines of entities %s unreadable: %s"
                       % (ids, error))
        raise ReflexSourceUnavailable(
            "GLPI entities %s: %s" % (ids, error))
    return set(_to_int(row.get("id"), 0) for row in rows
               if _to_int(row.get("id"), 0) > 0)


def build_configuration(backend, machine):
    """Configuration version and probe list applicable to a machine.

    Propagates ReflexSourceUnavailable: a configuration built on a membership
    that could not be read is not a smaller configuration, it is a wrong one.
    """
    entity_ids = []
    # None is "attached to no entity", 0 is "in the root entity": a truth
    # test would read the second like the first.
    entity_id = entity_identifier(machine.get("entity_id"))
    if entity_id is not None:
        entity_ids.append(entity_id)
    return backend.machine_config(
        machine.get("id"),
        group_ids=machine_group_ids(machine.get("uuid_inventorymachine")),
        entity_ids=entity_ids)


def send_configuration(xmppobject, backend, machine, sessionid=None,
                       force=False, built=None):
    """Push the probe configuration of a machine to its agent.

    Returns the version sent, or "" when nothing was sent. A pull is always
    answered, even for an unchanged configuration, or an agent that lost its
    file would stay mute.
    """
    machines_id = _to_int(machine.get("id"), 0)
    jid = str(machine.get("jid") or "")
    if machines_id <= 0 or not jid:
        return ""

    try:
        if built is None:
            built = build_configuration(backend, machine)
        version, probes = built
    except ReflexSourceUnavailable as error:
        # Amputated of the probes targeted by group, the payload would still
        # carry a fingerprint declaring it valid. Nothing is sent.
        logger.warning("reflex: configuration of %s postponed, %s"
                       % (machine.get("hostname") or jid, error))
        return ""
    state = backend.agent_config_state(machines_id) or {}
    if not force and state.get("sent_version") == version:
        if state.get("acked_version") == version:
            return ""
        # Sent but never acknowledged: served again on its own delay, so an
        # agent that is simply offline is not written to every round.
        sent_at = parse_moment(state.get("sent_at"))
        if sent_at is not None and (datetime.now() - sent_at) < timedelta(
                minutes=RESEND_AFTER_MINUTES):
            return ""

    payload = {
        "action": "reflex",
        "sessionid": sessionid or "reflexconfig%d" % machines_id,
        "base64": False,
        "ret": 0,
        "data": {
            "subaction": "config",
            "config_version": version,
            "probes": probes,
            "date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        },
    }
    try:
        xmppobject.send_message(mto=jid, mbody=json.dumps(payload),
                                mtype="chat")
    except Exception as error:
        logger.error("reflex: configuration not sent to %s: %s" % (jid, error))
        return ""

    backend.database.set_agent_config_sent(
        machines_id, machine.get("hostname") or "", version,
        probe_count=len(probes))
    logger.debug("reflex: configuration %s sent to %s (%d probe(s))"
                 % (version, jid, len(probes)))
    return version


# =============================================================================
# Queue of configuration changes
#
# probe_config_changes holds one row per console gesture that changes what
# machines must measure. This side turns the scopes into machines, serves them,
# then empties what it read; scheduling_reflex_config is the safety net.
# =============================================================================
CONFIG_CHANGES_PER_ROUND = 200

_config_changes_state = {"missing_warned": False}


def _table_missing(error):
    message = str(error).lower()
    return "probe_config_changes" in message \
        and ("1146" in message or "doesn't exist" in message)


def pending_config_changes(backend):
    """(max_id, rows) of the queue, (0, []) when it is empty.

    Only the rows up to MAX(id) are read, and only those are deleted later: a
    gesture written meanwhile stays for the next round.
    """
    row = backend.select_one(
        "SELECT MAX(id) AS max_id FROM probe_config_changes")
    max_id = _to_int((row or {}).get("max_id"), 0)
    if max_id <= 0:
        return 0, []
    rows = backend.select(
        "SELECT id, scope_type, scope_id FROM probe_config_changes "
        " WHERE id <= :max_id ORDER BY id", {"max_id": max_id})
    return max_id, rows


def probe_reach(backend, probe_id):
    """Targets reached by the placements of a probe, exclusions included.

    Returns (machine_ids, group_ids, entity_ids). Raises when the placements
    cannot be read: a probe whose reach is unknown is not a probe reaching
    nobody.
    """
    probe_id = _to_int(probe_id, 0)
    machine_ids, group_ids, entity_ids = set(), set(), set()
    if probe_id <= 0:
        return machine_ids, group_ids, entity_ids
    for placement in backend.select(
            "SELECT target_type, target_id FROM probe_assignments "
            " WHERE probe_id = :probe_id", {"probe_id": probe_id}):
        target_type = str(placement.get("target_type") or "").strip().lower()
        target_id = str(placement.get("target_id") or "").strip()
        if target_type == "machine" and _to_int(target_id, 0) > 0:
            machine_ids.add(_to_int(target_id, 0))
        elif target_type == "group" and _to_int(target_id, 0) > 0:
            group_ids.add(_to_int(target_id, 0))
        elif target_type == "entity" \
                and entity_identifier(target_id) is not None:
            entity_ids.add(entity_identifier(target_id))
    for exclusion in backend.select(
            "SELECT machines_id FROM probe_exclusions "
            " WHERE probe_id = :probe_id", {"probe_id": probe_id}):
        if _to_int(exclusion.get("machines_id"), 0) > 0:
            machine_ids.add(_to_int(exclusion.get("machines_id"), 0))
    return machine_ids, group_ids, entity_ids


def active_machines_among(machine_ids=None):
    """Active machines, all of them when machine_ids is None.

    Unlike active_machines(), raises ReflexSourceUnavailable: an empty answer
    here would empty the queue.
    """
    try:
        if machine_ids is None:
            return _rows(_xmpp_engine().execute(text(
                _ACTIVE_MACHINE_SQL + " ORDER BY m.id")))
        ids = sorted(set(_to_int(value, 0) for value in machine_ids))
        ids = [value for value in ids if value > 0]
        machines = []
        for batch in _in_batches(ids):
            fragment, params = _placeholders("mid", batch)
            machines.extend(_rows(_xmpp_engine().execute(text(
                _ACTIVE_MACHINE_SQL + " AND m.id IN (" + fragment + ")"
                " ORDER BY m.id"), params)))
        return machines
    except ReflexSourceUnavailable:
        raise
    except Exception as error:
        raise ReflexSourceUnavailable("active machines: %s" % error)


def changed_machines(backend, changes):
    """Active machines touched by queued changes.

    Returns (machines, unresolved): the machine rows, deduplicated and ordered
    by id, and the change rows that could not be translated and must stay
    queued.
    """
    machine_ids = set()
    groups, entities = {}, {}
    unresolved = []
    everything = []
    for change in changes:
        scope = str(change.get("scope_type") or "").strip().lower()
        scope_id = change.get("scope_id")
        if scope == "all":
            everything.append(change)
        elif scope == "machine":
            if _to_int(scope_id, 0) > 0:
                machine_ids.add(_to_int(scope_id, 0))
        elif scope == "group":
            if _to_int(scope_id, 0) > 0:
                groups.setdefault(_to_int(scope_id, 0), []).append(change)
        elif scope == "entity":
            if entity_identifier(scope_id) is not None:
                entities.setdefault(entity_identifier(scope_id),
                                    []).append(change)
        elif scope == "probe":
            try:
                reach = probe_reach(backend, scope_id)
            except Exception as error:
                logger.warning("reflex: reach of probe %s unreadable (%s), "
                               "change kept" % (scope_id, error))
                unresolved.append(change)
                continue
            machine_ids.update(reach[0])
            for group_id in reach[1]:
                groups.setdefault(group_id, []).append(change)
            for entity_id in reach[2]:
                entities.setdefault(entity_id, []).append(change)
        else:
            logger.warning("reflex: change %s of unknown scope '%s' dropped"
                           % (change.get("id"), scope))

    if everything:
        try:
            return active_machines_among(None), []
        except ReflexSourceUnavailable as error:
            logger.warning("reflex: machine list unreadable (%s), changes "
                           "kept" % error)
            return [], _distinct_changes(changes)

    for resolve, targets in ((machines_in_groups, groups),
                             (machines_in_entities, entities)):
        if not targets:
            continue
        try:
            machine_ids.update(resolve(sorted(targets)))
        except Exception as error:
            logger.warning("reflex: members of %s unreadable (%s), changes "
                           "kept" % (sorted(targets), error))
            for kept in targets.values():
                unresolved.extend(kept)

    try:
        machines = active_machines_among(machine_ids) if machine_ids else []
    except ReflexSourceUnavailable as error:
        logger.warning("reflex: machines %s unreadable (%s), changes kept"
                       % (sorted(machine_ids), error))
        return [], _distinct_changes(changes)
    return machines, _distinct_changes(unresolved)


def _distinct_changes(changes):
    seen = set()
    kept = []
    for change in changes:
        key = (str(change.get("scope_type") or "").strip().lower(),
               change.get("scope_id"))
        if key in seen:
            continue
        seen.add(key)
        kept.append({"scope_type": key[0], "scope_id": key[1]})
    return kept


def settle_config_changes(backend, max_id, remaining_ids, unresolved):
    """Empty what was read, and queue again what this round left.

    One transaction: the rows read disappear only if what they still owe is
    written back as machine rows or as the unresolved scopes themselves.
    """
    rows = [{"scope_type": "machine", "scope_id": _to_int(machines_id, 0)}
            for machines_id in remaining_ids if _to_int(machines_id, 0) > 0]
    rows.extend({"scope_type": change["scope_type"],
                 "scope_id": change["scope_id"]} for change in unresolved)
    with backend.engine.begin() as connection:
        connection.execute(text(
            "DELETE FROM probe_config_changes WHERE id <= :max_id"),
            {"max_id": _to_int(max_id, 0)})
        if rows:
            connection.execute(text(
                "INSERT INTO probe_config_changes (scope_type, scope_id) "
                "VALUES (:scope_type, :scope_id)"), rows)
    return len(rows)


def process_config_changes(xmppobject, backend,
                           limit=CONFIG_CHANGES_PER_ROUND):
    """One round of the queue.

    Returns None when the table does not exist, otherwise the counters of the
    round: machines served, configurations sent, failures, rows queued again.
    """
    try:
        max_id, changes = pending_config_changes(backend)
    except Exception as error:
        if not _table_missing(error):
            raise
        if not _config_changes_state["missing_warned"]:
            _config_changes_state["missing_warned"] = True
            logger.warning("reflex: probe_config_changes missing, the reflex "
                           "database is not migrated; changes wait for the "
                           "full sweep (%s)" % error)
        return None
    _config_changes_state["missing_warned"] = False

    result = {"changes": len(changes), "machines": 0, "sent": 0,
              "failed": 0, "requeued": 0}
    if not changes:
        return result

    machines, unresolved = changed_machines(backend, changes)
    limit = max(_to_int(limit, 0), 1)
    now, rest = machines[:limit], machines[limit:]
    result["machines"] = len(now)
    for machine in now:
        try:
            if send_configuration(xmppobject, backend, machine):
                result["sent"] += 1
        except Exception as error:
            result["failed"] += 1
            logger.error("reflex: configuration of %s failed: %s"
                         % (machine.get("hostname") or machine.get("id"),
                            error))

    result["requeued"] = settle_config_changes(
        backend, max_id, [machine.get("id") for machine in rest], unresolved)
    return result


# =============================================================================
# Which substitute runs reflex
#
# Every substitute loads the scheduled plugins of
# descriptor_scheduler_substitute: without this guard, ten of them would send
# the same message ten times.
# =============================================================================
SUBSTITUTE_CONF_NAME = "reflex.ini"
DEFAULT_SUBSTITUTE_JID = "master_mon@pulse"


def reflex_substitute_jid(xmppobject):
    """Bare JID of the substitute in charge of reflex, its .local overriding it.

    A missing or unreadable file leaves the shipped JID in place: reflex then
    runs where the package puts it rather than nowhere.
    """
    try:
        pathfileconf = os.path.join(xmppobject.config.pathdirconffile,
                                    SUBSTITUTE_CONF_NAME)
    except Exception:
        return DEFAULT_SUBSTITUTE_JID

    conf = configparser.ConfigParser()
    for name in (pathfileconf, "%s.local" % pathfileconf):
        if os.path.isfile(name):
            try:
                conf.read(name)
            except Exception as error:
                logger.warning("reflex: %s unreadable (%s)" % (name, error))
    try:
        return conf.get("parameters", "jid").strip() or DEFAULT_SUBSTITUTE_JID
    except Exception:
        return DEFAULT_SUBSTITUTE_JID


def is_reflex_substitute(xmppobject):
    """Whether the running substitute is the one that owns reflex."""
    try:
        current = str(xmppobject.boundjid.bare)
    except Exception:
        return False
    return current == reflex_substitute_jid(xmppobject)


# =============================================================================
# Language of a notification
#
# What this module stores is English, and that English is the translation key.
# A notification is sent in the language of whoever placed the probe, held by
# probe_assignments.language, through the very .mo files the console reads.
# Nothing here raises and nothing answers empty: a missing translation costs a
# language, never an alert.
# =============================================================================
GETTEXT_DOMAIN = "reflex"
# Where the package of the web console installs its catalogues.
LOCALE_DIR = "/usr/share/mmc/modules/reflex/locale"

# Catalogues already loaded, by language. A missing one is cached too: the
# file must be looked for once, not once per mail.
_CATALOGUES = {}


def catalogue(language):
    """The catalogue of one language, None when there is nothing to look up.

    The code is passed to gettext as it was stored, unchecked: a code nothing
    answers for falls back on the English, which is what a check would do.
    """
    code = str(language or "").strip()
    if not code:
        return None
    if code not in _CATALOGUES:
        loaded = None
        try:
            loaded = gettext.translation(GETTEXT_DOMAIN, localedir=LOCALE_DIR,
                                         languages=[code], fallback=True)
            if not isinstance(loaded, gettext.GNUTranslations):
                # What fallback=True answers when it found nothing.
                logger.info(
                    "reflex: no %s catalogue for %s in %s, the notifications "
                    "of that language leave in English"
                    % (GETTEXT_DOMAIN, code, LOCALE_DIR))
        except Exception as error:
            # A truncated .mo, an unreadable directory: the mail leaves in
            # English rather than not leaving.
            logger.warning("reflex: catalogue %s of %s unusable (%s)"
                           % (code, LOCALE_DIR, error))
            loaded = None
        _CATALOGUES[code] = loaded
    return _CATALOGUES[code]


def translate(value, language):
    """One stored string, in the language a notification is sent in.

    The English that went in comes back whenever there is nothing else to
    answer, gettext returning the key itself for a string it does not hold.
    """
    if value is None:
        return ""
    value = str(value)
    if not value:
        # gettext("") answers the header of the catalogue, not an empty string.
        return value
    book = catalogue(language)
    if book is None:
        return value
    try:
        return book.gettext(value)
    except Exception as error:
        logger.debug("reflex: '%s' not translated (%s)" % (value[:40], error))
        return value


def translated_pattern(pattern, values, language, fallback=None):
    """A translated pattern and its values, never raising on a bad one.

    A catalogue is edited by hand: a translator who drops a placeholder must
    not cost the mail its sending.
    """
    translated = translate(pattern, language)
    try:
        return translated % values
    except Exception:
        pass
    try:
        return pattern % values
    except Exception:
        if fallback is not None:
            return fallback
        return " ".join(str(value) for value in values)


def translate_format(pattern, value, language):
    """A translated pattern carrying one %s."""
    return translated_pattern(pattern, (value,), language, str(value))


# Keys as the database stores them, values as the catalogue of the web module
# holds them.
SEVERITY_LABELS = {
    "critical": "Critical",
    "high": "High",
    "medium": "Medium",
    "info": "Info",
}


def severity_label(severity, language):
    """The severity of an alert, worded and translated, never empty-handed.

    A severity this table does not know is printed as it is stored.
    """
    key = str(severity or "").strip().lower()
    if not key:
        return ""
    return translate(SEVERITY_LABELS.get(key, key.capitalize()), language)
