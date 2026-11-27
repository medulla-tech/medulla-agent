# -*- coding: utf-8; -*-
# SPDX-FileCopyrightText: 2018-2023 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-3.0-or-later

"""
kiosk database handler
"""
import json
import logging
import os
import re
import traceback

from sqlalchemy import bindparam, create_engine, text
from sqlalchemy.ext.automap import automap_base
from sqlalchemy.orm import scoped_session, sessionmaker

from lib.configuration import confParameter
from lib.managepackage import managepackage
from lib.plugins.glpi import Glpi
from lib.utils import getRandomName

logger = logging.getLogger()

# Entity me is entity pe or below it (rows of xmppmaster.local_glpi_entities)
ENTITY_AT_OR_BELOW_SQL = """(
           me.completename = pe.completename
           OR LEFT(me.completename, CHAR_LENGTH(pe.completename) + 3)
              = CONCAT(pe.completename, ' > '))"""

# GLPI entity (me) of a machine (m.uuid_inventorymachine), read from GLPI;
# a machine GLPI does not know, or deleted there, has none
MACHINE_ENTITY_JOIN_SQL = """
      JOIN xmppmaster.local_glpi_machines lgm
        ON m.uuid_inventorymachine REGEXP '^UUID[0-9]+$'
       AND lgm.id = CAST(SUBSTRING(m.uuid_inventorymachine, 5) AS UNSIGNED)
       AND lgm.is_deleted = 0
       AND lgm.is_template = 0
      JOIN xmppmaster.local_glpi_entities me ON me.id = lgm.entities_id"""

# Active profiles of the entity of a machine and of the entities above it
PROFILES_SQL = (
    """
    SELECT p.id, p.source, o.ou
      FROM (SELECT :uuid AS uuid_inventorymachine) m"""
    + MACHINE_ENTITY_JOIN_SQL
    + """
      JOIN profiles p ON p.active = 1
      JOIN xmppmaster.local_glpi_entities pe ON pe.id = p.entity_id
      LEFT JOIN profile_has_ous o ON o.profile_id = p.id
     WHERE """
    + ENTITY_AT_OR_BELOW_SQL
)

PACKAGES_SQL = """
    SELECT DISTINCT
           pk.uuid,
           pk.label AS name,
           pk.description,
           pk.version,
           pk.Qvendor AS vendor,
           pk.Qsoftware AS software,
           pk.Qversion AS version_software,
           pk.os
      FROM package_has_profil php
      JOIN pkgs.packages pk ON pk.uuid = php.package_uuid
     WHERE php.profil_id IN :profile_ids
"""

# Online machines with a kiosk
MACHINES_SQL = """
    SELECT DISTINCT m.jid
      FROM xmppmaster.machines m%s
     WHERE m.kiosk_presence = 'True'
       AND m.enabled = 1
       AND m.agenttype = 'machine'
"""

# Machines of the given entities and of the entities below them
ENTITIES_JOIN_SQL = (
    MACHINE_ENTITY_JOIN_SQL
    + """
      JOIN xmppmaster.local_glpi_entities pe
        ON pe.id IN :entity_ids
       AND """
    + ENTITY_AT_OR_BELOW_SQL
)


class Singleton(object):
    def __new__(type, *args):
        if "_the_instance" not in type.__dict__:
            type._the_instance = object.__new__(type)
        return type._the_instance


class KioskDatabase(Singleton):
    """
    Singleton Class to query the kioskmaster database.

    """

    is_activated = False

    def activate(self):  # jid, password, room, nick):
        if self.is_activated:
            return None
        self.logger = logging.getLogger()
        self.logger.debug("kiosk activation")
        self.engine = None
        self.sessionxmpp = None
        self.sessionglpi = None
        self.sessionkiosk = None
        self.config = confParameter()
        self.logger.info(
            "kiosk parameters connections is "
            " user = %s,host = %s, port = %s, schema = %s,"
            " poolrecycle = %s, poolsize = %s, pooltimeout %s"
            % (
                self.config.kiosk_dbuser,
                self.config.kiosk_dbhost,
                self.config.kiosk_dbport,
                self.config.kiosk_dbname,
                self.config.kiosk_dbpoolrecycle,
                self.config.kiosk_dbpoolsize,
                self.config.kiosk_dbpooltimeout,
            )
        )
        try:
            self.engine_kiosk_base = create_engine(
                "mysql://%s:%s@%s:%s/%s?charset=%s"
                % (
                    self.config.kiosk_dbuser,
                    self.config.kiosk_dbpasswd,
                    self.config.kiosk_dbhost,
                    self.config.kiosk_dbport,
                    self.config.kiosk_dbname,
                    self.config.charset,
                ),
                pool_recycle=self.config.kiosk_dbpoolrecycle,
                pool_size=self.config.kiosk_dbpoolsize,
                pool_timeout=self.config.kiosk_dbpooltimeout,
                convert_unicode=True,
            )
            self.Sessionkiosk = sessionmaker(bind=self.engine_kiosk_base)

            Base = automap_base()
            Base.prepare(self.engine_kiosk_base, reflect=True)

            # Only federated tables (beginning by local_) are automatically mapped
            # If needed, excludes tables from this list
            exclude_table = []
            # Dynamically add attributes to the object for each mapped class
            for table_name, mapped_class in Base.classes.items():
                if table_name in exclude_table:
                    continue
                if table_name.startswith("local"):
                    setattr(self, table_name.capitalize(), mapped_class)

            self.is_activated = True
            self.logger.debug("kiosk finish activation")
            return True
        except Exception:
            self.logger.error("We failed to connect to the Kiosk database.")
            self.logger.error("Please verify your configuration")
            self.is_activated = False
            return False

    def _fetch(self, statement, params=None):
        """Column names and rows of a query, run on a session of its own."""
        session = scoped_session(sessionmaker(bind=self.engine_kiosk_base))
        try:
            result = session.execute(statement, params or {})
            return list(result.keys()), result.fetchall()
        finally:
            session.remove()

    def get_profiles_of_machine(self, uuid_inventorymachine):
        """
        Active profiles of the GLPI entity of a machine and of the entities
        above it.

        Returns:
            list of (profile id, source, value); one row per value of the
            profile, value None when it has none.
        """
        _, rows = self._fetch(text(PROFILES_SQL), {"uuid": uuid_inventorymachine})
        return [(row[0], row[1], row[2]) for row in rows]

    def get_packages_of_profiles(self, profile_ids):
        """Packages of the given profiles, each one once."""
        if not profile_ids:
            return []
        statement = text(PACKAGES_SQL).bindparams(
            bindparam("profile_ids", expanding=True)
        )
        keys, rows = self._fetch(statement, {"profile_ids": list(profile_ids)})
        return [dict(zip(keys, row)) for row in rows]

    def get_kiosk_machines(self, entity_ids=None):
        """
        Jids of the online machines with a kiosk.

        Args:
            entity_ids: GLPI entities; only their machines and those of the
                entities below them are returned. Empty: every machine.
        """
        if not entity_ids:
            _, rows = self._fetch(text(MACHINES_SQL % ""))
        else:
            statement = text(MACHINES_SQL % ENTITIES_JOIN_SQL).bindparams(
                bindparam("entity_ids", expanding=True)
            )
            _, rows = self._fetch(statement, {"entity_ids": list(entity_ids)})
        return [row[0] for row in rows]


def _platform(name):
    """Platform key of the packages for the operating system of a machine."""
    name = name or ""
    if not name or re.match("Microsoft", name, re.I):
        return "win"
    if re.match("Darwin", name, re.I) or re.match("mac", name, re.I):
        return "mac"
    return "linux"


def _ou_path(value):
    """OU reported by a machine (A@@B@@C) in the form stored in the profiles (A/B/C)."""
    return (value or "").replace("\n", "").replace("\r", "").replace("@@", "/")


def _ou_applies(machine_ou, profile_ou):
    """True when the OU of the machine is the OU of the profile or below it."""
    if not machine_ou or not profile_ou:
        return False
    return machine_ou == profile_ou or machine_ou.startswith(profile_ou + "/")


def _applying_profiles(profiles, values):
    """
    Ids of the profiles applying to a machine.

    Args:
        profiles: rows of get_profiles_of_machine
        values: {source: values of the machine}; a source without value
            matches no profile
    """
    profile_ids = set()
    for profile_id, source, value in profiles:
        if source == "entity":
            profile_ids.add(profile_id)
        elif source in ("ou_user", "ou_machine"):
            if any(_ou_applies(ou, value) for ou in values.get(source, ())):
                profile_ids.add(profile_id)
    return profile_ids


def _machine_values(machine):
    """Values of the machine for the sources restricting a profile."""
    return {
        "ou_user": [_ou_path(machine.get("ad_ou_user"))],
        "ou_machine": [_ou_path(machine.get("ad_ou_machine"))],
    }


def _descriptor(package_uuid):
    """xmppdeploy.json of a package: None when unreadable, {} when invalid."""
    path = os.path.join(managepackage.packagedir(), package_uuid, "xmppdeploy.json")
    try:
        with open(path, "r") as descriptor:
            return json.load(descriptor)
    except OSError:
        return None
    except ValueError:
        return {}


def _has_section(descriptor, platform, label, prefix):
    labels = descriptor.get("metaparameter", {}).get(platform, {}).get("label", [])
    return any(name == label or name.startswith(prefix) for name in labels)


def _uninstall_has_content(descriptor, platform):
    """True when the uninstall section holds a real command or script."""
    in_section = False
    for step in descriptor.get(platform, {}).get("sequence", []):
        step_action = step.get("action", "")
        if step_action == "action_section_uninstall":
            in_section = True
        elif step_action in ("actionsuccescompletedend", "actionerrorcompletedend"):
            in_section = False
        elif in_section and (
            str(step.get("command", "")).strip() or str(step.get("script", "")).strip()
        ):
            return True
    return False


def _version_key(version):
    return [
        (0, int(part)) if part.isdigit() else (1, part)
        for part in re.split(r"[.\-_+ ]", str(version or ""))
    ]


def get_packages_for_machine(machine):
    """
    Packages the kiosk of a machine offers, in the form its agent expects.

    A profile applies to the machines of its entity and of the entities below
    it, restricted by its source: none for "entity", the OU of the machine or
    of its user at or below one OU of the profile for "ou_machine" and
    "ou_user". The other sources ("group", "ldap") match no machine.

    Args:
        machine: dict of XmppMasterDatabase().getMachinefromjid()

    Returns:
        list of dicts, one per package
    """
    uuid_inventorymachine = machine.get("uuid_inventorymachine")
    if not uuid_inventorymachine:
        return []

    database = KioskDatabase()
    profiles = database.get_profiles_of_machine(uuid_inventorymachine)
    profile_ids = _applying_profiles(profiles, _machine_values(machine))

    platform = _platform(machine.get("platform"))
    packages = []
    for pkg in database.get_packages_of_profiles(profile_ids):
        if platform not in (pkg["os"] or ""):
            continue
        descriptor = _descriptor(pkg["uuid"])
        if descriptor is None:
            continue

        launcher = descriptor.get("info", {}).get("launcher", "")
        uninstall = _has_section(
            descriptor, platform, "label_section_uninstall", "Uninst_"
        ) and _uninstall_has_content(descriptor, platform)
        update = _has_section(descriptor, platform, "label_section_update", "upd_")

        found = Glpi().find_software_info_for_machine(
            machine.get("uuid_inventorymachine"),
            {
                "software": pkg["software"] or "",
                "version_software": pkg["version_software"] or "",
                "vendor": pkg["vendor"] or "",
            },
        )
        installed = bool(found)

        if not installed:
            actions = ["Install"]
        else:
            actions = []
            if launcher != "":
                actions.append("Launch")
            if uninstall:
                actions.append("Delete")
            if update and _version_key(found[0]["version"]) < _version_key(
                pkg["version_software"]
            ):
                actions.append("Update")
            if not uninstall:
                actions.append("Installed")

        packages.append(
            {
                "icon": "kiosk.png",
                "right": "allowed",
                "launcher": launcher,
                "uninstall": uninstall,
                "update": update,
                "installed": installed,
                "uuid": pkg["uuid"],
                "version_software": pkg["version_software"],
                "vendor": pkg["vendor"],
                "version": pkg["version"],
                "software": pkg["software"],
                "description": pkg["description"],
                "name": pkg["name"],
                "action": actions,
            }
        )
    return packages


def send_packages(xmppobject, machine, subaction, sessionid=None):
    """
    Send to the kiosk of a machine the packages it offers.

    Nothing is sent when the packages cannot be computed: an empty list would
    empty the kiosk.

    Args:
        machine: dict of XmppMasterDatabase().getMachinefromjid()
        subaction: "initialisation_kiosk" or "profiles_updated"

    Returns:
        True when the message is sent
    """
    if not machine or not machine.get("jid"):
        return False
    try:
        packages = get_packages_for_machine(machine)
    except Exception:
        logger.error(
            "kiosk: packages of %s not computed\n%s"
            % (machine["jid"], traceback.format_exc())
        )
        return False
    message = {
        "action": "kiosk",
        "sessionid": sessionid or getRandomName(6, subaction),
        "data": {"subaction": subaction, "data": packages},
    }
    if subaction == "initialisation_kiosk":
        message["ret"] = 0
        message["base64"] = False
    xmppobject.send_message(
        mto=machine["jid"], mbody=json.dumps(message), mtype="chat"
    )
    return True
