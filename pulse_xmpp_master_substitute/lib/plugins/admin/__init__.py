# SPDX-FileCopyrightText: 2016-2023 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-3.0-or-later
# file : pulse_xmpp_master_substitute/lib/plugins/admin/__init__.py
from configparser import ConfigParser
import logging

from sqlalchemy import (
    create_engine,
    MetaData,
    select,
    func,
    and_,
    desc,
    or_,
    distinct,
    not_,
    Table,
    Column,
    Integer,
    ForeignKey,
    text,
    inspect,
)
from sqlalchemy.orm import sessionmaker, Query, scoped_session, Session
from sqlalchemy.ext.automap import automap_base
import functools

from pulse_xmpp_master_substitute.lib.configuration import confParameter

import traceback

logger = logging.getLogger()


class Singleton(object):
    def __new__(type, *args):
        if "_the_instance" not in type.__dict__:
            type._the_instance = object.__new__(type)
        return type._the_instance


class DatabaseHelper(Singleton):
    # Session decorator to create and close session automatically
    @classmethod
    def _sessionm(self, func):
        @functools.wraps(func)
        def __sessionm(self, *args, **kw):
            session_factory = sessionmaker(bind=self.engine_admin_base, expire_on_commit=False)
            sessionmultithread = scoped_session(session_factory)
            result = func(self, sessionmultithread, *args, **kw)
            sessionmultithread.remove()
            return result

        return __sessionm


class AdminDatabase(DatabaseHelper):
    is_activated = False

    def activate(self):
        if self.is_activated:
            return None

        self.logger = logging.getLogger()
        self.Sessionadmin = None
        self.logger.info("Admin database is connecting")
        self.config = confParameter()

        try:
            self.config.admin_dbpoolrecycle
            self.poolrecycle = self.config.admin_dbpoolrecycle
        except Exception:
            self.poolrecycle = self.config.dbpoolrecycle

        try:
            self.config.admin_dbpoolsize
            self.poolsize = self.config.admin_dbpoolsize
        except Exception:
            self.poolsize = self.config.dbpoolsize

        self.logger.info(
            "Admin parameters connections is "
            " user = %s,host = %s, port = %s, schema = %s,"
            " poolrecycle = %s, poolsize = %s, pool_timeout %s,"
            " echo sql query = %s"
            % (
                self.config.admin_dbuser,
                self.config.admin_dbhost,
                self.config.admin_dbport,
                self.config.admin_dbname,
                self.config.admin_dbpoolrecycle,
                self.config.admin_dbpoolsize,
                self.config.admin_dbpooltimeout,
                self.config.admin_dbechoquery,
            )
        )
        try:
            self.base = automap_base()
            # NOTE: explicit driver in the URL (pymysql here — swap for
            # mysqldb/mysqlconnector if that's what you have installed).
            # "mysql://" alone no longer has a safe implicit default to rely on.
            self.engine_admin_base = create_engine(
                "mysql+pymysql://%s:%s@%s:%s/%s"
                % (
                    self.config.admin_dbuser,
                    self.config.admin_dbpasswd,
                    self.config.admin_dbhost,
                    self.config.admin_dbport,
                    self.config.admin_dbname,
                ),
                pool_recycle=self.poolrecycle,
                pool_size=self.poolsize,
                echo=self.config.admin_dbechoquery,
                # convert_unicode was removed in modern SQLAlchemy — unicode
                # handling is automatic now, so the argument is simply dropped.
            )

            # MetaData no longer accepts a bound engine.
            self.metadata = MetaData()
            self.Sessionadmin = sessionmaker(bind=self.engine_admin_base)

            self.is_activated = True
            self.logger.debug("Admin activation done")
            if self.map() is True:
                self.logger.debug("Admin mapping done")
            else:
                self.logger.error("Admin mapping failed")
            return True
        except Exception as e:
            self.logger.error("We failed to connect to the Admin database.")
            self.logger.error("Please verify your configuration")
            # self.logger.error(e)
            self.is_activated = False
            return False

    def map(self):
        # engine=... / reflect=True is deprecated in favor of autoload_with.
        self.base.prepare(autoload_with=self.engine_admin_base)

        # Federated tables
        # If needed, excludes tables from this list
        exclude_table = []
        # Dynamically add attributes to the object for each mapped class
        for table_name, mapped_class in self.base.classes.items():
            if table_name in exclude_table:
                continue
            if table_name.startswith("local"):
                setattr(self, table_name.capitalize(), mapped_class)

        try:
            # automap table
            self.upd_list = self.base.classes.upd_list
            self.upd_method = self.base.classes.upd_method
            self.upd_msg_send = self.base.classes.upd_msg_send
            self.upd_package = self.base.classes.upd_package
            self.upd_package_unknown = self.base.classes.upd_package_unknown
            self.upd_rules = self.base.classes.upd_rules
            self.upd_list_pakage = self.base.classes.upd_list_pakage

            # autoload=True -> autoload_with=<engine or connection>
            self.version = Table(
                "version", self.metadata, autoload_with=self.engine_admin_base
            )

            return True
        except Exception:
            self.logger.error("\n%s" % (traceback.format_exc()))
            return False

    @staticmethod
    def _row_to_dict(row):
        """Replacement for the old (pre-0.5) mapped-instance .items() behavior.

        automap gives you real ORM instances, which no longer support
        dict-style .items()/.keys() like they did in very old SQLAlchemy.
        Rebuild the dict from the instance's mapped columns instead.
        """
        return {
            c.key: getattr(row, c.key) for c in inspect(row).mapper.column_attrs
        }

    @DatabaseHelper._sessionm
    def get_upd_list(self, session):
        resultproxy = session.query(self.upd_list).all()
        return [self._row_to_dict(row) for row in resultproxy]

    @DatabaseHelper._sessionm
    def get_upd_method(self, session):
        resultproxy = session.query(self.upd_method).all()
        return [self._row_to_dict(row) for row in resultproxy]

    @DatabaseHelper._sessionm
    def get_upd_msg_send(self, session):
        resultproxy = session.query(self.upd_msg_send).all()
        return [self._row_to_dict(row) for row in resultproxy]

    @DatabaseHelper._sessionm
    def get_upd_package(self, session):
        resultproxy = session.query(self.upd_package).all()
        return [self._row_to_dict(row) for row in resultproxy]

    @DatabaseHelper._sessionm
    def get_upd_rules(self, session):
        resultproxy = session.query(self.upd_rules).all()
        return [self._row_to_dict(row) for row in resultproxy]

    @DatabaseHelper._sessionm
    def get_upd_list_pakage(self, session):
        resultproxy = session.query(self.upd_list_pakage).all()
        return [self._row_to_dict(row) for row in resultproxy]

    @DatabaseHelper._sessionm
    def _ensure_inventory_entity_rules_table(self, session):
        """Create the global inventory tag->entity rules table in admin schema."""
        session.execute(
            text(
                """
                CREATE TABLE IF NOT EXISTS admin_inventory_entity_rules (
                  id INT AUTO_INCREMENT PRIMARY KEY,
                  enabled TINYINT(1) NOT NULL DEFAULT 1,
                  rule_name VARCHAR(190) NOT NULL DEFAULT '',
                  tag_name VARCHAR(100) NOT NULL DEFAULT 'TAG',
                  tag_value VARCHAR(255) NOT NULL,
                  entity_id INT NOT NULL,
                  priority INT NOT NULL DEFAULT 100,
                  stop_on_match TINYINT(1) NOT NULL DEFAULT 1,
                  comment VARCHAR(255) NOT NULL DEFAULT '',
                  created_by VARCHAR(100) NOT NULL DEFAULT 'root',
                  updated_by VARCHAR(100) NOT NULL DEFAULT 'root',
                  created_at DATETIME NOT NULL,
                  updated_at DATETIME NOT NULL,
                  UNIQUE KEY uniq_tag_rule (tag_name, tag_value, priority),
                  KEY idx_tag_rule_lookup (enabled, tag_name, tag_value, priority)
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4
                """
            )
        )
        session.commit()
        return True

    def ensure_inventory_entity_rules_schema(self):
        """Ensure the admin global rules schema for inventory entity mapping exists."""
        if not self.is_activated:
            self.activate()
        if not self.is_activated:
            return False
        return self._ensure_inventory_entity_rules_table()

    @DatabaseHelper._sessionm
    def resolve_inventory_entity_rule(self, session, tag_name, tag_value):
        """Resolve target entity from global admin rules for an inventory tag."""
        self._ensure_inventory_entity_rules_table()
        row = session.execute(
            text(
                """
                SELECT id, entity_id, rule_name, priority
                FROM admin_inventory_entity_rules
                WHERE enabled = 1
                  AND tag_name = :tag_name
                  AND tag_value = :tag_value
                ORDER BY priority ASC, id ASC
                LIMIT 1
                """
            ),
            {"tag_name": tag_name, "tag_value": tag_value},
        ).fetchone()
        if not row:
            return None
        return {
            "id": int(row[0]),
            "entity_id": int(row[1]),
            "rule_name": str(row[2] or ""),
            "priority": int(row[3]),
        }

    @DatabaseHelper._sessionm
    def list_inventory_entity_rules(self, session, enabled_only=False):
        """List global inventory entity rules for root admin interface."""
        self._ensure_inventory_entity_rules_table()
        where_clause = "WHERE enabled = 1" if enabled_only else ""
        rows = session.execute(
            text(
                f"""
                SELECT id, enabled, rule_name, tag_name, tag_value, entity_id,
                       priority, stop_on_match, comment, created_by, updated_by,
                       created_at, updated_at
                FROM admin_inventory_entity_rules
                {where_clause}
                ORDER BY priority ASC, id ASC
                """
            )
        ).fetchall()
        return [
            {
                "id": int(row[0]),
                "enabled": int(row[1]),
                "rule_name": str(row[2] or ""),
                "tag_name": str(row[3] or ""),
                "tag_value": str(row[4] or ""),
                "entity_id": int(row[5]),
                "priority": int(row[6]),
                "stop_on_match": int(row[7]),
                "comment": str(row[8] or ""),
                "created_by": str(row[9] or ""),
                "updated_by": str(row[10] or ""),
                "created_at": str(row[11]),
                "updated_at": str(row[12]),
            }
            for row in rows
        ]

    @DatabaseHelper._sessionm
    def upsert_inventory_entity_rule(
        self,
        session,
        tag_name,
        tag_value,
        entity_id,
        priority=100,
        rule_name="",
        stop_on_match=1,
        enabled=1,
        comment="",
        admin_user="root",
    ):
        """Create or update a global inventory entity rule (root admin API)."""
        self._ensure_inventory_entity_rules_table()
        session.execute(
            text(
                """
                INSERT INTO admin_inventory_entity_rules
                  (enabled, rule_name, tag_name, tag_value, entity_id, priority,
                   stop_on_match, comment, created_by, updated_by, created_at, updated_at)
                VALUES
                  (:enabled, :rule_name, :tag_name, :tag_value, :entity_id, :priority,
                   :stop_on_match, :comment, :created_by, :updated_by, NOW(), NOW())
                ON DUPLICATE KEY UPDATE
                  enabled = VALUES(enabled),
                  rule_name = VALUES(rule_name),
                  entity_id = VALUES(entity_id),
                  stop_on_match = VALUES(stop_on_match),
                  comment = VALUES(comment),
                  updated_by = VALUES(updated_by),
                  updated_at = NOW()
                """
            ),
            {
                "enabled": int(enabled),
                "rule_name": rule_name,
                "tag_name": tag_name,
                "tag_value": tag_value,
                "entity_id": int(entity_id),
                "priority": int(priority),
                "stop_on_match": int(stop_on_match),
                "comment": comment,
                "created_by": admin_user,
                "updated_by": admin_user,
            },
        )
        session.commit()
        return True

    @DatabaseHelper._sessionm
    def set_inventory_entity_rule_enabled(self, session, rule_id, enabled, admin_user="root"):
        """Enable or disable an existing global inventory entity rule."""
        self._ensure_inventory_entity_rules_table()
        session.execute(
            text(
                """
                UPDATE admin_inventory_entity_rules
                SET enabled = :enabled,
                    updated_by = :updated_by,
                    updated_at = NOW()
                WHERE id = :rule_id
                """
            ),
            {
                "enabled": int(enabled),
                "updated_by": admin_user,
                "rule_id": int(rule_id),
            },
        )
        session.commit()
        return True

    @DatabaseHelper._sessionm
    def delete_inventory_entity_rule(self, session, rule_id):
        """Delete a global inventory entity rule by identifier."""
        self._ensure_inventory_entity_rules_table()
        session.execute(
            text(
                """
                DELETE FROM admin_inventory_entity_rules
                WHERE id = :rule_id
                """
            ),
            {"rule_id": int(rule_id)},
        )
        session.commit()
        return True


AdminMasterDatabase = AdminDatabase
