# SPDX-FileCopyrightText: 2016-2023 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-3.0-or-later
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
)
from sqlalchemy.orm import sessionmaker, Query, scoped_session, mapper
from sqlalchemy.ext.automap import automap_base
import functools

from lib.configuration import confParameter

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
            session_factory = sessionmaker(bind=self.engine_admin_base)
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
            self.engine_admin_base = create_engine(
                "mysql://%s:%s@%s:%s/%s"
                % (
                    self.config.admin_dbuser,
                    self.config.admin_dbpasswd,
                    self.config.admin_dbhost,
                    self.config.admin_dbport,
                    self.config.admin_dbname,
                ),
                pool_recycle=self.poolsize,
                pool_size=self.poolsize,
                echo=self.config.admin_dbechoquery,
                convert_unicode=True,
            )

            self.metadata = MetaData(self.engine_admin_base)
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
        self.base.prepare(self.engine_admin_base, reflect=True)
        try:
            # automap table
            self.upd_list = self.base.classes.upd_list
            self.upd_method = self.base.classes.upd_method
            self.upd_msg_send = self.base.classes.upd_msg_send
            self.upd_package = self.base.classes.upd_package
            self.upd_package_unknown = self.base.classes.upd_package_unknown
            self.upd_rules = self.base.classes.upd_rules
            self.upd_list_pakage = self.base.classes.upd_list_pakage

            self.version = Table("version", self.metadata, autoload=True)

            return True
        except Exception:
            self.logger.error("\n%s" % (traceback.format_exc()))
            return False

    @DatabaseHelper._sessionm
    def get_upd_list(self, session):
        resultproxy = session.query(self.upd_list).all()
        return [
            {column: value for column, value in rowproxy.items()}
            for rowproxy in resultproxy
        ]

    @DatabaseHelper._sessionm
    def get_upd_method(self, session):
        resultproxy = session.query(self.upd_method).all()
        return [
            {column: value for column, value in rowproxy.items()}
            for rowproxy in resultproxy
        ]

    @DatabaseHelper._sessionm
    def get_upd_msg_send(self, session):
        resultproxy = session.query(self.upd_msg_send).all()
        return [
            {column: value for column, value in rowproxy.items()}
            for rowproxy in resultproxy
        ]

    @DatabaseHelper._sessionm
    def get_upd_package(self, session):
        resultproxy = session.query(self.upd_package).all()
        return [
            {column: value for column, value in rowproxy.items()}
            for rowproxy in resultproxy
        ]

    @DatabaseHelper._sessionm
    def get_upd_rules(self, session):
        resultproxy = session.query(self.upd_rules).all()
        return [
            {column: value for column, value in rowproxy.items()}
            for rowproxy in resultproxy
        ]

    @DatabaseHelper._sessionm
    def get_upd_list_pakage(self, session):
        resultproxy = session.query(self.upd_list_pakage).all()
        return [
            {column: value for column, value in rowproxy.items()}
            for rowproxy in resultproxy
        ]
