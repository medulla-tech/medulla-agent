# -*- coding: utf-8; -*-
# SPDX-FileCopyrightText: 2018-2023 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-3.0-or-later

"""
Mastering database handler
"""
# SqlAlchemy
from sqlalchemy import create_engine, func, and_, or_
from sqlalchemy.orm import sessionmaker
from sqlalchemy.exc import DBAPIError

# PULSE2 modules
# from mmc.database.database_helper import DatabaseHelper
# from mmc.plugins.pkgs import get_xmpp_package, xmpp_packages_list, package_exists
# from lib.plugins.imaging.schema import (
#     Profiles,
#     Packages,
#     Profile_has_package,
#     Profile_has_ou,
#     Acknowledgements,
# )

# Imported last
import logging
import time
from lib.configuration import confParameter
import functools
from datetime import datetime

try:
    from sqlalchemy.orm.util import _entity_descriptor
except ImportError:
    from sqlalchemy.orm.base import _entity_descriptor

from sqlalchemy.orm import scoped_session
from sqlalchemy.ext.automap import automap_base

Session = sessionmaker()


logger = logging.getLogger()


class Singleton(object):
    def __new__(type, *args):
        if "_the_instance" not in type.__dict__:
            type._the_instance = object.__new__(type)

        return type._the_instance


class DatabaseHelper(Singleton):
    # Session decorator to create and close session automatically
    @classmethod
    def _sessionmastering(self, func):
        @functools.wraps(func)
        def __session(self, *args, **kw):
            created = False
            if not self.sessionmastering:
                self.sessionmastering = sessionmaker(bind=self.engine_mastering_base)
                created = True
            result = func(self, self.session, *args, **kw)
            if created:
                self.sessionmastering.close()
                self.sessionmastering = None
            return result

        return __session

    # Session decorator to create and close session automatically
    @classmethod
    def _sessionm(self, func):
        @functools.wraps(func)
        def __sessionm(self, *args, **kw):
            session_factory = sessionmaker(bind=self.engine_mastering_base)
            sessionmultithread = scoped_session(session_factory)
            result = func(self, sessionmultithread, *args, **kw)
            sessionmultithread.remove()
            return result

        return __sessionm


class DiskMasteringDatabase(DatabaseHelper):
    """
    Singleton Class to query the mastering database.

    """
    is_activated = False

    def activate(self):  # jid, password, room, nick):
        if self.is_activated:
            return None
        self.logger = logging.getLogger()
        self.logger.debug("mastering activation")
        self.engine = None
        self.sessionxmpp = None
        self.sessionglpi = None
        self.sessionmastering = None
        self.config = confParameter()
        self.logger.info(
            "mastering parameters connections is "
            " user = %s,host = %s, port = %s, schema = %s,"
            " poolrecycle = %s, poolsize = %s, pooltimeout %s"
            % (
                self.config.diskmastering_dbuser,
                self.config.diskmastering_dbhost,
                self.config.diskmastering_dbport,
                self.config.diskmastering_dbname,
                self.config.diskmastering_dbpoolrecycle,
                self.config.diskmastering_dbpoolsize,
                self.config.diskmastering_dbpooltimeout,
            )
        )

        try:
            self.engine_mastering_base = create_engine(
                "mysql://%s:%s@%s:%s/%s?charset=%s"
                % (
                    self.config.diskmastering_dbuser,
                    self.config.diskmastering_dbpasswd,
                    self.config.diskmastering_dbhost,
                    self.config.diskmastering_dbport,
                    self.config.diskmastering_dbname,
                    self.config.charset,
                ),
                pool_recycle=self.config.diskmastering_dbpoolrecycle,
                pool_size=self.config.diskmastering_dbpoolsize,
                pool_timeout=self.config.diskmastering_dbpooltimeout,
                convert_unicode=True,
            )
            self.sessionmastering = sessionmaker(bind=self.engine_mastering_base)

            Base = automap_base()
            Base.prepare(self.engine_mastering_base, reflect=True)

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
            self.logger.debug("mastering finish activation")
            return True
        except Exception as e:
            self.logger.error("We failed to connect to the mastering database.")
            self.logger.error("Please verify your configuration")
            self.is_activated = False
            return False

    def initMappers(self):
        """
        Initialize all SQLalchemy mappers needed for the mastering database
        """
        # No mapping is needed, all is done on schema file
        return

    def getDbConnection(self):
        NB_DB_CONN_TRY = 2
        ret = None
        for i in range(NB_DB_CONN_TRY):
            try:
                ret = self.db.connect()
            except DBAPIError as e:
                logging.getLogger().error(e)
            except Exception as e:
                logging.getLogger().error(e)
            if ret:
                break
        if not ret:
            raise Exception("Database mastering connection error")
        return ret


    @DatabaseHelper._sessionm
    def get_action_details(self, session, action_id):
        sql = """SELECT * from actions where id = %s"""%action_id
        query = session.execute(sql).all()

        if query == None:
            return {}

        result = {}
        for e in query:
            result["id"] = e.id
            result["server_id"] = e.server_id
            result["gid"] = e.gid
            result["uuid"] = e.uuid
            result["session_id"] = e.session_id
            result["name"] = e.name
            result["config"] = e.config
            result["content"] = e.content
            result["status"] = e.status
            result["date_creation"] = e.date_creation
            result["date_start"] = e.date_start
            result["date_end"] = e.date_end

        return result

    @DatabaseHelper._sessionm
    def push_log(self, session, session_id, action_id, uuid, log="", date=None):
        if date is None:
            sql = """INSERT INTO results (action_id, session_id, uuid, content) VALUES(:action_id, :session_id, :uuid, :content)"""
            bindings = {"action_id": action_id, "session_id": session_id, "uuid": uuid, "content": log}
        else:
            sql = """INSERT INTO results (action_id, session_id, uuid, content, creation_date) VALUES(:action_id, :session_id, :uuid, :content, :creation_date)"""
            bindings = {
                "action_id": action_id,
                "uuid": uuid,
                "content": log,
                "creation_date": date,
                "session_id": session_id,
            }
        try:
            session.execute(sql, bindings)
            session.commit()
            session.flush()
        except Exception as e:
            logging.getLogger().error(e)
        return
