# -*- coding: utf-8; -*-
# SPDX-FileCopyrightText: 2004-2007 Linbox / Free&ALter Soft, http://linbox.com
# SPDX-FileCopyrightText: 2007-2010 Mandriva, http://www.mandriva.com
# SPDX-FileCopyrightText: 2016-2023 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-3.0-or-later

"""
Provides access to PKGS database
"""
import traceback
import os

# SqlAlchemy
from sqlalchemy import (
    and_,
    create_engine,
    MetaData,
    Table,
    asc,
    desc,
    distinct,
)
from sqlalchemy.orm import create_session, mapper
from sqlalchemy.exc import NoSuchTableError
from sqlalchemy.orm import sessionmaker
from sqlalchemy.orm import scoped_session
from sqlalchemy.ext.automap import automap_base

# ORM mappings
from lib.plugins.pkgs.orm.dependencies import Dependencies
from lib.plugins.pkgs.orm.extensions import Extensions
from lib.plugins.pkgs.orm.package_pending_exclusions import Package_pending_exclusions
from lib.plugins.pkgs.orm.packages import Packages
from lib.plugins.pkgs.orm.syncthingsync import Syncthingsync
from lib.plugins.pkgs.orm.pkgs_rules_algos import Pkgs_rules_algos
from lib.plugins.pkgs.orm.pkgs_rules_global import Pkgs_rules_global
from lib.plugins.pkgs.orm.pkgs_rules_local import Pkgs_rules_local
from lib.plugins.pkgs.orm.pkgs_shares_ars import Pkgs_shares_ars
from lib.plugins.pkgs.orm.pkgs_shares_ars_web import Pkgs_shares_ars_web
from lib.plugins.pkgs.orm.pkgs_shares import Pkgs_shares

from lib.configuration import confParameter
from lib.plugins.xmpp import XmppMasterDatabase

# Imported last
import logging
import functools

logger = logging.getLogger()
NB_DB_CONN_TRY = 2


class Singleton(object):
    def __new__(type, *args):
        if "_the_instance" not in type.__dict__:
            type._the_instance = object.__new__(type)
        return type._the_instance


class DatabaseHelper(Singleton):
    # Session decorator to create and close session automatically
    @classmethod
    def _sessionm(self, func1):
        @functools.wraps(func1)
        def __sessionm(self, *args, **kw):
            session_factory = sessionmaker(bind=self.engine_pkgsmmaster_base)
            sessionmultithread = scoped_session(session_factory)
            result = func1(self, sessionmultithread, *args, **kw)
            sessionmultithread.remove()
            return result

        return __sessionm


# TODO need to check for useless function (there should be many unused one...)


class PkgsDatabase(DatabaseHelper):
    """
    Singleton Class to query the pkgs database.

    """

    is_activated = False

    def activate(self):
        self.logger = logging.getLogger()
        if self.is_activated:
            return None
        self.logger.info("Pkgs database is connecting")
        self.config = confParameter()

        self.session = None
        self.logger.info(
            "Msc parameters connections is "
            " user = %s,host = %s, port = %s, schema = %s,"
            " poolrecycle = %s, poolsize = %s, pool_timeout %s"
            % (
                self.config.pkgs_dbuser,
                self.config.pkgs_dbhost,
                self.config.pkgs_dbport,
                self.config.pkgs_dbname,
                self.config.pkgs_dbpoolrecycle,
                self.config.pkgs_dbpoolsize,
                self.config.pkgs_dbpooltimeout,
            )
        )

        try:
            self.engine_pkgsmmaster_base = create_engine(
                "mysql://%s:%s@%s:%s/%s?charset=%s"
                % (
                    self.config.pkgs_dbuser,
                    self.config.pkgs_dbpasswd,
                    self.config.pkgs_dbhost,
                    self.config.pkgs_dbport,
                    self.config.pkgs_dbname,
                    self.config.charset,
                ),
                pool_recycle=self.config.pkgs_dbpoolrecycle,
                pool_size=self.config.pkgs_dbpoolsize,
                pool_timeout=self.config.pkgs_dbpooltimeout,
                convert_unicode=True,
            )

            self.metadata = MetaData(self.engine_pkgsmmaster_base)
            if not self.initTables():
                return False

            self.initMappers()
            self.metadata.create_all()
            # FIXME: should be removed
            self.session = create_session(bind=self.engine_pkgsmmaster_base)
            if self.session is not None:
                self.is_activated = True
                return True
            self.logger.error("Pkgs database connecting")
            return False
        except Exception as e:
            self.logger.error("We failed to connect to the Pkgs database.")
            self.logger.error("Please verify your configuration")
            self.is_activated = False
            return False

    def initTables(self):
        """
        Initialize all SQLalchemy tables
        """
        try:
            # packages
            self.package = Table("packages", self.metadata, autoload=True)

            # extensions
            self.extensions = Table("extensions", self.metadata, autoload=True)

            # Dependencies
            self.dependencies = Table("dependencies", self.metadata, autoload=True)

            # Syncthingsync
            self.syncthingsync = Table("syncthingsync", self.metadata, autoload=True)
            # package_pending_exclusions
            self.package_pending_exclusions = Table(
                "package_pending_exclusions", self.metadata, autoload=True
            )

            # pkgs_shares_ars_web
            self.pkgs_shares_ars_web = Table(
                "pkgs_shares_ars_web", self.metadata, autoload=True
            )

            # pkgs_shares_ars
            self.pkgs_shares_ars = Table(
                "pkgs_shares_ars", self.metadata, autoload=True
            )

            # pkgs_shares
            self.pkgs_shares = Table("pkgs_shares", self.metadata, autoload=True)

            # pkgs_rules_algos
            self.pkgs_rules_algos = Table(
                "pkgs_rules_algos", self.metadata, autoload=True
            )

            # pkgs_rules_global
            self.pkgs_rules_global = Table(
                "pkgs_rules_global", self.metadata, autoload=True
            )

            # pkgs_rules_local
            self.pkgs_rules_local = Table(
                "pkgs_rules_local", self.metadata, autoload=True
            )
        except NoSuchTableError as e:
            self.logger.error(
                "Cant load the Pkgs database : table '%s' does not exists"
                % (str(e.args[0]))
            )
            return False
        return True

    def initMappers(self):
        """
        Initialize all SQLalchemy mappers needed for the Pkgs database
        """

        Base = automap_base()
        Base.prepare(self.engine_pkgsmmaster_base, reflect=True)

        # Only federated tables (beginning by local_) are automatically mapped
        # If needed, excludes tables from this list
        exclude_table = []
        # Dynamically add attributes to the object for each mapped class
        for table_name, mapped_class in Base.classes.items():
            if table_name in exclude_table:
                continue
            if table_name.startswith("local"):
                setattr(self, table_name.capitalize(), mapped_class)

        mapper(Packages, self.package)
        mapper(Extensions, self.extensions)
        mapper(Dependencies, self.dependencies)
        mapper(Syncthingsync, self.syncthingsync)
        mapper(Package_pending_exclusions, self.package_pending_exclusions)
        mapper(Pkgs_shares, self.pkgs_shares)
        mapper(Pkgs_shares_ars, self.pkgs_shares_ars)
        mapper(Pkgs_shares_ars_web, self.pkgs_shares_ars_web)
        mapper(Pkgs_rules_algos, self.pkgs_rules_algos)
        mapper(Pkgs_rules_global, self.pkgs_rules_global)
        mapper(Pkgs_rules_local, self.pkgs_rules_local)

    ####################################

    @DatabaseHelper._sessionm
    def createPackage(self, session, package, pkgs_share_id=None, edition_status=1):
        """
        Insert the package config into database.
        Param:
            package : dict of the historical config of the package
        Returns:
            Packages object
        """

        request = session.query(Packages).filter(Packages.uuid == package["id"]).first()

        if request is None:
            new_package = Packages()
        else:
            new_package = request

        new_package.label = package["name"]
        new_package.uuid = package["id"]
        new_package.description = package["description"]
        new_package.version = package["version"]
        new_package.os = package["targetos"]
        new_package.metagenerator = package["metagenerator"]
        new_package.entity_id = package["entity_id"]
        if isinstance(package["sub_packages"], str):
            new_package.sub_packages = package["sub_packages"]
        elif isinstance(package["sub_packages"], list):
            new_package.sub_packages = ",".join(package["sub_packages"])
        new_package.reboot = package["reboot"]
        new_package.inventory_associateinventory = package["inventory"][
            "associateinventory"
        ]
        new_package.inventory_licenses = package["inventory"]["licenses"]
        new_package.Qversion = package["inventory"]["queries"]["Qversion"]
        new_package.Qvendor = package["inventory"]["queries"]["Qvendor"]
        new_package.Qsoftware = package["inventory"]["queries"]["Qsoftware"]
        new_package.boolcnd = package["inventory"]["queries"]["boolcnd"]
        new_package.postCommandSuccess_command = package["commands"][
            "postCommandSuccess"
        ]["command"]
        new_package.postCommandSuccess_name = package["commands"]["postCommandSuccess"][
            "name"
        ]
        new_package.installInit_command = package["commands"]["installInit"]["command"]
        new_package.installInit_name = package["commands"]["installInit"]["name"]
        new_package.postCommandFailure_command = package["commands"][
            "postCommandFailure"
        ]["command"]
        new_package.postCommandFailure_name = package["commands"]["postCommandFailure"][
            "name"
        ]
        new_package.command_command = package["commands"]["command"]["command"]
        new_package.command_name = package["commands"]["command"]["name"]
        new_package.preCommand_command = package["commands"]["preCommand"]["command"]
        new_package.preCommand_name = package["commands"]["preCommand"]["name"]
        new_package.pkgs_share_id = pkgs_share_id
        new_package.dition_status = edition_status

        if request is None:
            session.add(new_package)
        session.commit()
        session.flush()
        return new_package

    @DatabaseHelper._sessionm
    def remove_dependencies(self, session, package_uuid, status="delete"):
        """
        Remove the dependencies for the specified package.
        Params:
            package_uuid : string of the uuid of the package given as reference.
            status : string (default : delete) if the status is delete, then the
                function delete all in the dependencies table which refers to the package
        """
        session.query(Dependencies).filter(
            Dependencies.uuid_package == package_uuid
        ).delete()
        if status == "delete":
            session.query(Dependencies).filter(
                Dependencies.uuid_dependency == package_uuid
            ).delete()
        session.commit()
        session.flush()

    @DatabaseHelper._sessionm
    def refresh_dependencies(self, session, package_uuid, uuid_list):
        """
        Refresh the list of the dependencies for a specified package.
        Params:
            package_uuid : string of the reference uuid
            uuid_list : list of the dependencies associated to the reference.
                One reference has many dependencies.
        """
        self.remove_dependencies(package_uuid, "refresh")
        for dependency in uuid_list:
            new_dependency = Dependencies()
            new_dependency.uuid_package = package_uuid
            new_dependency.uuid_dependency = dependency
            session.add(new_dependency)
        session.commit()
        session.flush()

    @DatabaseHelper._sessionm
    def list_all(self, session):
        """
        Get the list of all the packages stored in database.

        Returns:
            list of packages serialized as dict
        """

        ret = session.query(Packages).all()
        packages = []
        for package in ret:
            packages.append(package.to_array())
        return packages

    @DatabaseHelper._sessionm
    def remove_package(self, session, uuid):
        """Delete the specified package from the DB
        Param :
            uuid: string of the uuid of the specified package.
        """
        session.query(Packages).filter(Packages.uuid == uuid).delete()
        session.commit()
        session.flush()

    ######## Extensions / Rules ##########
    @DatabaseHelper._sessionm
    def list_all_extensions(self, session):
        ret = session.query(Extensions).order_by(asc(Extensions.rule_order)).all()
        extensions = []
        for extension in ret:
            extensions.append(extension.to_array())
        return extensions

    @DatabaseHelper._sessionm
    def delete_extension(self, session, id):
        try:
            session.query(Extensions).filter(Extensions.id == id).delete()
            session.commit()
            session.flush()
            return True
        except BaseException:
            return False

    @DatabaseHelper._sessionm
    def raise_extension(self, session, id):
        """Raise the selected rule
        Param:
            id: int corresponding to the rule id we want to raise
        """
        rule_to_raise = session.query(Extensions).filter(Extensions.id == id).one()
        rule_to_switch = (
            session.query(Extensions)
            .filter(Extensions.rule_order < rule_to_raise.rule_order)
            .order_by(desc(Extensions.rule_order))
            .first()
        )

        rule_to_raise.rule_order, rule_to_switch.rule_order = (
            rule_to_switch.getRule_order(),
            rule_to_raise.getRule_order(),
        )
        session.commit()
        session.flush()

    @DatabaseHelper._sessionm
    def lower_extension(self, session, id):
        """Lower the selected rule
        Param:
            id: int corresponding to the rule id we want to raise
        """
        rule_to_lower = session.query(Extensions).filter(Extensions.id == id).one()
        rule_to_switch = (
            session.query(Extensions)
            .filter(Extensions.rule_order > rule_to_lower.rule_order)
            .order_by(asc(Extensions.rule_order))
            .first()
        )

        rule_to_lower.rule_order, rule_to_switch.rule_order = (
            rule_to_switch.getRule_order(),
            rule_to_lower.getRule_order(),
        )
        session.commit()
        session.flush()

    @DatabaseHelper._sessionm
    def get_last_extension_order(self, session):
        """Lower the selected rule
        Param:
            id: int corresponding to the rule id we want to raise
        """
        last_rule = (
            session.query(Extensions).order_by(desc(Extensions.rule_order)).first()
        )
        session.commit()
        session.flush()

        return last_rule.getRule_order()

    @DatabaseHelper._sessionm
    def add_extension(self, session, datas):
        """Lower the selected rule
        Param:
            id: int corresponding to the rule id we want to raise
        """
        if "id" in datas:
            request = (
                session.query(Extensions).filter(Extensions.id == datas["id"]).first()
            )
            rule = request
            if request is None:
                rule = Extensions()
        else:
            request = None
            rule = Extensions()

        if "rule_order" in datas:
            rule.rule_order = datas["rule_order"]

        if "rule_name" in datas:
            rule.rule_name = datas["rule_name"]

        if "name" in datas:
            rule.name = datas["name"]

        if "extension" in datas:
            rule.extension = datas["extension"]

        if "magic_command" in datas:
            rule.magic_command = datas["magic_command"]

        if "bang" in datas:
            rule.bang = datas["bang"]

        if "file" in datas:
            rule.file = datas["file"]

        if "strings" in datas:
            rule.strings = datas["strings"]

        if "proposition" in datas:
            rule.proposition = datas["proposition"]

        if "description" in datas:
            rule.description = datas["description"]

        if request is None:
            session.add(rule)

        session.commit()
        session.flush()

    @DatabaseHelper._sessionm
    def get_extension(self, session, id):
        return session.query(Extensions).filter(Extensions.id == id).first().to_array()

    # =====================================================================
    # pkgs FUNCTIONS synch syncthing
    # =====================================================================
    @DatabaseHelper._sessionm
    def setSyncthingsync(
        self,
        session,
        uuidpackage,
        relayserver_jid,
        typesynchro="create",
        watching="yes",
    ):
        try:
            new_Syncthingsync = Syncthingsync()
            new_Syncthingsync.uuidpackage = uuidpackage
            new_Syncthingsync.typesynchro = typesynchro
            new_Syncthingsync.relayserver_jid = relayserver_jid
            new_Syncthingsync.watching = watching
            session.add(new_Syncthingsync)
            session.commit()
            session.flush()
        except Exception as e:
            logging.getLogger().error(str(e))

    @DatabaseHelper._sessionm
    def get_relayservers_no_sync_for_packageuuid(self, session, uuidpackage):
        result_list = []
        try:
            relayserversync = (
                session.query(Syncthingsync)
                .filter(and_(Syncthingsync.uuidpackage == uuidpackage))
                .all()
            )
            session.commit()
            session.flush()

            for relayserver in relayserversync:
                res = {}
                res["uuidpackage"] = relayserver.uuidpackage
                res["typesynchro"] = relayserver.typesynchro
                res["relayserver_jid"] = relayserver.relayserver_jid
                res["watching"] = relayserver.watching
                res["date"] = relayserver.date
                result_list.append(res)
            return result_list
        except Exception as e:
            logging.getLogger().error(str(e))
            logger.error("\n%s" % (traceback.format_exc()))
            return []

    @DatabaseHelper._sessionm
    def pkgs_unregister_synchro_package(
        self, session, uuidpackage, typesynchro, jid_relayserver
    ):
        listJID = jid_relayserver.split("@")
        if len(listJID) > 0:
            userJID = "%s%%" % listJID[0]
            sql = """DELETE FROM `pkgs`.`syncthingsync`
                WHERE
                `syncthingsync`.`uuidpackage` like '%s' AND
                `syncthingsync`.`relayserver_jid`  like "%s" ;""" % (
                uuidpackage,
                userJID,
            )
            session.execute(sql)
            session.commit()
            session.flush()

    @DatabaseHelper._sessionm
    def pkgs_delete_synchro_package(self, session, uuidpackage):
        session.query(Syncthingsync).filter(
            Syncthingsync.uuidpackage == uuidpackage
        ).delete()
        session.commit()
        session.flush()

    @DatabaseHelper._sessionm
    def list_pending_synchro_package(self, session):
        pendinglist = session.query(
            distinct(Syncthingsync.uuidpackage).label("uuidpackage")
        ).all()
        session.commit()
        session.flush()
        result_list = []
        for packageuid in pendinglist:
            result_list.append(packageuid.uuidpackage)
        return result_list

    @DatabaseHelper._sessionm
    def pkgs_register_synchro_package(self, session, uuidpackage, typesynchro):
        # list id server relay
        list_server_relay = XmppMasterDatabase().get_List_jid_ServerRelay_enable(
            enabled=1
        )
        for jid in list_server_relay:
            # exclude local package server
            if jid[0].startswith("rspulse@pulse/"):
                continue
            self.setSyncthingsync(uuidpackage, jid[0], typesynchro, watching="yes")

    @DatabaseHelper._sessionm
    def clear_old_pending_synchro_package(self, session, timeseconde=35):
        sql = (
            """DELETE FROM `pkgs`.`syncthingsync`
            WHERE
                `syncthingsync`.`date` < DATE_SUB(NOW(), INTERVAL %d SECOND);"""
            % timeseconde
        )
        session.execute(sql)
        session.commit()
        session.flush()

    @DatabaseHelper._sessionm
    def get_package_summary(self, session, package_id):
        path = os.path.join("/", "var", "lib", "pulse2", "packages", package_id)
        size = 0
        files = []
        for root, dirs, files in os.walk(path):
            for file in files:
                size += os.path.getsize(os.path.join(root, file))

        diviser = 1000.0
        units = ["B", "Kb", "Mb", "Gb", "Tb"]

        count = 0
        next = True
        while next and count < len(units):
            if size / (diviser**count) > 1000:
                count += 1
            else:
                next = False

        query = (
            session.query(
                Packages.label,
                Packages.version,
                Packages.Qsoftware,
                Packages.Qversion,
                Packages.Qvendor,
                Packages.description,
            )
            .filter(Packages.uuid == package_id)
            .first()
        )
        session.commit()
        session.flush()
        result = {
            "name": "",
            "version": "",
            "Qsoftware": "",
            "Qversion": "",
            "Qvendor": "",
            "description": "",
            "files": files,
            "size": size,
            "Size": "%s %s" % (round(size / (diviser**count), 2), units[count]),
        }

        if query is not None:
            result["name"] = query.label
            result["version"] = query.version
            result["Qsoftware"] = query.Qsoftware
            result["Qversion"] = query.Qversion
            result["Qvendor"] = query.Qvendor
            result["description"] = query.description

        return result

    @DatabaseHelper._sessionm
    def delete_from_pending(self, session, pid="", jidrelay=[]):
        query = session.query(Syncthingsync)
        if pid != "":
            query = query.filter(Syncthingsync.uuidpackage == pid)
        if jidrelay != []:
            query = query.filter(Syncthingsync.relayserver_jid.in_(jidrelay))
        query = query.delete(synchronize_session="fetch")
        session.commit()
        session.flush()

    # =====================================================================
    # pkgs FUNCTIONS manage share
    # =====================================================================

    @DatabaseHelper._sessionm
    def SetPkgs_shares(
        self,
        session,
        name,
        comments,
        enabled,
        share_type,
        uri,
        ars_name,
        ars_id,
        share_path,
        usedquotas,
        quotas,
    ):
        try:
            new_Pkgs_shares = Pkgs_shares()
            new_Pkgs_shares.name = name
            new_Pkgs_shares.comments = comments
            new_Pkgs_shares.enabled = enabled
            new_Pkgs_shares.type = share_type
            new_Pkgs_shares.uri = uri
            new_Pkgs_shares.ars_name = ars_name
            new_Pkgs_shares.ars_id = ars_id
            new_Pkgs_shares.share_path = share_path
            new_Pkgs_shares.usedquotas = usedquotas
            new_Pkgs_shares.quotas = quotas
            session.add(new_Pkgs_shares)
            session.commit()
            session.flush()
            return new_Pkgs_shares.id
        except Exception as e:
            logging.getLogger().error(str(e))
            return None

    @DatabaseHelper._sessionm
    def SetPkgs_shares_ars(self, session, shareId, hostname, jid, pkgs_shares_id):
        """
        fild table :  id,hostname,jid,pkgs_shares_id
        warning id is not auto increment
        """
        try:
            new_Pkgs_shares_ars = Pkgs_shares_ars()
            new_Pkgs_shares_ars.id = shareId
            new_Pkgs_shares_ars.hostname = hostname
            new_Pkgs_shares_ars.jid = jid
            new_Pkgs_shares_ars.pkgs_shares_id = pkgs_shares_id
            session.add(new_Pkgs_shares_ars)
            session.commit()
            session.flush()
            return new_Pkgs_shares_ars.id
        except Exception as e:
            logging.getLogger().error(str(e))
            return None

    @DatabaseHelper._sessionm
    def SetPkgs_shares_ars_web(
        self,
        session,
        pkgs_share_id,
        ars_share_id,
        packages_id,
        status,
        fingerprint,
        size,
        edition_date,
    ):
        """
        fild table : id,ars_share_id,packages_id,status,finger_print,size,date_edition
        """
        try:
            new_Pkgs_shares_ars_web = Pkgs_shares_ars_web()
            new_Pkgs_shares_ars_web.ars_share_id = ars_share_id
            new_Pkgs_shares_ars_web.packages_id = packages_id
            new_Pkgs_shares_ars_web.status = status
            new_Pkgs_shares_ars_web.finger_print = fingerprint
            new_Pkgs_shares_ars_web.size = size
            new_Pkgs_shares_ars_web.date_edition = edition_date
            session.add(new_Pkgs_shares_ars_web)
            session.commit()
            session.flush()
            return new_Pkgs_shares_ars_web.id
        except Exception as e:
            logging.getLogger().error(str(e))
            return None

    @DatabaseHelper._sessionm
    def SetPkgs_rules_algos(self, session, name, description, level):
        try:
            new_Pkgs_rules_algos = Pkgs_rules_algos()
            session.add(new_Pkgs_rules_algos)
            new_Pkgs_rules_algos.name = name
            new_Pkgs_rules_algos.description = description
            new_Pkgs_rules_algos.level = level
            session.commit()
            session.flush()
            return new_Pkgs_rules_algos.id
        except Exception as e:
            logging.getLogger().error(str(e))
            return None

    @DatabaseHelper._sessionm
    def SetPkgs_rules_global(
        self, session, pkgs_rules_algos_id, pkgs_cluster_ars_id, order, subject
    ):
        try:
            new_Pkgs_rules_global = Pkgs_rules_global()
            new_Pkgs_rules_global.pkgs_rules_algos_id = pkgs_rules_algos_id
            new_Pkgs_rules_global.pkgs_cluster_ars_id = pkgs_cluster_ars_id
            new_Pkgs_rules_global.order = order
            new_Pkgs_rules_global.suject = subject
            session.add(new_Pkgs_rules_global)
            session.commit()
            session.flush()
            return new_Pkgs_rules_global.id
        except Exception as e:
            logging.getLogger().error(str(e))
            return None

    @DatabaseHelper._sessionm
    def SetPkgs_rules_local(
        self, session, pkgs_rules_algos_id, pkgs_shares_id, order, subject, permission
    ):
        try:
            new_Pkgs_rules_local = Pkgs_rules_local()
            new_Pkgs_rules_local.pkgs_rules_algos_id = pkgs_rules_algos_id
            new_Pkgs_rules_local.pkgs_shares_id = pkgs_shares_id
            new_Pkgs_rules_local.order = order
            new_Pkgs_rules_local.suject = subject
            new_Pkgs_rules_local.permission = permission
            session.add(new_Pkgs_rules_local)
            session.commit()
            session.flush()
            return new_Pkgs_rules_local.id
        except Exception as e:
            logging.getLogger().error(str(e))
            return None

    @DatabaseHelper._sessionm
    def pkgs_Orderrules(self, session):
        sql = """SELECT
                    *
                FROM
                    pkgs.pkgs_rules_algos
                ORDER BY level;"""
        result = session.execute(sql)
        session.commit()
        session.flush()
        return [x for x in result]

    @DatabaseHelper._sessionm
    def pkgs_sharing_rule_search(
        self, session, user_information, algoid, enabled=1, share_type=None
    ):
        sql = """SELECT
                    pkgs.pkgs_shares.id AS id_sharing,
                    pkgs.pkgs_shares.name AS name,
                    pkgs.pkgs_shares.comments AS comments,
                    pkgs.pkgs_shares.enabled AS enabled,
                    pkgs.pkgs_shares.type AS type,
                    pkgs.pkgs_shares.uri AS uri,
                    pkgs.pkgs_shares.ars_name AS ars_name,
                    pkgs.pkgs_shares.ars_id AS ars_id,
                    pkgs.pkgs_shares.share_path AS share_path,
                    pkgs.pkgs_rules_local.id AS id_rule,
                    pkgs.pkgs_rules_local.pkgs_rules_algos_id AS algos_id,
                    pkgs.pkgs_rules_local.order AS order_rule,
                    pkgs.pkgs_rules_local.subject AS subject,
                    pkgs.pkgs_rules_local.permission AS permission,
                    pkgs.pkgs_shares.quotas AS quotas,
                    pkgs.pkgs_shares.usedquotas AS usedquotas
                FROM
                    pkgs.pkgs_shares
                        INNER JOIN
                    pkgs.pkgs_rules_local ON pkgs.pkgs_rules_local.pkgs_shares_id = pkgs.pkgs_shares.id
                WHERE"""

        whereclause = """'%s' REGEXP (pkgs.pkgs_rules_local.suject)
                        AND pkgs.pkgs_shares.enabled = %s
                        AND pkgs.pkgs_rules_local.pkgs_rules_algos_id = %s""" % (
            user_information,
            enabled,
            algoid,
        )
        typeclause = ""
        if share_type is not None:
            typeclause = """ AND pkgs.pkgs_shares.type = '%s' """ % (share_type)
        sql = """ %s
                  %s %s
                  ORDER BY pkgs.pkgs_rules_local.order;""" % (
            sql,
            whereclause,
            typeclause,
        )
        result = session.execute(sql)
        session.commit()
        session.flush()
        ret = []
        if result:
            # create dict partage
            for y in result:
                resuldict = {}
                resuldict["id_sharing"] = y[0]
                resuldict["name"] = y[1]
                resuldict["comments"] = y[2]
                resuldict["type"] = y[4]
                resuldict["uri"] = y[5]
                resuldict["ars_name"] = y[6]
                resuldict["ars_id"] = y[7]
                resuldict["share_path"] = y[8]
                # information from table pkgs_rules_local or pkgs_rules_global
                resuldict["id_rule"] = y[9]
                resuldict["algos_id"] = y[10]
                resuldict["order_rule"] = y[11]
                resuldict["regexp"] = y[12]
                resuldict["permission"] = y[13]
                resuldict["quotas"] = y[14]
                resuldict["usedquotas"] = y[15]
                if resuldict["type"] == "global":
                    resuldict["nbpackage"] = self.nb_package_in_sharing(share_id=None)
                else:
                    resuldict["nbpackage"] = self.nb_package_in_sharing(
                        share_id=resuldict["id_sharing"]
                    )
                ret.append(resuldict)
        return ret

    def get_shares(self, session):
        """
        This function is used to obtain the list of the shares
        Args:
            session: The SQLAlchemy session

        Returns:
            It returns the list of the actual shares
        """
        query = session.query(Pkgs_shares).all()
        ret = [elem.toH() for elem in query]
        return ret

    @DatabaseHelper._sessionm
    def nb_package_in_sharing(self, session, share_id=None):
        sql = """SELECT
                    COUNT(*)
                FROM
                    pkgs.packages
                WHERE
                    packages.pkgs_share_id is NULL;"""
        logging.getLogger().debug(str(sql))
        if share_id is not None:
            sql = """SELECT
                        COUNT(*)
                    FROM
                        pkgs.packages
                    WHERE
                        packages.pkgs_share_id = %s;""" % (
                share_id
            )

        result = session.execute(sql)
        session.commit()
        session.flush()
        return [x for x in result][0][0]

    @DatabaseHelper._sessionm
    def pkgs_sharing_admin_profil(self, session):
        """
            This function is used to obtain packages list
            from the admin profile
        Args:
            session: The SQLAlchemy session

        Returns:
            It returns the list of the actual shares for the admin profile.
        """

        sql = """SELECT
                    pkgs.pkgs_shares.id AS id_sharing,
                    pkgs.pkgs_shares.name AS name,
                    pkgs.pkgs_shares.comments AS comments,
                    pkgs.pkgs_shares.enabled AS enabled,
                    pkgs.pkgs_shares.type AS type,
                    pkgs.pkgs_shares.uri AS uri,
                    pkgs.pkgs_shares.ars_name AS ars_name,
                    pkgs.pkgs_shares.ars_id AS ars_id,
                    pkgs.pkgs_shares.share_path AS share_path
                FROM
                    pkgs.pkgs_shares
                WHERE
                     pkgs.pkgs_shares.enabled = 1;"""
        logging.getLogger().debug(str(sql))
        result = session.execute(sql)
        session.commit()
        session.flush()
        ret = []
        if result:
            # create dict partage
            for y in result:
                resuldict = {}
                resuldict["id_sharing"] = y[0]
                resuldict["name"] = y[1]
                resuldict["comments"] = y[2]
                resuldict["type"] = y[4]
                resuldict["uri"] = y[5]
                resuldict["ars_name"] = y[6]
                resuldict["ars_id"] = y[7]
                resuldict["share_path"] = y[8]
                resuldict["permission"] = "rw"
                resuldict["quotas"] = y[9]
                resuldict["usedquotas"] = y[10]
                ret.append(resuldict)
                if resuldict["type"] == "global":
                    resuldict["nbpackage"] = self.nb_package_in_sharing(share_id=None)
                else:
                    resuldict["nbpackage"] = self.nb_package_in_sharing(
                        share_id=resuldict["id_sharing"]
                    )
        return ret

    @DatabaseHelper._sessionm
    def verifier_exist_uuid(self, session, uuid):
        """
        Vérifie si un UUID existe dans la table `packages`.

        Paramètres :
        uuid (str) : Le UUID à vérifier.

        Retourne :
        bool : True si le UUID existe, False sinon.
        """
        return session.query(Packages).filter_by(uuid=uuid).first() is not None
