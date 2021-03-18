# -*- coding: utf-8; -*-
#
# (c) 2004-2007 Linbox / Free&ALter Soft, http://linbox.com
# (c) 2007-2009 Mandriva, http://www.mandriva.com/
#
# $Id$
#
# This file is part of Pulse 2, http://pulse2.mandriva.org
#
# Pulse 2 is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# Pulse 2 is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Pulse 2; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
# MA 02110-1301, USA.

"""
Provides access to PKGS database
"""

# standard modules
import time
import traceback
import os
# SqlAlchemy
from sqlalchemy import and_, create_engine, MetaData, Table, Column, String, \
                       Integer, ForeignKey, select, asc, or_, desc, func, not_, distinct
from sqlalchemy.orm import create_session, mapper, relation
from sqlalchemy.exc import NoSuchTableError, TimeoutError
from sqlalchemy.orm.exc import NoResultFound
from sqlalchemy.orm import sessionmaker
from sqlalchemy.orm import scoped_session
import datetime
# ORM mappings
from lib.plugins.pkgs.orm.dependencies import Dependencies
from lib.plugins.pkgs.orm.extensions import Extensions
from lib.plugins.pkgs.orm.package_pending_exclusions import Package_pending_exclusions
from lib.plugins.pkgs.orm.packages import Packages
from lib.plugins.pkgs.orm.syncthingsync import Syncthingsync
from lib.configuration import confParameter
from lib.plugins.xmpp import XmppMasterDatabase
# Imported last
import logging
import functools

logger = logging.getLogger()
NB_DB_CONN_TRY = 2


class Singleton(object):

    def __new__(type, *args):
        if '_the_instance' not in type.__dict__:
            type._the_instance = object.__new__(type)
        return type._the_instance



class DatabaseHelper(Singleton):
    # Session decorator to create and close session automatically
    @classmethod
    def _sessionm(self, func1):
        @functools.wraps(func1)
        def __sessionm(self, *args, **kw):
            session_factory  = sessionmaker(bind=self.engine_pkgsmmaster_base)
            sessionmultithread = scoped_session(session_factory)
            result = func1(self, sessionmultithread , *args, **kw)
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
        self.engine_pkgsmmaster_base = create_engine('mysql://%s:%s@%s:%s/%s' % (self.config.pkgs_dbuser,
                                                                                self.config.pkgs_dbpasswd,
                                                                                self.config.pkgs_dbhost,
                                                                                self.config.pkgs_dbport,
                                                                                self.config.pkgs_dbname),
                                                    pool_recycle=self.config.dbpoolrecycle,
                                                    pool_size=self.config.dbpoolsize,
                                                    pool_timeout=self.config.pkgs_dbpooltimeout,
                                                    convert_unicode=True)

        self.metadata = MetaData(self.engine_pkgsmmaster_base)
        if not self.initTables():
            return False

        self.initMappers()
        self.metadata.create_all()
        # FIXME: should be removed
        self.session = create_session(bind=self.engine_pkgsmmaster_base)
        if self.session is not None:
        # self.session = sessionmaker(bind=self.engine_xmppmmaster_base)
            self.is_activated = True
            self.logger.debug("Msc database connected")
            return True
        self.logger.error("Msc database connecting")
        return False

    def initTables(self):
        """
        Initialize all SQLalchemy tables
        """
        try:
            # packages
            self.package = Table(
                "packages",
                self.metadata,
                autoload = True
            )

            # extensions
            self.extensions = Table(
                "extensions",
                self.metadata,
                autoload = True
            )

            # Dependencies
            self.dependencies = Table(
                "dependencies",
                self.metadata,
                autoload = True
            )

            # Syncthingsync
            self.syncthingsync = Table(
                "syncthingsync",
                self.metadata,
                autoload = True
            )
            #package_pending_exclusions
            self.package_pending_exclusions = Table(
                "package_pending_exclusions",
                self.metadata,
                autoload = True
            )

        except NoSuchTableError, e:
            self.logger.error("Cant load the Pkgs database : table '%s' does not exists"%(str(e.args[0])))
            return False
        return True

    def initMappers(self):
        """
        Initialize all SQLalchemy mappers needed for the Pkgs database
        """
        mapper(Packages, self.package)
        mapper(Extensions, self.extensions)
        mapper(Dependencies, self.dependencies)
        mapper(Syncthingsync, self.syncthingsync)
        mapper(Package_pending_exclusions, self.package_pending_exclusions)
    ####################################
  
    @DatabaseHelper._sessionm
    def createPackage(self, session, package):
        """
        Insert the package config into database.
        Param:
            package : dict of the historical config of the package
        Returns:
            Packages object
        """

        request = session.query(Packages).filter(Packages.uuid == package['id']).first()

        if request is None:
            new_package = Packages()
        else:
            new_package = request

        new_package.label = package['name']
        new_package.uuid = package['id']
        new_package.description = package['description']
        new_package.version = package['version']
        new_package.os = package['targetos']
        new_package.metagenerator = package['metagenerator']
        new_package.entity_id = package['entity_id']
        if type(package['sub_packages']) is str:
            new_package.sub_packages = package['sub_packages']
        elif type(package['sub_packages']) is list:
            new_package.sub_packages = ",".join(package['sub_packages'])
        new_package.reboot = package['reboot']
        new_package.inventory_associateinventory = package['inventory']['associateinventory']
        new_package.inventory_licenses = package['inventory']['licenses']
        new_package.Qversion = package['inventory']['queries']['Qversion']
        new_package.Qvendor = package['inventory']['queries']['Qvendor']
        new_package.Qsoftware = package['inventory']['queries']['Qsoftware']
        new_package.boolcnd = package['inventory']['queries']['boolcnd']
        new_package.postCommandSuccess_command = package['commands']['postCommandSuccess']['command']
        new_package.postCommandSuccess_name = package['commands']['postCommandSuccess']['name']
        new_package.installInit_command = package['commands']['installInit']['command']
        new_package.installInit_name = package['commands']['installInit']['name']
        new_package.postCommandFailure_command = package['commands']['postCommandFailure']['command']
        new_package.postCommandFailure_name = package['commands']['postCommandFailure']['name']
        new_package.command_command = package['commands']['command']['command']
        new_package.command_name = package['commands']['command']['name']
        new_package.preCommand_command = package['commands']['preCommand']['command']
        new_package.preCommand_name = package['commands']['preCommand']['name']

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
        session.query(Dependencies).filter(Dependencies.uuid_package == package_uuid).delete()
        if status == "delete":
            session.query(Dependencies).filter(Dependencies.uuid_dependency == package_uuid).delete()
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
    def delete_extension(self,session, id):
        try:
            session.query(Extensions).filter(Extensions.id == id).delete()
            session.commit()
            session.flush()
            return True
        except:
            return False

    @DatabaseHelper._sessionm
    def raise_extension(self,session, id):
        """ Raise the selected rule
        Param:
            id: int corresponding to the rule id we want to raise
        """
        rule_to_raise = session.query(Extensions).filter(Extensions.id == id).one()
        rule_to_switch = session.query(Extensions).filter(Extensions.rule_order < rule_to_raise.rule_order).order_by(desc(Extensions.rule_order)).first()

        rule_to_raise.rule_order, rule_to_switch.rule_order = rule_to_switch.getRule_order(), rule_to_raise.getRule_order()
        session.commit()
        session.flush()


    @DatabaseHelper._sessionm
    def lower_extension(self,session, id):
        """ Lower the selected rule
        Param:
            id: int corresponding to the rule id we want to raise
        """
        rule_to_lower = session.query(Extensions).filter(Extensions.id == id).one()
        rule_to_switch = session.query(Extensions).filter(Extensions.rule_order > rule_to_lower.rule_order).order_by(asc(Extensions.rule_order)).first()

        rule_to_lower.rule_order, rule_to_switch.rule_order = rule_to_switch.getRule_order(), rule_to_lower.getRule_order()
        session.commit()
        session.flush()

    @DatabaseHelper._sessionm
    def get_last_extension_order(self,session):
        """ Lower the selected rule
        Param:
            id: int corresponding to the rule id we want to raise
        """
        last_rule = session.query(Extensions).order_by(desc(Extensions.rule_order)).first()
        session.commit()
        session.flush()

        return last_rule.getRule_order()


    @DatabaseHelper._sessionm
    def add_extension(self,session, datas):
        """ Lower the selected rule
        Param:
            id: int corresponding to the rule id we want to raise
        """
        if 'id' in datas:
            request = session.query(Extensions).filter(Extensions.id == datas['id']).first()
            rule = request
            if request is None:
                rule = Extensions()
        else:
            request = None
            rule = Extensions()

        if 'rule_order' in datas:
            rule.rule_order = datas['rule_order']

        if 'rule_name' in datas:
            rule.rule_name = datas['rule_name']

        if 'name' in datas:
            rule.name = datas['name']

        if 'extension' in datas:
            rule.extension = datas['extension']

        if 'magic_command' in datas:
            rule.magic_command = datas['magic_command']

        if 'bang' in datas:
            rule.bang = datas['bang']

        if 'file' in datas:
            rule.file = datas['file']

        if 'strings' in datas:
            rule.strings = datas['strings']

        if 'proposition' in datas:
            rule.proposition = datas['proposition']

        if 'description' in datas:
            rule.description = datas['description']

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
    def setSyncthingsync( self, session, uuidpackage, relayserver_jid, typesynchro = "create", watching = 'yes'):
        try:
            new_Syncthingsync = Syncthingsync()
            new_Syncthingsync.uuidpackage = uuidpackage
            new_Syncthingsync.typesynchro =  typesynchro
            new_Syncthingsync.relayserver_jid = relayserver_jid
            new_Syncthingsync.watching =  watching
            session.add(new_Syncthingsync)
            session.commit()
            session.flush()
        except Exception, e:
            logging.getLogger().error(str(e))

    @DatabaseHelper._sessionm
    def get_relayservers_no_sync_for_packageuuid(self, session, uuidpackage):
        result_list = []
        try:
            relayserversync = session.query(Syncthingsync).filter(and_(Syncthingsync.uuidpackage == uuidpackage)).all()
            session.commit()
            session.flush()

            for relayserver in relayserversync:
                res={}
                res['uuidpackage'] = relayserver.uuidpackage
                res['typesynchro'] = relayserver.typesynchro
                res['relayserver_jid'] = relayserver.relayserver_jid
                res['watching'] = relayserver.watching
                res['date'] = relayserver.date
                result_list.append(res)
            return result_list
        except Exception, e:
            logging.getLogger().error(str(e))
            logger.error("\n%s"%(traceback.format_exc()))
            return []

    @DatabaseHelper._sessionm
    def pkgs_regiter_synchro_package(self, session, uuidpackage, typesynchro ):
        #list id server relay
        list_server_relay = self.get_List_jid_ServerRelay_enable(enabled=1)
        for jid in list_server_relay:
            #exclude local package server
            if jid[0].startswith("rspulse@pulse/"):
                continue
            self.setSyncthingsync(uuidpackage, jid[0], typesynchro , watching = 'yes')

    @DatabaseHelper._sessionm
    def pkgs_unregister_synchro_package(self, session, uuidpackage, typesynchro, jid_relayserver):
        listdata=jid_relayserver.split("@")
        if len(listdata)> 0:
            datadata = "%s%%"%listdata[0]
            sql ="""DELETE FROM `pkgs`.`syncthingsync`
                WHERE
                `syncthingsync`.`uuidpackage` like '%s' AND
                `syncthingsync`.`relayserver_jid`  like "%s" ;"""%(uuidpackage, datadata)
            session.execute(sql)
            session.commit()
            session.flush()

    @DatabaseHelper._sessionm
    def pkgs_delete_synchro_package(self, session, uuidpackage):
        session.query(Syncthingsync).filter(Syncthingsync.uuidpackage == uuidpackage).delete()
        session.commit()
        session.flush()

    @DatabaseHelper._sessionm
    def list_pending_synchro_package(self, session):
        pendinglist = session.query(distinct(Syncthingsync.uuidpackage).label("uuidpackage")).all()
        session.commit()
        session.flush()
        result_list = []
        for packageuid in pendinglist:
            result_list.append(packageuid.uuidpackage)
        return result_list


    @DatabaseHelper._sessionm
    def pkgs_register_synchro_package(self, session, uuidpackage, typesynchro ):
        #list id server relay
        list_server_relay = XmppMasterDatabase().get_List_jid_ServerRelay_enable(enabled=1)
        for jid in list_server_relay:
            #exclude local package server
            if jid[0].startswith("rspulse@pulse/"):
                continue
            self.setSyncthingsync(uuidpackage, jid[0], typesynchro , watching = 'yes')

    @DatabaseHelper._sessionm
    def clear_old_pending_synchro_package(self, session, timeseconde=35):
        sql ="""DELETE FROM `pkgs`.`syncthingsync`
            WHERE
                `syncthingsync`.`date` < DATE_SUB(NOW(), INTERVAL %d SECOND);"""%timeseconde
        session.execute(sql)
        session.commit()
        session.flush()

    @DatabaseHelper._sessionm
    def get_package_summary(self, session, package_id):

        path = os.path.join("/", "var" , "lib", "pulse2", "packages", package_id)
        size = 0
        files = []
        for root, dirs, files in os.walk(path):
            for file in files:
                size += os.path.getsize(os.path.join(root, file))

        diviser = 1000.0
        units = ['B', 'Kb', 'Mb', 'Gb', 'Tb']

        count = 0
        next = True
        while next and count < len(units):
            if size / (diviser**count) > 1000:
                count += 1
            else:
                next = False

        query = session.query(Packages.label,\
            Packages.version,\
            Packages.Qsoftware,\
            Packages.Qversion,\
            Packages.Qvendor,\
            Packages.description).filter(Packages.uuid == package_id).first()
        session.commit()
        session.flush()
        result = {
            'name' : '',
            'version': '',
            'Qsoftware' : '',
            'Qversion' : '',
            'Qvendor': '',
            'description' : '',
            'files' : files,
            'size' : size,
            'Size' : '%s %s'%(round(size/(diviser**count), 2), units[count])}

        if query is not None:
            result['name'] = query.label
            result['version'] = query.version
            result['Qsoftware'] = query.Qsoftware
            result['Qversion'] = query.Qversion
            result['Qvendor'] = query.Qvendor
            result['description'] = query.description

        return result

    @DatabaseHelper._sessionm
    def delete_from_pending(self, session, pid = "", jidrelay = []):
        query = session.query(Syncthingsync)
        if pid != "":
            query = query.filter(Syncthingsync.uuidpackage == pid)
        if jidrelay != []:
            query = query.filter(Syncthingsync.relayserver_jid.in_(jidrelay))
        query = query.delete(synchronize_session='fetch')
        session.commit()
        session.flush()
