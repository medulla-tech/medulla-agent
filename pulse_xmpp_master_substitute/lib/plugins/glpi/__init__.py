

# -*- coding: utf-8; -*-
# SPDX-FileCopyrightText: 2004-2007 Linbox / Free&ALter Soft, http://linbox.com
# SPDX-FileCopyrightText: 2007-2010 Mandriva, http://www.mandriva.com
# SPDX-FileCopyrightText: 2016-2023 Siveo <support@siveo.net>
# SPDX-FileCopyrightText: 2024-2025 Medulla, http://www.medulla-tech.io
# SPDX-License-Identifier: GPL-3.0-or-later

"""
This module declare all the necessary stuff to connect to a glpi database in it's
version 9.2
"""
import logging
from sqlalchemy import (
    create_engine,
    MetaData,
)
from sqlalchemy.orm import (
    sessionmaker,
)

try:
    from sqlalchemy.orm.util import _entity_descriptor
except ImportError:
    from sqlalchemy.orm.base import _entity_descriptor
try:
    from sqlalchemy.sql.expression import ColumnOperators
except ImportError:
    from sqlalchemy.sql.operators import ColumnOperators
from sqlalchemy.exc import OperationalError
from lib.configuration import confParameter

from lib.plugins.glpi.Glpi84 import Glpi84
from lib.plugins.glpi.Glpi92 import Glpi92
from lib.plugins.glpi.Glpi93 import Glpi93
from lib.plugins.glpi.Glpi94 import Glpi94
from lib.plugins.glpi.Glpi95 import Glpi95
from lib.plugins.glpi.Glpi100 import Glpi100
from lib.plugins.glpi.Glpi110 import Glpi110
from lib.plugins.glpi.Itsmng21 import Itsmng21


class Glpi:
    """
    Singleton Class to query the GLPI database in version > 0.80.
    """

    _instance = None  # Stocke l'instance unique du Singleton

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(Glpi, cls).__new__(cls)
        return cls._instance

    def __init__(self):
        if hasattr(self, "is_initialized"):
            return  # Empêche la réinitialisation de l'instance
        self.is_initialized = True

        self.is_activated = False
        self.config = confParameter()
        self.logger = logging.getLogger()
        self.logger.debug("Glpi initialization")

        self.engine = None
        self.dbpoolrecycle = 60
        self.dbpoolsize = 5
        self.sessionxmpp = None
        self.sessionglpi = None

    def activate(self):
        if self.is_activated:
            return None

        self.logger.info(
            "Glpi parameters connections: user = %s, host = %s, port = %s, schema = %s, poolrecycle = %s, poolsize = %s"
            % (
                self.config.glpi_dbuser,
                self.config.glpi_dbhost,
                self.config.glpi_dbport,
                self.config.glpi_dbname,
                self.config.xmpp_dbpoolrecycle,
                self.config.xmpp_dbpoolsize,
            )
        )

        try:
            self.engine_glpi = create_engine(
                f"mysql://{self.config.glpi_dbuser}:{self.config.glpi_dbpasswd}@{self.config.glpi_dbhost}:{self.config.glpi_dbport}/{self.config.glpi_dbname}?charset={self.config.charset}",
                pool_recycle=self.config.glpi_dbpoolrecycle,
                pool_size=self.config.glpi_dbpoolsize,
                pool_timeout=self.config.xmpp_dbpooltimeout,
                convert_unicode=True,
            )

            try:
                self._glpi_version = (
                    self.engine_glpi.execute("SELECT version FROM glpi_configs")
                    .fetchone()[0]
                    .replace(" ", "")
                )
            except OperationalError:
                self._glpi_version = (
                    self.engine_glpi.execute(
                        'SELECT value FROM glpi_configs WHERE name = "version"'
                    )
                    .fetchone()[0]
                    .replace(" ", "")
                )

            self.Session = sessionmaker(bind=self.engine_glpi)
            self.metadata = MetaData(self.engine_glpi)

            # Instanciation de la bonne version de GLPI
            versions_map = {
                "2.1": Itsmng21,
                "0.84": Glpi84,
                "9.2": Glpi92,
                "9.3": Glpi93,
                "9.4": Glpi94,
                "9.5": Glpi95,
                "10.0": Glpi100,
                "11.0": Glpi110,
            }

            for version_prefix, cls in versions_map.items():
                if self._glpi_version.startswith(version_prefix):
                    self.logger.debug(f"Version Glpi {self._glpi_version}")
                    self.version_instance = cls()
                    break

            self.is_activated = self.version_instance.activate()
            return True

        except Exception as e:
            self.logger.error("We failed to connect to the Glpi database.")
            self.logger.error("Please verify your configuration")
            if str(e) == "`glpi_plugin_glpiinventory_collects`":
                self.logger.error(
                    "Please verify that the glpiinventory plugin is installed and activated"
                )

            self.is_activated = False
            return False

    # Méthodes appelant directement la version correcte
    def getMachineBySerial(self, serial):
        return self.version_instance.getMachineBySerial(serial)

    def getMachineByUuidSetup(self, uuidsetupmachine):
        return self.version_instance.getMachineByUuidSetup(uuidsetupmachine)

    def getMachineInformationByUuidSetup(self, uuidsetupmachine):
        return self.version_instance.getMachineInformationByUuidSetup(uuidsetupmachine)

    def getMachineInformationByUuidMachine(self, idmachine):
        return self.version_instance.getMachineInformationByUuidMachine(idmachine)

    def getMachineByMacAddress(self, ctx, filter):
        return self.version_instance.getMachineByMacAddress(ctx, filter)

    def getLastMachineInventoryPart(
        self, uuid, part, minbound=0, maxbound=-1, filt=None, options=None, count=False
    ):
        return self.version_instance.getLastMachineInventoryPart(
            uuid, part, minbound, maxbound, filt, options, count
        )

    def getComputersOS(self, ids):
        return self.version_instance.getComputersOS(ids)

    def getMachineUUID(self, machine):
        return self.version_instance.getMachineUUID(machine)

    def getMachineOwner(self, machine):
        return self.version_instance.getMachineOwner(machine)

    def getLastMachineInventoryFull(self, uuid):
        return self.version_instance.getLastMachineInventoryFull(uuid)

    def getMachineByUUID(self, uuid):
        return self.version_instance.getMachineByUUID(uuid)

    def get_plugin_inventory_state(self, plugin_name=""):
        return self.version_instance.get_plugin_inventory_state(plugin_name)

    def addRegistryCollect(self, fullkey, keyname):
        return self.version_instance.addRegistryCollect(fullkey, keyname)

    def getRegistryCollect(self, fullkey):
        return self.version_instance.getRegistryCollect(fullkey)

    def machineobjectdymresult(self, ret):
        return self.version_instance._machineobjectdymresult(ret)

    def addRegistryCollectContent(self, computers_id, registry_id, key, value):
        return self.version_instance.addRegistryCollectContent(
            computers_id, registry_id, key, value
        )

