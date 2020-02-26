# -*- coding: utf-8; -*-
#
# (c) 2004-2007 Linbox / Free&ALter Soft, http://linbox.com
# (c) 2007-2010 Mandriva, http://www.mandriva.com
#
# $Id$
#
# This file is part of Mandriva Management Console (MMC).
#
# MMC is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# MMC is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with MMC.  If not, see <http://www.gnu.org/licenses/>.

"""
This module declare all the necessary stuff to connect to a glpi database in it's
version 9.2
"""
import os
import logging
import re
import base64
import json
import requests
import traceback
import sys
from sets import Set
import datetime
import calendar, hashlib
import time
from configobj import ConfigObj
from xmlrpclib import ProtocolError
import functools
from sqlalchemy import and_, create_engine, MetaData, Table, Column, String, \
        Integer, Date, ForeignKey, asc, or_, not_, desc, func, distinct
from sqlalchemy.orm import create_session, mapper, relationship, sessionmaker, Query, scoped_session
from sqlalchemy.orm.exc import MultipleResultsFound, NoResultFound
try:
    from sqlalchemy.orm.util import _entity_descriptor
except ImportError:
    from sqlalchemy.orm.base import _entity_descriptor
try:
    from sqlalchemy.sql.expression import ColumnOperators
except ImportError:
    from sqlalchemy.sql.operators import ColumnOperators
from sqlalchemy.exc import OperationalError, NoSuchTableError

# TODO rename location into entity (and locations in location)

#from mmc.plugins.glpi.config import GlpiConfig
#from mmc.plugins.glpi.utilities import complete_ctx
#from lib.plugins.kiosk import KioskDatabase
from lib.plugins.utils.database_utils import decode_latin1, encode_latin1, decode_utf8, encode_utf8, fromUUID, toUUID, setUUID

from lib.plugins.utils.database_utils import  DbTOA # pyflakes.ignore
#from mmc.plugins.dyngroup.config import DGConfig
from distutils.version import LooseVersion, StrictVersion
from lib.configuration import confParameter
from lib.plugins.xmpp import XmppMasterDatabase

from lib.plugins.glpi.Glpi84 import Glpi84
from lib.plugins.glpi.Glpi92 import Glpi92

glpi = None

class Glpi(object):
    """
    Singleton Class to query the glpi database in version > 0.80.

    """
    is_activated = False

    def activate(self):#jid, password, room, nick):
        global glpi
        if self.is_activated:
            return None
        self.config = confParameter()
        self.logger = logging.getLogger()
        self.logger.debug("Glpi activation")
        self.engine = None
        self.dbpoolrecycle = 60
        self.dbpoolsize = 5
        self.sessionxmpp = None
        self.sessionglpi = None

        #utilisation glpi base
        self.engine_glpi = create_engine('mysql://%s:%s@%s:%s/%s'%( self.config.glpi_dbuser,
                                                                self.config.glpi_dbpasswd,
                                                                self.config.glpi_dbhost,
                                                                self.config.glpi_dbport,
                                                                self.config.glpi_dbname),
                                    pool_recycle = self.config.dbpoolrecycle,
                                    pool_size = self.config.dbpoolsize
        )

        try:
            self._glpi_version = self.engine_glpi.execute('SELECT version FROM glpi_configs').fetchone().values()[0].replace(' ', '')
        except OperationalError:
            self._glpi_version = self.engine_glpi.execute('SELECT value FROM glpi_configs WHERE name = "version"').fetchone().values()[0].replace(' ', '')

        self.Session = sessionmaker(bind=self.engine_glpi)
        self.metadata = MetaData(self.engine_glpi)

        if self._glpi_version.startswith("0.84"):
            glpi = Glpi84()
        else:
            glpi = Glpi92()

        ret = glpi.activate()
        self.is_activated = glpi.is_activated

        #return ret

    def getMachineByMacAddress(self, ctx, filter):
        global glpi
        return glpi.getMachineByMacAddress(ctx, filter)

    def getLastMachineInventoryPart(self, uuid, part, minbound = 0, maxbound = -1, filt = None, options = None, count = False):
        global glpi
        return glpi.getLastMachineInventoryPart(uuid, part, minbound, maxbound, filt, options, count)

    def getRegistryCollect(self, fullkey):
        global glpi
        return glpi.getRegistryCollect(fullkey)

    def addRegistryCollectContent(self, computers_id, registry_id, key, value):
        global glpi
        return glpi.addRegistryCollectContent(computers_id, registry_id, key, value)

    def getComputersOS(self, ids):
        global glpi
        return glpi.getComputersOS(ids)

    def getMachineUUID(self, machine):
        global glpi
        return glpi.getMachineUUID(machine)

    def getMachineOwner(self, machine):
        global glpi
        return glpi.getMachineOwner(machine)

    def getLastMachineInventoryFull(self, uuid):
        global glpi
        return glpi.getLastMachineInventoryFull(uuid)

    def getMachineByUUID(self, uuid):
        global glpi
        return glpi.getMachineByUUID(uuid)
