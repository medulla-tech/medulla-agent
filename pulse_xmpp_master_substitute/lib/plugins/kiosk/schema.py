# -*- coding: utf-8; -*-
#
# (c) 2018 siveo, http://www.siveo.net
#
# This file is part of Pulse 2, http://www.siveo.net
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

from sqlalchemy import Column, String, Integer, \
    DateTime, Text, Enum
from sqlalchemy.dialects.mysql import TINYINT
from sqlalchemy.ext.declarative import declarative_base

Base = declarative_base()


class DBObj(object):
    # Function to convert mapped object to Dict
    # TODO : Do the same for relations [convert relations to subdicts]
    def toDict(self, relations=True):
        d = self.__dict__
        # Convert relations to dict, if 'relations'
        for k in d:
            if isinstance(d[k], DBObj):
                if relations:
                    d[k] = d[k].toDict()
                else:
                    del d[k]
        # Delete Sqlachemy instance state
        if '_sa_instance_state' in d:
            del d['_sa_instance_state']
        return d

    def fromDict(self, d, relations=False):
        # TODO: Test if d is dict
        if '_sa_instance_state' in d:
            del d['_sa_instance_state']
        # Actually we don't support relations
        for key, value in d.iteritems():
            if key and type(value) not in [type({}), type([])]:
                setattr(self, key, value)

    def __str__(self):
        return str(self.toDict())


class KioskDBObj(DBObj):
    # All Kiosk tables have id colmun as primary key
    id = Column(Integer, primary_key=True)


class Profiles(Base, KioskDBObj):
    # ====== Table name =========================
    __tablename__ = 'profiles'
    # ====== Fields =============================
    # Here we define columns for the table version.
    # Notice that each column is also a normal Python instance attribute.
    name = Column(String(50))
    active = Column(TINYINT)
    creation_date = Column(DateTime)


class Packages(Base, KioskDBObj):
    # ====== Table name =========================
    __tablename__ = 'package'
    # ====== Fields =============================
    # Here we define columns for the table version.
    # Notice that each column is also a normal Python instance attribute.
    name = Column(String(45))
    version_package = Column(String(45))
    software = Column(String(45))
    description = Column(String(200), nullable=True)
    version_software = Column(String(45))
    package_uuid = Column(String(45), unique=True)
    os = Column(String(45))


class Profile_has_package(Base, KioskDBObj):
    # ====== Table name =========================
    __tablename__ = 'package_has_profil'
    # ====== Fields =============================
    package_id = Column(Integer, nullable=False)
    profil_id = Column(Integer, nullable=False)
    package_status = Column(Enum('allowed', 'restricted'))


class Profile_has_ou(Base, KioskDBObj):
    # ====== Table name =========================
    __tablename__ = 'profile_has_ous'
    # ====== Fields =============================
    profile_id = Column(Integer, nullable=False)
    ou = Column(Text)
