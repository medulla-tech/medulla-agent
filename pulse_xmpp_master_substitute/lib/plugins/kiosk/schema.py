# -*- coding: utf-8; -*-
# SPDX-FileCopyrightText: 2018-2023 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-2.0-or-later

from sqlalchemy import Column, String, Integer, \
    DateTime, Text, Enum
from sqlalchemy.dialects.mysql import TINYINT
from sqlalchemy.ext.declarative import declarative_base
import datetime

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
    owner = Column(String(255), nullable=False, default="root")
    source = Column(String(255), nullable=False, default="ou")
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
    package_uuid = Column(Integer, nullable=False)
    profil_id = Column(Integer, nullable=False)
    package_status = Column(Enum('allowed', 'restricted'))


class Profile_has_ou(Base, KioskDBObj):
    # ====== Table name =========================
    __tablename__ = 'profile_has_ous'
    # ====== Fields =============================
    profile_id = Column(Integer, nullable=False)
    ou = Column(Text)


class Acknowledgements(Base, KioskDBObj):
    __tablename__ = "acknowledgements"
    id_package_has_profil = Column(Integer, nullable=False)
    askuser = Column(String(255), nullable=False)
    askdate = Column(DateTime, default=datetime.datetime.now, nullable=False)
    acknowledgedbyuser = Column(String(255), nullable=True)
    startdate = Column(DateTime, default=datetime.datetime.now, nullable=False)
    enddate = Column(DateTime, nullable=True)
    status = Column(
        Enum("waiting", "accepted", "rejected"), nullable=False, default="waiting"
    )
