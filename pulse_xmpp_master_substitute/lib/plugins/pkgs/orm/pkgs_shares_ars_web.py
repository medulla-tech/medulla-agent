# -*- coding: utf-8; -*-
# SPDX-FileCopyrightText: 2004-2007 Linbox / Free&ALter Soft, http://linbox.com
# SPDX-FileCopyrightText: 2007-2010 Mandriva, http://www.mandriva.com
# SPDX-FileCopyrightText: 2016-2023 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-3.0-or-later


""" Class to map pkgs.pkgs_shares_ars_web to SA
"""


class Pkgs_shares_ars_web(object):
    """Mapping between pkgs.pkgs_shares_ars_web and SA
    colunm table: 'id,ars_share_id,packages_id,status,finger_print,size,date_edition'
    """

    def getId(self):
        if self.id is not None:
            return self.id
        else:
            return 0

    def getArs_share_id(self):
        if self.ars_share_id is not None:
            return self.ars_share_id
        else:
            return -1

    def getPackages_id(self):
        if self.packages_id is not None:
            return self.packages_id
        else:
            return ""

    def getStatus(self):
        if self.status is not None:
            return self.status
        else:
            return ""

    def getFinger_print(self):
        if self.finger_print is not None:
            return self.finger_print
        else:
            return ""

    def getSize(self):
        if self.size is not None:
            return self.size
        else:
            return 0

    def getEdition_date(self):
        if self.date_edition is not None:
            return self.date_edition
        else:
            return ""

    def to_array(self):
        return {
            "id": self.getId(),
            "ars_share_id": self.getArs_share_id(),
            "packages_id": self.getPackages_id(),
            "status": self.getStatus(),
            "finger_print": self.getFinger_print(),
            "size": self.getSize(),
            "date_edition": self.getEdition_date(),
        }

    def toH(self):
        return {
            "id": self.id,
            "ars_share_id": self.ars_share_id,
            "packages_id": self.packages_id,
            "status": self.status,
            "finger_print": self.finger_print,
            "size": self.size,
            "date_edition": self.date_edition,
        }
