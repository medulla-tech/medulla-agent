# -*- coding: utf-8; -*-
# SPDX-FileCopyrightText: 2004-2007 Linbox / Free&ALter Soft, http://linbox.com
# SPDX-FileCopyrightText: 2007-2010 Mandriva, http://www.mandriva.com
# SPDX-FileCopyrightText: 2016-2023 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-3.0-or-later


""" Class to map pkgs.pkgs_shares_ars to SA
"""


class Pkgs_shares_ars(object):
    """Mapping between pkgs.pkgs_shares_ars and SA
    colunm : 'id,hostname,jid,pkgs_shares_id
    """

    def getId(self):
        if self.id is not None:
            return self.id
        else:
            return 0

    def getHostname(self):
        if self.hostname is not None:
            return self.hostname
        else:
            return ""

    def getJid(self):
        if self.jid is not None:
            return self.jid
        else:
            return ""

    def getShareid(self):
        if self.pkgs_shares_id is not None:
            return self.pkgs_shares_ars
        else:
            return ""

    def to_array(self):
        """
        This function serialize the object to dict.

        Returns:
            Dict of elements contained into the object.
        """
        return {
            "id": self.getId(),
            "hostname": self.getHostname(),
            "jid": self.getJid(),
            "pkgs_shares_id": self.getShareid(),
        }

    def toH(self):
        return {
            "id": self.id,
            "hostname": self.hostname,
            "jid": self.jid,
            "pkgs_shares_id": self.pkgs_shares_id,
        }
