# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2016-2023 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-3.0-or-later
# file : pulse_xmpp_master_substitute/pluginsmastersubstitute/plugin_update_linux.py

"""Plugin substitute de traitement des remontees updates Linux.

Ce plugin recoit un payload `system_info` encode en base64 depuis les agents,
decode son contenu JSON (zlib/gzip/JSON direct), puis delegue la persistence
des donnees de scan a la couche base de donnees XMPP master.
"""

import base64
import traceback
import os
import json
import logging
from lib.plugins.xmpp import XmppMasterDatabase
from lib.plugins.glpi import Glpi
from lib.plugins.kiosk import KioskDatabase
from lib.manageRSAsigned import MsgsignedRSA
from lib.plugins.pkgs import PkgsDatabase
from slixmpp import jid
from lib.utils import getRandomName
import re
from distutils.version import LooseVersion
import configparser
import netaddr
import zlib
import base64
import gzip
from io import BytesIO

# this import will be used later
# import types

logger = logging.getLogger()

plugin = {"VERSION": "1.0", "NAME": "update_linux", "TYPE": "substitute"}  # fmt: skip

# function comment for next feature
# this functions will be used later
# def function_dynamique_declaration_plugin(xmppobject):
# xmppobject.changestatusin_plugin = types.MethodType(changestatusin_plugin, xmppobject)
# def from_base64(b64_string: str) -> dict:
#         """
#         Décode une chaîne JSON compressée et encodée en base64.
#
#         Args:
#             b64_string (str): Chaîne encodée en base64.
#
#         Returns:
#             dict: Dictionnaire décodé.
#         """
#         compressed = base64.b64decode(b64_string)
#         return json.loads(zlib.decompress(compressed).decode("utf-8"))

def from_base64(b64_string: str) -> dict:
    """
    Décode une chaîne JSON encodée en base64.
    Supporte :
    - base64 standard / urlsafe
    - padding manquant
    - données zlib
    - données gzip
    - JSON non compressé
    """
    if not b64_string:
        raise ValueError("Chaîne base64 vide")

    b64_string = b64_string.strip()
    b64_string += "=" * (-len(b64_string) % 4)

    try:
        raw = base64.urlsafe_b64decode(b64_string)
    except Exception as e:
        raise ValueError("Décodage base64 impossible") from e

    # 1️⃣ Essai zlib
    try:
        data = zlib.decompress(raw)
        return json.loads(data.decode("utf-8"))
    except Exception:
        pass

    # 2️⃣ Essai gzip
    try:
        with gzip.GzipFile(fileobj=BytesIO(raw)) as f:
            data = f.read()
            return json.loads(data.decode("utf-8"))
    except Exception:
        pass

    # 3️⃣ Essai JSON direct (pas compressé)
    try:
        return json.loads(raw.decode("utf-8"))
    except Exception as e:
        raise ValueError(
            "Contenu décodé mais ni zlib, ni gzip, ni JSON valide"
        ) from e


def action(xmppobject, action, sessionid, data, msg, ret, dataobj):
    """Traite une remontee de scan Linux et met a jour la base master.

    Le plugin valide la presence du champ `system_info`, decode le payload,
    puis appelle `XmppMasterDatabase().update_machine_linux_from_scan(...)`.
    """
    try:
        logger.info("=====================================================")
        logger.info("call %s from %s", plugin, msg.get("from", "unknown"))
        logger.info("mise a jour Linux")
        logger.info("=====================================================")

        system_info_b64 = data.get("system_info") if isinstance(data, dict) else None
        if not system_info_b64:
            raise ValueError("Champ 'system_info' absent ou vide")

        scan_payload = from_base64(system_info_b64)
        XmppMasterDatabase().update_machine_linux_from_scan(scan_data=scan_payload)

        logger.info(
            "scan linux enregistre serialnumber=%s harduuid=%s serialuuid=%s counts=%s",
            scan_payload.get("serialnumber"),
            scan_payload.get("harduuid"),
            scan_payload.get("serialuuid"),
            scan_payload.get("counts"),
        )
        logger.info("=====================================================")
    except Exception:
        logger.exception(
            "Erreur traitement plugin update_linux depuis %s",
            msg.get("from", "unknown") if isinstance(msg, dict) else "unknown",
        )


