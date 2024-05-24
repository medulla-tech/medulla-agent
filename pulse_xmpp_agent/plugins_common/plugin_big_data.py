# -*- coding: utf-8 -*-
#
# (c) 2016-2020 siveo, http://www.siveo.net
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
#
# file pulse_xmpp_agent/plugins_common/plugin_big_data.py

import zlib
import base64
import traceback
import os
import json
import logging
from slixmpp import jid
from lib.utils import call_plugin
import time


logger = logging.getLogger()

plugin = {"VERSION": "1.0", "NAME": "big_data", "TYPE": "all"}  # fmt: skip


def action(xmppobject, action, sessionid, data, msg, dataobj):
    try:
        logger.debug("========================================================")
        logger.error("call %s from %s" % (plugin, msg["from"]))
        logger.debug("=======================================================")
        compteurcallplugin = getattr(xmppobject, "num_call%s" % action)
        if not hasattr(xmppobject, "received_data"):
            xmppobject.received_data = {}
            xmppobject.dating = {}
        if hasattr(xmppobject, "received_data"):
            # code plugin
            big_data(xmppobject, action, sessionid, data, msg, 0, dataobj)

    except Exception as e:
        logger.error("The %s. We encountered the error %s" % (plugin["NAME"], str(e)))
        logger.error("We obtained the backtrace %s" % traceback.format_exc())


def big_data(xmppobject, action, sessionid, data, msg, ret, dataobj):
    """
    Réassemble les segments de données reçus pour reconstruire le message complet.

    Args:
        xmppobject (object): Objet XMPP utilisé pour la communication.
        action (str): Action associée au message reçu.
        sessionid (str): Identifiant de session pour le message.
        data (dict): Données du message.
        msg (slixmpp.message.Message): Message XMPP contenant un segment de données.
        ret (str): Valeur de retour associée au message.
        dataobj (dict): Données supplémentaires associées au message.

    Returns:
        None
    """
    valuedata = int(time.time())  # Obtient le temps actuel en secondes
    subsessionid = (
        []
    )  # Initialise une liste pour stocker les identifiants de session à supprimer

    # Si la fonction de datation est activée
    if xmppobject.dating:
        for sessionidvalue in xmppobject.received_data.keys():
            if (
                sessionidvalue in xmppobject.dating
                and (valuedata - xmppobject.dating[sessionidvalue]) > 1800
            ):
                # Supprime la session dans received_data et dating si elle est périmée
                subsessionid.append(sessionidvalue)

    # Supprime les sessions périmées
    if subsessionid:
        for sessionidvalue in subsessionid:
            del xmppobject.received_data[sessionidvalue]
            del xmppobject.dating[sessionidvalue]

    # Ajoute le segment de données dans un dictionnaire
    if sessionid not in xmppobject.received_data:
        xmppobject.received_data[sessionid] = {}
        xmppobject.dating[sessionid] = valuedata

    # Obtient le numéro de segment et le nombre total de segments
    segment_number = data["nb_segment"]
    nb_segments_total = data["nb_segment_total"]
    xmppobject.received_data[sessionid][segment_number] = data["segment"]

    # Vérifie si tous les segments ont été reçus
    if len(xmppobject.received_data[sessionid]) == nb_segments_total:
        # Concatène les segments pour reconstruire les données complètes
        full_data_base64 = "".join(
            [
                xmppobject.received_data[sessionid][i]
                for i in range(1, nb_segments_total + 1)
            ]
        )
        full_data_compressed = base64.b64decode(full_data_base64)
        full_data_utf8 = zlib.decompress(full_data_compressed).decode("utf-8")
        del xmppobject.received_data[sessionid]
        logger.debug("count received_data %s" % len(xmppobject.received_data))
        # Convertit les données en JSON
        full_message = json.loads(full_data_utf8)
        path_module = f'{xmppobject.modulepath}/plugin_{full_message["action"]}.py'
        # Injecte le message dans le plugin
        call_plugin(
            path_module,
            xmppobject,
            full_message["action"],
            full_message["sessionid"],
            full_message["data"],
            msg,
            {},
        )
