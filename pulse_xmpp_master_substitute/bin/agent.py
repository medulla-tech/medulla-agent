#!/usr/bin/python3
# -*- coding: utf-8; -*-
# SPDX-FileCopyrightText: 2016-2023 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-3.0-or-later


from slixmpp import ClientXMPP
from slixmpp import jid
from slixmpp.xmlstream import handler, matcher
from slixmpp.exceptions import IqError, IqTimeout
from slixmpp.xmlstream.stanzabase import ET
from slixmpp.xmlstream.handler import CoroutineCallback
from slixmpp.xmlstream.handler import Callback
from slixmpp.xmlstream.matcher.xpath import MatchXPath
from slixmpp.xmlstream.matcher.stanzapath import StanzaPath
from slixmpp.xmlstream.matcher.xmlmask import MatchXMLMask
from datetime import datetime
from decimal import Decimal
import uuid
from pathlib import Path
import slixmpp
import sys
import os
import asyncio
import zlib

if sys.platform == "win32":
    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())

from os import listdir
from os.path import isfile, join
import logging
import base64
import json
import time
import posix_ipc

from lib.configuration import confParameter
from lib.utils import (
    getRandomName,
    call_plugin,
    ipfromdns,
    base_message_queue_posix,
)
import traceback
import signal
from lib.plugins.xmpp import XmppMasterDatabase
from lib.plugins.glpi import Glpi
from lib.manage_scheduler import manage_scheduler
import random
from lib import manageRSAsigned

logger = logging.getLogger()


def getComputerByMac(mac):
    ret = Glpi().getMachineByMacAddress("imaging_module", mac)
    if type(ret) is list:
        if len(ret) != 0:
            return ret[0]
        else:
            return None
    return ret


class MUCBot(slixmpp.ClientXMPP):
    def __init__(self, conf_file):  # jid, password, room, nick):
        self.fileconf = conf_file
        self.modulepath = os.path.abspath(
            os.path.join(
                os.path.dirname(os.path.realpath(__file__)),
                "..",
                "pluginsmastersubstitute",
            )
        )
        self.logger = logging.getLogger()
        signal.signal(signal.SIGINT, self.signal_handler)
        self.config = confParameter(conf_file)

        slixmpp.ClientXMPP.__init__(
            self,
            jid.JID(self.config.jidmastersubstitute),
            self.config.passwordconnection,
        )

        # update level log for slixmpp
        handler_slixmpp = logging.getLogger("slixmpp")
        logger.debug("slixmpp log level is %s" % self.config.log_level_slixmpp)
        handler_slixmpp.setLevel(self.config.log_level_slixmpp)

        msgkey = manageRSAsigned.MsgsignedRSA(self.boundjid.user)

        # We define the type of the Agent
        self.config.agenttype = "substitute"
        self.manage_scheduler = manage_scheduler(self)
        self.schedule("schedulerfunction", 10, self.schedulerfunction, repeat=True)

        self.agentmaster = jid.JID(self.config.jidmaster)
        self.add_event_handler("register", self.register)
        # self.add_event_handler("connecting", self.handle_connecting)
        self.add_event_handler("connected", self.handle_connected)
        self.add_event_handler("connection_failed", self.handle_connection_failed)
        self.add_event_handler("disconnected", self.handle_disconnected)
        self.add_event_handler("session_start", self.start)
        self.add_event_handler("message", self.message)

        self.schedule("Clean_old_queue", 10, self.Clean_old_queue, [200], repeat=True)
        self.add_event_handler(
            "restartmachineasynchrone", self.restartmachineasynchrone
        )

        self.register_handler(
            CoroutineCallback(
                "CustomXEP_Handle2",
                StanzaPath("/iq@type=result"),
                self._handle_custom_iq,
            )
        )
        self.register_handler(
            CoroutineCallback(
                "CustomXEP_Handle",
                StanzaPath("/iq@type=error"),
                self._handle_custom_iq_error,
            )
        )

        logger.debug("Starting Master sub (%s)" % (self.config.jidmastersubstitute))

        base_message_queue_posix().clean_file_all_message(prefixe=self.boundjid.user)

    def sendbigdatatoagent(self, jid_receiver, data_utf8_json, segment_size=65535):
        """
        Envoie de gros volumes de données à un agent XMPP en plusieurs segments.

        Args:
            jid_receiver (str): Le JID du destinataire.
            data_utf8_json (str): Les données JSON à envoyer, en format UTF-8.
            segment_size (int, optional): La taille maximale de chaque segment (par défaut: 65535).

        Returns:
            None
        """
        # Vérification si le message est assez gros pour nécessiter un découpage en segments
        if len(data_utf8_json) > segment_size:
            # Génération d'un identifiant de session
            sessionid = getRandomName(6, "big_data")
            # Compression et encodage en base64
            data_compressed = zlib.compress(data_utf8_json.encode("utf-8"))
            data_base64 = base64.b64encode(data_compressed).decode("utf-8")

            # Calcul du nombre total de segments nécessaires
            nb_segments_total = (len(data_base64) + segment_size - 1) // segment_size

            # Envoi des segments
            for i in range(nb_segments_total):
                # Découpage des données en segments de taille segment_size
                segment = data_base64[i * segment_size : (i + 1) * segment_size]
                # Construction du message
                message = {
                    "action": "big_data",  # Action spécifiée pour le plugin à appeler
                    "sessionid": sessionid,  # Identifiant de session
                    "data": {
                        "segment": segment,  # Données de ce segment
                        "nb_segment": i + 1,  # Numéro du segment actuel
                        "nb_segment_total": nb_segments_total,  # Nombre total de segments
                        "from": self.boundjid.full,
                    },  # JID de l'expéditeur
                }
                # Envoi du message à jid_receiver
                self.send_message(
                    mto=jid_receiver, mbody=json.dumps(message), mtype="chat"
                )
        else:
            # Envoi direct du message sans découpage
            self.send_message(mto=jid_receiver, mbody=data_utf8_json, mtype="chat")

    def Clean_old_queue(self, nbsecond):
        """
        Remove queue older than a defined seconds.

        Args:
            nbsecond: The number of seconds from which we delete the queue
        """
        queue_files = [
            queue_file
            for queue_file in os.listdir("/dev/mqueue")
            if queue_file != "mysend"
            and os.path.isfile(os.path.join("/dev/mqueue", queue_file))
        ]
        for queue_file in queue_files:
            path_queue = os.path.join("/dev/mqueue", queue_file)
            if time.time() - os.path.getmtime(path_queue) > nbsecond:
                try:
                    posix_ipc.unlink_message_queue("/" + queue_file)
                except:
                    logger.debug(
                        "An error occured while deleting the file %s from the queue"
                        % queue_file
                    )

    def clean_my_mpqueue(self):
        """
        Delete all the files from /dev/mqueue
        """
        mpqueue_files = [
            mpqueue_file
            for mpqueue_file in listdir("/dev/mqueue")
            if isfile(join("/dev/mqueue", mpqueue_file))
        ]
        for mpqueue_file in mpqueue_files:
            if mpqueue_file != "mysend":
                if mpqueue_file.startswith("/" + self.boundjid.user):
                    try:
                        posix_ipc.unlink_message_queue("/" + mpqueue_file)
                    except:
                        logger.error(
                            "An error occured while deleting the file %s" % mpqueue_file
                        )

    # -----------------------------------------------------------------------
    # ----------------------- Getion connection agent -----------------------
    # -----------------------------------------------------------------------

    # def handle_connecting(self, data):
    #     """
    #     success connecting agent
    #     """
    #     pass

    def handle_connected(self, data):
        """
        success connecting agent
        """
        logger.info(
            'Agent "%s" connected to Xmpp Server [ %s :%s ]'
            % (self.boundjid.bare, self.address[0], self.address[1])
        )

    def handle_connection_failed(self, data):
        """
        Gère le scénario où la connexion échoue.

        Cette méthode est appelée lorsque la tentative de connexion échoue. Elle effectue les actions suivantes :
        1. Déconnecte la connexion actuelle.
        2. Enregistre un message d'erreur indiquant l'échec de la connexion et les paramètres de connexion.
        3. Enregistre un message de débogage indiquant la tentative de reconnexion après un nombre spécifié de secondes.
        4. Attend le nombre spécifié de secondes.
        5. Réinitialise le compteur d'attente de la boucle de connexion.
        6. Tente de se reconnecter avec un délai spécifié et un code de raison.

        Paramètres :
        data (any) : Les données associées à l'événement d'échec de connexion.

        Retourne :
        None
        """
        self.disconnect()
        nbsecond = 5
        logger.error(
            "Connection failed: verify parameter connection for %s [%s:%s]"
            % (self.boundjid.bare, self.address[0], self.address[1])
        )
        logger.debug("Retrying connection in %d seconds..." % nbsecond)
        time.sleep(nbsecond)
        self._connect_loop_wait = 0
        self.reconnect(nbsecond, "from_handle_connection_failed")

    def handle_disconnected(self, data):
        """
        Gère le scénario où la connexion est déconnectée.

        Cette méthode est appelée lorsque la connexion est déconnectée. Elle effectue les actions suivantes :
        1. Enregistre un message d'avertissement indiquant la déconnexion et les paramètres de connexion.
        2. Enregistre un message de débogage indiquant la tentative de reconnexion après un nombre spécifié de secondes.
        3. Réinitialise le compteur d'attente de la boucle de connexion.
        4. Enregistre un message de débogage indiquant la tentative de reconnexion.
        5. Tente de se reconnecter avec un délai spécifié et un code de raison.

        Paramètres :
        data (any) : Les données associées à l'événement de déconnexion.

        Retourne :
        None
        """
        nbsecond = 5
        logger.warning(
            "disconnected : parameter connection for %s [%s:%s]"
            % (self.boundjid.bare, self.address[0], self.address[1])
        )
        logger.debug("Retrying connection in %d seconds..." % nbsecond)
        # time.sleep(nbsecond)
        self._connect_loop_wait = 0
        logger.debug("Retrying connection...")
        self.reconnect(nbsecond, "from_handle_disconnected")

    async def register(self, iq):
        """
        Fill out and submit a registration form.

        The form may be composed of basic registration fields, a data form,
        an out-of-band link, or any combination thereof. Data forms and OOB
        links can be checked for as so:

        if iq.match('iq/register/form'):
            # do stuff with data form
            # iq['register']['form']['fields']
        if iq.match('iq/register/oob'):
            # do stuff with OOB URL
            # iq['register']['oob']['url']

        To get the list of basic registration fields, you can use:
            iq['register']['fields']
        """
        resp = self.Iq()
        resp["type"] = "set"
        resp["register"]["username"] = self.boundjid.user
        resp["register"]["password"] = self.password
        try:
            await resp.send()
            logging.info("Account created for %s!" % self.boundjid)
        except IqError as e:
            logging.debug("Could not register account: %s" % e.iq["error"]["text"])
        except IqTimeout:
            logging.error("Could not register account No response from server.")
            self.disconnect()

    def _check_message(self, msg):
        """
        Vérifie la conformité d'un message stanza XMPP.

        Cette méthode analyse un message stanza XMPP pour s'assurer qu'il est correctement formaté
        et traite les différents types de messages en conséquence.

        Args:
            msg (dict): Le message stanza XMPP à vérifier.

        Returns:
            tuple: Un tuple contenant un booléen et une chaîne de caractères.
                Le booléen indique si le message est valide (True) ou non (False).
                La chaîne de caractères fournit des informations supplémentaires sur le résultat.

        Raises:
            Exception: Si une erreur se produit lors de la vérification du message.

        Exemples de types de messages traités :
            - "chat" : Message envoyé dans le contexte d'une conversation en tête-à-tête.
            - "groupchat" : Message envoyé dans le contexte d'un chat multi-utilisateurs.
            - "headline" : Message probablement généré par un service automatisé.
            - "normal" : Message unique envoyé en dehors du contexte d'une conversation en tête-à-tête ou d'un chat multi-utilisateurs.
            - "error" : Erreur liée à un message précédent envoyé par l'expéditeur.

        Si le message ne contient pas de clé "from", il est considéré comme mal formaté.
        Si le message ne contient pas de clé "body", il est considéré comme manquant le corps du message.
        """
        try:
            # vérifier la conformité du message
            msgkey = msg.keys()
            msgfrom = ""
            if "from" not in msgkey:
                logging.error("Stanza message bad format %s" % msg)
                return (
                    False,
                    "bad format",
                )
            msgfrom = str(msg["from"])
            if "type" in msgkey:
                # eg: ref section 2.1
                type = str(msg["type"])
                if type == "chat":
                    # Le message est envoyé dans le contexte d'une conversation en tête-à-tête
                    pass
                elif type == "groupchat":
                    # Le message est envoyé dans le contexte d'un chat multi-utilisateurs
                    logger.error("Stanza groupchat message no process %s " % msg)
                    msg.reply("Thank you, but I do not treat groupchat messages").send()
                    return False, "groupchat"
                elif type == "headline":
                    # Le message est probablement généré par un service automatisé
                    logger.error(
                        "Stanza headline (automated service) message no process %s "
                        % msg
                    )
                    return False, "headline"
                elif type == "normal":
                    # Le message est un message unique envoyé en dehors du contexte d'une conversation en tête-à-tête
                    # ou d'un chat multi-utilisateurs, et auquel il est attendu que le destinataire réponde
                    logger.warning("MESSAGE stanza normal %s" % msg)
                    msg.reply("Thank you, but I do not treat normal messages").send()
                    return False, "normal"
                elif type == "error":
                    # Une erreur s'est produite concernant un message précédent envoyé par l'expéditeur
                    logger.error("Stanza message from %s" % msgfrom)
                    self.errorhandlingstanza(msg, msgfrom, msgkey)
                    return False, "error"
                else:
                    logger.error("Stanza message type inconu %s" % type)
                    return False, "error"
        except Exception as e:
            logging.error("Stanza message bad format %s" % msg)
            logging.error("%s" % (traceback.format_exc()))
            return False, "error %s" % str(e)
        if "body" not in msgkey:
            logging.error("Stanza message body missing %s" % msg)
            return False, "error body missing"
        return True, "chat"

    def _errorhandlingstanza(self, msg, msgfrom, msgkey):
        """
        Analyse les informations d'une stanza XMPP en cas d'erreur.

        Cette méthode extrait et logue les informations pertinentes d'une stanza XMPP
        lorsqu'une erreur est détectée. Elle parcourt les éléments enfants du message
        et les informations d'erreur pour construire un message de log détaillé.

        Args:
            msg (dict): Le message stanza XMPP contenant l'erreur.
            msgfrom (str): L'expéditeur du message.
            msgkey (list): Les clés du message stanza.

        Returns:
            None

        Exemple d'utilisation :
            Cette méthode est généralement appelée lorsqu'une erreur est détectée dans
            une stanza XMPP pour enregistrer des informations détaillées sur l'erreur.

        Note:
            Cette méthode utilise la bibliothèque `slixmpp` pour la gestion des stanzas XMPP.
        """
        logging.error("child elements message")
        messagestanza = ""
        for t in msgkey:
            if t != "error" and t != "lang":
                e = str(msg[t])
                if e != "":
                    messagestanza += "%s : %s\n" % (t, e)
        if "error" in msgkey:
            messagestanza += "Error information\n"
            msgkeyerror = msg["error"].keys()
            for t in msg["error"].keys():
                if t != "lang":
                    e = str(msg["error"][t])
                    if e != "":
                        messagestanza += "%s : %s\n" % (t, e)
        if messagestanza != "":
            logging.error(messagestanza)

    # -----------------------------------------------------------------------
    # ---------------------- END analyse strophe xmpp -----------------------
    # -----------------------------------------------------------------------

    def send_message_to_master(self, msg):
        """
        Envoie un message stanza XMPP au maître.

        Cette méthode envoie un message stanza XMPP au substitut master en utilisant les informations
        fournies dans le message `msg`. Le message est sérialisé en JSON et envoyé en tant
        que message de type "chat".

        Args:
            msg (dict): Le message à envoyer, sous forme de dictionnaire. Ce dictionnaire
                        sera sérialisé en JSON avant d'être envoyé.

        Returns:
            None

        Exemple d'utilisation :
            Cette méthode est utilisée pour envoyer des messages de contrôle ou d'information
            au maître dans un contexte de communication XMPP.

        Note:
            Cette méthode utilise la bibliothèque `slixmpp` pour la gestion des stanzas XMPP.
        """
        self.send_message(
            mbody=json.dumps(msg), mto="%s/MASTER" % self.agentmaster, mtype="chat"
        )

    async def start(self, event):
        """
        Démarre l'agent de substitution XMPP.

        Cette méthode initialise l'agent de substitution XMPP en effectuant les étapes suivantes :
        - Initialise la liste des données à envoyer.
        - Charge et nettoie les messages de la file d'attente.
        - Envoie une présence initiale.
        - Récupère le roster (liste de contacts).
        - S'abonne au maître si l'agent n'est pas le maître lui-même.
        - Enregistre un message de démarrage dans les logs XMPP.
        - Appelle le plugin de démarrage avec les paramètres appropriés.

        Args:
            event: L'événement qui déclenche le démarrage de l'agent.

        Returns:
            None
        """
        self.datas_send = []
        mg = base_message_queue_posix()
        mg.load_file(self.boundjid.user)
        mg.clean_file_all_message(prefixe=self.boundjid.user)
        self.shutdown = False
        self.send_presence()
        await self.get_roster()
        if self.agentmaster != str(self.boundjid.bare):
            # Seul le substitut maître ne s'abonne pas à lui-même.
            logger.debug("subscribe %s to %s" % (self.boundjid.bare, self.agentmaster))
            self.send_presence(pto=self.agentmaster, ptype="subscribe")

        self.xmpplog(
            "Starting substitute agent",
            type="info",
            sessionname="",
            priority=-1,
            action="xmpplog",
            who=self.boundjid.bare,
            how="",
            why="",
            date=None,
            fromuser=self.boundjid.bare,
            touser="",
        )

        # Appel du plugin de démarrage
        startparameter = {
            "action": "start",
            "sessionid": getRandomName(6, "start"),
            "ret": 0,
            "base64": False,
            "data": {},
        }
        dataerreur = {
            "action": "result" + startparameter["action"],
            "data": {"msg": "error plugin : " + startparameter["action"]},
            "sessionid": startparameter["sessionid"],
            "ret": 255,
            "base64": False,
        }
        msg = {"from": self.boundjid.bare, "to": self.boundjid.bare, "type": "chat"}
        if "data" not in startparameter:
            startparameter["data"] = {}
        module = "%s/plugin_%s.py" % (self.modulepath, startparameter["action"])
        call_plugin(
            module,
            self,
            startparameter["action"],
            startparameter["sessionid"],
            startparameter["data"],
            msg,
            dataerreur,
        )

    def signal_handler(self, signal, frame):
        """
        Gère les signaux de fermeture de l'agent XMPP.

        Cette méthode est appelée lorsque l'agent reçoit un signal de fermeture (par exemple, CTRL-C).
        Elle envoie un message d'événement au maître si l'agent n'est pas le maître lui-même,
        puis arrête l'agent.

        Args:
            signal: Le signal reçu.
            frame: Le cadre d'exécution actuel.

        Returns:
            None
        """
        logger.debug("CTRL-C EVENT")
        msgevt = {
            "action": "evtfrommachine",
            "sessionid": getRandomName(6, "eventwin"),
            "ret": 0,
            "base64": False,
            "data": {"machine": self.boundjid.jid, "event": "CTRL_C_EVENT"},
        }
        if self.agentmaster != self.boundjid.bare:
            self.send_message_to_master(msgevt)
        self.shutdown = True
        logger.debug("shutdown xmpp agent %s!" % self.boundjid.user)
        self.loop.stop()

    def restartAgent(self, to):
        """
        Redémarre l'agent XMPP spécifié.

        Cette méthode envoie un message stanza XMPP pour redémarrer l'agent spécifié par l'adresse JID `to`.
        Le message contient une action "restartbot" et est envoyé en tant que message de type "chat".

        Args:
            to (str): L'adresse JID de l'agent à redémarrer.

        Returns:
            None
        """
        self.send_message(
            mto=to, mbody=json.dumps({"action": "restartbot", "data": ""}), mtype="chat"
        )

    async def restartmachineasynchrone(self, jid):
        """
        Redémarre une machine de manière asynchrone après un délai aléatoire.

        Cette méthode attend un délai aléatoire entre 10 et 20 secondes avant de redémarrer
        la machine spécifiée par l'adresse JID `jid`. Elle utilise `asyncio.sleep` pour gérer
        le délai de manière asynchrone.

        Args:
            jid (str): L'adresse JID de la machine à redémarrer.

        Returns:
            None
        """
        waittingrestart = random.randint(10, 20)
        # TODO : Remplacer print par log
        # print "Restart Machine jid %s after %s secondes" % (jid, waittingrestart)
        # time.sleep(waittingrestart)
        await asyncio.sleep(waittingrestart)
        # TODO : Remplacer print par log
        # print "Restart Machine jid %s fait" % jid
        # Vérifie si restartAgent n'est pas appelé depuis un plugin ou une lib.
        self.restartAgent(jid)

    def xmpplog(
        self,
        text,
        type="noset",
        sessionname="",
        priority=0,
        action="xmpplog",
        who="",
        how="",
        why="",
        module="",
        date=None,
        fromuser="",
        touser="",
    ):
        """
        Enregistre un message XMPP.

        Cette fonction enregistre un message XMPP avec les paramètres spécifiés. Si le nom de la session
        n'est pas fourni, un nom de session aléatoire est généré. Si les champs 'who' et 'touser'
        ne sont pas fournis, ils sont définis sur le JID nu de l'utilisateur lié. Si le plugin 'xmpp'
        est activé dans la configuration, le journal est stocké directement dans la base de données
        XmppMasterDatabase. Sinon, le journal est envoyé en tant que message au substitut log.

        Args:
            text (str): Le texte du message de journal.
            type (str, optional): Le type du message de journal. Par défaut, "noset".
            sessionname (str, optional): Le nom de la session. Par défaut, un nom aléatoire.
            priority (int, optional): La priorité du message de journal. Par défaut, 0.
            action (str, optional): L'action associée au message de journal. Par défaut, "xmpplog".
            who (str, optional): L'utilisateur qui a initié l'action. Par défaut, le JID nu de l'utilisateur lié.
            how (str, optional): Comment l'action a été effectuée.
            why (str, optional): La raison de l'action.
            module (str, optional): Le module associé à l'action.
            date (datetime, optional): La date de l'action. Par défaut, None.
            fromuser (str, optional): L'utilisateur d'où provient l'action. Par défaut, une chaîne vide.
            touser (str, optional): L'utilisateur vers lequel l'action est dirigée. Par défaut, le JID nu de l'utilisateur lié.

        Returns:
            None
        """
        if sessionname == "":
            sessionname = getRandomName(6, "logagent")
        if who == "":
            who = self.boundjid.bare
        if touser == "":
            touser = self.boundjid.bare

        if "xmpp" in self.config.plugins_list:
            # le substitut a direct acces a la base.
            # il inscrit sans passer par 1 message.
            if sessionname.startswith("update"):
                type = "update"
            XmppMasterDatabase().setlogxmpp(
                text,
                type=type,
                sessionname=sessionname,
                priority=priority,
                who=who,
                how=how,
                why=why,
                module=module,
                action="",
                touser=touser,
                fromuser=fromuser,
            )
        else:
            msgbody = {
                "action": "xmpplog",
                "sessionid": sessionname,
                "data": {
                    "log": "xmpplog",
                    "text": text,
                    "type": type,
                    "session": sessionname,
                    "priority": priority,
                    "action": action,
                    "who": who,
                    "how": how,
                    "why": why,
                    "module": module,
                    "date": None,
                    "fromuser": fromuser,
                    "touser": touser,
                },
            }
            self.send_message(
                mto=jid.JID(self.config.sub_logger),
                mbody=json.dumps(msgbody),
                mtype="chat",
            )

    def schedulerfunction(self):
        self.manage_scheduler.process_on_event()

    def __bool_data(self, variable, default=False):
        """
        Convertit une variable en valeur booléenne.

        Cette méthode convertit une variable en valeur booléenne. Si la variable est une chaîne de caractères
        représentant "true" (en minuscules), elle retourne True. Sinon, elle retourne la valeur par défaut.

        Args:
            variable (bool or str): La variable à convertir.
            default (bool, optional): La valeur par défaut à retourner si la conversion échoue. Par défaut, False.

        Returns:
            bool: La valeur booléenne convertie.
        """
        if isinstance(variable, bool):
            return variable
        elif isinstance(variable, str):
            if variable.lower() == "true":
                return True
        return default

    async def message(self, msg):
        """
        Traite un message XMPP reçu.

        Cette méthode traite un message XMPP reçu en effectuant les étapes suivantes :
        - Ignore les messages provenant de l'agent lui-même.
        - Vérifie que le type de message est "chat".
        - Vérifie la structure du message.
        - Charge le corps du message comme un objet JSON.
        - Traite les actions spécifiques dans le message.
        - Appelle les plugins pour traiter les actions restantes.

        Args:
            msg (dict): Le message XMPP à traiter.

        Returns:
            None
        """

        if msg["from"].bare == self.boundjid.bare:
            # Il est ignoré s'il provient de lui-même
            logger.debug("I am talking to myself, nothing to add!")
            return

        # Vérifie que le type est "chat". Sinon, rejette le message.
        if msg["type"] != "chat":
            logging.error(
                "Stanza %s message not processed: only 'chat' supported" % msg["type"]
            )
            return

        # . Vérifie la structure du message.
        is_correct_msg, typemessage = self._check_message(msg)
        if not is_correct_msg:
            logging.error("Stanza message not processed: bad format")
            return

        # Message de reponse générique d'erreur a renvoye à l'emetteur
        dataerreur = {
            "action": "resultmsginfoerror",
            "sessionid": "",
            "ret": 255,
            "base64": False,
            "data": {"msg": "ERROR: Message structure"},
        }

        try:
            # Charge le corps du message comme un objet JSON.
            dataobj = json.loads(msg["body"])
        except Exception as e:
            logging.error("Invalid message structure: %s" % str(e))
            self.send_message(
                mto=msg["from"], mbody=json.dumps(dataerreur), mtype="chat"
            )
            logger.error("\n%s" % traceback.format_exc())
            return

        # Traitement d'actions spécifiques dans le message
        if "action" in dataobj and dataobj["action"] == "infomachine":
            dd = {
                "data": dataobj,
                "action": dataobj["action"],
                "sessionid": getRandomName(6, "registration"),
                "ret": 0,
            }
            dataobj = dd

        # Liste d'actions à traiter directement
        list_action_traiter_directement = []
        if dataobj["action"] in list_action_traiter_directement:
            # Appelle directement la fonction correspondante avec les données.
            return

        # Appel des plugins pour traiter les actions restantes
        try:
            if "action" in dataobj and dataobj["action"] != "" and "data" in dataobj:
                if "base64" in dataobj and self.__bool_data(dataobj["data"]):
                    mydata = json.loads(base64.b64decode(dataobj["data"]))
                else:
                    mydata = dataobj["data"]

                if "sessionid" not in dataobj:
                    dataobj["sessionid"] = getRandomName(6, "missingid")
                    logger.warning(
                        "Session ID missing in message, assigned: %s"
                        % dataobj["sessionid"]
                    )

                # Supprime les données brutes après décodage
                del dataobj["data"]

                # Transforme "infomachine" en "registeryagent"
                if dataobj["action"] == "infomachine":
                    dataobj["action"] = "registeryagent"

                try:
                    # Traite le plugin lier a l'action
                    module = f"{self.modulepath}/plugin_{dataobj['action']}.py"
                    call_plugin(
                        module,
                        self,
                        dataobj["action"],
                        dataobj["sessionid"],
                        mydata,
                        msg,
                        dataobj.get("ret", 0),
                        dataerreur,
                    )
                except TypeError:
                    # Si le plugin est manquant
                    dataerreur["data"][
                        "msg"
                    ] = f"ERROR: Plugin {dataobj['action']} missing"
                    self.send_message(
                        mto=msg["from"], mbody=json.dumps(dataerreur), mtype="chat"
                    )
                    logging.error("TypeError: Plugin %s missing" % dataobj["action"])

                except Exception as e:
                    # Autres erreurs de plugin
                    logging.error(
                        "Error in plugin [%s]: %s" % (dataobj["action"], str(e))
                    )
                    if not dataobj["action"].startswith("result"):
                        dataerreur["data"][
                            "msg"
                        ] = f"ERROR: Plugin execution {dataobj['action']}"
                        # self.send_message(mto=msg["from"], mbody=json.dumps(dataerreur), mtype="chat")
        except Exception as e:
            # Erreur générale lors du traitement du message
            logging.error("Error processing message: %s" % str(e))
            dataerreur["data"]["msg"] = "ERROR: Message structure"
            self.send_message(
                mto=msg["from"], mbody=json.dumps(dataerreur), mtype="chat"
            )
            logger.error("\n%s" % traceback.format_exc())

    def get_or_create_eventloop(self):
        """
        Récupère ou crée une boucle d'événements asyncio.

        Cette méthode tente de récupérer la boucle d'événements asyncio actuelle. Si aucune boucle
        d'événements n'est trouvée, elle en crée une nouvelle et la définit comme boucle d'événements
        actuelle.

        Returns:
            asyncio.AbstractEventLoop: La boucle d'événements asyncio.
        """
        try:
            return asyncio.get_event_loop()
        except RuntimeError as ex:
            if "There is no current event loop in thread" in str(ex):
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                return asyncio.get_event_loop()

    def iqsendpulse1(self, to, datain, timeout):
        """
        Envoie une requête IQ avec un délai d'attente.

        Cette méthode envoie une requête IQ avec un délai d'attente spécifié. Elle encode les données
        en base64 et les envoie dans un message IQ. Si une erreur se produit, elle retourne un message
        d'erreur.

        Args:
            to (str): L'adresse JID du destinataire.
            datain (dict or list or str): Les données à envoyer.
            timeout (int): Le délai d'attente en secondes.

        Returns:
            str: Un message d'erreur en cas d'échec, sinon None.
        """
        tempo = time.time()
        datafile = {
            "sesssioniq": "",
            "time": tempo + timeout,
            "name_iq_queue": datain["name_iq_queue"],
        }
        if type(datain) is dict or type(datain) is list:
            try:
                data = json.dumps(datain)
            except Exception as e:
                logger.error("iqsendpulse : encode json : %s" % str(e))
                return '{"err" : "%s"}' % str(e).replace('"', "'")
        elif type(datain) is str:
            data = str(datain)
        else:
            data = datain
        try:
            data = base64.b64encode(bytes(data, "utf-8")).decode("utf8")
        except Exception as e:
            logger.error("iqsendpulse : encode base64 : %s" % str(e))
            return '{"err" : "%s"}' % str(e).replace('"', "'")
        try:
            iq = self.make_iq_get(queryxmlns="custom_xep", ito=to)
            datafile["sesssioniq"] = iq["id"]
            logger.debug("iq id=%s" % iq["id"])
            logger.debug("iq datafile=%s" % datafile)
            itemXML = ET.Element("{%s}data" % data)
            for child in iq.xml:
                if child.tag.endswith("query"):
                    child.append(itemXML)
            try:
                self.datas_send.append(datafile)
                result = iq.send(timeout=timeout)
            except IqError as e:
                err_resp = e.iq
                logger.error(
                    "iqsendpulse : Iq error %s" % str(err_resp).replace('"', "'")
                )
                logger.error("\n%s" % (traceback.format_exc()))
                ret = '{"err" : "%s"}' % str(err_resp).replace('"', "'")

            except IqTimeout:
                logger.error("iqsendpulse : Timeout Error")
                ret = '{"err" : "Timeout Error"}'
        except Exception as e:
            logger.error("iqsendpulse : error %s" % str(e).replace('"', "'"))
            logger.error("\n%s" % (traceback.format_exc()))
            ret = '{"err" : "%s"}' % str(e).replace('"', "'")

    def iqsendpulse(self, destinataire, msg, mtimeout):
        """
        Envoie une requête IQ avec un délai d'attente et gère la réponse via une file d'attente POSIX.

        Cette méthode envoie une requête IQ avec un délai d'attente spécifié et gère la réponse via une
        file d'attente POSIX. Elle encode les données en base64 et les envoie dans un message IQ. Si une
        erreur se produit, elle retourne un message d'erreur.

        Args:
            destinataire (str): L'adresse JID du destinataire.
            msg (bytes or dict or list or str): Les données à envoyer.
            mtimeout (int): Le délai d'attente en secondes.

        Returns:
            str: Le message reçu ou un message d'erreur en cas d'échec.
        """

        def close_posix_queue(name):
            # Keep result and remove datafile['name_iq_queue']
            logger.debug("close queue msg %s" % (name))
            try:
                posix_ipc.unlink_message_queue(name)
            except:
                pass

        if isinstance(msg, (bytes)):
            msg = msg.decode("utf-8")
        if isinstance(msg, (dict, list)):
            msg = json.dumps(msg, cls=ExtendedJSONEncoder)

        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        tempo = time.time()
        datafile = {"sesssioniq": "", "time": tempo + mtimeout + 1, "name_iq_queue": ""}
        try:
            data = base64.b64encode(bytes(msg, "utf-8")).decode("utf8")
        except Exception as e:
            logger.error("iqsendpulse : encode base64 : %s" % str(e))
            return '{"err" : "%s"}' % str(e).replace('"', "'")
        try:
            iq = self.make_iq_get(queryxmlns="custom_xep", ito=destinataire)
            datafile["sesssioniq"] = iq["id"]
            datafile["name_iq_queue"] = "/" + iq["id"]
            itemXML = ET.Element("{%s}data" % data)
            for child in iq.xml:
                if child.tag.endswith("query"):
                    child.append(itemXML)
            self.datas_send.append(datafile)
            result = iq.send(timeout=mtimeout)
        except IqError as e:
            err_resp = e.iq
            logger.error("iqsendpulse : Iq error %s" % str(err_resp).replace('"', "'"))
            logger.error("\n%s" % (traceback.format_exc()))
            ret = '{"err" : "%s"}' % str(err_resp).replace('"', "'")
            return ret
        # creation ou ouverture queu datafile['name_iq_queue']
        try:
            logger.debug(
                "***  send_iq_message_resquest create queue %s"
                % datafile["name_iq_queue"]
            )
            quposix = posix_ipc.MessageQueue(
                datafile["name_iq_queue"], posix_ipc.O_CREX, max_message_size=2097152
            )
        except posix_ipc.ExistentialError:
            logger.debug("***  open queue %s" % datafile["name_iq_queue"])
            quposix = posix_ipc.MessageQueue(datafile["name_iq_queue"])
        except OSError as e:
            logger.error("ERROR CREATE QUEUE POSIX %s" % e)
            logger.error("eg : admin (/etc/security/limits.conf and  /etc/sysctl.conf")
        except Exception as e:
            logger.error("exception %s" % e)
            logger.error("\n%s" % (traceback.format_exc()))

        # attente sur cette queue le result n mtimeout.
        try:
            logger.debug(
                "***  send_iq_message_resquest attente result %s"
                % datafile["name_iq_queue"]
            )
            msgout, priority = quposix.receive(mtimeout)
            logger.debug("send_iq_message_resquest recu result")
            msgout = bytes.decode(msgout, "utf-8")
            logger.debug("*** recu  %s" % msgout)
            close_posix_queue(datafile["name_iq_queue"])
            return msgout
        except posix_ipc.BusyError:
            logger.debug("*** rien recu dans %s" % datafile["name_iq_queue"])
            close_posix_queue(datafile["name_iq_queue"])
            logger.debug("***  timeout %s" % datafile["name_iq_queue"])
            ret = '{"err" : "timeout %s" % }'
            return ret

    async def _handle_custom_iq_error(self, iq):
        if iq["type"] == "error":
            errortext = iq["error"]["text"]
            if "User already exists" in errortext:
                # This is not an IQ error
                logger.info(
                    "No need to create the account for"
                    " user %s as it already exists." % self.boundjid.bare
                )
                self.isaccount = False
                return

            miqkeys = iq.keys()
            errortext = iq["error"]["text"]
            t = time.time()
            queue = ""
            liststop = []
            deleted_queue = []

            # logger.debug("time ref %s" % t)
            try:
                for ta in self.datas_send:
                    if ta["time"] < t:
                        logger.debug(
                            "The queue %s timed out, we remove it."
                            % ta["name_iq_queue"]
                        )
                        deleted_queue.append(ta["name_iq_queue"])
                        delqueue.append(ta["name_iq_queue"])
                        continue
                    if ta["sesssioniq"] == iq["id"]:
                        queue = ta["name_iq_queue"]
                        logger.debug("TRAITEMENT RESULT IN %s" % ta["name_iq_queue"])
                    liststop.append(ta)
                self.datas_send = liststop
                logger.debug("The pending lists to remove %s" % deleted_queue)
                # delete les queues terminees
                # on supprime les ancienne liste.
                for ta in deleted_queue:
                    try:
                        logger.debug("delete queue %s" % ta["name_iq_queue"])
                        posix_ipc.unlink_message_queue(ta["name_iq_queue"])
                    except:
                        pass
                if not queue:
                    # pas de message recu return
                    logger.debug("pas de queue trouver on quitte")
                    return
                else:
                    logger.debug("QUEUE DEFINIE POUR SORTIE")
                # queue existe pour le resultat
                # creation ou ouverture de queues
                try:
                    logger.debug("essai de creer queue %s" % queue)
                    quposix = posix_ipc.MessageQueue(
                        queue, posix_ipc.O_CREX, max_message_size=2097152
                    )
                    logger.debug("create queue  pour envoi du result %s" % queue)
                except posix_ipc.ExistentialError:
                    logger.debug("essai ouvrir queue %s" % queue)
                    quposix = posix_ipc.MessageQueue(queue)
                    logger.debug("open queue %s" % queue)
                except OSError as e:
                    logger.error("ERROR CREATE QUEUE POSIX %s" % e)
                    logger.error(
                        "eg : admin (/etc/security/limits.conf and  /etc/sysctl.conf"
                    )
                    return
                except Exception as e:
                    logger.error("exception %s" % e)
                    logger.error("\n%s" % (traceback.format_exc()))
                    return
                ret = '{"err" : "%s"}' % errortext
                quposix.send(ret, 2)
            except AttributeError:
                pass
            except Exception as e:
                logger.error("exception %s" % e)
                logger.error("\n%s" % (traceback.format_exc()))

    async def _handle_custom_iq(self, iq):
        """
        Gère les erreurs de requête IQ personnalisées.

        Cette méthode gère les erreurs de requête IQ personnalisées en vérifiant le type d'erreur et
        en prenant les mesures appropriées, telles que la suppression des files d'attente expirées et
        l'envoi de messages d'erreur.

        Args:
            iq (dict): La requête IQ contenant l'erreur.

        Returns:
            None
        """
        if iq["query"] != "custom_xep":
            return
        if iq["type"] == "get":
            pass
        elif iq["type"] == "set":
            pass
        elif iq["type"] == "error":
            logger.debug("ERROR ERROR TYPE %s" % iq["id"])

        elif iq["type"] == "result":
            logger.debug(
                "we got an iq with result type. The id of this iq is: %s" % iq["id"]
            )
            t = time.time()
            queue = ""
            liststop = []
            deleted_queue = []

            for ta in self.datas_send:
                if ta["time"] < t:
                    deleted_queue.append(ta["name_iq_queue"])
                    continue
                if ta["sesssioniq"] == iq["id"]:
                    queue = ta["name_iq_queue"]
                liststop.append(ta)
            self.datas_send = liststop
            logger.debug("The pending lists to remove %s" % deleted_queue)
            # delete les queues terminees
            # on supprime les ancienne liste.
            for ta in deleted_queue:
                try:
                    logger.debug("delete queue %s" % ta["name_iq_queue"])
                    posix_ipc.unlink_message_queue(ta["name_iq_queue"])
                except:
                    pass
            if not queue:
                # pas de message recu return
                logger.debug("pas de queue trouver on quitte")
                return
            else:
                logger.debug("QUEUE DEFINIE POUR SORTIE")
            # queue existe pour le resultat
            # creation ou ouverture de queues
            try:
                logger.debug("essai de creer queue %s" % queue)
                quposix = posix_ipc.MessageQueue(
                    queue, posix_ipc.O_CREX, max_message_size=2097152
                )
                logger.debug("create queue  pour envoi du result %s" % queue)
            except posix_ipc.ExistentialError:
                logger.debug("essai ouvrir queue %s" % queue)
                quposix = posix_ipc.MessageQueue(queue)
                logger.debug("open queue %s" % queue)
            except OSError as e:
                logger.error("ERROR CREATE QUEUE POSIX %s" % e)
                logger.error(
                    "eg : admin (/etc/security/limits.conf and  /etc/sysctl.conf"
                )
            except Exception as e:
                logger.error("exception %s" % e)
                logger.error("\n%s" % (traceback.format_exc()))
            for child in iq.xml:
                if child.tag.endswith("query"):
                    for z in child:
                        if z.tag.endswith("data"):
                            ret = base64.b64decode(bytes(z.tag[1:-5], "utf-8"))
                            quposix.send(ret, 2)
                            logger.debug("Result inject to %s" % (queue))
                            try:
                                strdatajson = base64.b64decode(
                                    bytes(z.tag[1:-5], "utf-8")
                                )
                                data = json.loads(strdatajson.decode("utf-8"))
                                quposix.send(data["result"], 2)
                                return data["result"]
                            except Exception as e:
                                logger.error("_handle_custom_iq : %s" % str(e))
                                logger.error("\n%s" % (traceback.format_exc()))
                                ret = '{"err" : "%s"}' % str(e).replace('"', "'")
                                quposix.send(ret, 2)
                                return ret
                            ret = "{}"
                            quposix.send(ret, 2)
                            return ret
        else:
            # ... This will capture error responses too
            ret = "{}"
            return ret

        # self.register_handler(Callback(
        #'CustomXEP Handler3',
        # StanzaPath('iq@type=result/custom_xep'),
        # self._handle_custom_iq_get))

    def info_xmppmachinebyuuid(self, uuid):
        """
        Récupère les informations d'une machine XMPP par son UUID.

        Cette méthode récupère les informations d'une machine XMPP en utilisant son UUID. Elle interroge
        la base de données XmppMasterDatabase pour obtenir les détails de la machine associée à l'UUID
        spécifié.

        Args:
            uuid (str): L'UUID de la machine XMPP.

        Returns:
            dict: Les informations de la machine XMPP associée à l'UUID spécifié.
        """
        return XmppMasterDatabase().getGuacamoleRelayServerMachineUuid("UUID%s" % uuid)


class DateTimebytesEncoderjson(json.JSONEncoder):
    """
    JSON encoder subclass that handles serialization of `datetime` and `bytes` objects.

    This class extends the default `json.JSONEncoder` to provide additional
    functionality for serializing objects that are not natively supported by the
    `json` module, such as `datetime` and `bytes`.

    - `datetime` objects are converted to ISO 8601 formatted strings (e.g., "2024-12-03T12:34:56").
    - `bytes` objects are decoded into UTF-8 strings.

    These transformations ensure compatibility when encoding complex Python objects
    into JSON, which is particularly useful when working with APIs, logging, or
    saving structured data. If an object is not a `datetime` or `bytes`, the default
    encoder behavior is applied.

    Example:
        ```python
        from datetime import datetime
        import json

        data = {
            "timestamp": datetime.now(),
            "binary_data": b"example bytes",
            "message": "Hello, World!"
        }

        encoded_data = json.dumps(data, cls=DateTimebytesEncoderjson)
        print(encoded_data)
        # Output: {"timestamp": "2024-12-03T12:34:56", "binary_data": "example bytes", "message": "Hello, World!"}
        ```
    """

    def default(self, obj):
        if isinstance(obj, datetime):
            encoded_object = obj.isoformat()
        elif isinstance(obj, bytes):
            encoded_object = obj.decode("utf-8")
        else:
            encoded_object = json.JSONEncoder.default(self, obj)
        return encoded_object


class ExtendedJSONEncoder(json.JSONEncoder):
    """
    JSON encoder subclass that handles serialization of additional Python objects.

    This class extends the default `json.JSONEncoder` to provide additional functionality
    for serializing objects that are not natively supported by the `json` module. The encoder
    ensures that these objects are transformed into JSON-compatible representations.

    Supported Types and Their Transformations:
    - `datetime`: Converted to ISO 8601 formatted strings (e.g., "2024-12-03T12:34:56").
    - `bytes`: Decoded into UTF-8 strings (e.g., `b"example"` -> `"example"`).
    - `Decimal`: Converted to `float` for approximate representation.
    - `UUID`: Converted to their string representation (e.g., "550e8400-e29b-41d4-a716-446655440000").
    - `set` and `frozenset`: Converted to lists for JSON compatibility.
    - `Path` (from `pathlib`): Converted to strings (e.g., `Path('/path/to/file')` -> `"/path/to/file"`).
    - Custom Objects: Serialized via a `__json__()` method if the method is defined in the object.

    These transformations ensure compatibility when encoding complex Python objects into JSON,
    which is particularly useful for APIs, logging, or saving structured data.

    If an object is not of one of the supported types, the default encoder behavior is applied,
    which may raise a `TypeError` for unsupported types.

    Example Usage:
        ```python
        from datetime import datetime
        from decimal import Decimal
        import json
        import uuid
        from pathlib import Path

        class CustomObject:
            def __init__(self, value):
                self.value = value

            def __json__(self):
                return {"custom_value": self.value}

        data = {
            "timestamp": datetime.now(),
            "binary_data": b"example bytes",
            "decimal_value": Decimal("123.45"),
            "unique_id": uuid.uuid4(),
            "file_path": Path("/path/to/file"),
            "set_data": {1, 2, 3},
            "custom": CustomObject("example")
        }

        encoded_data = json.dumps(data, cls=ExtendedJSONEncoder)
        print(encoded_data)
        # Output:
        # {
        #   "timestamp": "2024-12-03T12:34:56",
        #   "binary_data": "example bytes",
        #   "decimal_value": 123.45,
        #   "unique_id": "550e8400-e29b-41d4-a716-446655440000",
        #   "file_path": "/path/to/file",
        #   "set_data": [1, 2, 3],
        #   "custom": {"custom_value": "example"}
        # }
        ```

    Attributes:
        None

    Notes:
        - Use this encoder as the `cls` argument in `json.dumps()` when serializing data containing
        unsupported types.
        - Be mindful of potential precision loss when converting `Decimal` to `float`.
    """

    def default(self, obj):
        if isinstance(obj, datetime):
            return obj.isoformat()
        elif isinstance(obj, bytes):
            return obj.decode("utf-8")
        elif isinstance(obj, Decimal):
            return float(obj)
        elif isinstance(obj, uuid.UUID):
            return str(obj)
        elif isinstance(obj, (set, frozenset)):
            return list(obj)
        elif isinstance(obj, Path):
            return str(obj)
        elif hasattr(obj, "__json__"):
            return obj.__json__()
        else:
            return super().default(obj)
