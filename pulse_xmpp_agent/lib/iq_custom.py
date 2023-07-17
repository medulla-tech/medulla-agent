#!/usr/bin/python3
# -*- coding: utf-8; -*-
# SPDX-FileCopyrightText: 2016-2023 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-2.0-or-later

import os
import sys
from pulse_xmpp_agent.lib.utils import (
    name_random,
    getRandomName,
    call_plugin,
    call_plugin_separate,
    simplecommand,
    convert,
    MotDePasse,
    DateTimebytesEncoderjson,
)
import asyncio
import datetime
import time

# this import will be used later
import types
import netaddr
import configparser
import re

# 3rd party modules
import gzip
import ipaddress
import inspect
from slixmpp import ClientXMPP

import threading
import logging
import traceback

# from collections import OrderedDict
from pprint import pprint
import uuid
import json
import yaml
import xml.etree.ElementTree as ET

DEBUGPULSE = 25
logger = logging.getLogger()


class ContrainteCleNonVerifieeException(Exception):
    pass


class iq_value:
    """
    Classe représentant une structure de données pour stocker des paires clé-valeur avec expiration basée sur le temps.
    """

    def __init__(self):
        """
        Initialise la classe iq_value.
        """
        self.dictionnaire = {}
        self.contenuetype = (
            "string"  # Par défaut, le contenu est une chaîne de caractères
        )
        self.contrainte_cle = None
        self.contraintes_val = {
            "uuid": r"^[a-f\d]{8}-[a-f\d]{4}-[a-f\d]{4}-[a-f\d]{4}-[a-f\d]{12}$",
            "tel": r"^\+\d{1,3}-\d{1,}-\d{3,}-\d{4}$",
            "postal": r"^\d{5}$",
            "email": r"^[\w\.-]+@[\w\.-]+\.\w+$",
            "alphanum": r"^[a-zA-Z0-9]+$",
            "jid": r"^[a-zA-Z0-9_.-]+@[a-zA-Z0-9_.-]+\.[a-zA-Z0-9_.-]+$",
            "ipv4": r"^(\d{1,3}\.){3}\d{1,3}$",
            "ipv6": r"^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$",
            "url": r"^(http|https)://[^\s/$.?#].[^\s]*$",
            "hashtags": r"#(\w+)",
        }

    def ajouter_valeur(self, cle, valeur, duree_expiration):
        """
        Ajoute une valeur avec une clé donnée au dictionnaire avec une durée d'expiration spécifiée en secondes,
        sous réserve que la clé satisfasse la contrainte définie.

        Args:
            cle (Any): La clé associée à la valeur.
            valeur (Any): La valeur à ajouter.
            duree_expiration (int): La durée d'expiration en secondes.

        Raises:
            ContrainteCleNonVerifieeException: Si la clé ne satisfait pas la contrainte définie.

        Returns:
            None
        """
        if self._verifier_cle(cle):
            expiration = int(time.time()) + duree_expiration
            self.dictionnaire[cle] = (valeur, expiration)
        else:
            raise ContrainteCleNonVerifieeException(
                f"La contrainte de clé n'est pas vérifiée pour la clé : {cle}"
            )

    def _verifier_cle(self, cle):
        """
        Vérifie si la clé satisfait la contrainte définie.

        Args:
            cle (Any): La clé à vérifier.

        Returns:
            bool: True si la clé satisfait la contrainte, False sinon.
        """
        if self.contrainte_cle is None:
            return True
        return re.fullmatch(self.contrainte_cle, str(cle)) is not None

    def set_new_contrainte_cle(self, contrainte):
        """
        Définit la contrainte de clé en spécifiant une expression régulière.

        Args:
            contrainte (str): L'expression régulière représentant la contrainte de clé.

        Returns:
            None
        """
        self.contrainte_cle = contrainte

    def set_contrainte_cle_def(self, contrainte):
        """
        Définit la contrainte utilise sur les clés en utilisant une valeur prédéfinie correspondant a la contrainte
        Si la contrainte prédéfinie n'existe pas, la contrainte de clé est ignorée.

        Args:
            contrainte (str): La valeur prédéfinie correspondant à la contrainte de clé.

        Returns:
            None
        """
        if contrainte.lower() in self.contraintes_val:
            self.contrainte_cle = self.contraintes_val[contrainte.lower()]
        else:
            logger.warning(
                "iq_value : contrainte pas definie, on ignore la contrainte impose."
            )

    def get_valeurs(self, cle):
        """
        Récupère la valeur et le temps d'expiration associés à une clé donnée.

        Args:
            cle (Any): La clé dont on veut récupérer la valeur.

        Returns:
            Tuple[Optional[Any], Optional[int]]: Un tuple contenant la valeur et le temps d'expiration associés à la clé,
            ou (None, None) si la clé n'existe pas.
        """
        if cle in self.dictionnaire:
            return self.dictionnaire[cle]
        return None, None

    def get_valeur_only(self, cle):
        """
        Récupère uniquement la valeur associée à une clé donnée.

        Args:
            cle (Any): La clé dont on veut récupérer la valeur.

        Returns:
            Any: La valeur associée à la clé, ou None si la clé n'existe pas.
        """
        if cle in self.dictionnaire:
            valeur, _ = self.dictionnaire[cle]
            return valeur
        return None

    def get_validite(self, cle):
        """
        Récupère le temps restant (en secondes) avant l'expiration de la clé donnée.

        Args:
            cle (Any): La clé dont on veut vérifier la validité.

        Returns:
            Optional[int]: Le temps restant en secondes avant l'expiration de la clé,
            ou None si la clé n'existe pas.
        """
        if cle in self.dictionnaire:
            maintenant = int(time.time())
            _, expiration = self.dictionnaire[cle]
            temps_restant = expiration - maintenant
            return temps_restant
        return None

    def mettre_a_jour_valeur(self, cle, nouvelle_valeur):
        """
        Met à jour la valeur associée à une clé donnée.

        Args:
            cle (Any): La clé dont on veut mettre à jour la valeur.
            nouvelle_valeur (Any): La nouvelle valeur à associer à la clé.

        Returns:
            None
        """
        if cle in self.dictionnaire:
            valeur, expiration = self.dictionnaire[cle]
            self.dictionnaire[cle] = (nouvelle_valeur, expiration)

    def obtenir_valeur(self, cle):
        """
        Récupère une valeur du dictionnaire en vérifiant si la clé a expiré. Si la clé a expiré, elle est supprimée du dictionnaire.

        Args:
            cle (Any): La clé dont on veut récupérer la valeur.

        Returns:
            Optional[Any]: La valeur associée à la clé si elle n'a pas expiré, sinon None.
        """
        maintenant = int(time.time())
        if cle in self.dictionnaire:
            valeur, expiration = self.dictionnaire[cle]
            if expiration > maintenant:
                return valeur
            else:
                del self.dictionnaire[cle]
        return None

    def nettoyer_valeurs_expirees(self):
        """
        Supprime toutes les clés du dictionnaire qui ont expiré.

        Returns:
            None
        """
        maintenant = int(time.time())
        cles_a_supprimer = []
        for cle, (_, expiration) in self.dictionnaire.items():
            if expiration <= maintenant:
                cles_a_supprimer.append(cle)
        for cle in cles_a_supprimer:
            del self.dictionnaire[cle]

    def __str__(self):
        """
        Retourne une représentation sous forme de chaîne de l'objet iq_value.

        Returns:
            str: La représentation de l'objet iq_value.
        """
        lines = []
        for cle, (valeur, expiration) in self.dictionnaire.items():
            lines.append(f"Clé: {cle}")
            lines.append(
                f"Expiration: {expiration} secondes ({datetime.datetime.fromtimestamp(expiration)})"
            )
            lines.append("Valeur:")
            if self.contenuetype == "string":
                lines.append(valeur)
            elif self.contenuetype == "xml":
                try:
                    xml_prettified = self._prettify_xml(valeur)
                    lines.append(xml_prettified)
                except ET.ParseError:
                    lines.append(valeur)
            elif self.contenuetype == "yaml":
                try:
                    yaml_prettified = self._prettify_yaml(valeur)
                    lines.append(yaml_prettified)
                except (yaml.YAMLError, TypeError):
                    lines.append(valeur)
            elif self.contenuetype == "json":
                try:
                    json_prettified = self._prettify_json(valeur)
                    lines.append(json_prettified)
                except (json.JSONDecodeError, TypeError):
                    lines.append(valeur)
            lines.append("")
        return "\n".join(lines)

    # def __str__(self):
    # """
    # Retourne une représentation formatée du dictionnaire sous forme de chaîne de caractères.

    # Returns:
    # str: La représentation formatée du dictionnaire.
    # """
    # return pprint.pformat(dict(self.dictionnaire))

    def augmenter_temps(self, duree):
        """
        Augmente le temps d'expiration de toutes les clés du dictionnaire de la durée spécifiée en secondes. Les clés qui ont déjà expiré sont supprimées.

        Args:
            duree (int): La durée en secondes à ajouter au temps d'expiration.

        Returns:
            None
        """
        maintenant = int(time.time())
        nouvelles_cles_a_supprimer = []
        for cle, (valeur, expiration) in self.dictionnaire.items():
            nouvelle_expiration = expiration + duree
            if nouvelle_expiration <= maintenant:
                nouvelles_cles_a_supprimer.append(cle)
            else:
                self.dictionnaire[cle] = (valeur, nouvelle_expiration)

        for cle in nouvelles_cles_a_supprimer:
            del self.dictionnaire[cle]

    def afficher_cles_et_temps(self):
        """
        Affiche les clés, les temps d'expiration et les temps restants pour chaque clé dans le dictionnaire.

        Returns:
            str: La représentation formatée des clés, temps d'expiration et temps restants.
        """
        maintenant = int(time.time())
        tableau = []
        tableau.append(
            "{:<40} {:<20} {:<10}".format("Clé", "Temps d'expiration", "Temps restant")
        )

        for cle, (valeur, expiration) in self.dictionnaire.items():
            temps_restant = expiration - maintenant
            date_heure = datetime.datetime.fromtimestamp(expiration)
            # Formater la date et l'heure selon le format souhaité
            date_heure_formattee = date_heure.strftime("%Y-%m-%d %H:%M:%S")
            tableau.append(
                "{:<40} {:<20} {:<10}".format(cle, date_heure_formattee, temps_restant)
            )

        return "\n".join(tableau)

    def print_cles_et_temps(self):
        """
        Affiche les clés, les temps d'expiration et les temps restants pour chaque clé dans le dictionnaire.

        Returns:
            None
        """
        maintenant = int(time.time())
        print(
            "{:<40} {:<20} {:<10}".format("Clé", "Temps d'expiration", "Temps restant")
        )

        for cle, (valeur, expiration) in self.dictionnaire.items():
            temps_restant = expiration - maintenant
            print("{:<40} {:<20} {:<10}".format(cle, expiration, temps_restant))

    def iq_existe(self, cle):
        """
        Vérifie si une clé existe dans le dictionnaire.

        Args:
            cle (Any): La clé à vérifier.

        Returns:
            bool: True si la clé existe, False sinon.
        """
        return cle in self.dictionnaire

    def supprimer_valeur(self, cle):
        """
        Supprime la valeur correspondant à une clé donnée du dictionnaire, si elle existe.

        Args:
            cle (Any): La clé de la valeur à supprimer.

        Returns:
            None
        """
        if cle in self.dictionnaire:
            del self.dictionnaire[cle]

    def valeur_existe(self, valeur):
        """
        Vérifie si une valeur donnée existe dans le dictionnaire.

        Args:
            valeur (Any): La valeur à vérifier.

        Returns:
            bool: True si la valeur existe, False sinon.
        """
        for cle, (v, _) in self.dictionnaire.items():
            if v == valeur:
                return True
        return False

    def obtenir_toutes_cles(self):
        """
        Retourne une liste de toutes les clés présentes dans le dictionnaire.

        Returns:
            List[Any]: Une liste contenant toutes les clés du dictionnaire.
        """
        return list(self.dictionnaire.keys())

    def obtenir_toutes_valeurs(self):
        """
        Retourne une liste de toutes les valeurs présentes dans le dictionnaire.

        Returns:
            List[Any]: Une liste contenant toutes les valeurs du dictionnaire.
        """
        return [v for v, _ in self.dictionnaire.values()]

    def taille_dictionnaire(self):
        """
        Retourne le nombre d'éléments présents dans le dictionnaire.

        Returns:
            int: Le nombre d'éléments du dictionnaire.
        """
        return len(self.dictionnaire)

    def valeur_a_expire(self, cle):
        """
        Vérifie si une valeur donnée a expiré en fonction de sa clé.

        Args:
            cle (Any): La clé de la valeur à vérifier.

        Returns:
            bool: True si la valeur a expiré, False sinon.
        """
        maintenant = int(time.time())
        if cle in self.dictionnaire:
            _, expiration = self.dictionnaire[cle]
            return expiration <= maintenant
        return False

    def temps_restant_avant_expiration(self, cle):
        """
        Retourne le temps restant avant l'expiration d'une valeur donnée en fonction de sa clé.

        Args:
            cle (Any): La clé de la valeur dont on veut obtenir le temps restant.

        Returns:
            int: Le temps restant en secondes avant l'expiration de la valeur, ou 0 si la clé n'existe pas ou la valeur a déjà expiré.
        """
        maintenant = int(time.time())
        if cle in self.dictionnaire:
            _, expiration = self.dictionnaire[cle]
            temps_restant = expiration - maintenant
            return temps_restant if temps_restant > 0 else 0
        return 0

    def fusionner(self, autre_iq_value):
        """
        Fusionne une autre instance de la classe iq_value dans l'instance actuelle.

        Args:
            autre_iq_value (iq_value): L'autre instance de iq_value à fusionner.

        Returns:
            None
        """
        for cle, (valeur, expiration) in autre_iq_value.dictionnaire.items():
            self.dictionnaire[cle] = (valeur, expiration)

    def valeur_vide(self, cle):
        """
        Vérifie si la valeur associée à une clé donnée est vide ou None.

        Args:
            cle (Any): La clé dont on veut vérifier la valeur.

        Returns:
            bool: True si la valeur est vide ou None, False sinon.
        """
        self.nettoyer_valeurs_expirees()
        if cle in self.dictionnaire:
            valeur, _ = self.dictionnaire[cle]
            if valeur is None or valeur == "":
                return None
            else:
                return valeur
        return False

    def set_contenuetype(self, contenuetype):
        """
        Définit le type de contenu attendu pour la valeur.

        Args:
            contenuetype (str): Le type de contenu souhaité. Peut prendre les valeurs 'string', 'xml', 'yaml', 'json'.

        Returns:
            None
        """
        contenuetype = contenuetype.lower()
        if contenuetype in ["string", "xml", "yaml", "json"]:
            self.contenuetype = contenuetype
        else:
            raise ValueError("Le type de contenu spécifié n'est pas valide.")

    def verifier_type_contenu(self, valeur):
        """
        Vérifie le type de contenu de la valeur en fonction du type de contenu défini.

        Args:
            valeur: La valeur à vérifier.

        Returns:
            bool: True si le type de contenu est valide, False sinon.
        """
        if self.contenuetype == "string":
            return isinstance(valeur, str)
        elif self.contenuetype == "xml":
            try:
                ET.fromstring(valeur)
                return True
            except ET.ParseError:
                return False
        elif self.contenuetype == "yaml":
            try:
                yaml.safe_load(valeur)
                return True
            except (yaml.YAMLError, TypeError):
                return False
        elif self.contenuetype == "json":
            try:
                json.loads(valeur)
                return True
            except (json.JSONDecodeError, TypeError):
                return False
        return False

    # Méthodes auxiliaires pour la mise en forme du contenu

    def _prettify_xml(self, xml_string):
        """
        Formatte une chaîne de caractères XML pour qu'elle soit plus lisible.

        Args:
            xml_string (str): La chaîne de caractères XML à formater.

        Returns:
            str: La chaîne de caractères XML formatée.
        """
        root = ET.fromstring(xml_string)
        xml_prettified = ET.tostring(root, encoding="unicode", method="xml")
        return xml_prettified

    def _prettify_yaml(self, yaml_string):
        """
        Formatte une chaîne de caractères YAML pour qu'elle soit plus lisible.

        Args:
            yaml_string (str): La chaîne de caractères YAML à formater.

        Returns:
            str: La chaîne de caractères YAML formatée.
        """
        yaml_data = yaml.safe_load(yaml_string)
        yaml_prettified = yaml.dump(yaml_data, sort_keys=False, indent=4)
        return yaml_prettified

    def _prettify_json(self, json_string):
        """
        Formatte une chaîne de caractères JSON pour qu'elle soit plus lisible.

        Args:
            json_string (str): La chaîne de caractères JSON à formater.

        Returns:
            str: La chaîne de caractères JSON formatée.
        """
        json_data = json.loads(json_string)
        json_prettified = json.dumps(json_data, sort_keys=False, indent=4)
        return json_prettified


class Myiq(threading.Thread):
    """
    Cette classe est utilisée pour exécuter une tâche en arrière-plan.

    :param xmppobject: L'objet XMPP.
    :type xmppobject: object
    :param to: Le destinataire.
    :type to: str
    :param data: Les données à envoyer.
    :type data: dict
    :param timeout: Le temps d'attente maximal.
    :type timeout: int
    :param sessionid: L'ID de session.
    :type sessionid: str

    :return: None
    """

    def __init__(self, xmppobject, to, data, timeout=900, sessionid=None):
        threading.Thread.__init__(self)
        self.param = {
            "xmppobject": xmppobject,
            "sessionid": sessionid,
            "data": data,
            "to": to,
            "timeout": timeout,
        }
        self.result = None

    def run(self):
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        myiq = iq_custom_xep(
            self.param["xmppobject"],
            self.param["to"],
            self.param["data"],
            timeout=self.param["timeout"],
            sessionid=self.param["sessionid"],
        )
        self.result = myiq.iq_send()

    def iqsend(self):
        """
        Cette fonction envoie une requête IQ.

        :return: None
        """
        self.start()
        self.join(self.param["timeout"])
        if self.is_alive():
            self._stop()
            raise TimeoutError("Le thread a dépassé le temps d'exécution maximal.")
        else:
            return self.result


class iq_custom_xep:
    def __init__(self, xmppobject, to, dict_str, timeout=30, sessionid=None):
        # verification ressource dans JID
        self.iq = None
        self.fin = False
        self.result_iq = {}
        try:
            self.data = None
            self.timeout = int(timeout)
            self.sessionid = (
                sessionid
                if sessionid
                else getRandomName(8, pref="__" + xmppobject.boundjid.user + "__")
            )
            logger.debug("sessionid %s" % self.sessionid)
            self.xmppobject = (
                xmppobject if xmppobject.__class__.__name__ == "MUCBot" else None
            )
            res = to.strip().split("/")
            if not (len(res) == 2 and res[1] != ""):
                logger.error("Pas de ressource dans jid")
                self.to = None
            else:
                self.to = to
            try:
                if isinstance(dict_str, (dict, list)):
                    self.data = convert.encode_to_string_base64(
                        json.dumps(dict_str, cls=DateTimebytesEncoderjson)
                    )
                elif isinstance(dict_str, (bytes, str)):
                    if convert.check_base64_encoding(dict_str):
                        self.data = convert.convert_bytes_datetime_to_string(dict_str)
                    elif isinstance(dict__str, (bytes)):
                        self.data = convert.encode_to_string_base64(dict_str)
            except Exception as e:
                logger.error("%s" % (traceback.format_exc()))
                self.data = None

            if (
                self.data
                and self.timeout
                and self.sessionid
                and self.xmppobject
                and self.to
            ):
                try:
                    # creation de iq
                    self.iq = self.xmppobject.make_iq_get(
                        queryxmlns="custom_xep", ito=self.to
                    )
                    itemXML = ET.Element("{%s}data" % self.data)
                    for child in self.iq.xml:
                        if child.tag.endswith("query"):
                            child.append(itemXML)
                    self.iq["id"] = self.sessionid
                except Exception as e:
                    logger.error("%s" % (traceback.format_exc()))
            else:
                if not self.data:
                    logger.error("message nmal initialise")
                if not self.timeout:
                    logger.error("timeout nmal initialise")
                if not self.sessionid:
                    logger.error("sessionid nmal initialise")
                if not self.xmppobject:
                    logger.error("xmppobject nmal initialise")
                if not self.to:
                    logger.error("to nmal initialise")

        except Exception as e:
            logger.error("%s" % (traceback.format_exc()))

    def iq_send(self):
        logger.debug("#############################################################")
        logger.debug("####################### iq_send #######################")
        logger.debug("#############################################################")
        logger.debug(
            "#############################################################%s " % self.iq
        )

        if not self.iq:
            logger.debug("######################BYBYBY########################")
            return '{"error" : "initialisation erreur"}'
        timeoutloop = float(self.timeout + 5)
        logger.debug("#############################################################")
        logger.debug("####################### send #######################")
        logger.debug("#############################################################")

        logger.debug(" iq class %s  " % self.iq.__class__.__name__)

        self.iq.send(
            callback=self.on_response,
            timeout=int(self.timeout),
            timeout_callback=self.on_timeout,
        )
        logger.debug("#############################################################")
        logger.debug(
            "####################### send ####################### %s" % self.on_timeout
        )
        logger.debug("#############################################################")
        while True:
            if not timeoutloop:
                er = "IQ type get id [%s] to [%s] in Timeout" % (
                    self.iq["id"],
                    self.iq["to"],
                )
                self.result_iq = {"error": er}
                return self.result_iq
            timeoutloop = timeoutloop - 0.5
            if self.fin:
                logger.debug(
                    "#############################################################"
                )
                logger.debug(
                    "####################### termine on fin #######################"
                )
                logger.debug(
                    "#############################################################"
                )
                break
            time.sleep(0.5)
            logger.debug("timrout %s" % timeoutloop)
        # la reponse
        self.reponse_iq = self.iq
        return self.result_iq

    def on_response(self, reponse_iq):
        logger.debug("#############################################################")
        logger.debug(
            "on_response iq id %s from %s" % (reponse_iq["iq"], reponse_iq["from"])
        )
        logger.debug("#############################################################")
        self.result_iq = {"error": "on_response"}
        try:
            self.reponse_iq = reponse_iq
            if reponse_iq["type"] == "error":
                texterror = ""
                actionerror = ""
                logger.error("on_response1 %s" % reponse_iq["type"])
                for child in reponse_iq.xml:
                    logger.error("---------\nchild %s" % child)
                    if child.tag.endswith("error"):
                        logger.error("result iq avec erreur")
                        for z in child:
                            logger.error("########\nz %s" % z.tag)
                            if z.tag.endswith("text"):
                                if z.text:
                                    texterror = "IQ Messsage is %s" % z.text
                                    logger.error(texterror)
                            elif z.tag.endswith("service-unavailable"):
                                actionerror = (
                                    "service-unavailable, Verify presense agent %s (user and resourse]"
                                    % reponse_iq["from"]
                                )
                                logger.error(actionerror)
                            elif z.tag.endswith("remote-server-not-found"):
                                actionerror = (
                                    "remote-server-not-found, Verify domaine jid agent %s"
                                    % reponse_iq["from"]
                                )
                                logger.error(actionerror)
                            elif z.tag.endswith("undefined-condition"):
                                actionerror = (
                                    "condition d'erreur pas définie dans le protocole XMPP iq xml iq \n verify jornal ejabberd for analyse %s"
                                    % reponse_iq.xml
                                )
                                logger.error(actionerror)

                self.result_iq = {
                    "error": "IQ error id [%s] to [%s] (%s) : %s"
                    % (reponse_iq["id"], reponse_iq["to"], texterror, actionerror)
                }
                self.fin = True
                return
            elif reponse_iq["type"] == "result":
                # traitement du result
                logger.debug("traitement de iq get custom_xep")
                for child in reponse_iq.xml:
                    if child.tag.endswith("query"):
                        # select data element query
                        for z in child:
                            # recuperation (bytes data) encode en base64
                            data = z.tag[1:-5]
                            try:
                                self.result_iq = convert.decode_base64_to_string_(data)
                                return self.result_iq
                            except Exception as e:
                                logger.error("on_response custom_xep : %s" % str(e))
                                logger.error("\n%s" % (traceback.format_exc()))
                                logger.error("xml reponse : %s " % str(e))
                                return {"err": "erreur decodage iq"}
            else:
                self.result_iq = {"error": "type iq [%s] " % reponse_iq["type"]}
                self.fin = True
        except Exception as e:
            self.result_iq = {"error": "type iq [%s] " % str(e)}
            self.fin = True
        finally:
            self.fin = True

    def on_timeout(self, reponse_iq):
        self.reponse_iq = reponse_iq
        er = "IQ type get id [%s] to [%s] in Timeout" % (
            reponse_iq["id"],
            reponse_iq["to"],
        )
        logger.error(er)
        self.result_iq = {"error": er}
        self.fin = True


if __name__ == "__main__":
    unittest.main()
