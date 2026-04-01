# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2016-2026 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-3.0-or-later

"""
lib/create_deploy_builder.py
============================
Module de création de déploiements directs MSC/XMPP.

Ce module expose la classe ``InstantDeployBuilder`` qui encapsule l'intégralité
de la séquence nécessaire pour créer un déploiement direct sur une machine
distante, depuis la création des entrées MSC jusqu'à l'envoi XMPP.

Usage basique
-------------
::

    from lib.create_deploy_builder import InstantDeployBuilder

    sessionid = (
        InstantDeployBuilder(xmppobject, msg, data, "install")
        .mark_as_update()   # préfixe @upd@ dans le titre → filtrage dans les vues
        .priority_high()    # spooling high côté relay
        .deploy()           # crée toutes les entrées et envoie le message XMPP
    )

Règles de visibilité des titres
--------------------------------
Les vues de déploiement filtrent l'affichage en lisant les préfixes du titre.
Les valeurs reconnues sont :

    * ``@upd@``   — déploiement de mise à jour Windows (masqué dans les vues
                   générales de déploiement applicatif)
    * ``@kiosk@`` — déploiement déclenché par le kiosk (affiché uniquement
                   dans la vue kiosk)

Ces préfixes sont ajoutés **avant** le nom du package dans le titre final.
Sans préfixe, le déploiement est visible dans toutes les vues classiques.

Imports nécessaires dans le plugin appelant
-------------------------------------------
::

    from lib.create_deploy_builder import InstantDeployBuilder
"""

import datetime
import logging
import os
import time
import traceback

# --- dépendances internes ---
from lib.managepackage import managepackage
from lib.plugins.msc import MscDatabase
from lib.plugins.xmpp import XmppMasterDatabase


logger = logging.getLogger()

# ---------------------------------------------------------------------------
# Constantes de préfixes de visibilité
# Les vues PHP/SQL s'appuient sur ces marqueurs pour décider si elles doivent
# afficher la ligne dans l'interface.  Ne pas modifier sans adapter les vues.
# ---------------------------------------------------------------------------
PREFIX_UPDATE = "@upd@"      # déploiement automatique de mise à jour Windows
PREFIX_KIOSK = "@kiosk@"     # déploiement déclenché par le kiosk


class InstantDeployBuilder:
    """
    Constructeur de déploiement direct MSC/XMPP.

    Cette classe suit le patron *builder* : chaque méthode de configuration
    retourne ``self`` pour permettre le chaînage.  L'appel final à
    :meth:`deploy` crée toutes les entrées en base et envoie le message XMPP.

    Séquence interne de ``deploy()``
    ---------------------------------
    1. Résolution de la machine cible via ``getMachinefromjid``.
    2. Résolution de la date d'installation (``utcdatetime`` du payload ou
       date courante).
    3. Chargement du descripteur de package (``xmppdeploy.json``).
    4. Création de la commande MSC (``commands`` + ``commands_on_host``).
    5. Écriture des paramètres avancés XMPP (``has_login_command``).
    6. Construction et envoi du message ``applicationdeploymentjson`` au relay.
    7. Écriture de l'entrée de suivi dans la table ``deploy``.
    8. Journalisation XMPP (``xmpplog``).

    Paramètres du constructeur
    --------------------------
    xmppobject :
        Objet XMPP du substitute.  Doit exposer les méthodes
        ``send_session_command``, ``xmpplog``, ``boundjid`` et ``config``.
    message :
        Dictionnaire XMPP standard.  ``message["from"]`` est utilisé pour
        identifier et résoudre la machine cible.
    data :
        Dictionnaire de données du plugin.  Le champ ``uuid`` désigne le
        package à déployer.  Le champ optionnel ``utcdatetime`` fixe la date
        de début.
    sectionname : str, optional
        Section du descripteur de package à exécuter.
        Valeurs courantes : ``"install"`` (défaut), ``"uninstall"``,
        ``"update"``.

        Clés obligatoires de ``data``
        ------------------------------
        ``data["uuid"]`` : str
            UUID du package à déployer.  Doit correspondre à un package présent
            dans la base PkgsDatabase **et** dans le répertoire de packages
            (``/var/lib/pulse2/packages/sharing/…``).
            Exemple : ``"d192b630-test_ijgjo4nq9d224j4oqkdq0q"``

        Clés optionnelles de ``data``
        ------------------------------
        ``data["utcdatetime"]`` : str | datetime | None
            Date et heure de début du déploiement.  Formats acceptés :
            ``"YYYY-MM-DD HH:MM:SS"``, ``"YYYY-MM-DDTHH:MM:SS"``,
            ``"YYYY-MM-DDTHH:MM:SSZ"``, ou tout format ISO 8601.
            Si absent ou ``None``, la date courante est utilisée.
            Exemple : ``"2026-04-01 03:00:00"``

    Exemple minimal
    ---------------
    ::

        sessionid = InstantDeployBuilder(xmppobject, msg, data).deploy()

    Exemple complet avec options
    ----------------------------
    ::

        sessionid = (
            InstantDeployBuilder(xmppobject, msg, data, "uninstall")
            .mark_as_update()
            .set_title_suffix("KB5034122 uninstall")
            .priority_immediate()
            .set_deployment_intervals("08:00-18:00")
            .require_reboot(False)
            .deploy()
        )

        Exemple de ``data`` minimal valide
        ------------------------------------
        ::

            data = {
                "uuid": "d192b630-kb5034122-package-uuid",   # OBLIGATOIRE
            }

        Exemple de ``data`` complet
        ----------------------------
        ::

            data = {
                "uuid":        "d192b630-kb5034122-package-uuid",   # OBLIGATOIRE
                "utcdatetime": "2026-04-01 03:00:00",               # optionnel
            }
    """

    def __init__(self, xmppobject, message, data, sectionname=None):
        """
        Initialise le builder avec les paramètres contextuels du déploiement.

        Parameters
        ----------
        xmppobject :
            Objet XMPP actif du substitute.
        message :
            Message XMPP reçu (dict).  ``message["from"]`` identifie la
            machine cible.
        data : dict
            Données du plugin.  Doit contenir au minimum ``uuid`` (UUID du
            package à déployer).  Peut contenir ``utcdatetime`` pour planifier
            le départ.
        sectionname : str, optional
            Section du descriptor à exécuter.  Défaut : ``"install"``.
        """
        self.xmppobject = xmppobject
        self.message = message
        self.data = data

        # section du descripteur (install / uninstall / update / …)
        self.sectionname = sectionname or "install"

        # paramètre JSON envoyé à createcommanddirectxmpp
        self.section = '"section":"%s"' % self.sectionname

        # paramètre enregistré dans has_login_command côté XMPP
        # (doit rester cohérent avec self.section)
        self.parameterspackage = self.section

        # suffixe affiché après "-@deploylistblack@- : " dans le titre MSC
        self.title_suffix = self.sectionname

        # liste des préfixes de visibilité à ajouter avant le nom du package
        # exemple : ["@upd@"]  →  "@upd@ NomPackage-@deploylistblack@- : install"
        self._title_prefixes = []

        # --- paramètres MSC -----------------------------------------------
        # délai (secondes) avant la première tentative de reconnexion
        self.next_connection_delay = 60

        # nombre maximum de tentatives de connexion
        self.max_connection_attempt = 4

        # bande passante allouée au déploiement en Ko/s (0 = illimité)
        self.bandwidth = 0

        # plages horaires autorisées pour le déploiement (chaîne MSC)
        self.deployment_intervals = ""

        # redémarrage requis en fin de déploiement (0/1)
        self.rebootrequired = 0

        # extinction requise en fin de déploiement (0/1)
        self.shutdownrequired = 0

        # transfert via syncthing (0/1)
        self.syncthing = 0

        # --- paramètres avancés XMPP (params_json de has_login_command) ---
        # clé reconnue par le relay : "spooling" → "high" | "ordinary"
        self.advanced_params = {}

    # -----------------------------------------------------------------------
    # Méthodes de marquage de visibilité
    # -----------------------------------------------------------------------

    def add_title_prefix(self, prefix):
        """
        Ajoute un préfixe de visibilité au titre du déploiement.

        Les préfixes permettent aux vues PHP/SQL de filtrer l'affichage.
        Appels successifs cumulatifs (pas de doublons).

        Parameters
        ----------
        prefix : str
            Préfixe à ajouter, ex. ``"@upd@"``, ``"@kiosk@"``.

        Returns
        -------
        InstantDeployBuilder
            ``self`` pour le chaînage.
        """
        if prefix and prefix not in self._title_prefixes:
            self._title_prefixes.append(prefix)
        return self

    def mark_as_update(self):
        """
        Marque le déploiement comme mise à jour Windows (préfixe ``@upd@``).

        Les vues de déploiement applicatif masqueront cette ligne.
        Seule la vue dédiée aux mises à jour Windows l'affichera.

        Returns
        -------
        InstantDeployBuilder
            ``self`` pour le chaînage.
        """
        return self.add_title_prefix(PREFIX_UPDATE)

    def mark_as_kiosk(self):
        """
        Marque le déploiement comme déclenché par le kiosk (préfixe ``@kiosk@``).

        Seule la vue kiosk affichera cette ligne dans l'interface.

        Returns
        -------
        InstantDeployBuilder
            ``self`` pour le chaînage.
        """
        return self.add_title_prefix(PREFIX_KIOSK)

    def set_title_prefixes(self, prefixes):
        """
        Remplace la liste des préfixes de visibilité.

        Parameters
        ----------
        prefixes : list[str]
            Liste de préfixes, ex. ``["@upd@", "@kiosk@"]``.

        Returns
        -------
        InstantDeployBuilder
            ``self`` pour le chaînage.
        """
        self._title_prefixes = [p for p in prefixes if p]
        return self

    # -----------------------------------------------------------------------
    # Configuration du titre
    # -----------------------------------------------------------------------

    def set_title_suffix(self, suffix):
        """
        Définit le suffixe affiché après ``-@deploylistblack@- :`` dans le titre.

        Par défaut ce suffixe est égal à ``sectionname``.  Le surcharger permet
        d'y inclure un label humain, un numéro de KB, etc.

        Parameters
        ----------
        suffix : str
            Suffixe à utiliser, ex. ``"KB5034122 uninstall"``.

        Returns
        -------
        InstantDeployBuilder
            ``self`` pour le chaînage.
        """
        if suffix:
            self.title_suffix = suffix
        return self

    # -----------------------------------------------------------------------
    # Priorité / spooling
    # -----------------------------------------------------------------------

    def set_spooling(self, priority):
        """
        Fixe la priorité de spooling sur le relay.

        La valeur est transmise au relay dans ``data["advanced"]["spooling"]``.
        Elle est interprétée par ``plugin_applicationdeploymentjson`` :

        * ``"high"``     — le déploiement passe en tête de file.
        * ``"ordinary"`` — comportement standard, respecte la file d'attente.

        Parameters
        ----------
        priority : str
            ``"high"`` ou ``"ordinary"``.

        Returns
        -------
        InstantDeployBuilder
            ``self`` pour le chaînage.

        Raises
        ------
        ValueError
            Si la valeur n'est pas ``"high"`` ou ``"ordinary"``.
        """
        if priority not in ("high", "ordinary"):
            raise ValueError(
                "spooling doit être 'high' ou 'ordinary', reçu : %r" % priority
            )
        self.advanced_params["spooling"] = priority
        return self

    def priority_high(self):
        """
        Spooling haute priorité : passe en tête de file sur le relay.

        Returns
        -------
        InstantDeployBuilder
            ``self`` pour le chaînage.
        """
        return self.set_spooling("high")

    def priority_ordinary(self):
        """
        Spooling priorité ordinaire : respecte la file d'attente sur le relay.

        Returns
        -------
        InstantDeployBuilder
            ``self`` pour le chaînage.
        """
        return self.set_spooling("ordinary")

    def priority_immediate(self):
        """
        Déploiement immédiat : spooling ``"high"`` + délai et tentatives minimaux.

        Combine :
        * ``spooling = "high"``
        * ``next_connection_delay = 0``
        * ``max_connection_attempt = 1``

        À utiliser pour les correctifs critiques ou les désinstallations urgentes.

        Returns
        -------
        InstantDeployBuilder
            ``self`` pour le chaînage.
        """
        self.next_connection_delay = 0
        self.max_connection_attempt = 1
        return self.priority_high()

    # -----------------------------------------------------------------------
    # Paramètres de reconnexion et bande passante
    # -----------------------------------------------------------------------

    def set_retry_policy(self, next_connection_delay=None, max_connection_attempt=None):
        """
        Configure la politique de reconnexion de la commande MSC.

        Parameters
        ----------
        next_connection_delay : int, optional
            Délai en secondes avant la première tentative de connexion.
            Défaut conservé si ``None``.
        max_connection_attempt : int, optional
            Nombre maximum de tentatives.  Défaut conservé si ``None``.

        Returns
        -------
        InstantDeployBuilder
            ``self`` pour le chaînage.
        """
        if next_connection_delay is not None:
            self.next_connection_delay = int(next_connection_delay)
        if max_connection_attempt is not None:
            self.max_connection_attempt = int(max_connection_attempt)
        return self

    def set_bandwidth(self, bandwidth):
        """
        Limite la bande passante utilisée pour le transfert.

        Parameters
        ----------
        bandwidth : int
            Bande passante en Ko/s.  ``0`` = illimité.

        Returns
        -------
        InstantDeployBuilder
            ``self`` pour le chaînage.
        """
        self.bandwidth = int(bandwidth)
        return self

    def set_deployment_intervals(self, deployment_intervals):
        """
        Fixe les plages horaires autorisées pour le déploiement.

        Parameters
        ----------
        deployment_intervals : str
            Plages au format MSC, ex. ``"08:00-12:00,14:00-18:00"``.
            ``None`` ou chaîne vide = pas de restriction.

        Returns
        -------
        InstantDeployBuilder
            ``self`` pour le chaînage.
        """
        self.deployment_intervals = deployment_intervals or ""
        return self

    # -----------------------------------------------------------------------
    # Options post-déploiement
    # -----------------------------------------------------------------------

    def require_reboot(self, required=True):
        """
        Demande un redémarrage de la machine en fin de déploiement.

        Parameters
        ----------
        required : bool
            ``True`` pour activer le redémarrage.  Défaut : ``True``.

        Returns
        -------
        InstantDeployBuilder
            ``self`` pour le chaînage.
        """
        self.rebootrequired = 1 if required else 0
        return self

    def require_shutdown(self, required=True):
        """
        Demande l'extinction de la machine en fin de déploiement.

        Parameters
        ----------
        required : bool
            ``True`` pour activer l'extinction.  Défaut : ``True``.

        Returns
        -------
        InstantDeployBuilder
            ``self`` pour le chaînage.
        """
        self.shutdownrequired = 1 if required else 0
        return self

    def set_syncthing(self, enabled=True):
        """
        Active ou désactive le transfert via syncthing.

        Parameters
        ----------
        enabled : bool
            ``True`` pour activer syncthing.  Défaut : ``True``.

        Returns
        -------
        InstantDeployBuilder
            ``self`` pour le chaînage.
        """
        self.syncthing = 1 if enabled else 0
        return self

    # -----------------------------------------------------------------------
    # Méthodes internes
    # -----------------------------------------------------------------------

    def _resolve_machine(self):
        """
        Résout la machine cible à partir du JID contenu dans ``message["from"]``.

        Returns
        -------
        dict | None
            Dictionnaire machine tel que retourné par ``getMachinefromjid``,
            ou ``None`` si la machine n'est pas trouvée.
        """
        return XmppMasterDatabase().getMachinefromjid(self.message["from"])

    def _resolve_install_date(self):
        """
        Détermine la date de début d'installation.

        Ordre de priorité :
        1. ``data["utcdatetime"]`` s'il est présent et parsable.
        2. Date et heure courantes.

        Formats acceptés pour ``utcdatetime`` :
        * ``"YYYY-MM-DD HH:MM:SS"``
        * ``"YYYY-MM-DDTHH:MM:SS"``
        * ``"YYYY-MM-DDTHH:MM:SSZ"``
        * Tout format supporté par ``datetime.fromisoformat``.

        Returns
        -------
        datetime.datetime
            Date de début d'installation (timezone naïve).
        """
        raw_date = self.data.get("utcdatetime")
        if not raw_date:
            return datetime.datetime.now()

        # si c'est déjà un objet datetime, retour direct
        if isinstance(raw_date, datetime.datetime):
            return raw_date

        raw_date = str(raw_date).strip()
        # tentative avec les formats les plus courants
        for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%dT%H:%M:%SZ"):
            try:
                return datetime.datetime.strptime(raw_date, fmt)
            except ValueError:
                continue

        # tentative fromisoformat (Python 3.7+)
        try:
            return datetime.datetime.fromisoformat(
                raw_date.replace("Z", "+00:00")
            ).replace(tzinfo=None)
        except ValueError:
            logger.warning(
                "utcdatetime '%s' non parsable, utilisation de l'heure courante.",
                raw_date,
            )
            return datetime.datetime.now()

    def _build_title(self, package_name):
        """
        Construit le titre complet du déploiement.

        Le titre suit le schéma :
        ``[préfixes] NomPackage-@deploylistblack@- : suffixe``

        Les préfixes (ex. ``@upd@``, ``@kiosk@``) sont placés en tête pour
        que les vues puissent les détecter sans ambiguïté.

        Parameters
        ----------
        package_name : str
            Nom humain du package extrait de ``package["info"]["name"]``.

        Returns
        -------
        str
            Titre formaté prêt à être écrit dans la table ``commands``.
        """
        base = "%s-@deploylistblack@- : %s" % (package_name, self.title_suffix)
        if self._title_prefixes:
            return "%s %s" % (" ".join(self._title_prefixes), base)
        return base

    def _build_datasend(
        self, package, path, commandid, nameuser, jidrelay, jidmachine, uuidmachine
    ):
        """
        Construit le dictionnaire ``datasend`` envoyé au relay via XMPP.

        Ce dictionnaire est reçu par ``plugin_applicationdeploymentjson`` côté
        relay, qui orchestre le transfert et l'exécution du package.

        Parameters
        ----------
        package : dict
            Descripteur complet du package (``xmppdeploy.json``).
        path : str
            Chemin local vers le répertoire du package.
        commandid : int
            Identifiant de la commande MSC créée.
        nameuser : str
            Login de l'utilisateur connecté sur la machine.
        jidrelay : str
            JID du relay server responsable de la machine.
        jidmachine : str
            JID de la machine cible.
        uuidmachine : str
            UUID inventaire de la machine cible.

        Returns
        -------
        dict
            Dictionnaire ``datasend`` complet.
        """
        # récupération des paramètres avancés enregistrés dans has_login_command
        objdeployadvanced = XmppMasterDatabase().datacmddeploy(commandid)
        if not objdeployadvanced:
            logger.error(
                "has_login_command manquant pour la commande %s" % commandid
            )
            objdeployadvanced = {}

        return {
            "name": package["info"]["name"],
            "login": nameuser,
            "idcmd": commandid,
            "advanced": objdeployadvanced,      # paramètres avancés (spooling, …)
            "methodetransfert": "pushrsync",    # méthode de transfert du package
            "path": path,                       # chemin local du package
            "packagefile": os.listdir(path),    # liste des fichiers du package
            "jidrelay": jidrelay,
            "jidmachine": jidmachine,
            "jidmaster": self.xmppobject.boundjid.bare,
            "iprelay": XmppMasterDatabase().ipserverARS(jidrelay)[0],
            "ippackageserver": XmppMasterDatabase().ippackageserver(jidrelay)[0],
            "portpackageserver": XmppMasterDatabase().portpackageserver(jidrelay)[0],
            "ipmachine": XmppMasterDatabase().ipfromjid(jidmachine)[0],
            "ipmaster": self.xmppobject.config.Server,
            "Dtypequery": "TQ",
            "Devent": "DEPLOYMENT START",
            "uuid": uuidmachine,
            "descriptor": package,              # descripteur complet pour le relay
            "transfert": True,
        }

    # -----------------------------------------------------------------------
    # Point d'entrée principal
    # -----------------------------------------------------------------------

    def deploy(self):
        """
        Exécute la séquence complète de déploiement direct.

        Étapes réalisées
        ----------------
        1. Résolution de la machine via son JID.
        2. Résolution de la date d'installation.
        3. Chargement du descripteur et du chemin du package.
        4. Création de la commande MSC (table ``commands``).
        5. Création de la cible (table ``target``).
        6. Liaison commande ↔ machine (table ``commands_on_host``).
        7. Enregistrement des paramètres avancés XMPP (``has_login_command``).
        8. Construction et envoi du message ``applicationdeploymentjson``.
        9. Écriture du suivi dans la table ``deploy``.
        10. Journalisation XMPP.

        Returns
        -------
        str | None
            ``sessionid`` XMPP du déploiement si tout s'est bien passé,
            ``None`` en cas d'erreur.
        """
        try:
            # --- 1. machine ---------------------------------------------------
            machine = self._resolve_machine()
            if not machine:
                logger.error(
                    "Déploiement annulé : machine introuvable pour le jid %s"
                    % self.message["from"]
                )
                return None

            # --- 2. date d'installation ---------------------------------------
            install_date = self._resolve_install_date()

            # l'utilisateur connecté au moment du déploiement
            nameuser = machine.get("lastuser") or ""

            # --- 3. package ---------------------------------------------------
            package = managepackage.getdescriptorpackageuuid(self.data["uuid"])
            path = managepackage.getpathpackagebyuuid(self.data["uuid"])

            if package is None:
                logger.error(
                    "Déploiement %s sur %s annulé : xmppdeploy.json introuvable."
                    % (self.data["uuid"], machine["hostname"])
                )
                return None

            package_name = package["info"]["name"]
            title = self._build_title(package_name)

            # --- 4. création de la commande MSC --------------------------------
            command = MscDatabase().createcommanddirectxmpp(
                self.data["uuid"],
                "",                        # start_file (vide pour pushrsync)
                self.section,              # parameters / section JSON
                "malistetodolistfiles",    # files  (liste gérée côté relay)
                "enable",                  # start_script
                "enable",                  # clean_on_success
                install_date,
                install_date + datetime.timedelta(hours=1),  # end_date (+1 h)
                nameuser,                  # connect_as
                nameuser,                  # creator
                title,                     # titre affiché dans les vues
                self.next_connection_delay,
                self.max_connection_attempt,
                0,                         # maxbw (géré via has_login_command)
                self.deployment_intervals,
                None,                      # fk_bundle
                None,                      # order_in_bundle
                None,                      # proxies
                "none",                    # proxy_mode
                "active",                  # state
                "1",                       # sum_running
                cmd_type=0,
            )

            commandid = command.id
            commandstart = command.start_date
            commandstop = command.end_date

            # informations relay / machine nécessaires pour la suite
            jidrelay = machine["groupdeploy"]
            uuidmachine = machine["uuid_inventorymachine"]
            jidmachine = machine["jid"]

            # --- 5 & 6. target + commands_on_host ----------------------------
            target = MscDatabase().xmpp_create_Target(uuidmachine, machine["hostname"])
            MscDatabase().xmpp_create_CommandsOnHost(
                commandid,
                target["id"],
                machine["hostname"],
                commandstop,
                commandstart,
            )

            # --- 7. paramètres avancés XMPP -----------------------------------
            # enregistrés dans has_login_command, relus ensuite par datacmddeploy
            # pour être injectés dans datasend["advanced"]
            XmppMasterDatabase().addlogincommand(
                nameuser,
                commandid,
                "",   # grpid
                "",   # nb_machine_in_grp
                "",   # instructions_nb_machine_for_exec
                "",   # instructions_datetime_for_exec
                self.parameterspackage,   # section JSON
                self.rebootrequired,
                self.shutdownrequired,
                self.bandwidth,
                self.syncthing,
                self.advanced_params,     # dict JSON → params_json (spooling…)
            )

            # --- 8. envoi XMPP ------------------------------------------------
            datasend = self._build_datasend(
                package, path, commandid, nameuser,
                jidrelay, jidmachine, uuidmachine,
            )
            sessionid = self.xmppobject.send_session_command(
                jidrelay,
                "applicationdeploymentjson",
                datasend,
                datasession=None,
                encodebase64=False,
            )

            # --- 9. entrée de suivi deploy ------------------------------------
            XmppMasterDatabase().adddeploy(
                commandid,
                jidmachine,
                jidrelay,
                machine["hostname"],
                uuidmachine,
                self.data["uuid"],
                "DEPLOYMENT START",
                sessionid,
                nameuser,
                nameuser,
                # titre court pour l'historique (sans les préfixes de visibilité)
                package_name
                + "-@deploylistblack@- "
                + commandstart.strftime("%Y/%m/%d %H:%M:%S"),
                "",
                commandstart,
                commandstop,
                machine["macaddress"],
            )

            # --- 10. log XMPP -------------------------------------------------
            timestamp_install_date = int(time.mktime(install_date.timetuple()))
            module_name = "Deployment | %s | Start" % self.sectionname.capitalize()
            self.xmppobject.xmpplog(
                "Start %s on machine %s" % (self.sectionname, jidmachine),
                type="deploy",
                sessionname=sessionid,
                priority=-1,
                action="",
                who=nameuser,
                how="",
                why=self.xmppobject.boundjid.bare,
                module=module_name,
                date=timestamp_install_date,
                fromuser=nameuser,
                touser="",
            )

            logger.info("Déploiement créé : package_uuid=%s", self.data["uuid"])
            return sessionid

        except Exception:
            logging.getLogger().error("\n%s" % traceback.format_exc())
            return None


# ---------------------------------------------------------------------------
# Exemples d'utilisation — exécutés uniquement en mode direct (python3 fichier.py)
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    # -----------------------------------------------------------------------
    # NOTE : ce bloc est DOCUMENTAIRE.
    # Les objets xmppobject, msg et data sont fictifs : remplacez-les par les
    # vrais objets disponibles dans le contexte du plugin.
    # -----------------------------------------------------------------------

    # Simulation des objets de contexte (ne pas utiliser en production)
    class _FakeXmpp:
        """Bouchon minimal de xmppobject pour illustrer les appels."""
        class boundjid:
            bare = "substitute@pulse"
        class config:
            Server = "192.168.1.1"
        def send_session_command(self, *a, **kw):
            print("  → send_session_command appelé")
            return "fake-session-id"
        def xmpplog(self, *a, **kw):
            print("  → xmpplog appelé :", a[0])

    xmppobject = _FakeXmpp()                   # objet XMPP du substitute
    msg = {"from": "pc-win11.domain@pulse"}    # message XMPP reçu

    print("=" * 60)

    # ------------------------------------------------------------------
    # CAS 1 — Déploiement d'installation standard
    # Vue : visible dans toutes les vues classiques (pas de préfixe)
    # Titre généré : "NomPackage-@deploylistblack@- : install"
    # ------------------------------------------------------------------
    print("CAS 1 : installation standard")
    data_install = {"uuid": "abc123-package-uuid", "utcdatetime": None}
    sessionid = (
        InstantDeployBuilder(xmppobject, msg, data_install, "install")
        .deploy()
    )
    print("  sessionid :", sessionid)
    print()

    # ------------------------------------------------------------------
    # CAS 2 — Désinstallation d'une mise à jour Windows
    # Vue : masqué dans les vues classiques grâce au préfixe @upd@.
    #        Affiché uniquement dans la vue "Windows Update".
    # Titre généré : "@upd@ NomPackage-@deploylistblack@- : uninstall"
    # ------------------------------------------------------------------
    print("CAS 2 : désinstallation update Windows (@upd@)")
    data_uninstall = {"uuid": "kb500001-update-uuid"}
    sessionid = (
        InstantDeployBuilder(xmppobject, msg, data_uninstall, "uninstall")
        .mark_as_update()                       # préfixe @upd@
        .set_title_suffix("KB5034122 uninstall")
        .priority_immediate()                   # spooling=high, délai=0, tentatives=1
        .deploy()
    )
    print("  sessionid :", sessionid)
    print()

    # ------------------------------------------------------------------
    # CAS 3 — Installation haute priorité avec plage horaire
    # Vue : visible dans les vues classiques (pas de préfixe).
    # Le relay placera ce déploiement en tête de file (spooling=high).
    # ------------------------------------------------------------------
    print("CAS 3 : installation haute priorité avec plage horaire")
    data_hp = {"uuid": "office365-package-uuid"}
    sessionid = (
        InstantDeployBuilder(xmppobject, msg, data_hp, "install")
        .priority_high()                        # spooling = high
        .set_deployment_intervals("08:00-18:00")
        .set_retry_policy(next_connection_delay=30, max_connection_attempt=6)
        .set_bandwidth(2048)                    # limité à 2 Mo/s
        .deploy()
    )
    print("  sessionid :", sessionid)
    print()

    # ------------------------------------------------------------------
    # CAS 4 — Installation planifiée à une date précise + redémarrage
    # Vue : visible dans les vues classiques.
    # ------------------------------------------------------------------
    print("CAS 4 : installation planifiée + redémarrage")
    data_planned = {
        "uuid": "driver-critical-uuid",
        "utcdatetime": "2026-04-01 03:00:00",  # installation à 3h du matin
    }
    sessionid = (
        InstantDeployBuilder(xmppobject, msg, data_planned, "install")
        .set_title_suffix("driver critique planifié")
        .require_reboot(True)                   # redémarrage après installation
        .priority_ordinary()                    # respecte la file d'attente
        .deploy()
    )
    print("  sessionid :", sessionid)
    print()

    # ------------------------------------------------------------------
    # CAS 5 — Déploiement kiosk
    # Vue : masqué dans toutes les vues sauf la vue kiosk (@kiosk@).
    # Titre généré : "@kiosk@ NomPackage-@deploylistblack@- : install"
    # ------------------------------------------------------------------
    print("CAS 5 : déploiement kiosk (@kiosk@)")
    data_kiosk = {"uuid": "firefox-kiosk-uuid"}
    sessionid = (
        InstantDeployBuilder(xmppobject, msg, data_kiosk, "install")
        .mark_as_kiosk()                        # préfixe @kiosk@
        .set_title_suffix("Firefox kiosk")
        .priority_high()
        .deploy()
    )
    print("  sessionid :", sessionid)
    print()

    # ------------------------------------------------------------------
    # CAS 6 — Mise à jour kiosk (cumul de préfixes @kiosk@ + @upd@)
    # Vue : visible uniquement dans la vue kiosk ET la vue update,
    #        masqué dans toutes les autres.
    # Titre généré : "@kiosk@ @upd@ NomPackage-@deploylistblack@- : update"
    # ------------------------------------------------------------------
    print("CAS 6 : mise à jour depuis le kiosk (@kiosk@ @upd@)")
    data_kiosk_upd = {"uuid": "firefox-update-uuid"}
    sessionid = (
        InstantDeployBuilder(xmppobject, msg, data_kiosk_upd, "update")
        .mark_as_kiosk()                        # préfixe @kiosk@
        .mark_as_update()                       # préfixe @upd@
        .set_title_suffix("Firefox update kiosk")
        .deploy()
    )
    print("  sessionid :", sessionid)
    print()

    print("=" * 60)
    print("Tous les exemples ont été exécutés (mode bouchon, sans BDD réelle).")
