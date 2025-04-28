# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2022-2023 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-3.0-or-later
# file plugin_recombine_file.py

import logging
import json
import platform
import os
import traceback
import hashlib
from datetime import datetime
import zipfile
import uuid
import time
import re
import base64
import shutil

from lib.utils import set_logging_level

plugin = {"VERSION": "1.0", "NAME": "recombine_file", "TYPE": "all"}  # fmt: skip

logger = logging.getLogger()


@set_logging_level
def action(objectxmpp, action, sessionid, data, message, dataerreur):
    logger.debug("###################################################")
    logger.debug("call %s from %s session id %s" % (plugin, message["from"], sessionid))
    logger.debug("###################################################")
    logger.debug("json entree %s" % json.dumps(data, indent=4))

    # verification des clefs
    if not verifier_cles_non_vides(
        data,
        [
            "namefile",
            "directory",
            "type",
            "contenttype",
            "segment",
            "dir_uuid_machine",
            "dir_segment",
        ],
    ):
        logger.error("message error recombine_file")
        return

    if data["contenttype"].lower().startswith("package"):
        package = data["location"]
        data["type"] = "location"
        data["contenttype"] = "directory"
        if platform.system() in ["Linux", "Darwin"]:
            data["location"] = os.path.join("/var/lib/pulse2/packages", package)
        elif platform.system() == "Windows":
            data["location"] = os.path.join(
                r"C:\Program Files\Pulse\var\tmp\packages", package
            )

    # on veriy les types de transfert
    if platform.system() in ["Linux", "Darwin"]:
        if data["type"].lower().startswith("backup"):
            directory_path = "/var/lib/pulse2/zip_transfert"
        elif data["type"].lower().startswith("packages"):
            directory_path = "/var/lib/pulse2/packages/"
        elif data["type"].lower().startswith("location"):
            if not verifier_cles_non_vides(data, ["location"]):
                logger.error("type location. la location n'est pas transmise")
                return
            elif not chemin_valide(data["location"]):
                logger.error(
                    "location n'est pas 1 chemin correct %s" % data["location"]
                )
                return
            directory_path = os.path.dirname(data["location"])
            namefileresult = os.path.basename(data["location"])
        else:
            logger.error(
                "type transfert incorect, le type doit etre dans la liste [ 'backup', 'packages', 'location' ]"
            )
            return
        tmp_dir = "/tmp"
    elif platform.system() == "Windows":
        if data["type"].lower().startswith("backup"):
            directory_path = r"C:\Program Files\Pulse\var\zip_transfert"
        elif data["type"].lower().startswith("packages"):
            directory_path = r"C:\Program Files\Pulse\var\tmp\packages"
        elif data["type"].lower().startswith("location"):
            if not verifier_cles_non_vides(data, ["location"]):
                logger.error("type location. la location n'est pas transmise")
                return
            elif not chemin_valide(data["location"]):
                logger.error(
                    "location n'est pas 1 chemin correct %s" % data["location"]
                )
                return
            if data["contenttype"].lower().startswith("file"):
                # on recuperer le repertoire ou le fichier ou doit se trouver
                # quand c'est 1 fichier location doit contenir le path et le nom de fichier de reception
                directory_path = os.path.dirname(data["location"].replace("/", "\\"))
                namefileresult = os.path.basename(data["location"].replace("/", "\\"))
                directory_path = directory_path.replace("\\", "/")
            else:
                directory_path = data["location"]
        else:
            logger.error(
                "type transfert incorect, le type doit etre dans la liste [ 'backup', 'packages', 'location' ]"
            )
            return
        tmp_dir = r"C:\Windows\Temp"
    else:
        logger.error("os inconue")
        return

    if data["type"].lower().startswith("location"):
        repertoire_temporaire_reception = os.path.join(
            tmp_dir, data["dir_uuid_machine"]
        )
    else:
        repertoire_temporaire_reception = os.path.join(
            tmp_dir, data["dir_uuid_machine"], data["dir_segment"]
        )

    try:
        if not os.path.exists(repertoire_temporaire_reception):
            # logger.debug("creation repertoire temporaire reception %s " % repertoire_temporaire_reception)
            os.makedirs(repertoire_temporaire_reception, exist_ok=True)

        if not os.path.exists(directory_path):
            # logger.debug("creation  %s " % directory_path)
            os.makedirs(directory_path, exist_ok=True)
    except Exception:
        logger.error("We hit the backtrace \n %s" % traceback.format_exc())

    # logger.error(f"repertoire_temporaire_reception: {repertoire_temporaire_reception}")
    # logger.error(f"directory_path  : {directory_path}" )

    file_transfert = os.path.join(repertoire_temporaire_reception, data["namefile"])

    if data["segment"] == 0:
        # logger.debug("DEBUT TRAITEMENT MANIFEST")
        # logger.debug("fichier %s" % json.dumps(data, indent=4 ))
        # manifest
        # creation des chemin
        manifest_file = os.path.join(repertoire_temporaire_reception, "manifeste")
        # logger.debug("creation manifeste transfert %s" % manifest_file)
        try:
            with open(manifest_file, "w") as json_file:
                json.dump(data, json_file, indent=4)
        except Exception as e:
            logger.error(
                f"Erreur lors de l'écriture du manifest de transfert en JSON : {e}"
            )
            logger.error("We hit the backtrace \n %s" % traceback.format_exc())
        # logger.debug("CREATION FICHIER MANIFESTE %s " % manifest_file )

        # Création d'un fichier vide
        try:
            # logger.debug("creation file transfer %s" % file_transfert)
            with open(file_transfert, "wb") as file:
                pass  # Ne fait rien, mais crée le fichier vide
        except Exception as e:
            logger.error(f"Erreur lors de l'écriture du fichier JSON : {e}")
            logger.error("We hit the backtrace \n %s" % traceback.format_exc())
        # logger.debug("FIN TRAITEMENT MANIFEST")
    else:
        # logger.debug("DEBUT TRAITEMENT SEGMENT")

        if not verifier_cles_non_vides(data, ["nbtotal", "content", "nb", "directory"]):
            logger.error("message error TRAITEMENT SEGMENT")
            return
        try:
            # logger.debug("creation file transfer %s" % file_transfert)

            with open(file_transfert, "ab") as file:
                file.write(base64.b64decode(data["content"]))  # Décodage en Base64
            file_size_bytes = get_file_size(file_transfert)
            if file_size_bytes is not None:
                file_size_human = convert_size(file_size_bytes)
                logger.debug(
                    f"La taille du fichier est : {file_size_bytes} octets ({file_size_human})"
                )
        except Exception as e:
            logger.error(f"Erreur lors de l'écriture du fichier JSON : {e}")
            logger.error("We hit the backtrace \n %s" % traceback.format_exc())

        if data["nbtotal"] == data["segment"]:
            try:
                md5 = md5_hash(file_transfert)
                # logger.error("md5 is %s" % md5 )
                # on charge le manifest pour controler le md5
                manifest_file = os.path.join(
                    repertoire_temporaire_reception, "manifeste"
                )
                with open(manifest_file, "r") as json_file:
                    data_manifest = json.load(json_file)
                if data_manifest["md5"] == md5:
                    logger.debug("transfert archive reussi md5 correct")
                else:
                    logger.error(
                        "le md5 n'est pas du transfert n'est pas correct abandon et netoyage"
                    )
                    supprimer_repertoire(repertoire_temporaire_reception)
                    return
            except Exception:
                logger.error(
                    "transfert terminer. 1 erreur dans le md5 %s"
                    % traceback.format_exc()
                )
                return
            try:
                # if data['type'].lower().startswith('location

                # on recupere le repertoire ou decompresser l'archive
                name_repertoire_reception = restaurer_caracteres(data["directory"])
                name_repertoire_decompression = re.sub(
                    r"^[A-Za-z]:", "", name_repertoire_reception
                )
                name_repertoire_decompression1 = re.sub(
                    r"\.zip$", "", name_repertoire_decompression
                )
                if data["type"].lower() in ["backup", "packages"]:
                    name_repertoire_decomp = (
                        directory_path.replace("\\", "/")
                        + name_repertoire_decompression1
                    )
                    if data["contenttype"].lower().startswith("file"):
                        name_repertoire_decomp = os.path.dirname(name_repertoire_decomp)
                else:
                    name_repertoire_decomp = directory_path
                # logger.debug("directory_path %s"  % directory_path)
                # logger.debug("il faut faire le traitement de decompression to %s"  % name_repertoire_decomp)

                # on cree le repertoire si non exist
                if not os.path.exists(name_repertoire_decomp):
                    # logger.debug("creation  %s " % name_repertoire_decomp)
                    os.makedirs(name_repertoire_decomp, exist_ok=True)
                # logger.debug("decompresser_archive file zip %s"%(file_transfert)  )
                # logger.debug("decompresser_archive vers repertoire %s"%(name_repertoire_decomp)  )

                if (
                    data["contenttype"].lower().startswith("file")
                    and "location" in data
                    and data["location"]
                ):
                    # logger.debug("nouveau_nom file %s"%(namefileresult)  )
                    decompresser_archive(
                        file_transfert,
                        name_repertoire_decomp,
                        nouveau_nom=namefileresult,
                    )
                else:
                    decompresser_archive(file_transfert, name_repertoire_decomp)
                # logger.error("et on remet a zero le fichier"  )
                # with open( file_transfert, 'wb') as file:
                # pass
                logger.debug("nettoyage repertoire de travail")
                supprimer_repertoire(repertoire_temporaire_reception)
            except Exception:
                logger.error("We hit the backtrace \n %s" % traceback.format_exc())


def md5_hash(file_path):
    """
    Calcule le hash MD5 d'un fichier.

    Paramètre:
    file_path (str): Le chemin du fichier pour lequel le hash MD5 doit être calculé.

    Retourne:
    str: Le hash MD5 sous forme de chaîne hexadécimale.
    """
    hash_md5 = hashlib.md5()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_md5.update(chunk)
    return hash_md5.hexdigest()


def decompresser_archive(fichier_zip, repertoire_destination, nouveau_nom=None):
    """
    Décompresse un fichier ZIP dans un répertoire spécifié. Si un nouveau nom est fourni,
    le fichier extrait est renommé.

    Paramètres:
    fichier_zip (str): Le chemin du fichier ZIP à décompresser.
    repertoire_destination (str): Le répertoire dans lequel extraire les fichiers.
    nouveau_nom (str, optionnel): Nouveau nom pour le fichier extrait. Si défini, l'archive
    doit contenir exactement un fichier.

    Retourne:
    bool: Retourne True si la décompression s'est effectuée avec succès, False sinon.

    Exceptions:
    FileNotFoundError: Si le fichier ZIP n'existe pas.
    ValueError: Si l'archive contient plus d'un fichier lorsque nouveau_nom est spécifié.
    """
    try:
        # Vérifier si le fichier ZIP existe
        if not os.path.exists(fichier_zip):
            raise FileNotFoundError(f"Le fichier ZIP {fichier_zip} n'existe pas.")

        # Créer le répertoire de destination s'il n'existe pas déjà
        if not os.path.exists(repertoire_destination):
            os.makedirs(repertoire_destination)

        # Ouvrir le fichier ZIP
        with zipfile.ZipFile(fichier_zip, "r") as zip_ref:
            # Vérifier si nouveau_nom est défini
            if nouveau_nom:
                # Vérifier que l'archive contient exactement un fichier
                noms_fichiers = zip_ref.namelist()
                if len(noms_fichiers) != 1:
                    raise ValueError(
                        "L'archive ZIP doit contenir exactement un fichier."
                    )

                # Extraire le fichier
                nom_fichier = noms_fichiers[0]
                zip_ref.extract(nom_fichier, repertoire_destination)

                # Renommer le fichier extrait
                chemin_fichier_extrait = os.path.join(
                    repertoire_destination, nom_fichier
                )
                chemin_fichier_renomme = os.path.join(
                    repertoire_destination, nouveau_nom
                )

                # Vérifier si le fichier de destination existe déjà
                if os.path.exists(chemin_fichier_renomme):
                    os.remove(chemin_fichier_renomme)  # Supprimer le fichier existant

                os.rename(chemin_fichier_extrait, chemin_fichier_renomme)
            else:
                # Extraire tout le contenu du fichier ZIP
                zip_ref.extractall(repertoire_destination)

        return True
    except Exception as e:
        logger.error(f"Erreur lors de la décompression de l'archive : {e}")
        return False


def verifier_cles_non_vides(data, cles):
    """
    Vérifie si toutes les clés spécifiées existent dans le dictionnaire
    et si leurs valeurs ne sont pas None ou vides.

    Args:
        data (dict): Le dictionnaire à vérifier.
        cles (list): Une liste de clés à vérifier dans le dictionnaire.

    Returns:
        bool: True si toutes les clés existent et leurs valeurs ne sont pas vides, sinon False.
    """
    logger.debug("verifier_cles_non_vides")
    for cle in cles:
        if cle not in data:  # Vérifie l'existence et la valeur non vide
            logger.error("cle missing %s" % cle)
            return False
        if isinstance(data[cle], int):
            continue
        if not data[cle]:
            return False
    return True


def get_file_size(file_path):
    """
    Retourne la taille d'un fichier en octets.

    Args:
        file_path (str): Chemin du fichier.

    Returns:
        int: Taille du fichier en octets.
    """
    try:
        size = os.path.getsize(file_path)
        return size
    except Exception as e:
        logger.error(f"Erreur lors de la récupération de la taille du fichier : {e}")
        return None


def convert_size(size_bytes):
    """
    Convertit une taille en octets en une taille lisible par un humain.

    Args:
        size_bytes (int): Taille en octets.

    Returns:
        str: Taille lisible par un humain.
    """
    if size_bytes is None:
        return "Taille inconnue"

    for unit in ["octets", "Ko", "Mo", "Go", "To"]:
        if size_bytes < 1024:
            return f"{size_bytes:.2f} {unit}"
        size_bytes /= 1024


def remplacer_caracteres(chaine):
    """
    Remplace certains caractères spéciaux dans une chaîne par des codes spécifiques.

    Paramètre:
    chaine (str): La chaîne à modifier.

    Remplacements effectués:
    - '\\' est remplacé par '@@'.
    - Les espaces sont remplacés par '@nbsp@'.
    - '/' est remplacé par '@47@'.
    - '\\' est remplacé par '@92@'.
    - '.' est remplacé par '@46@'.

    Retourne:
    str: La chaîne modifiée avec les caractères remplacés.
    """
    chaine = chaine.replace("\\", "@@")
    chaine = chaine.replace(" ", "@nbsp@")
    chaine = chaine.replace("/", "@47@")
    chaine = chaine.replace("\\", "@92@")
    chaine = chaine.replace(".", "@46@")
    return chaine


def restaurer_caracteres(chaine):
    """
    Restaure les caractères spéciaux dans une chaîne modifiée.

    Paramètre:
    chaine (str): La chaîne contenant les codes à restaurer.

    Remplacements effectués:
    - '@58@' est remplacé par ':'.
    - '@46@' est remplacé par '.'.
    - '@92@' est remplacé par '\\'.
    - '@47@' est remplacé par '/'.
    - '@nbsp@' est remplacé par un espace.

    Retourne:
    str: La chaîne restaurée avec les caractères originaux.
    """
    chaine = chaine.replace("@58@", ":")
    chaine = chaine.replace("@46@", ".")
    chaine = chaine.replace("@92@", "\\")
    chaine = chaine.replace("@47@", "/")
    chaine = chaine.replace("@nbsp@", " ")
    return chaine


def chemin_valide(chemin):
    """
    Vérifie si un chemin est valide en essayant de le normaliser et de l'obtenir en chemin absolu.

    Paramètre:
    chemin (str): Le chemin à vérifier.

    Retourne:
    bool: True si le chemin est valide, False sinon.
    """
    try:
        # Utilise os.path.normpath pour normaliser le chemin
        # et os.path.abspath pour obtenir un chemin absolu
        chemin_normalise = os.path.abspath(chemin)
        return True
    except Exception as e:
        return False


def supprimer_repertoire(repertoire):
    """
    Supprime un répertoire ainsi que tout son contenu.

    Paramètre:
    repertoire (str): Le chemin du répertoire à supprimer.

    Retourne:
    None

    Actions:
    - Si le répertoire existe, il est supprimé avec tout son contenu.
    - Si le répertoire n'existe pas, un message de debug est enregistré dans le logger.
    """
    if os.path.exists(repertoire):
        shutil.rmtree(repertoire)
        logger.debug(
            f"Le répertoire '{repertoire}' et tout son contenu ont été supprimés."
        )
    else:
        logger.debug(f"Le répertoire '{repertoire}' n'existe pas.")
