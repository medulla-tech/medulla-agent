# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2022-2023 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-3.0-or-later
# file plugin_recombine_file.py

# ce plugin recois les segment de fichier transferer et les reconstitut.
# puis il decompresse l'archive a l'endroit preciser.
#
#
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
repertoire = "C:\Program Files\Pulse\var\zip_transfert"

@set_logging_level
def action(objectxmpp, action, sessionid, data, message, dataerreur):
    logger.debug("###################################################")
    logger.debug(
        "call %s from %s session id %s" % (plugin, message["from"], sessionid)
    )
    logger.debug("###################################################")

    # verification des clefs
    if not verifier_cles_non_vides(data, [  "namefile",
                                            "directory",
                                            "type",
                                            "contenttype",
                                            "segment",
                                            "dir_uuid_machine",
                                            "dir_segment"]):
        logger.error("message error recombine_file"  )
        return
    # on veriy les types de transfert
    if platform.system() in ['Linux', 'Darwin']:
        if data['type'].lower().startswith("backup"):
            directory_path = '/var/lib/pulse2/zip_transfert'
        elif data['type'].lower().startswith("packages"):
            directory_path = '/var/lib/pulse2/packages/'
        elif data['type'].lower().startswith("location"):
            if not verifier_cles_non_vides(data, ["location"]):
                logger.error("type location. la location n'est pas transmise")
                return
            elif not chemin_valide( data["location"] ):
                logger.error("location n'est pas 1 chemin correct %s" % data["location"] )
                return
            directory_path = data['location']
        else:
            logger.error("type transfert incorect, le type doit etre dans la liste [ 'backup', 'packages', 'location' ]")
        tmp_dir = "/tmp"
    elif platform.system() == 'Windows':
        if data['type'].lower().startswith("backup"):
            directory_path = r'C:/Program Files/Pulse/var/zip_transfert'
        elif data['type'].lower().startswith("packages"):
            directory_path = r'C:/Program Files/Pulse/var/tmp/packages'
        elif data['type'].lower().startswith("location"):
            if not verifier_cles_non_vides(data, ["location"]):
                logger.error("type location. la location n'est pas transmise")
                return
            elif not chemin_valide( data["location"] ):
                logger.error("location n'est pas 1 chemin correct %s" % data["location"] )
                return
            directory_path = data['location']
        else:
            logger.error("type transfert incorect, le type doit etre dans la liste [ 'backup', 'packages', 'location' ]")
            return
        tmp_dir = r"C:\Windows\Temp"
    else:
        logger.error("os inconue")
        return

    repertoire_temporaire_reception = os.path.join(tmp_dir, data['dir_uuid_machine'], data['dir_segment'] )
    try:
        if not os.path.exists(repertoire_temporaire_reception):
            logger.debug("creation repertoire temporaire reception %s " % repertoire_temporaire_reception)
            os.makedirs(repertoire_temporaire_reception, exist_ok=True)

        if not os.path.exists(directory_path):
            logger.debug("creation  %s " % directory_path)
            os.makedirs(directory_path, exist_ok=True)
    except Exception:
        logger.error("We hit the backtrace \n %s" % traceback.format_exc())

    file_transfert =  os.path.join( repertoire_temporaire_reception, data['namefile'])
    if data['segment'] == 0:
        logger.debug("DEBUT TRAITEMENT MANIFEST")
        logger.debug("fichier %s" % json.dumps(data, indent=4 ))
        # manifest
        # creation des chemin
        manifest_file =  os.path.join(repertoire_temporaire_reception, "manifeste")
        logger.debug("creation manifeste transfert %s" % manifest_file)
        try:
            with open(manifest_file, 'w') as json_file:
                json.dump(data, json_file, indent=4)
        except Exception as e:
            logger.error(f"Erreur lors de l'écriture du manifest de transfert en JSON : {e}")
            logger.error("We hit the backtrace \n %s" % traceback.format_exc())
        # Création d'un fichier vide
        try:
            logger.debug("creation file transfer %s" % file_transfert)
            with open( file_transfert, 'wb') as file:
                pass  # Ne fait rien, mais crée le fichier vide
        except Exception as e:
            logger.error(f"Erreur lors de l'écriture du fichier JSON : {e}")
            logger.error("We hit the backtrace \n %s" % traceback.format_exc())
        logger.debug("FIN TRAITEMENT MANIFEST")
    else:
        logger.debug("DEBUT TRAITEMENT SEGMENT")
        if not verifier_cles_non_vides(data, ["nbtotal",
                                            "content",
                                            "nb",
                                            "directory"]):
            logger.error("message error TRAITEMENT SEGMENT"  )
            return
        try:
            logger.debug("creation file transfer %s" % file_transfert)

            with open( file_transfert, 'ab') as file:
                file.write(base64.b64decode(data['content']))# Décodage en Base64
            file_size_bytes = get_file_size(file_transfert)
            if file_size_bytes is not None:
                file_size_human = convert_size(file_size_bytes)
                logger.debug(f"La taille du fichier est : {file_size_bytes} octets ({file_size_human})")
        except Exception as e:
            logger.error(f"Erreur lors de l'écriture du fichier JSON : {e}")
            logger.error("We hit the backtrace \n %s" % traceback.format_exc())

        if data['nbtotal'] == data['segment']:
            try:
                md5 = md5_hash(file_transfert)
                logger.error("md5 is %s" % md5 )
                # on charge le manifest pour controler le md5
                manifest_file =  os.path.join(repertoire_temporaire_reception, "manifeste")
                with open(manifest_file, 'r') as json_file:
                    data_manifest = json.load(json_file)
                if data_manifest['md5'] == md5:
                    logger.debug("transfert archive reussi md5 correct")
                else:
                    logger.error("le md5 n'est pas du transfert n'est pas correct")
                    supprimer_repertoire(repertoire_temporaire_reception)
                    return
            except Exception:
                logger.error("transfert terminer. 1 erreur dans le md5 %s" % traceback.format_exc())
                return
            try:
                # on recupere le repertoire ou decompresser l'archive
                name_repertoire_reception = restaurer_caracteres(data['directory'])
                name_repertoire_decompression =  re.sub(r'^[A-Za-z]:', '', name_repertoire_reception)
                name_repertoire_decompression1 =  re.sub(r'\.zip$', '', name_repertoire_decompression)
                if data['type'].lower() in ['backup','packages']:
                    name_repertoire_decomp =  directory_path.replace("\\",'/') +  name_repertoire_decompression1
                else:
                    name_repertoire_decomp = directory_path
                logger.error("directory_path %s"  % directory_path)

                if data['contenttype'].lower().startswith('file'):
                    name_repertoire_decomp = os.path.dirname(name_repertoire_decomp)

                logger.error("il faut faire le traitement de decompression to %s"  % name_repertoire_decomp)

                # on cree le repertoire si non exist
                if not os.path.exists(name_repertoire_decomp):
                    logger.debug("creation  %s " % name_repertoire_decomp)
                    os.makedirs(name_repertoire_decomp, exist_ok=True)
                logger.error("decompresser_archive %s"%(file_transfert)  )
                decompresser_archive(file_transfert, name_repertoire_decomp)
                logger.error("et on remet a zero le fichier"  )
                # with open( file_transfert, 'wb') as file:
                    # pass
                logger.error("et on remet a zero le fichier"  )
                supprimer_repertoire(repertoire_temporaire_reception)
            except Exception:
                logger.error("We hit the backtrace \n %s" % traceback.format_exc())

def md5_hash(file_path):
    """Calcule le hash MD5 d'un fichier."""
    hash_md5 = hashlib.md5()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_md5.update(chunk)
    return hash_md5.hexdigest()

def decompresser_archive(fichier_zip, repertoire_destination):
    # Vérifier si le fichier ZIP existe
    if not os.path.exists(fichier_zip):
        raise FileNotFoundError(f"Le fichier ZIP {fichier_zip} n'existe pas.")

    # Créer le répertoire de destination s'il n'existe pas déjà
    if not os.path.exists(repertoire_destination):
        os.makedirs(repertoire_destination)

    # Ouvrir et extraire tout le contenu du fichier ZIP
    with zipfile.ZipFile(fichier_zip, 'r') as zip_ref:
        zip_ref.extractall(repertoire_destination)

def check_and_create_directory_backup(data):
    """
    Vérifie le type de transfert de fichiers (backup, package ou location), et crée
    le répertoire approprié s'il n'existe pas encore, en fonction du système d'exploitation.

    Args:
        data (dict): Dictionnaire contenant les informations sur le type et l'emplacement du transfert.
                     Clés attendues :
                     - 'type': Type de transfert (backup ou package).
                     - 'location': Chemin spécifique de l'emplacement (facultatif).

    Returns:
        str: Chemin du répertoire créé ou existant, ou None si aucune action n'est effectuée.

    Raises:
        None: Ne lève pas d'exception mais journalise les erreurs si le système d'exploitation est non supporté
              ou si le chemin fourni est incorrect.
    """
    directory_path = None
    tmp_dir = None
    logger.debug("START check_and_create_directory_backup")
    # Vérification du type de donnée
    # if not verifier_cles_non_vides(data, ['type', 'contenttype']):
        # logger.error("Une ou plusieurs clés sont manquantes ou vides.")
        # return None, None

    # Cas des backups
    if data['type'].lower().startswith("backup"):
        logger.debug("START iiii")
        return get_directory_path_for_os('/var/lib/pulse2/zip_transfert', r'C:\Program Files\Pulse\var\zip_transfert')
    # Cas des packages
    elif data['type'].lower().startswith("package"):
        logger.debug("START BBBB")
        directory_path, tmp_dir = get_directory_path_for_os('/var/lib/pulse2/packages', r'C:\Program Files\Pulse\var\tmp\packages')
    # Cas d'un emplacement personnalisé
    elif "location" in data and data['location']:
        logger.debug("START VVVVV")
        directory_path, tmp_dir = validate_and_get_custom_location(data['location'])

    # Création du répertoire si valide
    if directory_path:
        if not os.path.exists(directory_path):
            os.makedirs(directory_path, exist_ok=True)
    return directory_path, tmp_dir


def get_directory_path_for_os(linux_path, windows_path):
    """
    Retourne le chemin du répertoire en fonction du système d'exploitation.
    Retourne également le répertoire des fichiers temporaires.

    Args:
        linux_path (str): Chemin du répertoire pour les systèmes basés sur Unix.
        windows_path (str): Chemin du répertoire pour Windows.

    Returns:
        tuple: Un tuple contenant le chemin du répertoire approprié et le chemin du répertoire temporaire,
               ou (None, None) si le système d'exploitation n'est pas supporté.
    """
    logger.debug("START get_directory_path_for_os")
    if platform.system() in ['Linux', 'Darwin']:
        logger.debug("Linux or macOS detected")
        return linux_path, "/tmp"
    elif platform.system() == 'Windows':
        logger.debug("Windows detected")
        return windows_path,
    else:
        logger.error("Unsupported operating system")
        return None, None

def validate_and_get_custom_location(location):
    """
    Valide et retourne le chemin personnalisé en fonction du système d'exploitation.

    Args:
        location (str): Chemin personnalisé.

    Returns:
        str: Chemin personnalisé validé ou None si le chemin est invalide.
    """
    if platform.system() in ['Linux', 'Darwin']:
        if location.startswith("/var/lib/pulse2"):
            return location, "/tmp"
        else:
            logger.error("Invalid path for Linux/MacOS")
    elif platform.system() == 'Windows':
        if location.startswith(r"C:\Program Files\Pulse\var"):
            return location, "C:\\Windows\\Temp"
        else:
            logger.error("Invalid path for Windows")
    else:
        logger.error("Unsupported operating system for location")
    return None, None

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
            logger.error("cle missing %s" % cle )
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
        print(f"Erreur lors de la récupération de la taille du fichier : {e}")
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

    for unit in ['octets', 'Ko', 'Mo', 'Go', 'To']:
        if size_bytes < 1024:
            return f"{size_bytes:.2f} {unit}"
        size_bytes /= 1024

def remplacer_caracteres(chaine):
    # Remplacer \\ par  @@
    chaine = chaine.replace('\\', '@@')
    # Remplacer les espaces par @nbsp@
    chaine = chaine.replace(' ', '@nbsp@')
    # Remplacer les barres obliques / par &#47;
    chaine = chaine.replace('/', '@47@')
    # Remplacer les barres obliques \ par &#92;
    chaine = chaine.replace('\\', '@92@')
    # Remplacer . par  &#92;
    chaine = chaine.replace('.', '@46@')
    return chaine

def restaurer_caracteres(chaine):
    # Remplacer @58@ par @
    chaine = chaine.replace('@58@', ':')
    # Remplacer @46@ par .
    chaine = chaine.replace('@46@', '.')
    # Remplacer @92@ par \
    chaine = chaine.replace('@92@', '\\')
    # Remplacer @47@ par /
    chaine = chaine.replace('@47@', '/')
    # Remplacer @nbsp@ par espace
    chaine = chaine.replace('@nbsp@', ' ')
    return chaine


def chemin_valide(chemin):
    try:
        # Utilise os.path.normpath pour normaliser le chemin
        # et os.path.abspath pour obtenir un chemin absolu
        chemin_normalise = os.path.abspath(chemin)
        return True
    except Exception as e:
        return False


def supprimer_repertoire(repertoire):
    if os.path.exists(repertoire):
        shutil.rmtree(repertoire)
        logger.debug(f"Le répertoire '{repertoire}' et tout son contenu ont été supprimés.")
    else:
        logger.debug(f"Le répertoire '{repertoire}' n'existe pas.")
