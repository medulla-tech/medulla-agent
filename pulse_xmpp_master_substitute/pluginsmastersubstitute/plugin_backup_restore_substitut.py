#!/usr/bin/python3
# -*- coding: utf-8; -*-
# SPDX-FileCopyrightText: 2016-2023 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-3.0-or-later
# pulse_xmpp_master_substitute/pluginsmastersubstitute/plugin_backup_restore_substitut.py

# ce plugin est appeler depuis mmc
# il a comme but de transferer des fichier de backup


"""
This plugin can be called from quick action
"""
import traceback
import json
import logging
import os
import hashlib
from datetime import datetime
import zipfile
import uuid
import time
import re
import base64

var_file_zipzer = "/var/lib/pulse2/zip_transfert"

logger = logging.getLogger()

plugin = {"VERSION": "1.0", "NAME": "backup_restore_substitut", "TYPE": "mastersub"}

def action(xmppobject, action, sessionid, data, message, ret, dataobj=None):
    logger.debug("###################################################")
    logger.debug("call %s from %s" % (plugin, message["from"]))
    logger.debug("###################################################")
    logger.debug("datafffffffffffffff %s" % json.dumps(data['data'], indent=4))
    try:
        datamsg=data['data']
        logger.debug("datamsg %s" % datamsg.keys())
        # Spécifier le chemin où créer le répertoire ZIP
        var_file_zipzer = "/var/lib/pulse2/zip_transfert"
        # Créer le répertoire s'il n'existe pas
        os.makedirs(var_file_zipzer, exist_ok=True)
        if 'directorylist' in datamsg and datamsg['directorylist']:
            for directory in datamsg['directorylist']:
                logger.debug("creation d'un fichier zip depuis 1 repertoire : %s" % directory)
                if directory:
                    repertoire_zip = os.path.join(datamsg['base_path'], directory[0])
                    logger.info("repertoire_zip %s" %repertoire_zip)
                    name_file_zip_actuel = generer_name_avec_timestamp(datamsg['machine_dest_backup']['uuid_serial_machine'],
                                                                    os.path.join(directory[1]))
                    archive_fichier_name_zip = f'{name_file_zip_actuel}.zip'
                    logger.info("archive_fichier_name_zip %s" %archive_fichier_name_zip)
                    path_archive_fichier_name_zip  = os.path.join(var_file_zipzer, archive_fichier_name_zip)
                    logger.info("creation d'un fichier zip %s" %path_archive_fichier_name_zip)
                    if not zipper_repertoire( repertoire_zip, path_archive_fichier_name_zip):
                        logger.info("demande de compression dun repertoire inexistant")
                        continue
                    # Exemple d'utilisation
                    manager = ZipFileManager(var_file_zipzer)
                    manager.analyze_and_cleanup()
                    output_dir_list = process_zip_files(var_file_zipzer, var_file_zipzer, datamsg['machine_dest_backup']['uuid_serial_machine'], segment_size=64000)
        if 'filelist' in datamsg and datamsg['filelist']:
            for files in datamsg['filelist']:
                logger.debug("creation d'un fichier zip depuis 1 fichier : %s" % files)
                if files:
                    input_file = os.path.join(datamsg['base_path'], files[0])
                    logger.info("imput file a zipper %s" %input_file)
                    name_file_zip_actuel = generer_name_avec_timestamp(datamsg['machine_dest_backup']['uuid_serial_machine'],
                                                                    os.path.join(files[1]))
                    archive_fichier_name_zip = f'{name_file_zip_actuel}.zip'
                    logger.info("archive_fichier_name_zip %s" %archive_fichier_name_zip)

                    path_archive_fichier_name_zip  = os.path.join(var_file_zipzer, archive_fichier_name_zip)
                    logger.info("creation d'un fichier zip %s" %path_archive_fichier_name_zip)
                    if not zipper_fichier(input_file, path_archive_fichier_name_zip, fichier_vide=True):
                    # if not zipper_repertoire( file_zip, path_archive_fichier_name_zip):
                        logger.info("demande de compression dun fichier inexistant")
                        continue
                    # Exemple d'utilisation
                    manager = ZipFileManager(var_file_zipzer)
                    manager.analyze_and_cleanup()
                    output_dir_list = process_zip_files(var_file_zipzer,
                                                        var_file_zipzer,
                                                        datamsg['machine_dest_backup']['uuid_serial_machine'],
                                                        segment_size=64000,
                                                        type_transfert = "backup",
                                                        location = None,
                                                        contenttype = "file"
                                                        )
    except Exception:
        logger.error("%s" % (traceback.format_exc()))

def process_zip_files(input_dir,
                      output_dir_base_trunck,
                      uuid_serial_machine,
                      segment_size=8000,
                      type_transfert = "backup",
                      location = None,
                      contenttype = "directory"):
    """
    Lit tous les fichiers ZIP d'un répertoire, les découpe et enregistre les segments dans un répertoire de sortie basé sur le JID.
        contenttype file ou directory
    """
    output_dir_list=[]
    output_dir_base = f"{output_dir_base_trunck}/{uuid_serial_machine}"

    # Vérifier si le répertoire de base existe, sinon le créer
    if not os.path.exists(output_dir_base):
        os.makedirs(output_dir_base)

    # Parcourir tous les fichiers dans le répertoire d'entrée
    for file_name in os.listdir(input_dir):
        if file_name.endswith(".zip"):  # Vérifier si c'est un fichier ZIP
            file_path = os.path.join(input_dir, file_name)
            output_dir = os.path.join(output_dir_base, os.path.splitext(file_name)[0])

            # Créer le répertoire de sortie pour chaque fichier ZIP
            if not os.path.exists(output_dir):
                os.makedirs(output_dir)

            # Appeler la fonction split_file pour découper le fichier ZIP
            split_file(file_path,
                       output_dir,
                       segment_size,
                       type_transfert,
                       location,
                       contenttype)

            logger.debug(f"Fichier {file_name} découpé et enregistré dans {output_dir}")
            try:
                os.remove(file_path)
                logger.debug(f"Le fichier {file_name} a été effacé avec succès.")
                return True
            except FileNotFoundError:
                logger.error(f"Le fichier {file_name} n'existe pas.")
                return output_dir_list
            except PermissionError:
                logger.error(f"Vous n'avez pas les permissions nécessaires pour effacer le fichier {file_name}.")
                return output_dir_list
            except Exception as e:
                logger.error(f"Une erreur s'est produite lors de l'effacement du fichier {file_name}: {e}")
                return output_dir_list
            output_dir_list.append(output_dir)
    return output_dir_list

def md5_hash(file_path):
    """Calcule le hash MD5 d'un fichier."""
    hash_md5 = hashlib.md5()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_md5.update(chunk)
    return hash_md5.hexdigest()

def split_file(file_path,
               output_dir,
               segment_size=8000,
               type_transfert =  "backup",
               location = None ,
               contenttype = "directory"):
    """Découpe un fichier en segments et enregistre chaque segment sous forme de fichier JSON en base64."""
    # Vérifier si le répertoire de sortie existe, sinon le créer
    logger.error(f"split_file file_path {file_path}: ")
    logger.error(f"split_file output_dir {output_dir}: ")
    logger.error(f"split_file contenttype {contenttype}: ")


    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    # Obtenir les informations de base du fichier
    file_name = os.path.basename(file_path)
    file_size = os.path.getsize(file_path)
    total_parts = (file_size + segment_size - 1) // segment_size
    file_uuid = str(uuid.uuid4())
    directory_or_file= file_name
    if file_name.endswith(".zip"):
        directory_or_file = file_name[:-4]
    try:
        parties = file_name.split('_')
        # Prendre seulement la 3e partie
        directory_or_file = parties[2]
    except ValueError as ve:
        logger.error("pas 1 fichier zip")
        return None

    # Calculer le hash MD5 du fichier original
    original_md5 = md5_hash(file_path)

    # Lecture et découpe du fichier en segments
    with open(file_path, "rb") as f:
        part_num = 0
        while chunk := f.read(segment_size):
            # Encodage de la partie en base64
            encoded_content = base64.b64encode(chunk).decode('utf-8')

            # Création du fichier JSON pour cette partie
            part_data = {
                "namefile": file_name,
                "directory":directory_or_file,
                "nb": part_num + 1,
                "nbtotal": total_parts,
                "content": encoded_content,
                "type": type_transfert,
                "location": location,
                "contenttype": contenttype
            }

            part_file_name = f"{file_uuid}_{part_num+1}.json"
            part_file_path = os.path.join(output_dir, part_file_name)

            with open(part_file_path, "w") as part_file:
                json.dump(part_data, part_file)

            part_num += 1

    # Création du fichier manifeste
    manifest_data = {
        "namefile": file_name,
        "directory":directory_or_file,
        "creation": str(datetime.now()),
        "nb_total": total_parts,
        "md5": original_md5,
        "type_file": "zip" if file_name.endswith('.zip') else "unknown",
        "size_trunck": segment_size,
        "type": type_transfert,
        "location": location,
        "contenttype": contenttype
    }

    manifest_file_name = f"{file_uuid}_0.manif"
    manifest_file_path = os.path.join(output_dir, manifest_file_name)

    with open(manifest_file_path, "w") as manifest_file:
        json.dump(manifest_data, manifest_file)

    logger.debug(f"Fichier découpé en {total_parts} parties et manifest généré.")

def recombine_file(manifest_path, input_dir, output_file):
    """Recompose le fichier original à partir des segments JSON et vérifie le hash MD5."""
    # Lire le fichier manifeste
    with open(manifest_path, "r") as manifest_file:
        manifest_data = json.load(manifest_file)

    original_file_name = manifest_data["le nom reelle du fichier"]
    total_parts = manifest_data["nombre total de partie"]
    original_md5 = manifest_data["md5"]

    file_uuid = os.path.basename(manifest_path).split("_")[0]

    with open(output_file, "wb") as output_f:
        # Recomposer le fichier à partir des fichiers JSON
        for part_num in range(1, total_parts + 1):
            part_file_name = f"{file_uuid}_{part_num}.json"
            part_file_path = os.path.join(input_dir, part_file_name)

            with open(part_file_path, "r") as part_file:
                part_data = json.load(part_file)
                # Décoder le contenu base64 et l'écrire dans le fichier de sortie
                decoded_content = base64.b64decode(part_data["content"])
                output_f.write(decoded_content)

    # Vérification du hash MD5 du fichier recomposé
    recombined_md5 = md5_hash(output_file)
    if recombined_md5 == original_md5:
        logger.debug(f"Fichier recomposé avec succès, MD5 vérifié : {recombined_md5}")
    else:
        logger.debug(f"Erreur : le MD5 recomposé {recombined_md5} ne correspond pas à l'original {original_md5}.")


def check_manifests(directory):
    """Vérifie tous les manifestes dans un répertoire et retourne deux listes :
    - Manifestes complets : Tous les fichiers nécessaires sont présents.
    - Manifestes incomplets : Certains fichiers manquent.
    """
    complete_manifests = []
    incomplete_manifests = []

    # Parcourir tous les fichiers dans le répertoire
    for file_name in os.listdir(directory):
        # Chercher uniquement les fichiers manifeste (suffixe _0.manif)
        if file_name.endswith("_0.manif"):
            manifest_path = os.path.join(directory, file_name)

            # Lire le fichier manifeste
            with open(manifest_path, "r") as manifest_file:
                manifest_data = json.load(manifest_file)

            total_parts = manifest_data["nombre total de partie"]
            file_uuid = file_name.split("_")[0]

            # Vérifier que toutes les parties de fichiers existent
            all_parts_present = True
            for part_num in range(1, total_parts + 1):
                part_file_name = f"{file_uuid}_{part_num}.json"
                part_file_path = os.path.join(directory, part_file_name)
                if not os.path.exists(part_file_path):
                    all_parts_present = False
                    break

            if all_parts_present:
                complete_manifests.append(file_name)
            else:
                incomplete_manifests.append(file_name)

    return complete_manifests, incomplete_manifests


def remplacer_caracteres(chaine):
    # Remplacer @ par  @@
    chaine = chaine.replace('@', '@64@')
    # Remplacer les : par  &#58
    chaine = chaine.replace(':', '@58@')
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
    chaine = chaine.replace('@58@', ':')
    # Remplacer @46@ par .
    chaine = chaine.replace('@46@', '.')
    # Remplacer @92@ par \
    chaine = chaine.replace('@92@', '\\')
    # Remplacer @47@ par /
    chaine = chaine.replace('@47@', '/')
    # Remplacer @nbsp@ par espace
    chaine = chaine.replace('@nbsp@', ' ')
    # Remplacer @@ par @
    chaine = chaine.replace('@64@', '@')

    return chaine

def time_since_timestamp(timestamp):
    """
    Calcule le temps écoulé depuis un timestamp donné.

    Args:
        timestamp (int): Le timestamp à partir duquel calculer le temps écoulé.

    Returns:
        tuple: Un tuple contenant le nombre de jours, heures, minutes et secondes écoulés depuis le timestamp.
    """
    # Obtenir le temps actuel
    current_time = time.time()

    # Calculer la différence en secondes
    time_difference = current_time - timestamp

    # Convertir la différence en jours, heures, minutes et secondes
    days = time_difference // (24 * 3600)
    time_difference %= (24 * 3600)
    hours = time_difference // 3600
    time_difference %= 3600
    minutes = time_difference // 60
    seconds = time_difference % 60

    return int(days), int(hours), int(minutes), int(seconds)

def generer_name_avec_timestamp(jid_dest_backup, pathnamefile, millisecondes=False):
    """
    Génère un UUID aléatoire et y ajoute un timestamp.

    :param millisecondes: Si True, utilise le timestamp en millisecondes. Par défaut, c'est False.
    :return: Une chaîne contenant l'UUID et le timestamp.
    """
    # emplacement = remplacer_caracteres(pathnamefile)
    emplacement = pathnamefile
    # Obtenir le timestamp
    if millisecondes:
        timestamp = int(time.time() * 1000)  # Timestamp en millisecondes
    else:
        timestamp = int(time.time())  # Timestamp en secondes
    # Combiner le UUID et le timestamp
    nom_file_emplacement = f"{timestamp}_{jid_dest_backup}_{emplacement}"
    return remplacer_caracteres(nom_file_emplacement)

def generer_uuid_avec_timestamp(millisecondes=False):
    """
    Génère un UUID aléatoire et y ajoute un timestamp.

    :param millisecondes: Si True, utilise le timestamp en millisecondes. Par défaut, c'est False.
    :return: Une chaîne contenant l'UUID et le timestamp.
    """
    # Générer un UUID aléatoire
    uuid_aleatoire = uuid.uuid4()

    # Obtenir le timestamp
    if millisecondes:
        timestamp = int(time.time() * 1000)  # Timestamp en millisecondes
    else:
        timestamp = int(time.time())  # Timestamp en secondes

    # Combiner le UUID et le timestamp
    uuid_timestamp = f"{timestamp}-{uuid_aleatoire}"

    return uuid_timestamp


class ZipFileManager:
    """
    Classe qui gère les fichiers ZIP dans un répertoire en conservant les fichiers les plus récents
    basés sur un horodatage (timestamp) dans le nom du fichier, et en supprimant les fichiers plus anciens.

    Le format attendu des fichiers ZIP est : <timestamp>_<reste_du_nom>.zip
    """

    def __init__(self, directory):
        """
        Initialise un gestionnaire de fichiers ZIP pour le répertoire spécifié.

        :param directory: Le répertoire contenant les fichiers ZIP à gérer.
        """
        self.directory = directory
        self.files_to_keep = {}

    def analyze_and_cleanup(self):
        """
        Analyse les fichiers ZIP dans le répertoire et supprime les fichiers obsolètes.

        Garde uniquement le fichier ZIP le plus récent pour chaque combinaison unique de nom de fichier (sans timestamp).
        """
        # Lire tous les fichiers .zip dans le répertoire
        zip_files = [f for f in os.listdir(self.directory) if f.endswith('.zip')]

        # Analyser chaque fichier
        for file in zip_files:
            # Vérifier que le fichier correspond au format attendu : <timestamp>_<reste_du_nom>.zip
            match = re.match(r'(\d+)_([A-Za-z0-9@:_\-\\]+)\.zip', file)
            if match:
                timestamp, file_rest = match.groups()
                key = file_rest

                # Garder le fichier avec le plus grand timestamp (le plus récent)
                if key not in self.files_to_keep or int(timestamp) > int(self.files_to_keep[key][0]):
                    self.files_to_keep[key] = (timestamp, file)

        # Supprimer les fichiers obsolètes
        for file in zip_files:
            match = re.match(r'(\d+)_([A-Za-z0-9@:_\-\\]+)\.zip', file)
            if match:
                timestamp, file_rest = match.groups()
                key = file_rest

                # Si un fichier plus récent existe, supprimer l'ancien
                if key in self.files_to_keep and self.files_to_keep[key][1] != file:
                    self.delete_file(file)

    def delete_file(self, file):
        """
        Supprime un fichier ZIP du répertoire.

        :param file: Le nom du fichier à supprimer.
        """
        file_path = os.path.join(self.directory, file)
        os.remove(file_path)
        logger.debug(f"Supprimé : {file_path}")




def zipper_fichier(fichier, fichier_zip, fichier_vide=True):
    """
    Zipe un seul fichier.

    Args:
        fichier (str): Le chemin du fichier à zipper.
        fichier_zip (str): Le nom du fichier zip de sortie.
        fichier_vide (bool, optional): Si True, inclut les fichiers vides dans le zip. (par défaut: True)

    Returns:
        None: La fonction crée un fichier zip et n'a pas de valeur de retour.
    """
     # Vérifier si le répertoire existe
    if not os.path.exists(fichier):
        return None

    with zipfile.ZipFile(fichier_zip, 'w', zipfile.ZIP_DEFLATED) as zipf:
        if os.path.islink(fichier):
            # Ajouter le lien symbolique en tant que tel dans le zip sans compression
            zipf.write(fichier, os.path.basename(fichier), compress_type=zipfile.ZIP_STORED)
        else:
            # Inclure les fichiers vides si demandé
            if fichier_vide or os.path.getsize(fichier) > 0:
                zipf.write(fichier, os.path.basename(fichier))
    return True


def zipper_repertoire(repertoire, fichier_zip, resoudre_liens=False, repertoire_vide=True, fichier_vide=True):
    """
    Zipe le contenu d'un répertoire, y compris tous les fichiers, sous-répertoires,
    répertoires vides et fichiers vides.

    Args:
        repertoire (str): Le chemin du répertoire à zipper.
        fichier_zip (str): Le nom du fichier zip de sortie.
        resoudre_liens (bool, optional): Si True, résout les liens symboliques et ajoute leurs cibles au zip.
                                         Si False, ajoute les liens symboliques tels quels. (par défaut: False)
        repertoire_vide (bool, optional): Si True, inclut les répertoires vides dans le zip. (par défaut: False)
        fichier_vide (bool, optional): Si True, inclut les fichiers vides dans le zip. (par défaut: False)

    Returns:
        None: Si le répertoire n'existe pas ou est vide.
        True: Si le répertoire n'est pas vide et le fichier zip a été créé.
    """
    # Vérifier si le répertoire existe
    if not os.path.exists(repertoire):
        return None

    # Vérifier si le répertoire est vide
    if not os.listdir(repertoire):
        return None

    with zipfile.ZipFile(fichier_zip, 'w', zipfile.ZIP_DEFLATED) as zipf:
        # Parcourt tous les fichiers et sous-répertoires dans le répertoire spécifié
        for root, dirs, files in os.walk(repertoire):
            # Ajouter le répertoire courant (même s'il est vide)
            chemin_rel_repertoire = os.path.relpath(root, repertoire)
            if repertoire_vide or files:  # Inclut les répertoires vides ou ceux avec des fichiers
                zipf.write(root, chemin_rel_repertoire)  # Ajoute le répertoire courant au zip

            for file in files:
                chemin_complet = os.path.join(root, file)  # Chemin complet du fichier
                chemin_rel = os.path.relpath(chemin_complet, repertoire)  # Chemin relatif pour le zip

                if os.path.islink(chemin_complet):
                    if resoudre_liens:
                        # Résoudre le lien symbolique et ajouter la cible au zip
                        chemin_cible = os.readlink(chemin_complet)
                        zipf.write(chemin_cible, chemin_rel)
                    else:
                        # Ajouter le lien symbolique en tant que tel dans le zip
                        zipf.write(chemin_complet, chemin_rel)
                else:
                    # Inclure les fichiers vides si demandé
                    if fichier_vide or os.path.getsize(chemin_complet) > 0:
                        zipf.write(chemin_complet, chemin_rel)

    return True
#
# def zipper_repertoire( repertoire, fichier_zip, resoudre_liens = False):
#     with zipfile.ZipFile(fichier_zip, 'w', zipfile.ZIP_DEFLATED) as zipf:
#         for root, dirs, files in os.walk(repertoire):
#             for file in files:
#                 chemin_complet = os.path.join(root, file)
#                 chemin_rel = os.path.relpath(chemin_complet, repertoire)
#
#                 if os.path.islink(chemin_complet):
#                     if resoudre_liens:
#                         # Résoudre le lien symbolique et ajouter la cible
#                         chemin_cible = os.readlink(chemin_complet)
#                         zipf.write(chemin_cible, chemin_rel)
#                     else:
#                         # Ajouter le lien symbolique en tant que tel
#                         zipf.write(chemin_complet, chemin_rel)
#                 else:
#                     # Ajouter le fichier normal
#                     zipf.write(chemin_complet, chemin_rel)

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
