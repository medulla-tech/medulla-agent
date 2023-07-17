# coding: utf-8
# SPDX-FileCopyrightText: 2016-2023 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-2.0-or-later

"""
This plugin check regularly if packages have been modified
"""
import json
import logging
from lib.utils import getRandomName, simplecommand, file_put_contents, file_get_contents

import hashlib
import os
import configparser
import re

# import MySQLdb
import traceback
import sys

if sys.version_info >= (3, 0, 0):
    basestring = (str, bytes)

logger = logging.getLogger()
plugin = {"VERSION": "1.1", "NAME": "scheduling_ars_synchronization", "TYPE": "relayserver", "SCHEDULED": True}  # fmt: skip

SCHEDULE = {"schedule": "*/1 * * * *", "nb": -1}

# Will be integrated in the configuration of the substitutes
substitute = "monsubstitute"
JSON_NAMES = ["xmppdeploy", "conf"]


def schedule_main(xmppobject):
    logger.info("========scheduling_ars_synchronisation==========")
    logger.info(plugin)
    logger.info("=================================================\n")
    return

    # if xmppobject.config.agenttype in ["relayserver"]:
    # try:
    # pkgsdata = pkgsbase(xmppobject)
    # if xmppobject.num_call_scheduling_ars_synchronization == 0:
    # __read_conf_scheduling_ars_synchronization(xmppobject, pkgsdata)

    # lien_obj = lncreate(
    # xmppobject.config.list_folder_sources,
    # xmppobject.config.location_packages,
    # )
    ## Only for ARS
    # try:
    # newfingerprints = {}
    # dateedition = {}
    # for source in xmppobject.config.list_folder_sources:
    # if xmppobject.config.debug_info_ars_synchro:
    # logger.info(
    # "Creation Finger print for packages in directory %s"
    # % source
    # )
    # cmd = (
    #'du -hb -d1 --exclude="\\.stfolder" %s | awk \'{n=split($2, tab, "/") ; if ( length(tab[n]) != 0) printf("%%s,%%s\\n", tab[n],  $1);}\''
    # % source
    # )
    # if xmppobject.config.debug_info_ars_synchro:
    # logger.info("cmd for search size %s" % cmd)
    # resultcmd = simplecommand(cmd)
    # if resultcmd["code"] == 0:
    # for result in resultcmd["result"]:
    # tab = [x.strip() for x in result.split(",")]
    # if len(tab[0]) == 36:
    ## We are searching for the JSON modification
    ## date
    # fiche_path = os.path.join(
    # source, tab[0], "xmppdeploy.json"
    # )
    # md5 = finger_print_md5(fiche_path)
    # tab.append(md5)
    # newfingerprints[tab[0]] = ",".join(tab)
    # StatResult = os.stat(fiche_path)
    # dateedition[tab[0]] = [
    # str(StatResult.st_ctime),
    # str(StatResult.st_mtime),
    # tab[1],
    # ]
    # if xmppobject.config.debug_info_ars_synchro:
    # logger.info(
    # "Creation NEW FINGERPRINT LIST : %s"
    # % json.dumps(newfingerprints, indent=4)
    # )
    # xmppobject.config.PACKAGES_ID = initialisation_packages_id(pkgsdata)
    # if xmppobject.config.debug_info_ars_synchro:
    # logger.info(
    # "PACKAGE ID IN BASE IS %s" % xmppobject.config.PACKAGES_ID
    # )

    # keyclean = []
    # for newfingerprint in newfingerprints:
    # if newfingerprint in xmppobject.config.PACKAGES_ID:
    # file_src = os.path.join(
    # xmppobject.config.pakage_print_fingers_base, newfingerprint
    # )
    # if xmppobject.config.debug_info_ars_synchro:
    # logger.info(
    # "check synchro for PACKAGE ID %s IN BASE "
    # % newfingerprint
    # )
    # if not os.path.isfile(file_src):
    # if xmppobject.config.debug_info_ars_synchro:
    # logger.info(
    # "** New Package is exit in partage %s"
    # % newfingerprints[newfingerprint]
    # )
    ## New package
    ## We reinitialize the package list and we write the
    ## fingerprint the base.
    # if xmppobject.config.debug_info_ars_synchro:
    # logger.info(
    # "create new file fingerprint in %s" % file_src
    # )
    # file_put_contents(
    # file_src, getRandomName(14, pref="fingerprint_fake_")
    # )
    # else:
    ## The list of the package used are only the packages
    ## from the packages of the package SQL table
    # keyclean.append(newfingerprint)

    # if xmppobject.config.debug_info_ars_synchro:
    # logger.info(
    # "** the packages existants in the sharing and not in package base are ignored."
    # )
    # for cleankeydirect in keyclean:
    # if xmppobject.config.debug_info_ars_synchro:
    # logger.info(
    # "** the packages existants in the sharing %s is ignored."
    # % cleankeydirect
    # )
    # del newfingerprints[cleankeydirect]
    # filesupp = os.path.join(
    # xmppobject.config.pakage_print_fingers_base, cleankeydirect
    # )
    # if os.path.isfile(filesupp):
    # os.remove(filesupp)
    # if xmppobject.config.debug_info_ars_synchro:
    # logger.info("*************TEST FINGERPRINT****************")
    ## on verifie si il y a des changements dans les figers print entre ceux enregistres et ceux de notre list.
    ## on en profite pour virer les fichier finger print orphelin
    ## on charge la liste de nos figerprint.
    # lfile = [
    # f
    # for f in os.listdir(xmppobject.config.pakage_print_fingers_base)
    # if len(f) == 36
    # ]
    # for filea in lfile:
    # filepath = os.path.join(
    # xmppobject.config.pakage_print_fingers_base, filea
    # )
    # if filea not in xmppobject.config.PACKAGES_ID:
    # os.remove(filepath)
    # else:
    # if filea in newfingerprints:
    ## We can compare the fingerprints
    # if xmppobject.config.debug_info_ars_synchro:
    # logger.info(
    # "We are checking for changes in the package %s"
    # % filea
    # )
    # figerpfichier = file_get_contents(filepath)
    # if newfingerprints[filea] != figerpfichier:
    # if xmppobject.config.debug_info_ars_synchro:
    # logger.info(
    # "We found changes in the package %s" % filea
    # )
    # file_put_contents(filepath, newfingerprints[filea])
    ## The fingerprint has changed
    ## We update it on the base.
    # newfingerprint = newfingerprints[filea]
    ## Date of the last modification
    # dateeditionbase = dateedition[filea][1]
    # if dateedition[filea][0] == dateedition[filea][1]:
    # status = "creation"
    # else:
    # status = "update"
    # sizepackage = dateedition[filea][2]
    # idars = xmppobject.config.ARS_ID
    # idpackage = xmppobject.config.PACKAGES_ID[filea]
    # create_or_update_pkgs_shares_ars_web(
    # xmppobject,
    # pkgsdata,
    # idars,
    # idpackage,
    # sizepackage,
    # status,
    # dateeditionbase,
    # newfingerprint,
    # )

    # else:
    # if xmppobject.config.debug_info_ars_synchro:
    # logger.info(
    # "We found no changes in the package %s" % filea
    # )
    # lien_obj.create_symlink()
    # except Exception as e:
    # logger.error(" %s : %s" % (plugin["NAME"], str(e)))
    # logger.error("\n%s" % (traceback.format_exc()))
    # finally:
    # pkgsdata.disconect_pkgs()


# def __read_conf_scheduling_ars_synchronization(xmppobject, pkgsdata):
# """
# Read the plugin configuration
# The xmppobject.config.pathdirconffile contains the location of the configuration folder.
# """

# namefichierconf = plugin["NAME"] + ".ini"
## path cf function directoryconffile() for oss and type agent

# xmppobject.pathfileconfscheduling_ars_synchronization = os.path.join(
# xmppobject.config.nameplugindir, namefichierconf
# )
# logger.info(
# "Read Configuration in File %s"
# % xmppobject.pathfileconfscheduling_ars_synchronization
# )

## application des valeurs par default
# fgpp = os.path.abspath(
# os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", "INFOSTMP")
# )

# path_packageagent = os.path.join(fgpp, "package_agent")

# if not os.path.exists(path_packageagent):
# os.mkdir(path_packageagent)
# os.chmod(path_packageagent, 0o777)

## creation base fingerprint
# pakage_print_fingers_base = os.path.join(path_packageagent, "base")

# if not os.path.exists(pakage_print_fingers_base):
# os.mkdir(pakage_print_fingers_base)
# os.chmod(pakage_print_fingers_base, 0o777)

# xmppobject.config.pakage_print_fingers_base = pakage_print_fingers_base

# logger.info("%s" % xmppobject.config.pakage_print_fingers_base)
# xmppobject.config.list_folder_sources = ["/var/lib/pulse2/packages/sharing/global"]
# xmppobject.config.location_packages = "/var/lib/pulse2/packages"
# xmppobject.config.modulo = 20

## FIXME: Implement me
## xmppobject.config.xmppmaster_dbhost = "localhost"
## xmppobject.config.xmpp_master_dbuser = "xmppmaster"
## xmppobject.config.xmpp_master_dbpasswd = "xmppmaster"
## xmppobject.config.xmpp_master_dbname = "xmppmaster"

## default parameter
# xmppobject.config.pkgs_dbhost = "localhost"
# xmppobject.config.pkgs_dbuser = "pkgs"
# xmppobject.config.pkgs_dbpasswd = "pkgs"
# xmppobject.config.pkgs_dbname = "pkgs"
# xmppobject.config.pkgs_dbport = 3306
# xmppobject.config.pkgs_connect_timeout = 15

# xmppobject.config.debug_info_ars_synchro = False

# if not os.path.isfile(xmppobject.pathfileconfscheduling_ars_synchronization):
# logger.warning(
# "plugin %s\nConfiguration file  missing\n"
# "%s"
# % (plugin["NAME"], xmppobject.pathfileconfscheduling_ars_synchronization)
# )
# else:
## on charge la configuration file
## xmppobject.pathfileconfscheduling_ars_synchronization
# Config = configparser.ConfigParser()
# Config.read(xmppobject.pathfileconfscheduling_ars_synchronization)
# if os.path.exists(
# xmppobject.pathfileconfscheduling_ars_synchronization + ".local"
# ):
# Config.read(
# xmppobject.pathfileconfscheduling_ars_synchronization + ".local"
# )

# if Config.has_section("global"):
# if Config.has_option("global", "debug_info"):
# xmppobject.config.debug_info_ars_synchro = Config.getboolean(
# "global", "debug_info"
# )
# if Config.has_option("global", "location_folder_packages"):
# xmppobject.config.location_packages = Config.get(
# "global", "location_folder_packages"
# )
# if Config.has_option("global", "list_folder_sources"):
# list_folder_sources = Config.get("global", "list_folder_sources")
# xmppobject.config.list_folder_sources = [
# str(x.strip())
# for x in re.split(r"[;,:@\(\)\[\]\|\s]\s*", list_folder_sources)
# if x.strip() != ""
# ]
## FIXME: Implement me
## if Config.has_section("fingerprint"):
## if Config.has_option("fingerprint",
## "exclude"):
## exclude = Config.get('fingerprint',
## 'exclude')
## xmppobject.config.exclude =  [str(x.strip()) \
## for x in re.split(r'[;,:@\(\)\[\]\|\s]\s*', exclude) \
## if x.strip() != "" ]

## if Config.has_option("fingerprint",
## "modulo"):
## xmppobject.config.modulo = Config.getint('fingerprint',
## 'modulo')
## if Config.has_section("xmpp_master_db"):
## if Config.has_option("xmpp_master_db",
## "xmppmaster_dbhost"):
## xmppobject.config.xmppmaster_dbhost = Config.get('xmpp_master_db',
## 'xmppmaster_dbhost')
## if Config.has_option("xmpp_master_db",
## "xmpp_master_dbuser"):
## xmppobject.config.xmpp_master_dbuser = Config.get('xmpp_master_db',
## 'xmpp_master_dbuser')
## if Config.has_option("xmpp_master_db",
## "xmpp_master_dbpasswd"):
## xmppobject.config.xmpp_master_dbpasswd = Config.get('xmpp_master_db',
## 'xmpp_master_dbpasswd')
## if Config.has_option("xmpp_master_db",
## "xmpp_master_dbname"):
## xmppobject.config.xmpp_master_dbname = Config.get('xmpp_master_db',
## 'xmpp_master_dbname')
## if Config.has_option("xmpp_master_db",
## "xmpp_master_dbport"):
## xmppobject.config.xmpp_master_dbport = Config.getint('xmpp_master_db',
## 'xmpp_master_dbport')
# if Config.has_section("pkgsdatabase"):
# if Config.has_option("pkgsdatabase", "pkgs_dbhost"):
# xmppobject.config.pkgs_dbhost = Config.get(
# "pkgsdatabase", "pkgs_dbhost"
# )
# if Config.has_option("pkgsdatabase", "pkgs_dbuser"):
# xmppobject.config.pkgs_dbuser = Config.get(
# "pkgsdatabase", "pkgs_dbuser"
# )
# if Config.has_option("pkgsdatabase", "pkgs_dbpasswd"):
# xmppobject.config.pkgs_dbpasswd = Config.get(
# "pkgsdatabase", "pkgs_dbpasswd"
# )
# if Config.has_option("pkgsdatabase", "pkgs_dbname"):
# xmppobject.config.pkgs_dbname = Config.get(
# "pkgsdatabase", "pkgs_dbname"
# )
# if Config.has_option("pkgsdatabase", "pkgs_dbport"):
# xmppobject.config.pkgs_dbport = Config.getint(
# "pkgsdatabase", "pkgs_dbport"
# )
# if Config.has_option("pkgsdatabase", "pkgs_connect_timeout"):
# xmppobject.config.pkgs_connect_timeout = Config.getint(
# "pkgsdatabase", "pkgs_connect_timeout"
# )

## on recupere les id des packages
# sql = (
# """SELECT
# id
# FROM
# pkgs.pkgs_shares_ars
# WHERE
# pkgs_shares_ars.jid LIKE '%s%%' limit 1;"""
# % xmppobject.boundjid.user
# )

# result = pkgsdata.fetching(sql)
# if xmppobject.config.debug_info_ars_synchro:
# if result is not None:
# xmppobject.config.ARS_ID = int(result[0][0])
# logger.info(
# "Ars id of %s is %s"
# % (xmppobject.boundjid.user, xmppobject.config.ARS_ID)
# )
# return False


# def finger_print_md5(file):
# json_md5 = ""
# try:
# with open(file, "r") as source_file:
# json_md5 = hashlib.md5(source_file.read().encode("utf-8")).hexdigest()
# except BaseException:
# json_md5 += ""
# return json_md5


# def initialisation_packages_id(pkgsdata):
# result = pkgsdata.fetching("""SELECT uuid, id FROM pkgs.packages;""")
# ret = {}
# if result is not None:
# for t in result:
# ret[t[0]] = int(t[1])
# return ret


# def create_or_update_pkgs_shares_ars_web(
# xmppobject,
# pkgsdata,
# idars,
# idpackage,
# sizepackage,
# status,
# dateeditionbase,
# fingerprint,
# ):
# sql = """SELECT
# id
# FROM
# pkgs_shares_ars_web
# WHERE
# `ars_share_id` = %s AND `packages_id` = %s limit 1;""" % (
# idars,
# idpackage,
# )
# if xmppobject.config.debug_info_ars_synchro:
# logger.info("search if package exist \n : %s" % sql)
# result = pkgsdata.fetching(sql)
# if result:
# sql = """UPDATE `pkgs`.`pkgs_shares_ars_web`
# SET
# `status` = 'update',
# `finger_print` = '%s',
# `size` = '%s',
# `date_edition` = FROM_UNIXTIME(%s)
# WHERE
# (`ars_share_id` = '%s')
# AND (`packages_id` = '%s');""" % (
# fingerprint,
# sizepackage,
# dateeditionbase,
# idars,
# idpackage,
# )
# if xmppobject.config.debug_info_ars_synchro:
# logger.info(
# "Update fingerprint in base %s for ars %s\n%s"
# % (fingerprint, xmppobject.boundjid.user, sql)
# )
# result = pkgsdata.commit(sql)
# if result:
# if xmppobject.config.debug_info_ars_synchro:
# logger.info("update result %s" % result)
# else:
# logger.info("INSERT %s" % type(result))

# sql = """INSERT INTO
# `pkgs`.`pkgs_shares_ars_web` (`ars_share_id`,
# `packages_id`,
# `status`,
# `finger_print`,
# `size`,
# `date_edition`)
# VALUES ('%s',
#'%s',
#'create',
#'%s',
#'%s',
# FROM_UNIXTIME(%s));""" % (
# idars,
# idpackage,
# fingerprint,
# sizepackage,
# dateeditionbase,
# )
# if xmppobject.config.debug_info_ars_synchro:
# logger.info(
# "Insert fingerprint in base %s for ars %s\n%s"
# % (fingerprint, xmppobject.boundjid.user, sql)
# )
# result = pkgsdata.commit(sql)
# if result:
# if xmppobject.config.debug_info_ars_synchro:
# logger.info("insert result %s" % result)


# class pkgsbase:
# def __init__(self, xmppobject):
# self.boolconnectionbase = False
# self.dbconnectionpkgs = None
# self.xmppobject = xmppobject

# def connection_pkgs(self):
# if self.boolconnectionbase:
# return self.dbconnectionpkgs
# else:
# try:
# self.dbconnectionpkgs = MySQLdb.connect(
# host=self.xmppobject.config.pkgs_dbhost,
# user=self.xmppobject.config.pkgs_dbuser,
# passwd=self.xmppobject.config.pkgs_dbpasswd,
# db=self.xmppobject.config.pkgs_dbname,
# port=self.xmppobject.config.pkgs_dbport,
# connect_timeout=self.xmppobject.config.pkgs_connect_timeout,
# )
# self.boolconnectionbase = True
# return self.dbconnectionpkgs
# except MySQLdb.Error as e:
# self.boolconnectionbase = False
# self.dbconnectionpkgs = None
# logger.error(
# "pkgbase connect verify connect to mysql base pkgs: %s" % str(e)
# )
# return self.dbconnectionpkgs
# except Exception as e:
# self.boolconnectionbase = False
# self.dbconnectionpkgs = None
# logger.error("\n%s" % (traceback.format_exc()))
# return self.dbconnectionpkgs

# def disconect_pkgs(self):
# if self.boolconnectionbase:
# self.dbconnectionpkgs.close()

# def is_connection_pkgs(self):
# return self.boolconnectionbase

# def fetching(self, query):
# results = None
# try:
# if not self.boolconnectionbase:
# self.connection_pkgs()

# if self.boolconnectionbase:
# try:
# cursor = self.dbconnectionpkgs.cursor()
# cursor.execute(query)
# results = cursor.fetchall()
# return results
# except MySQLdb.Error as e:
# logger.error("Error: unable to fecth data %s" % str(e))
# return results
# finally:
# cursor.close()
# except Exception as e:
# logger.error("Error: unable to connection %s" % str(e))
# return results

# def commit(self, query):
# results = None
# try:
# if not self.boolconnectionbase:
# self.connection_pkgs()

# if self.boolconnectionbase:
# try:
# cursor = self.dbconnectionpkgs.cursor()
# results = cursor.execute(query)
# self.dbconnectionpkgs.commit()
# return results
# except MySQLdb.Error as e:
# self.dbconnectionpkgs.rollback()
# logger.error("Error: unable to fecth data %s" % str(e))
# return results
# finally:
# cursor.close()
# except Exception as e:
# logger.error("Error: unable to connection %s" % str(e))
# return results


# class lncreate:
# def __init__(
# self,
# list_path_abs,
# path_abs_dest,
# groupname="syncthing",
# username="syncthing",
# mode=0o755,
# ):
# if isinstance(list_path_abs, basestring):
# self.list_path_abs = [
# str(x.strip())
# for x in re.split(r"[;,:@\(\)\[\]\|\s]\s*", list_path_abs)
# if x.strip() != ""
# ]
# elif isinstance(list_path_abs, list):
# self.list_path_abs = list_path_abs
# else:
# self.list_path_abs = ""
# self.mode = mode
# self.groupname = groupname
# self.username = username
# self.path_abs_dest = path_abs_dest
# if not os.path.exists(self.path_abs_dest):
# os.makedirs(self.path_abs_dest, mode)

# def remove_links(self):
# for f in os.listdir(self.path_abs_dest):
# if len(f) == 36:
# ln = os.path.join(self.path_abs_dest, f)
# if not os.path.exists(ln) and os.path.islink(ln):
# os.unlink(ln)

# def create_symlink(self):
# self.remove_links()
# for srcrep in self.list_path_abs:
# for f in os.listdir(srcrep):
# if len(f) == 36:
# srcdir = os.path.join(srcrep, f)
# destdir = os.path.join(self.path_abs_dest, f)
# if not os.path.islink(destdir):
# os.symlink(srcdir, destdir)
# else:
# os.unlink(destdir)
# os.symlink(srcdir, destdir)
