#!/usr/bin/python3
# -*- coding: utf-8; -*-
# SPDX-FileCopyrightText: 2016-2023 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-3.0-or-later

import sys
import os
import os.path
import json
import logging

logger = logging.getLogger()


class managepackage:
    # variable de classe
    agenttype = "relayserver"

    @staticmethod
    def packagedir():
        """
        This function provide the path of the package folder.

        @return: string: The path of the package folder.
        """
        if sys.platform.startswith("linux"):
            if managepackage.agenttype == "relayserver":
                return os.path.join("/", "var", "lib", "pulse2", "packages")
            else:
                return os.path.join(os.path.expanduser("~pulseuser"), "packages")
        elif sys.platform.startswith("win"):
            return os.path.join(
                "c:", "progra~1", "Pulse", "var", "tmp", "packages"
            )
        elif sys.platform.startswith("darwin"):
            return os.path.join("/opt", "Pulse", "packages")
        else:
            return None

    @staticmethod
    def search_list_package():
        """
        This function searches packages in the global and
        local shares.
        """
        packagelist = []
        dirpackage = os.path.join("/", "var", "lib", "pulse2", "packages")
        global_package_folder = os.path.join(dirpackage, "sharing", "global")
        packagelist = [
            os.path.join(global_package_folder, f)
            for f in os.listdir(global_package_folder)
            if len(f) == 36
        ]
        local_package_folder = os.path.join(dirpackage, "sharing")
        share_pathname = [
            os.path.join(local_package_folder, f)
            for f in os.listdir(local_package_folder)
            if f != "global"
        ]
        for part in share_pathname:
            filelist = [os.path.join(part, f) for f in os.listdir(part) if len(f) == 36]
            packagelist += filelist
        return packagelist

    @staticmethod
    def package_for_deploy_from_share(sharedir=None):
        """
        This function creates symlinks in the packages directory
        to the target in the local/global share
        """
        if sharedir is None:
            dirpackage = managepackage.packagedir()
        else:
            sharedir = os.path.abspath(os.path.realpath(sharedir))
        for x in managepackage.search_list_package():
            print(x, os.path.join(dirpackage, os.path.basename(x)))
            try:
                os.symlink(x, os.path.join(dirpackage, os.path.basename(x)))
            except OSError:
                pass

    @staticmethod
    def remove_symlinks(dirpackage=None):
        """
        This function remove symlinks
        """
        if dirpackage is None:
            dirpackage = managepackage.packagedir()
        else:
            dirpackage = os.path.abspath(os.path.realpath(dirpackage))
        packagelist = [
            os.path.join(dirpackage, f) for f in os.listdir(dirpackage) if len(f) == 36
        ]
        for fi in packagelist:
            if os.path.islink(fi) and not os.path.exists(fi):
                os.remove(fi)

    @staticmethod
    def listpackages():
        """
        This functions is used to list the packages
        Returns:
            It returns the list of the packages.
        """
        listfolder = [x for x in os.listdir(managepackage.packagedir()) if len(x) == 36]
        return [os.path.join(managepackage.packagedir(), x) for x in listfolder]

    @staticmethod
    def loadjsonfile(filename):
        """
        This function is used to load a json file
        Args:
            filename: The filename of the json file to load
        Returns:
            It returns the content of the JSON file
        """
        if os.path.exists(filename):
            with open(filename, "r") as file:
                data = json.load(file)
                return data
        else:
            logger.error(f"The json file {filename} is missing.")
            return None

    @staticmethod
    def getdescriptorpackagename(packagename):
        for package in managepackage.listpackages():
            if not os.path.isfile(os.path.join(package, "xmppdeploy.json")):
                logger.error(
                    f'The {os.path.join(package, "xmppdeploy.json")} file is missing'
                )
                return None

            try:
                outputJSONFile = managepackage.loadjsonfile(
                    os.path.join(package, "xmppdeploy.json")
                )
                if (
                    "info" in outputJSONFile
                    and (
                        "software" in outputJSONFile["info"]
                        and "version" in outputJSONFile["info"]
                    )
                    and (
                        outputJSONFile["info"]["software"] == packagename
                        or outputJSONFile["info"]["name"] == packagename
                    )
                ):
                    return outputJSONFile
            except Exception as e:
                logger.error(
                    "Please verify the format of the descriptor for"
                    "the package %s." % packagename
                )
                logger.error(f"we are encountering the error: {str(e)}")
        return None

    @staticmethod
    def getversionpackagename(packagename):
        """
        This function is used to get the version of the package
        WARNING: If more one package share the same name,
                 this function will return the first one.
        Args:
            packagename: This is the name of the package
        Returns:
            It returns the version of the package
        """
        for package in managepackage.listpackages():
            if not os.path.isfile(os.path.join(package, "xmppdeploy.json")):
                logger.error(
                    f'The {os.path.join(package, "xmppdeploy.json")} file is missing'
                )
                return None

            try:
                outputJSONFile = managepackage.loadjsonfile(
                    os.path.join(package, "xmppdeploy.json")
                )
                if (
                    "info" in outputJSONFile
                    and (
                        "software" in outputJSONFile["info"]
                        and "version" in outputJSONFile["info"]
                    )
                    and (
                        outputJSONFile["info"]["software"] == packagename
                        or outputJSONFile["info"]["name"] == packagename
                    )
                ):
                    return outputJSONFile["info"]["version"]
            except Exception as e:
                logger.error(
                    "Please verify the version for the package %s in the descriptor"
                    "in the xmppdeploy.json file." % package
                )
                logger.error(f"we are encountering the error: {str(e)}")
        return None

    @staticmethod
    def getpathpackagename(packagename):
        """
        This function is used to get the name of the package
        Args:
            packagename: This is the name of the package
        Returns:
            It returns the name of the package
        """
        for package in managepackage.listpackages():
            if not os.path.isfile(os.path.join(package, "xmppdeploy.json")):
                logger.error(
                    f'The {os.path.join(package, "xmppdeploy.json")} file is missing'
                )
                return None

            try:
                outputJSONFile = managepackage.loadjsonfile(
                    os.path.join(package, "xmppdeploy.json")
                )
                if "info" in outputJSONFile and (
                    (
                        "software" in outputJSONFile["info"]
                        and outputJSONFile["info"]["software"] == packagename
                    )
                    or (
                        "name" in outputJSONFile["info"]
                        and outputJSONFile["info"]["name"] == packagename
                    )
                ):
                    return package
            except Exception as e:
                logger.error(
                    "Please verify the name for the package %s in the descriptor"
                    "in the xmppdeploy.json file." % package
                )
                logger.error(f"we are encountering the error: {str(e)}")
        return None

    @staticmethod
    def getpathpackagebyuuid(uuidpackage):
        """
        This function is used to find the package based on the uuid
        Args:
            uuidpackage: The uuid of the package we are searching
        Returns:
            We return the package, it returns None if any error or if
                the package is not found.
        """
        for package in managepackage.listpackages():
            if not os.path.isfile(os.path.join(package, "xmppdeploy.json")):
                logger.error(
                    f'The {os.path.join(package, "xmppdeploy.json")} file is missing'
                )
                return None

            try:
                outputJSONFile = managepackage.loadjsonfile(
                    os.path.join(package, "conf.json")
                )
                if "id" in outputJSONFile and outputJSONFile["id"] == uuidpackage:
                    return package
            except Exception as e:
                logger.error(f"The conf.json for the package {package} is missing")
                logger.error(f"we are encountering the error: {str(e)}")
        logger.error(f"We did not find the package {uuidpackage}")
        return None

    @staticmethod
    def getversionpackageuuid(packageuuid):
        """
        This function is used to find the version of the package based
            on the uuid
        Args:
            packageuuid: The uuid of the package we are searching
        Returns:
            We return the version of package, it returns None if
                any error or if the package is not found.
        """
        for package in managepackage.listpackages():
            if not os.path.isfile(os.path.join(package, "xmppdeploy.json")):
                logger.error(
                    f'The {os.path.join(package, "xmppdeploy.json")} file is missing'
                )
                return None

            if not os.path.isfile(os.path.join(package, "conf.json")):
                logger.error(
                    f'The file {os.path.join(package, "conf.json")} is missing. It cannot work witout it.'
                )
                return None

            try:
                outputJSONFile = managepackage.loadjsonfile(
                    os.path.join(package, "conf.json")
                )
                if (
                    "id" in outputJSONFile
                    and outputJSONFile["id"] == packageuuid
                    and "version" in outputJSONFile
                ):
                    return outputJSONFile["version"]
            except Exception as e:
                logger.error(
                    f"package {packageuuid} verify format descriptor conf.json [{str(e)}]"
                )
        logger.error(
            "package %s verify version" "in descriptor conf.json [%s]" % (packageuuid)
        )
        return None

    @staticmethod
    def getnamepackagefromuuidpackage(uuidpackage):
        pathpackage = os.path.join(
            managepackage.packagedir(), uuidpackage, "xmppdeploy.json"
        )
        if os.path.isfile(pathpackage):
            outputJSONFile = managepackage.loadjsonfile(pathpackage)
            return outputJSONFile["info"]["name"]
        else:
            logger.error(f"The file {pathpackage} is missing")
        return None

    @staticmethod
    def getdescriptorpackageuuid(packageuuid):
        jsonfile = os.path.join(
            managepackage.packagedir(), packageuuid, "xmppdeploy.json"
        )
        if os.path.isfile(jsonfile):
            try:
                return managepackage.loadjsonfile(jsonfile)
            except Exception as error_loading:
                logger.error(f"An error occured while loading the file {jsonfile}")
                return None
        else:
            logger.error(f"The file {jsonfile} is missing")
        return None

    @staticmethod
    def getpathpackage(uuidpackage):
        return os.path.join(managepackage.packagedir(), uuidpackage)


class search_list_of_deployment_packages:
    """
    Recursively search for all dependencies for this package
    """

    def __init__(self, packageuuid):
        self.list_of_deployment_packages = set()
        self.packageuuid = packageuuid

    def search(self):
        self.__recursif__(self.packageuuid)
        return self.list_of_deployment_packages

    def __recursif__(self, packageuuid):
        self.list_of_deployment_packages.add(packageuuid)
        objdescriptor = managepackage.getdescriptorpackageuuid(packageuuid)
        if objdescriptor is not None:
            ll = self.__list_dependence__(objdescriptor)
            for y in ll:
                if y not in self.list_of_deployment_packages:
                    self.__recursif__(y)

    def __list_dependence__(self, objdescriptor):
        if (
            objdescriptor is not None
            and "info" in objdescriptor
            and "Dependency" in objdescriptor["info"]
        ):
            return objdescriptor["info"]["Dependency"]
        else:
            return []
