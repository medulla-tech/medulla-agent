#!/usr/bin/python3
# SPDX-FileCopyrightText: 2016-2023 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-3.0-or-later

import sys
import os
import os.path
import json
import logging

logger = logging.getLogger()


class managepackage:
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
                os.environ["ProgramFiles"], "Pulse", "var", "tmp", "packages"
            )
        elif sys.platform.startswith("darwin"):
            return os.path.join("/opt", "Pulse", "var", "tmp", "packages")
        else:
            return None

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
        if os.path.isfile(filename):
            with open(filename, "r", encoding="utf-8", errors="ignore") as info:
                jsonFile = info.read()
            try:
                outputJSONFile = json.loads(jsonFile)
                return outputJSONFile
            except Exception as e:
                logger.error("We failed to decode the file %s" % filename)
                logger.error("we encountered the error: %s" % str(e))
        else:
            logger.error("The file %s does not exist" % filename)
        return None

    @staticmethod
    def getdescriptorpackagename(packagename):
        for package in managepackage.listpackages():
            if not os.path.isfile(os.path.join(package, "xmppdeploy.json")):
                logger.error(
                    "The %s file is missing" % os.path.join(package, "xmppdeploy.json")
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
                logger.error("we are encountering the error: %s" % str(e))
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
                    "The %s file is missing" % os.path.join(package, "xmppdeploy.json")
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
                logger.error("we are encountering the error: %s" % str(e))
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
                    "The %s file is missing" % os.path.join(package, "xmppdeploy.json")
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
                logger.error("we are encountering the error: %s" % str(e))
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
                    "The %s file is missing" % os.path.join(package, "xmppdeploy.json")
                )
                return None
            try:
                outputJSONFile = managepackage.loadjsonfile(
                    os.path.join(package, "conf.json")
                )
                if "id" in outputJSONFile and outputJSONFile["id"] == uuidpackage:
                    return package
            except Exception as e:
                logger.error("The conf.json for the package %s is missing" % package)
                logger.error("we are encountering the error: %s" % str(e))
        logger.error("We did not find the package %s" % uuidpackage)
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
                    "The %s file is missing" % os.path.join(package, "xmppdeploy.json")
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
                    "package %s verify format descriptor conf.json [%s]"
                    % (packageuuid, str(e))
                )
        logger.error(
            "package %s verify version" "in descriptor conf.json %s" % packageuuid
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
            logger.error("The %s file is missing" % pathpackage)
        return None

    @staticmethod
    def getdescriptorpackageuuid(packageuuid):
        jsonfile = os.path.join(
            managepackage.packagedir(), packageuuid, "xmppdeploy.json"
        )
        if os.path.isfile(jsonfile):
            try:
                outputJSONFile = managepackage.loadjsonfile(jsonfile)
                return outputJSONFile
            except Exception:
                return None
        else:
            logger.error("The %s file is missing" % xmppdeployFile)
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
