#!/usr/bin/python3
# -*- coding: utf-8; -*-
# SPDX-FileCopyrightText: 2016-2023 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-3.0-or-later

"""
    this class allows via a rest interface to configure syncthing.

    The principle, we get the active configuration in a json.
    rq: this configuration is retrieved in json, it corresponds to the syncthing conf file, which is written to it in xml.

    Then we modify this configuration json. once it has been modified, the new configuration is applied.
    We can check that the new configuration has been applied.

    The actions planned:
    DEVICE: add / supp / edition DEVICE (device, corresponds to a machine)
    FOLDER: add / supp / edition FOLDER (folder is a shared directory)

    shared folders, and corresponding machines.
"""

import requests
import json
from lxml import etree
import urllib.parse
import socket
from threading import Lock
from lib.utils import (
    Program,
    getRandomName,
    simplecommand,
    file_put_contents,
)
from urllib.parse import urlparse
import logging
import traceback
import time
import os
import sys

import configparser

logger = logging.getLogger()


def read_announceserver(
    configfile="/var/lib/syncthing-depl/.config/syncthing/config.xml",
):
    tree = etree.parse(configfile)
    root = tree.getroot()
    pathxmldevice = ".//options/globalAnnounceServer"
    if listresult := root.xpath(pathxmldevice):
        result = listresult[0].text
        o = urlparse(result)
        hostname = o.netloc
        if o.port:
            strport = -len(f":{o.port}")
            hostname = hostname[:strport]
            return root, hostname
    return root, ""


def conf_ars_deploy(
    port=23000,
    configfile="/var/lib/syncthing-depl/.config/syncthing/config.xml",
    deviceName="pulse",
):
    """
    It updates the address field in the configuration file for the specified device.

    Args:
        port: The synthinc port used
        configifile: The syncthing configuration file used
        deviceName: The syncthing's device name

    Returns:
        It create a new syncthing configuration file with the new informations
    """
    if deviceName != "":
        logger.info(f"xml conf : {configfile} device  {deviceName}")

    root, adressurl = read_announceserver(configfile)
    if adressurl != "":
        pathxmldevice = f".//device[@name ='{deviceName}']"
        listresult = root.xpath(pathxmldevice)
        if len(listresult) != 1:
            msg = (
                f"{deviceName} device is not present in Synthing configuration. Please make sure Syncthing is properly configured"
                if len(listresult) == 0
                else f"Two devices or more named '{deviceName}' are configured in Syncthing. Please check Syncthing config [{configfile}] to remove the unused one"
            )
            logger.error(f"{msg}")
            pathxmldeviceerrormsg = f".//device[@name ='{deviceName}']"
            listresulterrordevice = root.xpath(pathxmldeviceerrormsg)
            for devicexml in listresulterrordevice:
                logger.error("%s" % etree.tostring(devicexml, pretty_print=True))


def save_xml_file(
    elementxml, configfile="/var/lib/syncthing-depl/.config/syncthing/config.xml"
):
    file_put_contents(
        configfile, etree.tostring(elementxml, pretty_print=True, encoding="unicode")
    )


def iddevice(
    configfile="/var/lib/syncthing-depl/.config/syncthing/config.xml", deviceName=None
):
    """
    This function retrieve the id of the syncthing device.
    Args:
        configfile: The configuration file where the id are searched.
        deviceName: The syncthing's device name.

    Returns:
        It returns the id of the syncthing device.
    """
    try:
        if deviceName is None:
            deviceName = socket.gethostname()

        if deviceName == "":
            return ""
        logger.debug(f"The configuration file is {configfile}")
        logger.debug(f"The device name is {deviceName}")

        tree = etree.parse(configfile)
        root = tree.getroot()
        pathxmldevice = f".//device[@name='{deviceName}']"
        listresult = root.xpath(pathxmldevice)
        if len(listresult) == 0:
            msg = f"The device named {deviceName} is not present in the syncthing's configuration. There is no id for this device."
            logger.warning(f"{msg}")
            return ""
        deviceID = listresult[0].attrib["id"]
        logger.info(f"find device id {deviceID}")
        return deviceID
    except Exception as e:
        logger.error(f"{str(e)} search iddevice syncthing {configfile}")
        logger.error("\n%s" % (traceback.format_exc()))
        return ""


"""
    class use for xmpp on each server syncthing in local
"""


class syncthingapi:
    def __init__(
        self,
        urlweb="http://localhost",
        port=8384,
        configfile="/var/lib/syncthing/.config/syncthing/config.xml",
        idapirest=None,
    ):
        self.configfile = configfile
        self.home = os.path.basename(self.configfile)
        self.synchro = False
        self.mutex = Lock()
        self.readingconf = 0
        self.urlweb = urlweb
        self.port = port
        self.urlbase = f"{self.urlweb}:{port}/"
        self.urlbaserest = f"{self.urlbase}rest"
        self.device_id = None
        self.cleansharesyncthinglist = []
        self.tailleconf = self.taille_config_xml()
        self.errornb = 0
        if idapirest is None:
            self.tree = etree.parse(configfile)
            self.idapirest = self.tree.xpath("/configuration/gui/apikey")[0].text
        else:
            self.idapirest = idapirest

        self.headers = {"X-API-KEY": f"{self.idapirest}"}
        time.sleep(5)
        self.reload_config()
        try:
            logger.debug(f"Syncthing  Version {self.version}")
            logger.debug(f"Device id {self.device_id}")
            logger.debug(f"config file {configfile}")
        except BaseException:
            logger.error("An error occured while trying to configure syncthing.")
        # bash command xmllint --xpath "//configuration/gui/apikey/text()" /var/lib/syncthing/.config/syncthing/config.xml

    def taille_config_xml(self):
        return os.path.getsize(self.configfile)

    def getpathconfigfile(self):
        return self.configfile

    def getidapi(self):
        return self.idapirest

    def reload_config(self, clean=True):
        time.sleep(2)
        self.config = self.get_config()  # content all config
        self.tailleconf = self.taille_config_xml()
        self.synchro = True
        if len(self.config) != 0:
            self.folders = self.config["folders"]
            self.devices = self.config["devices"]
            self.version = self.config["version"]
            self.guiinformation = self.config["gui"]
            try:
                self.ignoredFolders = self.config["ignoredFolders"]
            except BaseException:
                self.ignoredFolders = []
            try:
                self.ignoredDevices = self.config["ignoredDevice"]
            except BaseException:
                self.ignoredDevices = []
            try:
                self.pendingDevices = self.config["pendingDevices"]
            except BaseException:
                self.pendingDevices = []

            self.options = self.config["options"]

            hostname = socket.gethostname()
            device_id_tmp = None
            for device in self.devices:
                if device["name"] == hostname:
                    self.device_id = device["deviceID"]
                    break
                elif device["name"] == "pulse":
                    device_id_tmp = device["deviceID"]
            if self.device_id is None and device_id_tmp is not None:
                self.device_id = device_id_tmp
        if clean:
            self.pendingdevice_accept()
            self.clean_pendingFolders_ignoredFolders_in_devices()
            self.clean_remoteIgnoredDevices()
            self.validate_chang_config()

    def pendingdevice_accept(self):
        if "pendingDevices" in self.config and len(self.config["pendingDevices"]) != 0:
            for pendingdevice in self.config["pendingDevices"]:
                logger.info(f"_ pendingdevice {pendingdevice}")
                # exist device?
                if not self.is_exist_device_in_config(pendingdevice["deviceID"]):
                    # add device
                    self.add_device_syncthing(
                        pendingdevice["deviceID"],
                        pendingdevice["name"],
                        introducer=False,
                        autoAcceptFolders=False,
                        address=["dynamic"],
                    )
        self.clean_pending()

    def save_conf_to_file(self, filedatajson):
        with open(filedatajson, "w") as outfile:
            json.dump(self.config, outfile, indent=4)

    def get_config(self):
        """
        Returns the current configuration.
        dict python
        """
        try:
            re = self.__getAPIREST__("/system/config")
            res = json.loads(re.content)
            self.readingconf = 0
            return res
        except Exception as e:
            logger.error("impossible for read config syncthing Rest")
            if self.readingconf == 0:
                self.readingconf += 1
                nbwaitting = 4
                logger.info(f"try again after {nbwaitting} seconds of waiting.")
                time.sleep(3)
                return self.get_config()
        return {}

    def post_config(self, config=None):
        """
        Post the full contents of the configuration,
        in the same format as returned by the corresponding GET request.
        The configuration will be saved to disk and the configInSync flag
        set to false. Restart Syncthing to activate.
        """
        if config is None:
            config = self.config
        try:
            re = self.__postAPIREST__("/system/config", dictpython=config)
        except BaseException:
            logger.error("\n%s" % (traceback.format_exc()))
            return ""
        return re

    def post_discovery(self, deviceid, adress, port=22000):
        params = {"device": deviceid, "addr": f"{adress}:{port}"}
        return self.__postAPIREST__("/system/discovery", paramsurl=params)

    def post_debug(self, eneablelist="", disablelist=""):
        """
        Enables or disables debugging for specified facilities. Give one or both of enable
        and disable query parameters, with comma separated facility names.
        To disable debugging of the beacon and discovery packages,
        and enable it for config and db:
        $ curl -H X-API-Key:abc123 -X POST 'http://localhost:8384/rest/system/debug?disable=beacon,discovery&enable=config,db'

        e.g
        objetApirest.post_debug(eneablelist = config, db, disablelist = "beacon,discovery")
        """
        params = {"disable": disablelist, "enable": eneablelist}
        return self.__postAPIREST__("/system/debug", paramsurl=params)

    def get_stats_device(self):
        re = self.__getAPIREST__("/stats/device")
        return json.loads(re.content)

    def get_events_type(self, type, limit="5", since="0", datasection=None):
        def Diff(li1, li2):
            return list(set(li1) - set(li2))

        if isinstance(type, str):
            type = [type]
        datas_event = self.get_events(limit=limit, since=since)
        tablekey = [
            "folders",
            "gui",
            "devices",
            "options",
            "version",
            "ignoredDevices",
            "summary",
        ]
        tabeventtype = [
            "ConfigSaved",
            "DeviceConnected",
            "DeviceDisconnected",
            "DeviceDiscovered",
            "DevicePaused",
            "DeviceRejected",
            "DeviceResumed",
            "DownloadProgress",
            "FolderCompletion",
            "FolderErrors",
            "FolderRejected",
            "Folder Scan Progress",
            "FolderSummary",
            "ItemFinished",
            "ItemStarted",
            "Listen Addresses Changed",
            "LocalChangeDetected",
            "LocalIndexUpdated",
            "Login Attempt",
            " RemoteChangeDetected",
            "Remote Download Progress",
            "RemoteIndexUpdated",
            "Starting",
            "StartupComplete",
            "StateChanged",
        ]
        re = [eventdata for eventdata in datas_event if eventdata["type"] in type]
        if datasection is not None:
            if isinstance(datasection, str):
                datasection = [datasection]
            for section in datasection:
                if section not in tablekey:
                    logger.warning(f"session  {section} no exist in Event struct")

            for typename in type:
                if typename not in tabeventtype:
                    logger.warning(
                        f"event type {typename} no exist; Event struct missing"
                    )

            kk = Diff(tablekey, datasection)
            for e in re:
                for t in kk:
                    try:
                        del e["data"][t]
                    except KeyError:
                        pass
        return re

    def get_events(self, since=None, limit=None, eventslist=None, timeout=1):
        """
        To receive events, perform a HTTP GET of /rest/events.

        To filter the event list, in effect creating a specific subscription for only the desired event types, add a parameter events=EventTypeA,EventTypeB,...
        where the event types are any of the Event Types.
            ConfigSaved, DeviceConnected, DeviceDisconnected, DeviceDiscovered, DevicePaused, DeviceRejected, DeviceResumed, DownloadProgress, FolderCompletion, FolderErrors, FolderRejected, Folder Scan Progress, FolderSummary, ItemFinished, ItemStarted, Listen Addresses Changed, LocalChangeDetected, LocalIndexUpdated, Login Attempt, RemoteChangeDetected, Remote Download Progress, RemoteIndexUpdated, Starting, StartupComplete, StateChanged

        The optional parameter since=<lastSeenID> sets the ID of the last event you’ve already seen.
        Syncthing returns a JSON encoded array of event objects,
        starting at the event just after the one with this last seen ID.
        The default value is 0, which returns all events. There is a limit to the number of events buffered,
        so if the rate of events is high or the time between polling calls is long some events might be missed.
        This can be detected by noting a discontinuity in the event IDs.

        If no new events are produced since <lastSeenID>,
        the HTTP call blocks and waits for new events to happen before returning.
        By default it times out after 60 seconds returning an empty array.
        The time out duration can be customized with the optional parameter timeout=seconds.

        To receive only a limited number of events, add the limit=n parameter with a suitable value for n and only the last n events will be returned.
        This can be used to catch up with the latest event ID after a disconnection for example: /rest/events?since=0&limit=1.
        """
        params = {}
        if since is not None:
            params["since"] = since
        if limit is not None:
            params["limit"] = limit
        if eventslist is not None:
            params["events"] = eventslist
        params["timeout"] = timeout
        re = self.__getAPIREST__("/events", paramsurl=params)
        return json.loads(re.content)

    def post_error_clear(self, eneablelist="", disablelist=""):
        """
        Post with empty to body to remove all recent errors.
        """
        re = self.__postAPIREST__("/system/error/clear")

    def post_error(self, error_text):
        """
        Poster un message d'erreur dans le corps (texte brut)
        pour enregistrer une nouvelle erreur.
        La nouvelle erreur sera affiché sur tous les clients de l'interface graphique active.

        curl -X POST -d 'who=world' -H "Content-Type : text/plain" http://localhost:8106/hello
        """
        posturl = f"{self.urlbaserest}/system/error"
        header = self.headers.copy()
        header["Content-Type"] = "text/plain"
        requests.post(posturl, headers=header, data=error_text)

    def post_pause(self, deviceid=None):
        """
        Pause the given device or all devices.

        Takes the optional parameter device (device ID).
        When ommitted, pauses all devices. Returns status 200 and no content upon success, or status 500 and a plain text error on failure.
        """
        if deviceid is not None:
            params = {"device": deviceid}
            self.__postAPIREST__("/system/pause", paramsurl=params)
        else:
            self.__postAPIREST__("/system/pause")

    def post_ping(self):
        """
        Retourne un objet.{"ping": "pong"}
        """
        return self.__postAPIREST__("/system/ping")

    def post_reset(self, deviceid=None):
        """
        Post with empty body to erase the current index database and
        restart Syncthing. With no query parameters, the entire database is
        erased from disk. By specifying the folder parameter
        with a valid folder ID, only information for that folder will be erased:

        $ curl -X POST -H "X-API-Key: abc123" http://localhost:8384/rest/system/reset?folder=default
        """
        if deviceid is not None:
            params = {"device": deviceid}
            self.__postAPIREST__("/system/rest", paramsurl=params)
        else:
            self.__postAPIREST__("/system/reset")

    def post_restart(self):
        """
        Post with empty body to immediately restart Syncthing.
        """
        re = self.__postAPIREST__("/system/restart")
        logger.info(f"{re}")
        return re

    def post_resume(self, deviceid=None):
        """
        Pause the given device or all devices.

        Takes the optional parameter device (device ID).
        When ommitted, pauses all devices. Returns status 200 and no content
        upon success, or status 500 and a plain text error on failure.
        """
        if deviceid is not None:
            params = {"device": deviceid}
            self.__postAPIREST__("/system/resume", paramsurl=params)
        else:
            self.__postAPIREST__("/system/resume")

    def post_shutdown(self):
        """
        Post with empty body to cause Syncthing to exit and not restart.
        """
        self.__postAPIREST__("/system/shutdown")

    def post_upgrade(self):
        """
        Perform an upgrade to the newest released version and restart.
        Does nothing if there is no newer version than currently running.
        """
        self.__postAPIREST__("/system/upgrade")

    def get_db_browse(self, folder, labeldepth=None, prefix=None):
        """
        Returns the directory tree of the global model. Directories are always JSON objects
        (map/dictionary), and files are always arrays of modification time and size.
        The first integer is the files modification time, and the second integer is the file size.

        The call takes one mandatory folder parameter and two optional parameters.
        Optional parameter levels defines how deep within the tree we want to dwell
        down (0 based, defaults to unlimited depth) Optional parameter prefix defines
        a prefix within the tree where to start building the structure.

        $ curl -s http://localhost:8384/rest/db/browse?folder=default
        """
        params = {"folder": folder}
        if labeldepth is not None and isinstance(labeldepth, (int)):
            params["levels"] = labeldepth
        if prefix is not None:
            params["prefix"] = prefix
        re = self.__getAPIREST__("/db/browse", paramsurl=params)
        return json.loads(re.content)

    def get_db_completion(self, folder, device):
        """
        Returns the completion percentage (0 to 100)
        for a given device and folder. Takes device and folder parameters.
        return
        {
            "completion": 0
        }
        """
        params = {"folder": folder, "device": device}
        re = self.__getAPIREST__("/db/completion", paramsurl=params)
        return json.loads(re.content)

    def get_db_file(self, folder, namefile):
        """
        Returns most data available about a given file, including version and availability. Takes folder and file parameters.
        """
        params = {"folder": folder, "file": namefile}
        re = self.__getAPIREST__("/db/file", paramsurl=params)
        return json.loads(re.content)

    def get_db_ignores(self, folder):
        """
        Takes one parameter, folder, and returns the content of
        the .stignore as the ignore field. A second field, expanded,
        provides a list of strings which represent globbing patterns described
        by gobwas/glob (based on standard wildcards) that match the patterns
        in .stignore and all the includes. If appropriate these globs are
        prepended by the following modifiers: ! to negate the glob, (?i)
        to do case insensitive matching and (?d)
        to enable removing of ignored files in an otherwise empty directory.
        return
        {
            "ignore": [
                "(?i)/Backups"
            ],
            "expanded": [
                "(?i)Backups",
                "(?i)Backups/**"
            ]
        }
        """
        params = {"folder": folder}
        re = self.__getAPIREST__("/db/ignores", paramsurl=params)
        return json.loads(re.content)

    def post_db_override(
        self,
        folder,
    ):
        """
        Request override of a send-only folder. Takes the mandatory parameter folder (folder ID).

        curl -X POST http://127.0.0.1:8384/rest/db/override?folder=default
        """
        params = {"folder": folder}
        self.__postAPIREST__("/db/override", paramsurl=params)

    def get_db_need(self, folder, page=None, perpage=None):
        """
        Takes one mandatory parameter, folder, and returns lists of files
        which are needed by this device in order for it to become in sync.
        Furthermore takes an optional page and perpage arguments for pagination.
        Pagination happens, across the union of all needed files,
        that is - across all 3 sections of the response.
        For example, given the current need state is as follows:
            progress has 15 items
            queued has 3 items
            rest has 12 items

        If you issue a query with page=1 and perpage=10,
        only the progress section in the response will have 10 items.
        If you issue a request query with page=2 and perpage=10,
        progress section will have the last 5 items,
        queued section will have all 3 items, and rest section will have first 2 items.
        If you issue a query for page=3 and perpage=10,
        you will only have the last 10 items of the rest section.

        In all these calls,
            total will be 30 to indicate the total number of available items.
        """
        params = {"folder": folder}

        if page is not None:
            params["page"] = page
        if perpage is not None:
            params["perpage"] = perpage

        re = self.__getAPIREST__("/db/need", paramsurl=params)
        return json.loads(re.content)

    def get_db_status(self, folder):
        """
        Returns information about the current status of a folder.
        Parameters: folder, the ID of a folder.
        """
        params = {"folder": folder}
        re = self.__getAPIREST__("/db/status", paramsurl=params)
        return json.loads(re.content)

    def post_db_prio(self, folder, pathfile=None):
        """
        Moves the file to the top of the download queue.
        curl -X POST http://127.0.0.1:8384/rest/db/prio?folder=default&file=foo/bar
        Response contains the same output as GET /rest/db/need

        @param filelist files string de file seperate by ,
        e.g
            filelist = "foo,bar"
        """
        params = {"folder": folder}
        if pathfile is not None:
            params["file"] = pathfile
        re = self.__postAPIREST__("/db/prio", paramsurl=params)
        logger.info(f"{re}")
        return re

    def post_db_scan(self, folder=None, sub=None, next=None):
        """
        Request immediate scan.
        Takes the optional parameters folder (folder ID), sub (path relative to the folder root)
        and next (time in seconds). If folder is omitted or empty all folders are scanned.
        If sub is given, only this path (and children, in case it’s a directory)
        is scanned. The next argument delays Syncthing’s automated rescan interval
        for a given amount of seconds.
        Requesting scan of a path that no longer exists, but previously did,
        is valid and will result in Syncthing noticing the deletion of the path in question.
        Returns status 200 and no content upon success,
        or status 500 and a plain text error if an error occurred during scanning.

        curl -X POST http://127.0.0.1:8384/rest/db/scan?folder=default&sub=foo/bar
        """
        params = {}
        if folder is not None:
            params["folder"] = folder
        if sub is not None:
            params["sub"] = sub
        if next is not None and isinstance(next, (int)):
            params["next"] = next
        re = self.__postAPIREST__("/db/scan", paramsurl=params)
        logger.info(f"{re}")
        return re

    def post_db_ignores(self, folder, python_ignores):
        """
        Expects a format similar to the output of GET call, but only
        containing the ignore field (expanded field should be omitted).
        It takes one parameter, folder, and either updates the content
        of the .stignore echoing it back as a response, or returns an error.
        """
        params = {"folder": folder}
        re = self.__postAPIREST__(
            "/db/ignores", dictpython=python_ignores, paramsurl=params
        )
        logger.info(f"{re}")
        return re

    def get_debug(self):
        """
        Returns the set of debug facilities and which of them are currently enabled.
        """
        re = self.__getAPIREST__("/system/debug")
        return json.loads(re.content)

    def get_Version(self):
        """
        Renvoie les informations de la version actuelle de Syncthing.

        {
            "Arc" :  "amd64" ,
            "longVersion" :  "syncthing v0.10.27 + 3 gea8c3de (go1.4 darwin-amd64 par défaut) jb @ syno 16/03/2015 11:01:29 UTC" ,
            "os" :  "darwin" ,
            "version" :  "v0.10.27 + 3 gea8c3de"
        }

        """
        re = self.__getAPIREST__("/system/Version")
        return json.loads(re.content)

    def get_connections(self):
        """
        Returns the list of configured devices and some metadata associated with them.
        The list also contains the local device itself as not connected.

        The connection types are TCP (Client), TCP (Server), Relay (Client) and Relay (Server).
        """
        re = self.__getAPIREST__("/system/connections")
        return json.loads(re.content)

    def get_upgrade(self):
        """
        Checks for a possible upgrade and returns an object
        describing the newest version and upgrade possibility.
        return {
                    "latest": "v0.10.27",
                    "newer": false,
                    "running": "v0.10.27+5-g36c93b7" }
        """
        re = self.__getAPIREST__("/system/upgrade")

        return json.loads(re.content)

    def get_status(self):
        """
        Returns information about current system status and resource usage.
        """
        re = self.__getAPIREST__("/system/status")

        return json.loads(re.content)

    def get_ping(self):
        """
        Returns a {"ping": "pong"} object.
        {
            "ping": "pong"
        }
        """
        re = self.__getAPIREST__("/system/ping")
        return json.loads(re.content)

    def get_log(self):
        """
        Returns the list of recent log entries.
        {
        "messages": [
            {
            "when": "2014-09-18T12:59:26.549953186+02:00",
            "message": "This is a log entry"
            }
        ]
        }
        """
        re = self.__getAPIREST__("/system/log")

        return json.loads(re.content)

    def get_error(self):
        """
        Returns the list of recent errors.
        {
        "errors": [
            {
            "when": "2014-09-18T12:59:26.549953186+02:00",
            "message": "This is an error string"
            }
        ]
        }
        """
        re = self.__getAPIREST__("/system/error")

        return json.loads(re.content)

    def get_discovery(self):
        """
        Returns the contents of the local discovery cache.

            {
            "LGFPDIT7SKNNJVJZA4FC7QNCRKCE753K72BW5QD2FOZ7FRFEP57Q": [
                "192.162.129.11:22000"
            ]
            }
        """
        re = self.__getAPIREST__("/system/discovery")
        return json.loads(re.content)

    def is_config_sync(self):
        """
        Returns whether the config is in sync,
        i.e. whether the running configuration is the same as that on disk.
        """
        re = self.__getAPIREST__("/system/config/insync").content
        return json.loads(re)["configInSync"]

    def json_string(self, pythondict):
        """
        converti python dict to json string
        """
        return json.dumps(pythondict, indent=4)

    def show_rest(self, pythondict):
        """
        affiche json format
        """
        rest = self.json_string(pythondict)
        logger.info(f"{rest}")
        return rest

    def nb_folders(self):
        """
        return nb de folder from config
        """
        return len(self.folders)

    def get_list_folders_name(self):
        """
        return list name folder fron config
        """
        result = []
        for folder in self.folders:
            if folder["label"] == "":
                result.append(str(folder["id"]))
            else:
                result.append(str(folder["label"]))
        return result

    def get_list_folders_id(self):
        """
        return list id folder fron config
        """
        return [str(folder["id"]) for folder in self.folders]

    def nb_devices(self):
        """
        return nb de folder from config
        """
        return len(self.get_list_devices_id())

    def get_list_devices_name(self):
        """
        return list devices name fron config
        """
        return [str(device["name"]) for device in self.devices if device["name"] != ""]

    def get_list_devices_adress(self):
        """
        return list devices adress fron config
        """
        return [
            str(device["addresses"]) for device in self.devices if device["name"] != ""
        ]

    def get_list_devices_id(self):
        """
        return list devices id fron config
        """
        return [
            str(device["deviceID"]) for device in self.devices if device["name"] != ""
        ]

    def get_id_device_local(self):
        return self.device_id

    # private function
    def __getAPIREST__(self, cmd, paramsurl={}):
        try:
            geturl = f"{self.urlbaserest}{cmd}"
            if len(paramsurl) != 0:
                string_param_url = urllib.parse.urlencode(paramsurl)
                geturl = f"{geturl}?{string_param_url}"
            rest = requests.get(geturl, headers=self.headers)
        except Exception as e:
            logger.error(
                "syncthingapirest.py __getAPIREST__ verify syncthing running and ready"
            )
            time.sleep(1)
            self.errornb = self.errornb + 1
            if self.errornb > 4:
                logger.error("\n%s" % (traceback.format_exc()))
            else:
                logger.warning("connection lost get REST")
            return {}
        self.errornb = 0
        return rest

    def __postAPIREST__(self, cmd, dictpython={}, paramsurl={}, RestCurl=False):
        def analyseresult(r):
            if r.status_code == 200:
                return r.text
            elif r.status_code in [301, 302]:
                return {"error": "redirection, respectivement permanente et temporaire"}
            elif r.status_code == 400:
                return {"error": "Bad Request", "msg": r.text}
            elif r.status_code == 401:
                return {"error": "utilisateur non authentifie", "msg": r.text}
            elif r.status_code == 403:
                return {"error": "accès refusé "}
            elif r.status_code == 404:
                return {"error": "page non trouvée"}
            elif r.status_code in [500, 503]:
                return {"error": f"erreur serveur {r.status_code}", "msg": r.text}
            elif r.status_code == 504:
                return {"error": "le serveur n'a pas répondu"}
            else:
                return {"error": f"inconue code {r.status_code}", "msg": r.text}

        r = None
        posturl = f"{self.urlbaserest}{cmd}"
        if len(paramsurl) != 0:
            string_param_url = urllib.parse.urlencode(paramsurl)
            posturl = f"{posturl}?{string_param_url}"

        if len(dictpython) == 0:
            if RestCurl:
                cmddate = f"""command curl curl -X POST --header "X-API-Key: {self.headers["X-API-KEY"]}"  {posturl}"""
                logger.info(f"{cmddate}")
            try:
                r = requests.post(posturl, headers=self.headers)
            except BaseException:
                self.errornb = self.errornb + 1
                if self.errornb > 4:
                    logger.error("\n%s" % (traceback.format_exc()))
                else:
                    logger.warning("connection lost post REST")
                time.sleep(5)
        else:
            if RestCurl:
                cmddate = f"""curl -X POST --header "X-API-Key: {self.headers["X-API-KEY"]}"  {posturl}  -d '{json.dumps(dictpython)}' """
                logger.info(f"{cmddate}")
            try:
                r = requests.post(
                    posturl, headers=self.headers, data=json.dumps(dictpython)
                )
            except BaseException:
                self.errornb = self.errornb + 1
                if self.errornb > 4:
                    logger.error("\n%s" % (traceback.format_exc()))
                else:
                    logger.warning("connection lost post REST")
        if r is None:
            return None
        self.errornb = 0
        result = analyseresult(r)
        if isinstance(result, str) and "error" in result:
            logger.error(f"{result}")
        return result

    def add_device_to_folder(self, strlabel, id_device):
        self.mutex.acquire()
        try:
            for folder in self.folders:
                if folder["label"] == strlabel:
                    folder["devices"].append(
                        {"deviceID": id_device, "introducedBy": ""}
                    )
                    self.synchro = False
        finally:
            self.mutex.release()

    def create_template_struct_device(
        self,
        str_name,
        id_device,
        introducer=False,
        autoAcceptFolders=False,
        address=["dynamic"],
    ):
        return {
            "pendingFolders": [],
            "compression": "metadata",
            "skipIntroductionRemovals": False,
            "maxRecvKbps": 0,
            "allowedNetworks": [],
            "certName": "",
            "maxRequestKiB": 0,
            "introducer": introducer,
            "name": str_name,
            "paused": False,
            "deviceID": id_device,
            "ignoredFolders": [],
            "maxSendKbps": 0,
            "introducedBy": "",
            "autoAcceptFolders": autoAcceptFolders,
            "addresses": address,
        }

    def add_device_syncthing(
        self,
        keydevicesyncthing,
        namerelay,
        introducer=False,
        autoAcceptFolders=False,
        address=["dynamic"],
    ):
        result = False
        self.mutex.acquire()
        try:
            # test si device existe
            for device in self.devices:
                if device["deviceID"] == keydevicesyncthing:
                    # la devise existe deja
                    result = False
            logger.debug(f"add device syncthing {keydevicesyncthing}")
            dsyncthing_tmp = self.create_template_struct_device(
                namerelay,
                str(keydevicesyncthing),
                introducer=introducer,
                autoAcceptFolders=autoAcceptFolders,
                address=address,
            )

            logger.debug(
                "add device [%s]syncthing to ars %s\n%s"
                % (keydevicesyncthing, namerelay, json.dumps(dsyncthing_tmp, indent=4))
            )
            self.config["devices"].append(dsyncthing_tmp)
            self.synchro = False
            result = True
        finally:
            self.mutex.release()
            return result
        return False

    def is_exist_folder_id(self, idfolder):
        return any(folder["id"] == idfolder for folder in self.folders)

    def add_folder_dict_if_not_exist_id(self, dictaddfolder):
        self.mutex.acquire()
        try:
            if not self.is_exist_folder_id(dictaddfolder["id"]):
                self.folders.append(dictaddfolder)
                self.synchro = False
                return True
        finally:
            self.mutex.release()
        return False

    def add_device_in_folder_if_not_exist(self, folderid, keydevice, introducedBy=""):
        result = False
        self.mutex.acquire()
        try:
            for folder in self.folders:
                if folderid == folder["id"]:
                    # folder trouve
                    for device in folder["devices"]:
                        if device["deviceID"] == keydevice:
                            # device existe
                            result = False
                    new_device = {"deviceID": keydevice, "introducedBy": introducedBy}
                    if new_device not in folder["devices"]:
                        folder["devices"].append(new_device)
                    self.synchro = False
                    result = True
        finally:
            self.mutex.release()
            return result
        return False

    def add_device_in_folder(self, folderjson, keydevice, introducedBy=""):
        """add device sur structure folder"""
        result = False
        self.mutex.acquire()
        try:
            for device in folderjson["devices"]:
                if device["deviceID"] == keydevice:
                    # device existe
                    return False
            new_device = {"deviceID": keydevice, "introducedBy": introducedBy}
            folderjson["devices"].append(new_device)
            result = True
        finally:
            self.mutex.release()
            return result
        return False

    def validate_chang_config(self):
        self.mutex.acquire()
        try:
            if not self.synchro:
                time.sleep(1)
                self.post_config()
                time.sleep(2)
                self.post_restart()
                time.sleep(2)
                self.synchro = True
        except Exception as e:
            logger.error(f"{str(e)}")
        finally:
            self.mutex.release()

    def is_format_key_device(self, keydevicesyncthing):
        if len(str(keydevicesyncthing)) != 63:
            logger.warning("size key device diff of 63")
        listtest = keydevicesyncthing.split("-")
        if len(listtest) != 8:
            logger.error("group key diff of 8")
            return False
        for z in listtest:
            if len(z) != 7:
                logger.error("size group key diff of 7")
                return False
            index = 1 + 1
        return True

    def is_exist_device_in_config(self, keydevicesyncthing):
        return any(device["deviceID"] == keydevicesyncthing for device in self.devices)

    def create_template_struct_folder(
        self, str_name, path_folder, id=None, typefolder="slave"
    ):
        if id is None:
            id = getRandomName(15, pref="auto_")
        if typefolder.lower() == "slave":
            typefolder = "receiveonly"
        elif typefolder.lower() == "master":
            typefolder = "sendonly"
        elif typefolder.lower() == "all":
            typefolder = "sendreceive"
        return {
            "copyOwnershipFromParent": False,
            "useLargeBlocks": False,
            "rescanIntervalS": 3600,
            "copiers": 0,
            "paused": False,
            "pullerPauseS": 0,
            "autoNormalize": True,
            "id": id,
            "scanProgressIntervalS": 0,
            "hashers": 0,
            "filesystemType": "basic",
            "label": str_name,
            "disableTempIndexes": False,
            "pullerMaxPendingKiB": 0,
            "ignorePerms": False,
            "markerName": ".stfolder",
            "disableSparseFiles": False,
            "fsWatcherDelayS": 10,
            "path": path_folder,
            "fsWatcherEnabled": True,
            "minDiskFree": {"unit": "%", "value": 1},
            "ignoreDelete": False,
            "weakHashThresholdPct": 25,
            "type": typefolder,
            "devices": [{"deviceID": self.device_id, "introducedBy": ""}],
            "maxConflicts": -1,
            "order": "random",
            "versioning": {"params": {}, "type": ""},
        }

    def del_device_from_folder(self, folderid, deviceid):
        """Dissociate the device from the folder.
        Params:
            folderid: str of the folder id
            deviceid : str of the device id"""
        self.mutex.acquire()
        try:
            for folder in self.config["folders"]:
                if folder["id"] == folderid:
                    for device in folder["devices"]:
                        if device["deviceID"] == deviceid:
                            folder["devices"].remove(device)
                            self.synchro = False
        finally:
            self.mutex.release()

    def del_folder(self, folderid):
        """Dissociate the device from the folder.
        Params:
            folderid: str of the folder id"""

        self.mutex.acquire()
        try:
            for folder in self.config["folders"]:
                if folder["id"] == folderid:
                    self.config["folders"].remove(folder)
                    self.synchro = False
        finally:
            self.mutex.release()

    def clean_pendingFolders_ignoredFolders_in_devices(self):
        self.mutex.acquire()
        try:
            for device in self.config["devices"]:
                if "pendingFolders" in device:
                    del device["pendingFolders"]
                    self.synchro = False
                if "ignoredFolders" in device:
                    del device["ignoredFolders"]
                    self.synchro = False
        finally:
            self.mutex.release()

    def clean_pending(self):
        self.mutex.acquire()
        try:
            if (
                "pendingDevices" in self.config
                and len(self.config["pendingDevices"]) != 0
            ):
                self.config["pendingDevices"] = []
                self.synchro = False
        finally:
            self.mutex.release()

    def clean_remoteIgnoredDevices(self):
        self.mutex.acquire()
        try:
            if (
                "remoteIgnoredDevices" in self.config
                and len(self.config["remoteIgnoredDevices"]) != 0
            ):
                self.config["remoteIgnoredDevices"] = []
                self.synchro = False
        finally:
            self.mutex.release()

    def set_pause_folder(self, folderid, paused=False):
        self.mutex.acquire()
        try:
            for folder in self.config["folders"]:
                if folder["id"] == folderid:
                    if "paused" not in folder or folder["paused"] != paused:
                        folder["paused"] = paused
                        self.synchro = False
                    return
        finally:
            self.mutex.release()

    def maxRecvKbps(self, kb=0, config=None):
        if kb == 0:
            logger.info("Syncthing: RECV rate limit is False")
        else:
            logger.info("Syncthing: RECV limit rade is %d Kb" % kb)
        if config is None:
            self.mutex.acquire()
            try:
                config = self.config
                if "options" in config:
                    if config["options"]["maxRecvKbps"] != kb:
                        config["options"]["maxRecvKbps"] = kb
                        self.synchro = False
            finally:
                self.mutex.release()
        elif "options" in config:
            config["options"]["maxRecvKbps"] = kb

    def maxSendKbps(self, kb=0, config=None):
        if kb == 0:
            logger.info("Syncthing: SEND  rate limit is False")
        else:
            logger.info("Syncthing: SEND limit rate is %d Kb" % kb)

        if config is None:
            self.mutex.acquire()
            try:
                config = self.config
                if "options" in config:
                    if config["options"]["maxSendKbps"] != kb:
                        config["options"]["maxSendKbps"] = kb
                        self.synchro = False
            finally:
                self.mutex.release()
        elif "options" in config:
            config["options"]["maxSendKbps"] = kb

    def get_list_device_used_in_folder(self):
        devicelist = set()
        for folder in self.config["folders"]:
            for device in folder["devices"]:
                devicelist.add(device["deviceID"])
        return list(devicelist)

    def display_list_id_folder(self):
        for folder in self.config["folders"]:
            print(folder["id"])

    def display_list_id_device(self):
        for device in self.config["devices"]:
            print(device["deviceID"])


class syncthing(syncthingapi):
    def delete_folder_id_pulsedeploy(self, id):
        self.clean_pending()
        self.clean_remoteIgnoredDevices()
        self.mutex.acquire()
        try:
            # id des partages utilisé pour les menus et les packages dans
            # pulse.
            idpermanent = ["pulsemaster_bootmenus", "pulsemaster_packages"]

            listfolderid = [
                x["id"] for x in self.config["folders"] if x["id"] not in idpermanent
            ]
            if not listfolderid:
                logger.debug(f"folder id {id} not exist")
                return

            if id in listfolderid:
                indexfolderid = listfolderid.index(id)
            else:
                logger.debug(f"folder id {id} not exist in folder list {listfolderid}")
                return

            # recuper les devices utiliser dans le folder a supprimer
            listedevicedel = [
                x["deviceID"] for x in self.config["folders"][indexfolderid]["devices"]
            ]
            # recherche si device utiliser dans 1 autre folder.
            for indexfolder in range(len(self.config["folders"])):
                if (
                    self.config["folders"][indexfolder]["id"] in idpermanent
                    or self.config["folders"][indexfolder]["id"] == id
                ):
                    continue
                list_device_folder_data = [
                    x["deviceID"]
                    for x in self.config["folders"][indexfolder]["devices"]
                ]
                for t in list_device_folder_data:
                    listdevicecopy = list(listedevicedel)
                    if t in listdevicecopy:
                        listedevicedel.remove(t)
            devices = [x["deviceID"] for x in self.config["devices"]]
            listdelindex = [
                indexdd
                for indexdd in range(len(devices))
                if devices[indexdd] in listedevicedel
            ]
            listdelindex.reverse()
            # on supprime le folder
            del self.config["folders"][indexfolderid]
            self.synchro = False
            self.synchro = False
            # on supprime les device.
            for indexsupp in listdelindex:
                del self.config["devices"][indexsupp]
        except BaseException:
            logger.error("\n%s" % (traceback.format_exc()))
        finally:
            self.mutex.release()

    def delete_device_is_not_list(self, listdeviceutil):
        to_delete = []
        for i, elem in enumerate(self.devices):
            if elem["name"] == "pulse":
                continue
            if elem["deviceID"] not in listdeviceutil:
                to_delete.append(i)
        to_delete.reverse()
        for i in to_delete:
            del self.devices[i]

    def delete_folder_pulse_deploy(self, id, reload=True):
        if reload:
            self.reload_config()
        self.del_folder(id)
        listdeviceutil = self.get_list_device_used_in_folder()
        self.delete_device_is_not_list(listdeviceutil)

    def ignore_shareid(self, shareid, reload=True):
        if reload:
            self.reload_config()


class syncthingprogram(Program):
    def __init__(
        self, console=False, browser=False, home="", logfile="", agenttype="relayserver"
    ):
        Program.__init__(self)
        self.console = console
        self.browser = browser
        self.home = home
        self.logfile = logfile
        self.agenttype = agenttype

    def start_syncthing(self):
        if sys.platform.startswith("linux"):
            if self.agenttype == "relayserver":
                os.system("systemctl restart syncthing@syncthing-depl.service")
            else:
                os.system("systemctl restart syncthing@pulseuser.service")
        elif sys.platform.startswith("win"):
            if self.home == "":
                self.home = "c:\\progra~1\\pulse\\etc\\syncthing\\"
            if self.logfile == "":
                self.logfile = "c:\\progra~1\\pulse\\var\\log\\syncthing.log"

            self.stop_syncthing()

            agentconf = os.path.join(
                "c:\\", "progra~1", "Pulse", "etc", "agentconf.ini"
            )
            Config = configparser.ConfigParser()
            Config.read(agentconf)

            syncthing_bin = os.path.join(
                "c:\\", "progra~1", "Pulse", "bin", "syncthing.exe"
            )

            if not os.path.isfile(syncthing_bin):
                logger.error(
                    "Syncthing is not installed, Changing configuration to not use it yet."
                )

                is_syncthing_activated = 1
                if Config.has_option("syncthing", "activation"):
                    is_syncthing_activated = Config.get("syncthing", "activation")

                if is_syncthing_activated:
                    Config.set("syncthing", "activation", "0")
                    with open(agentconf, "w") as configfile:
                        Config.write(configfile)

                query_cmd = 'reg query "hklm\\software\\microsoft\\windows\\currentversion\\uninstall\\Pulse Syncthing" /s | Find "DisplayVersion"'
                query_result = simplecommand(query_cmd)
                if query_result["code"] == 0:
                    delete_cmd = 'reg delete "hklm\\software\\microsoft\\windows\\currentversion\\uninstall\\Pulse Syncthing" /f'
                    delete_result = simplecommand(delete_cmd)
                    if delete_result["code"] == 0:
                        logger.debug("Syncthing has been removed from the registry")

            cmd = [f"{syncthing_bin}", f"-home={self.home}", f"-logfile={self.logfile}"]

            if not self.console:
                cmd.append("-no-console")
            if not self.browser:
                cmd.append("-no-browser")
            self.startprogram(cmd, "syncthing")
        elif sys.platform.startswith("darwin"):
            if self.home == "":
                self.home = "/opt/Pulse/etc/syncthing/"
            if self.logfile == "":
                self.logfile = "/opt/Pulse/var/log/syncthing.log"

            self.stop_syncthing()
            cmd = f"""export STNODEFAULTFOLDER=1;nohup /opt/Pulse/bin/syncthing -home="{self.home}" -logfile="{self.logfile}" -no-browser &"""
            self.startprogram(cmd, "syncthing")

        time.sleep(4)

    def stop_syncthing(self):
        if "syncthing" in self.programlist:
            del self.programlist["syncthing"]

        if sys.platform.startswith("win"):
            os.system("taskkill /f /im syncthing.exe")
        elif sys.platform.startswith("linux"):
            if self.agenttype == "relayserver":
                os.system("systemctl stop syncthing@syncthing-depl.service")
            else:
                os.system("systemctl stop syncthing@pulseuser.service")
        elif sys.platform.startswith("darwin"):
            os.system("kill -9 `ps -A|grep Syncthing| awk -F ' ' '{print $1}'`")

    def restart_syncthing(self):
        self.stop_syncthing()
        self.start_syncthing()

    def syncthing_on(self):
        if sys.platform.startswith("win"):
            cmd = 'asklist | findstr "syncthing.exe"'
        else:
            cmd = "ps ax |  grep syncthing | grep -v grep"
        result = simplecommand(cmd)
        return len(result["result"]) > 4

    def statussyncthing(self):
        pass
