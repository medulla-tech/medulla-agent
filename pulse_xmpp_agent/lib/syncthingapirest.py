#!/usr/bin/env python
# -*- coding: utf-8; -*-
#
# (c) 2016 siveo, http://www.siveo.net
#
# This file is part of Pulse 2, http://www.siveo.net
#
# Pulse 2 is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# Pulse 2 is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Pulse 2; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
# MA 02110-1301, USA.
# 
# file : lib/syncthingapirest.py

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
import requests, json
from lxml import etree
import urllib
import socket

""" class use for xmpp on each server syncthing in local """

class syncthing():
    def __init__(   self, 
                    urlweb = 'http://localhost', 
                    port = 8384, 
                    configfile = "/var/lib/syncthing/.config/syncthing/config.xml",
                    idapirest = None):
        self.urlweb = urlweb
        self.port = port
        self.urlbase = "%s:%s/"%(self.urlweb,port )
        self.urlbaserest = "%srest"%(self.urlbase)
        if idapirest is None:
            self.tree = etree.parse(configfile)
            self.idapirest = self.tree.xpath('/configuration/gui/apikey')[0].text
        else:
            self.idapirest = idapirest
        self.headers = { 'X-API-KEY': "%s"% self.idapirest }
        self.reload_config()
        # bash command xmllint --xpath "//configuration/gui/apikey/text()" /var/lib/syncthing/.config/syncthing/config.xml


    def reload_config(self):
        self.config = self.get_config() # content all config
        self.folders = self.config['folders']
        self.devices = self.config['devices']
        self.version = self.config['version']
        self.guiinformation = self.config['gui']
        try:
            self.ignoredFolders = self.config['ignoredFolders']
        except:
            self.ignoredFolders = []
        try:
            self.ignoredDevices = self.config['ignoredDevice']
        except:
            self.ignoredDevices = []

        self.options  = self.config['options']

        hostname = socket.gethostname()
        for device in self.devices:
            if device['name'] == hostname:
                self.device_id = device['deviceID']
                break

    def save_conf_to_file(self, filedatajson):
        with open(filedatajson, 'w') as outfile:
            json.dump(self.config, outfile, indent = 4)

    def get_config(self):
        """
            Returns the current configuration.
            dict python
        """
        re = self.__getAPIREST__("/system/config")
        return json.loads(re.content)


    def post_config(self):
        """
            Post the full contents of the configuration,
            in the same format as returned by the corresponding GET request.
            The configuration will be saved to disk and the configInSync flag
            set to false. Restart Syncthing to activate.
        """
        re = self.__postAPIREST__("/system/config", dictpython = self.config)
        return re

    def post_discovery(self, deviceid, adress, port=22000):
        params = { "device" : deviceid, "addr"  : "%s:%s"%(adress,port) }
        re = self.__postAPIREST__("/system/discovery", paramsurl=params)
        return re

    def post_debug(self, eneablelist="", disablelist =""):
        """
            Enables or disables debugging for specified facilities. Give one or both of enable
            and disable query parameters, with comma separated facility names.
            To disable debugging of the beacon and discovery packages,
            and enable it for config and db:
            $ curl -H X-API-Key:abc123 -X POST 'http://localhost:8384/rest/system/debug?disable=beacon,discovery&enable=config,db'
 
            e.g 
            objetApirest.post_debug(eneablelist = config, db, disablelist = "beacon,discovery")
        """
        params = { "disable" : disablelist, "enable"  : eneablelist}
        re = self.__postAPIREST__("/system/debug", paramsurl=params)
        return re

    def get_stats_device(self):
        re = self.__getAPIREST__("/stats/device")
        return json.loads(re.content)

    def get_events_type(self, type, limit = "5", since = "0", datasection = None):
        def Diff(li1, li2):
            return (list(set(li1) - set(li2)))

        if isinstance(type, basestring):
            type = [type]
        datas_event = self.get_events(limit = limit, since = since)
        tablekey = ["folders", "gui", "devices", "options", "version", "ignoredDevices", "summary"]
        tabeventtype =["ConfigSaved", "DeviceConnected", "DeviceDisconnected", "DeviceDiscovered", "DevicePaused", "DeviceRejected", "DeviceResumed", "DownloadProgress", "FolderCompletion", "FolderErrors", "FolderRejected", "Folder Scan Progress", "FolderSummary", "ItemFinished", "ItemStarted", "Listen Addresses Changed", "LocalChangeDetected", "LocalIndexUpdated", "Login Attempt"," RemoteChangeDetected", "Remote Download Progress", "RemoteIndexUpdated", "Starting", "StartupComplete", "StateChanged"]
        re = [eventdata for eventdata in datas_event if eventdata['type'] in type]
        print len(re)
        if datasection is not None:
            if isinstance(datasection, basestring):
                datasection =[datasection]
            for section in datasection:
                if section not in tablekey:
                    print "Warning la section %s n'existe pas dans la structure Event"%section

            for typename in type:
                if typename not in tabeventtype:
                    print "Warning la type event %s n'existe pas dans la structure Event"%typename

            kk = Diff(tablekey, datasection)
            for e in re:
                for t in kk:
                    try:
                     del e['data'][t]
                    except KeyError:
                        pass
        return re



    def get_events(self, since = None, limit = None, eventslist = None):
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
            params['since'] = since
        if limit is not None:
            params['limit'] = limit
        if eventslist is not None:
            params['events'] = eventslist
        re = self.__getAPIREST__("/events", paramsurl=params)
        return json.loads(re.content)

    def post_error_clear(self, eneablelist="", disablelist =""):
        """
            Post with empty to body to remove all recent errors.
        """
        re = self.__postAPIREST__("/system/error/clear")
        print re

    def post_error(self, error_text):
        """
            Poster un message d'erreur dans le corps (texte brut)
            pour enregistrer une nouvelle erreur. 
            La nouvelle erreur sera affiché sur tous les clients de l'interface graphique active.

            curl -X POST -d 'who=world' -H "Content-Type : text/plain" http://localhost:8106/hello
        """
        posturl = "%s%s"%(self.urlbaserest, "/system/error")
        header = self.headers.copy()
        header['Content-Type']="text/plain"
        print header
        requests.post(posturl, headers = header, data = error_text )


    def post_pause(self, deviceid=None):
        """
            Pause the given device or all devices.

            Takes the optional parameter device (device ID).
            When ommitted, pauses all devices. Returns status 200 and no content upon success, or status 500 and a plain text error on failure.
        """
        if deviceid != None:
            params = { "device" : deviceid }
            self.__postAPIREST__("/system/pause", paramsurl = params)
        else:
            self.__postAPIREST__("/system/pause")

    def post_ping(self):
        """
            Retourne un objet.{"ping": "pong"}
        """
        return  self.__postAPIREST__("/system/ping")

    def post_reset(self, deviceid=None):
        """
            Post with empty body to erase the current index database and 
            restart Syncthing. With no query parameters, the entire database is
            erased from disk. By specifying the folder parameter
            with a valid folder ID, only information for that folder will be erased:

            $ curl -X POST -H "X-API-Key: abc123" http://localhost:8384/rest/system/reset?folder=default
        """
        if deviceid != None:
            params = { "device" : deviceid }
            self.__postAPIREST__("/system/rest", paramsurl = params)
        else:
            self.__postAPIREST__("/system/reset")

    def post_restart(self):
        """
            Post with empty body to immediately restart Syncthing.
        """
        re = self.__postAPIREST__("/system/restart")
        print re

    def post_resume(self, deviceid=None):
        """
            Pause the given device or all devices.

            Takes the optional parameter device (device ID).
            When ommitted, pauses all devices. Returns status 200 and no content
            upon success, or status 500 and a plain text error on failure.
        """
        if deviceid != None:
            params = { "device" : deviceid }
            self.__postAPIREST__("/system/resume", paramsurl = params)
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


    def get_db_browse(self, folder, labeldepth = None, prefix = None):
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
        params = { "folder" : folder }
        if labeldepth != None and isinstance(labeldepth , ( int ) ):
            params['levels'] = labeldepth
        if prefix != None:
            params['prefix'] = prefix
        re = self.__getAPIREST__("/db/browse", paramsurl =params)
        return json.loads(re.content)


    def get_db_completion(self, folder, device ):
        """
            Returns the completion percentage (0 to 100) 
            for a given device and folder. Takes device and folder parameters.
            return 
            {
                "completion": 0
            }
        """
        params = { "folder" : folder, "device" : device }
        re = self.__getAPIREST__("/db/completion", paramsurl =params)
        return json.loads(re.content)


    def get_db_file(self, folder, namefile ):
        """
            Returns most data available about a given file, including version and availability. Takes folder and file parameters.
        """
        params = { "folder" : folder, "file" : namefile }
        re = self.__getAPIREST__("/db/file", paramsurl = params)
        return json.loads(re.content)


    def get_db_ignores(self, folder ):
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
        params = { "folder" : folder}
        re = self.__getAPIREST__("/db/ignores", paramsurl = params)
        return json.loads(re.content)


    def post_db_override(self, folder,):
        """
            Request override of a send-only folder. Takes the mandatory parameter folder (folder ID).

            curl -X POST http://127.0.0.1:8384/rest/db/override?folder=default
        """
        params = { "folder" : folder}
        self.__postAPIREST__("/db/override",  paramsurl = params )


    def get_db_need(self, folder, page = None, perpage = None ):
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
        params = { "folder" : folder}

        if page != None:
            params['page'] = page
        if perpage != None:
            params['perpage'] = perpage
        
        re = self.__getAPIREST__("/db/need", paramsurl = params)
        return json.loads(re.content)


    def get_db_status(self, folder):
        """
            Returns information about the current status of a folder.
            Parameters: folder, the ID of a folder.
        """
        params = { "folder" : folder}
        re = self.__getAPIREST__("/db/status", paramsurl = params)
        return json.loads(re.content)


    def post_db_prio(self, folder, pathfile = None ):
        """
            Moves the file to the top of the download queue.
            curl -X POST http://127.0.0.1:8384/rest/db/prio?folder=default&file=foo/bar
            Response contains the same output as GET /rest/db/need

            @param filelist files string de file seperate by ,
            e.g
                filelist = "foo,bar"
        """
        params = { "folder" : folder}
        if pathfile != None:
            params['file']=pathfile
        re = self.__postAPIREST__("/db/prio", paramsurl = params )
        print re


    def post_db_scan(self, folder = None, sub = None, next = None):
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
        params = { }
        if folder != None:
            params['folder'] = folder
        if sub != None:
            params['sub'] = sub
        if next != None and isinstance(next , ( int ) ):
            params['next'] = next
        re = self.__postAPIREST__("/db/scan", paramsurl = params )
        print re

    def post_db_ignores(self, folder, python_ignores ):
        """
            Expects a format similar to the output of GET call, but only
            containing the ignore field (expanded field should be omitted).
            It takes one parameter, folder, and either updates the content
            of the .stignore echoing it back as a response, or returns an error.
        """
        params = { "folder" : folder}
        re = self.__postAPIREST__("/db/ignores", dictpython = python_ignores, paramsurl = params )
        print re


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
        return json.loads(re)['configInSync']

    def json_string(self, pythondict):
        """ 
            converti python dict to json string
        """
        return json.dumps(pythondict, indent = 4)

    def show_rest(self, pythondict):
        """ 
        affiche json format
        """
        print  self.json_string(pythondict)

    def nb_folders(self):
        """
            return nb de folder from config
        """
        return len(self.folders)

    def get_list_folders_name(self):
        """
            return list name folder fron config
        """
        result=[]
        for folder in self.folders:
            if folder['label'] == "":
                result.append(str(folder['id']))
            else:
                result.append(str(folder['label']))
        return result

    def get_list_folders_id(self):
        """
            return list id folder fron config
        """
        return [str(folder['id']) for folder in self.folders ]

    def nb_devices(self):
        """
            return nb de folder from config
        """
        return len(self.get_list_devices_id())

    def get_list_devices_name(self):
        """
            return list devices name fron config
        """
        return [str(device['name']) for device in self.devices if device['name'] != ""]

    def get_list_devices_adress(self):
        """
            return list devices adress fron config
        """
        return [str(device['addresses']) for device in self.devices if device['name'] != ""]

    def get_list_devices_id(self):
        """
            return list devices id fron config
        """
        return [str(device['deviceID']) for device in self.devices if device['name'] != ""]

    def get_id_device_local(self):
        return self.device_id

    #private function
    def __getAPIREST__(self, cmd, paramsurl = {}):
        geturl = "%s%s"%(self.urlbaserest, cmd)
        if len(paramsurl) != 0:
            string_param_url = urllib.urlencode(paramsurl)
            geturl = geturl+"?"+string_param_url
        rest = requests.get(geturl,headers=self.headers)
        return rest

    def __postAPIREST__(self, cmd, dictpython = {}, paramsurl = {}, RestCurl=False):
        def analyseresult(r):
            #r.headers['content-type']
            #r.encoding
            if r.status_code == 200:
                return  r.text
            elif r.status_code == 301  or  r.status_code == 302:
                return {"error" : "redirection, respectivement permanente et temporaire"}
            elif r.status_code == 401:
                return {"error" : "utilisateur non authentifié"}
            elif r.status_code == 403:
                return {"error" : "accès refusé "}
            elif r.status_code == 404 :
                return {"error" : "page non trouvée"}
            elif r.status_code == 500  or  r.status_code == 503:
                return {"error" : "erreur serveur %s"%r.status_code, "msg" : r.text }
            elif r.status_code == 504 :
                return {"error" : "le serveur n'a pas répondu"}
            else :
                return {"error" : "inconue code %s"%r.status_code, "msg" : r.text }

        posturl = "%s%s"%(self.urlbaserest, cmd)
        if len(paramsurl) != 0:
            string_param_url = urllib.urlencode(paramsurl)
            posturl = posturl+"?"+string_param_url
        if len(dictpython) == 0:
            if RestCurl:
                cmddate  = """command curl curl -X POST --header "X-API-Key: %s"  %s"""%(self.headers['X-API-KEY'], posturl)
                print cmddate
            r = requests.post(posturl, headers = self.headers)
            return analyseresult(r)
        else:
            if RestCurl:
                cmddate  = """curl -X POST --header "X-API-Key: %s"  %s  -d '%s' """%(self.headers['X-API-KEY'], posturl, json.dumps(dictpython)) 
                print cmddate
            r = requests.post(posturl,headers = self.headers, data = json.dumps(dictpython))
            return analyseresult(r)

    def add_device_to_folder(self, strlabel, id_device ):
        for folder in self.folders:
            if folder['label'] == strlabel:
                folder['devices'].append({  "deviceID": id_device, 
                                            "introducedBy": ""})

    def  create_template_struct_device(self, str_name, id_device):
        return{
                "compression": "metadata", 
                "skipIntroductionRemovals": False, 
                "maxRecvKbps": 0, 
                "allowedNetworks": [], 
                "certName": "", 
                "introducer": False, 
                "name": str_name, 
                "paused": False, 
                "deviceID": id_device, 
                "maxSendKbps": 0, 
                "introducedBy": "", 
                "autoAcceptFolders": False, 
                "addresses": [
                    "dynamic"
                ]
            }

    def create_template_struct_folder(self, str_name, path_folder):
        return {
            "useLargeBlocks": False,                                                                                                                                                
            "rescanIntervalS": 3600,                                                                                                                                                
            "copiers": 0,                                                                                                                                                           
            "paused": False, 
            "pullerPauseS": 0, 
            "autoNormalize": True, 
            "id": "", 
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
            "minDiskFree": {
                "unit": "%", 
                "value": 1
            }, 
            "ignoreDelete": False, 
            "weakHashThresholdPct": 25, 
            "type": "sendreceive", 
            "devices": [
                {
                    "deviceID": self.device_id, 
                    "introducedBy": ""
                }
            ], 
            "maxConflicts": -1, 
            "order": "random", 
            "versioning": {
                "params": {}, 
                "type": ""
            }
        }
if __name__ == '__main__':
    pass
