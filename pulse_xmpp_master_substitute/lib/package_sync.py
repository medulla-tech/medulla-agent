# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2026 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-3.0-or-later
# file : pulse_xmpp_master_substitute/lib/package_sync.py

"""
Has every relay received a package? Asked to the Syncthing of the server, which copies
the package shares to the relays. A relay only checks that the directory of a package
exists before a transfer: a deployment started too early fails, or sends a partial package.

Nothing here belongs to a module: any deployment may ask before it starts.
"""

import os
import xml.etree.ElementTree as ElementTree

import requests

CONFIG = "/var/lib/syncthing/.config/syncthing/config.xml"
TIMEOUT = 10
# Written with every package: known to Syncthing once it has read the package
DESCRIPTOR = "xmppdeploy.json"
# States of a folder Syncthing is reading: a package may be half known
READING = ("scanning", "scan-waiting")
# Files a relay still needs, read by pages
PAGE = 1000


class Unknown(Exception):
    """Syncthing cannot tell: not installed, not reachable, package outside its folders."""


def read_config(path=CONFIG):
    """Address and key of the local Syncthing, its folders and the names of its devices."""
    try:
        root = ElementTree.parse(path).getroot()
        gui = root.find("gui")
        scheme = "https" if gui.get("tls") == "true" else "http"
        return {
            "url": "%s://%s/rest/" % (scheme, gui.findtext("address")),
            "key": gui.findtext("apikey"),
            "folders": [
                {
                    "id": folder.get("id"),
                    "path": os.path.realpath(os.path.expanduser(folder.get("path"))),
                    "devices": [device.get("id") for device in folder.findall("device")],
                }
                for folder in root.findall("folder")
            ],
            "names": {device.get("id"): device.get("name") for device in root.findall("device")},
        }
    except (OSError, ElementTree.ParseError, AttributeError, TypeError) as error:
        raise Unknown("Syncthing configuration %s not read: %s" % (path, error))


def rest(config):
    def get(command, **params):
        """Answer of the Syncthing REST command, None when it knows no such object."""
        try:
            # The address is local: its certificate is self-signed
            answer = requests.get(config["url"] + command, params=params, timeout=TIMEOUT,
                                  headers={"X-API-Key": config["key"]}, verify=False)
            if answer.status_code == 404:
                return None
            answer.raise_for_status()
            return answer.json()
        except (requests.RequestException, ValueError) as error:
            raise Unknown("Syncthing %s: %s" % (command, error))

    return get


def short(name):
    return (name or "").split(".")[0].lower()


def needs(get, folder, device, prefix):
    """The device still needs a file of the package."""
    page = 1
    while True:
        answer = get("db/remoteneed", folder=folder, device=device, page=page, perpage=PAGE)
        if answer is None:
            raise Unknown("Syncthing does not know what %s needs" % device)
        files = answer.get("files") or []
        if any((entry.get("name") or "").startswith(prefix) for entry in files):
            return True
        if len(files) < PAGE:
            return False
        page += 1


def pending(package_dir, relays=None, config=None, get=None):
    """Why a deployment of the package waits, None when the relays have it.

    package_dir: directory of the package on the server, a link to its share included.
    relays: host names of the relays that may serve the machine, as Syncthing names
    its devices. Without one of them among the devices, every connected relay is asked."""
    config = config or read_config()
    get = get or rest(config)
    path = os.path.realpath(package_dir)
    folder = next((folder for folder in config["folders"]
                   if path.startswith(folder["path"] + os.sep)), None)
    if folder is None:
        raise Unknown("no Syncthing folder holds %s" % path)
    descriptor = os.path.join(os.path.relpath(path, folder["path"]), DESCRIPTOR)
    known = get("db/file", folder=folder["id"], file=descriptor)
    if not known or not known.get("local"):
        return "package not read by Syncthing yet"
    state = (get("db/status", folder=folder["id"]) or {}).get("state")
    if state in READING:
        return "Syncthing still reads the share (%s)" % state
    server = (get("system/status") or {}).get("myID")
    wanted = set(short(name) for name in relays or ())
    devices = [device for device in folder["devices"] if short(config["names"].get(device)) in wanted]
    if not devices:
        connections = (get("system/connections") or {}).get("connections", {})
        devices = [device for device in folder["devices"]
                   if connections.get(device, {}).get("connected")]
    prefix = os.path.dirname(descriptor) + "/"
    for device in devices:
        # The server serves its own machines from the share itself
        if device != server and needs(get, folder["id"], device, prefix):
            return "relay %s still receives the package" % (config["names"].get(device) or device)
    return None
