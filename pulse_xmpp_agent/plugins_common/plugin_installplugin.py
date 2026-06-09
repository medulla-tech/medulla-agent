# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2016-2023 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-3.0-or-later

import os
import logging
import json
import importlib.util
from importlib.machinery import SourceFileLoader
from lib.utils import set_logging_level

plugin = {"VERSION": "1.28", "NAME": "installplugin", "TYPE": "all"}  # fmt: skip


def _validate_plugin_file(pathfile):
    """Validate that a plugin file can be imported and exposes a plugin dict."""
    module_name = f"_installplugin_validation_{os.path.basename(pathfile).replace('.', '_')}"

    # spec_from_file_location may return None for non-.py suffixes (e.g. .tmp).
    spec = importlib.util.spec_from_file_location(module_name, pathfile)
    if spec is None or spec.loader is None:
        loader = SourceFileLoader(module_name, pathfile)
        spec = importlib.util.spec_from_loader(module_name, loader)

    if spec is None or spec.loader is None:
        raise ImportError(f"Unable to build import spec for {pathfile}")

    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    metadata = getattr(module, "plugin", None)
    if not isinstance(metadata, dict):
        raise ValueError("Missing or invalid 'plugin' metadata")

    for key in ("NAME", "VERSION"):
        if key not in metadata:
            raise ValueError(f"Missing plugin metadata key: {key}")

    return metadata


@set_logging_level
def action(objectxmpp, action, sessionid, data, message, dataerreur):
    if action != "installplugin":
        return
    if len(data) != 0:
        logger = logging.getLogger()
        pluginname = data.get("pluginname", "unknown")
        namefile = os.path.join(objectxmpp.config.pathplugins, pluginname)
        tempfile = f"{namefile}.tmp"
        target = getattr(message.get("to"), "user", "unknown")
        expected_version = data.get("version", "unknown")

        logger.info(
            "(AGENT)Installing plugin candidate plugin=%s target=%s final_path=%s tmp_path=%s expected_version=%s",
            pluginname,
            target,
            namefile,
            tempfile,
            expected_version,
        )
        try:
            with open(tempfile, "w", encoding="utf-8") as fileplugin:
                fileplugin.write(str(data.get("datafile", "")))

            metadata = _validate_plugin_file(tempfile)
            os.replace(tempfile, namefile)

            dataerreur["ret"] = 0
            dataerreur["data"][
                "msg"
            ] = f'Installing plugin {pluginname} on {target} (validated {metadata.get("VERSION")})'
            logger.info(
                "(AGENT)Plugin installed plugin=%s target=%s final_path=%s installed_version=%s",
                pluginname,
                target,
                namefile,
                metadata.get("VERSION", "unknown"),
            )
        except Exception as e:
            if os.path.exists(tempfile):
                try:
                    os.remove(tempfile)
                except OSError:
                    pass

            reason = str(e).replace("\n", " ").strip()
            logger.error(
                "(AGENT)Plugin validation failed plugin=%s target=%s final_path=%s tmp_path=%s expected_version=%s reason=%s",
                pluginname,
                target,
                namefile,
                tempfile,
                expected_version,
                reason,
            )
            dataerreur["data"][
                "msg"
            ] = f'Installing plugin {pluginname} on {target} failed: {reason}'
            dataerreur["ret"] = 255
        dataerreur["action"] = "resultmsginfoerror"
        objectxmpp.send_message(
            mto=message["from"], mbody=json.dumps(dataerreur), mtype="chat"
        )
