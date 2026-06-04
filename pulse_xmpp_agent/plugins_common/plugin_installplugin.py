# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2016-2023 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-3.0-or-later

import importlib.util
import importlib.machinery
import io
import os
import py_compile
import logging
import json
import traceback
import time
from lib.utils import set_logging_level

plugin = {"VERSION": "1.28", "NAME": "installplugin", "TYPE": "all"}  # fmt: skip


def _normalize_plugin_source(payload):
    """Normalise le contenu reçu pour l'écrire comme source Python UTF-8."""
    if isinstance(payload, bytes):
        return payload.decode("utf-8")
    if isinstance(payload, str):
        return payload
    return str(payload)


def _validate_plugin_file(pathfile):
    """Refuse l'activation d'un plugin si compilation, import ou métadonnées échouent."""
    # The agent rechecks the candidate plugin locally even if the substitute
    # already validated it. This protects against transport corruption or a
    # mismatch between substitute and agent environments.
    py_compile.compile(pathfile, doraise=True)

    module_name = os.path.splitext(os.path.basename(pathfile))[0].replace(".", "_")
    loader = importlib.machinery.SourceFileLoader(module_name, pathfile)
    spec = importlib.util.spec_from_loader(module_name, loader, origin=pathfile)
    if spec is None or spec.loader is None:
        raise ImportError(f"Unable to build import spec for {pathfile}")

    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    metadata = getattr(module, "plugin", None)
    if not isinstance(metadata, dict):
        raise ValueError("Missing plugin metadata dictionary 'plugin'")
    if "NAME" not in metadata or "VERSION" not in metadata:
        raise ValueError("Plugin metadata must define NAME and VERSION")

    return metadata


def _build_install_log_prefix(sessionid, pluginname, target, expected_version):
    exec_id = f"{sessionid}-{int(time.time() * 1000)}"
    return (
        f"[installplugin][session={sessionid}][exec={exec_id}]"
        f"[target={target}][plugin={pluginname}][expected_version={expected_version}]"
    )


@set_logging_level
def action(objectxmpp, action, sessionid, data, message, dataerreur):
    """Installe un plugin uniquement après validation du fichier temporaire."""
    if action != "installplugin":
        return
    if len(data) != 0:
        plugin_name = data.get("pluginname", "")
        target = getattr(message.get("to"), "user", "unknown")
        expected_version = data.get("version")
        log_prefix = _build_install_log_prefix(
            sessionid, plugin_name, target, expected_version
        )

        namefile = os.path.join(objectxmpp.config.pathplugins, plugin_name)
        tempfile = f"{namefile}.tmp"
        logging.getLogger().info(
            "%s START final_path=%s tmp_path=%s",
            log_prefix,
            namefile,
            tempfile,
        )
        try:
            pluginsource = _normalize_plugin_source(data["datafile"])
            # Le plugin candidat est écrit à côté du vrai fichier pour éviter de casser
            # le plugin actif tant que la validation n'est pas terminée.
            with io.open(tempfile, "w", encoding="utf-8") as fileplugin:
                fileplugin.write(pluginsource)
            logging.getLogger().info("%s TEMP_WRITTEN bytes=%s", log_prefix, len(pluginsource))

            metadata = _validate_plugin_file(tempfile)
            logging.getLogger().info(
                "%s VALIDATION_OK detected_name=%s detected_version=%s",
                log_prefix,
                metadata.get("NAME"),
                metadata.get("VERSION"),
            )
            # Le remplacement atomique ne se fait qu'après validation complète.
            os.replace(tempfile, namefile)
            logging.getLogger().info("%s ACTIVATED final_path=%s", log_prefix, namefile)

            dataerreur["ret"] = 0
            dataerreur["data"]["install_action"] = "installplugin"
            dataerreur["data"]["pluginname"] = plugin_name
            dataerreur["data"]["plugin_version"] = metadata["VERSION"]
            dataerreur["data"][
                "msg"
            ] = (
                f'Installing plugin {plugin_name} on {target} '
                f'validated and activated with version {metadata["VERSION"]}'
            )
            logging.getLogger().info("%s END status=success", log_prefix)
        except Exception as e:
            # En échec, on retire seulement le temporaire et on laisse le plugin actif intact.
            if os.path.exists(tempfile):
                os.unlink(tempfile)
            logging.getLogger().error(
                "%s END status=failure final_path=%s tmp_path=%s error=%s\n%s",
                log_prefix,
                namefile,
                tempfile,
                str(e),
                traceback.format_exc(),
            )
            dataerreur["data"]["install_action"] = "installplugin"
            dataerreur["data"]["pluginname"] = plugin_name
            dataerreur["data"]["plugin_version"] = data.get("version")
            dataerreur["data"][
                "msg"
            ] = (
                f'Installing plugin {plugin_name} on {target} '
                f'failed validation: {str(e)}'
            )
            dataerreur["ret"] = 255
        dataerreur["action"] = "resultmsginfoerror"
        objectxmpp.send_message(
            mto=message["from"], mbody=json.dumps(dataerreur), mtype="chat"
        )
