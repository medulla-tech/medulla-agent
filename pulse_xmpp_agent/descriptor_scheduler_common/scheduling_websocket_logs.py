#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import re
import json
import logging
import pathlib
import platform
import datetime
import subprocess
import configparser
from lib.agentconffile import directoryconffile

logger = logging.getLogger()
plugin = {"VERSION": "1.1", "NAME": "scheduling_websocket_logs", "TYPE": "all", "SCHEDULED": True}
SCHEDULE = {"schedule": "*/5 * * * *", "nb": -1}

def schedule_main(objectxmpp):
    date = datetime.datetime.now()
    logger.debug("================= scheduling_websocket_logs =================")
    logger.debug(f"call scheduled {plugin} at {str(date)}")
    logger.debug(f"crontab {SCHEDULE}")
    logger.debug("============================================================")

    log_config = read_config_file()
    if not log_config:
        logger.error("The configuration could not be read.")
    else:
        if is_server_running():
            logger.debug("The WebSocket server is already launched on port 5555")
        else:
            logger.info("The WebSocket server is not launched. Current launch ...")
            start_websocket_server(log_config)

def read_config_file():
    """
    Bed the configuration files 'scheduling_websocket_logs.ini' and 'scheduling_websocket_logs.ini.local'
    and builds a dictionary structured by group.

    Example :
    - "Apache2/Access.log" -> {"Apache2": {"Access": "/var/log/apache2/access.log"}}
    - "apache2/error.log" -> {"apache2": {"error": "/var/log/apache2/error.log"}}
    - "Ejabberd/error.log" -> {"ejabberd": {"error": "/var/log/ejabberd/error.log"}}
    """
    main_config = os.path.join(directoryconffile(), 'scheduling_websocket_logs.ini')
    local_config = os.path.join(directoryconffile(), 'scheduling_websocket_logs.ini.local')

    ensure_config_file_exists(main_config, fill_if_empty=False)
    ensure_config_file_exists(local_config, fill_if_empty=True)

    config = configparser.ConfigParser()
    config.read([main_config, local_config])
    log_paths = {}

    if "websocket_logs" not in config:
        logger.error(f"Section [Websocket_logs] absent in {main_config}")
        return log_paths

    default_base = r"C:\Program Files\Medulla\var\log" if platform.system() == "Windows" else "/var/log/"

    prefixes = {}
    if config.has_section("prefixes"):
        for key, value in config.items("prefixes"):
            prefixes[key.strip()] = value.strip()

    key, logs_str = next(iter(config["websocket_logs"].items()))
    logs = [log.strip() for log in logs_str.split(",")]

    for log in logs:
        if os.path.isabs(log):
            filepath = log
        elif "/" in log:
            group, remainder = log.split("/", 1)
            if group in prefixes:
                filepath = os.path.join(prefixes[group], remainder)
            else:
                filepath = os.path.join(default_base, log)
        else:
            filepath = os.path.join(default_base, log)

        if platform.system() == "Windows":
            filepath = str(pathlib.Path(filepath).resolve(strict=False))

        group = "default" if "/" not in log else log.split("/")[0]
        file_key = os.path.basename(filepath).split('.')[0].lower()

        if group not in log_paths:
            log_paths[group] = {}
        log_paths[group][file_key] = filepath

    return log_paths

def is_server_running():
    """
    Check if port 5555 listens.
    - Windows: use 'Netstat -ano |Findstr: 5555 'to filter the output directly.
    - Linux/MacOS: use 'netstat -tuln' and seek ': 5555'.
    """
    try:
        if platform.system() == "Windows":
            output = subprocess.check_output("netstat -ano | findstr :5555", shell=True, universal_newlines=True)
            return "LISTENING" in output

        else:
            output = subprocess.check_output(["netstat", "-tuln"], universal_newlines=True)
            return ":5555" in output

    except subprocess.CalledProcessError:
        return False
    except Exception as e:
        logger.error(f"Error when checking the 5555 port: {e}")
        return False

def ensure_config_file_exists(filepath, fill_if_empty=False):
    """
    Check the existence of the configuration file and create it with a different template depending on the OS.
    """
    if platform.system() == "Windows":
        template = (
            "[websocket_logs]\n"
            "log_path = networkevents.log, service.log, xmpp-agent-machine.log\n"
        )
    else:
        template = (
            "[websocket_logs]\n"
            "log_path = apache2/access.log, apache2/error.log, ejabberd/ejabberd.log, ejabberd/error.log, "
            "mmc/pulse2-package-server.log, mmc/pulse2-register-pxe.log, pulse/xmpp-agent-relay.log, "
            "pulse/pulse-package-watching.log\n"
        )

    if not os.path.exists(filepath):
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(template)
        logger.info(f"Configuration file created with template: {filepath}")

    else:
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                content = f.read()
            if content.strip() == "":
                with open(filepath, "w", encoding="utf-8") as f:
                    f.write(template)
                logger.info(f"Existing file was empty, updated with template: {filepath}")
            elif fill_if_empty:
                config = configparser.ConfigParser()
                config.read_string(content)
                if not config.has_option("websocket_logs", "log_path") or config.get("websocket_logs", "log_path").strip() == "":
                    with open(filepath, "w", encoding="utf-8") as f:
                        f.write(template)
                    logger.info(f"Configuration file updated with template: {filepath}")
                else:
                    logger.debug(f"Existing file is OK: {filepath}")
            else:
                logger.debug(f"Existing file is OK: {filepath}")
        except Exception as e:
            logger.error(f"Error reading {filepath}: {e}")
            with open(filepath, "w", encoding="utf-8") as f:
                f.write(template)
            logger.info(f"Configuration file created with template after error: {filepath}")

def get_python_command():
    """Return the correct Python command according to the operating system."""
    if platform.system() == "Windows":
        return r"C:\Program Files\Python3\python.exe"
    return "python3"

def start_websocket_server(log_config):
    """
    Launches the WebSocket server by the JSON configuration.
    Adapts the command for Windows and Linux.
    """
    json_config = json.dumps(log_config)
    try:
        if platform.system() == "Windows":
            process = subprocess.Popen(
                [get_python_command(), '-m', 'pulse_xmpp_agent.lib.websocket_server', '--log_path', json_config],
                creationflags=subprocess.CREATE_NEW_PROCESS_GROUP
            )
        else:
            process = subprocess.Popen(
                [get_python_command(), '-m', 'pulse_xmpp_agent.lib.websocket_server', '--log_path', json_config],
                preexec_fn=os.setsid
            )
        logger.info(f"WebSocket server launched (PID: {process.pid})")
    except Exception as e:
        logger.error(f"Error when launching the WebSocket server: {e}")
