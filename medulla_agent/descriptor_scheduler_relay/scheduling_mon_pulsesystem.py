# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2016-2023 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-3.0-or-later

"""
This plugin checks the status of a few counters and sends the information to the monitoring agent

******* Warning *************
This plugin is for monitoring

The following operations must be done to allow reporting of cpu and memory usage by systemd for medulla services
crudini --set /etc/systemd/system.conf Manager DefaultMemoryAccounting yes
crudini --set /etc/systemd/system.conf Manager DefaultCPUAccounting yes
crudini --set /etc/systemd/system.conf Manager BlockIOAccounting yes
systemctl daemon-reexec
python3 -m medulla_debug_tools server --action=manage_medulla_services --options=dryrun=no,deps=yes,only_subs='',action=restart
"""

import json
import logging
import traceback
import re
import os
import distro
import configparser

logger = logging.getLogger()
import subprocess
import socket
import psutil
from xml.etree import ElementTree
import requests
from datetime import datetime
from medulla_agent.lib.utils import (
    file_put_contents,
    getRandomName,
    file_get_contents,
)
from medulla_agent.lib.agentconffile import directoryconffile
import mysql.connector

plugin = {"VERSION": "1.42", "NAME": "scheduling_mon_medullasystem", "TYPE": "relayserver", "SCHEDULED": True}  # fmt: skip

SCHEDULE = {"schedule": "*/15 * * * *", "nb": -1}

globalstruct = {}


class DateTimeEncoder(json.JSONEncoder):
    """
    Custom encoder for use by json for dates management
    """

    def default(self, obj):
        return (
            obj.isoformat()
            if isinstance(obj, datetime)
            else json.JSONEncoder.default(self, obj)
        )


def schedule_main(xmppobject):
    logger.info("===========scheduling_mon_medullasystem============")
    logger.info(plugin)
    logger.info("=================================================\n")
    if xmppobject.num_call_scheduling_mon_medullasystem == 0:
        __read_conf_scheduling_mon_medullasystem(xmppobject)

    # infostmpdir to save alert in INFOSTMP
    infostmpdir = os.path.abspath(
        os.path.join(os.path.dirname(os.path.realpath(__file__)), "..", "INFOSTMP")
    )

    try:
        if xmppobject.config.agenttype in ["relayserver"]:
            # code ars
            system_json = {}
            system_json["general_status"] = "info"
            # System services
            if hasattr(xmppobject.config, "services_enable"):
                services_enable = xmppobject.config.services_enable
            else:
                services_enable = False

            if services_enable:
                service_json = {}
                # List all active services
                active_services = []
                cmd = "systemctl -t service --state=active | grep running"
                result_services = subprocess.Popen(
                    cmd, text=True, shell=True, stdout=subprocess.PIPE
                )
                for line in result_services.stdout.readlines():
                    active_services.append(line.split(".")[0])
                for service_name in xmppobject.config.services_list:
                    service_json[service_name] = {}
                    if service_name == "syncthing":
                        service = "syncthing@syncthing"
                    elif service_name == "openldap":
                        service = "slapd"
                    elif service_name == "mysql":
                        service = "mariadb"
                    elif service_name == "apache":
                        if distro.id() in [
                            "CentOS Linux",
                            "centos",
                            "fedora",
                            "Red Hat Enterprise Linux Server",
                            "redhat",
                            "Mageia",
                        ]:
                            service = "httpd"
                        elif distro.id() in ["debian"]:
                            service = "apache2"
                    elif service_name == "tomcat":
                        if distro.id() in ["debian"]:
                            service = "tomcat8"
                        else:
                            service = "tomcat"
                    else:
                        service = service_name
                    filename = os.path.join(
                        infostmpdir, "mon_service_%s_alert.json" % service_name
                    )
                    if service in active_services:
                        service_json[service_name]["status"] = 1
                        result_memory = subprocess.Popen(
                            [
                                "systemctl",
                                "show",
                                "%s" % service,
                                "-p",
                                "MemoryCurrent",
                            ],
                            text=True,
                            stdout=subprocess.PIPE,
                        )
                        service_json[service_name]["memory"] = int(
                            result_memory.stdout.readline().split("=")[1]
                        )
                        result_cpu = subprocess.Popen(
                            ["systemctl", "show", "%s" % service, "-p", "CPUUsageNSec"],
                            text=True,
                            stdout=subprocess.PIPE,
                        )
                        service_json[service_name]["cpu"] = (
                            int(result_cpu.stdout.readline().split("=")[1]) / 1000000000
                        )
                        if service_name in xmppobject.config.openfiles_check:
                            result_openfiles = subprocess.Popen(
                                ["lsof", "-u", "%s" % service],
                                text=True,
                                stdout=subprocess.PIPE,
                            )
                            service_json[service_name]["nbopenfiles"] = len(
                                result_openfiles.stdout.readlines()
                            )
                        # Remove previous status file if present as error is gone
                        if os.path.isfile(filename):
                            os.remove(filename)
                    else:
                        service_json[service_name]["status"] = 0
                        service_json[service_name]["memory"] = 0
                        service_json[service_name]["cpu"] = 0
                        if service_name in xmppobject.config.openfiles_check:
                            service_json[service_name]["nbopenfiles"] = 0
                        metriques_json = {}
                        metriques_json["general_status"] = "error"
                        metriques_json["services"] = {}
                        metriques_json["services"][service_name] = {}
                        metriques_json["services"][service_name]["status"] = 0
                        check_and_send_alert(
                            xmppobject,
                            filename,
                            True,
                            metriques_json,
                            service_name,
                            service,
                            "Service %s is down" % service,
                        )
                system_json["services"] = service_json

            # System ports
            if xmppobject.config.ports_enable:
                ports_json = {}
                # list all listening ports
                listening_ports = []
                for c in psutil.net_connections(kind="inet"):
                    if c.status == "LISTEN":
                        host, port = c.laddr
                        listening_ports.append(port)
                # check if port is in list of listening ports
                for port_name in xmppobject.config.ports_list:
                    if port_name == "syncthing":
                        service = "syncthing@syncthing"
                    elif port_name == "openldap":
                        service = "slapd"
                    elif port_name == "mysql":
                        service = "mariadb"
                    elif port_name == "apache":
                        if distro.id() in [
                            "CentOS Linux",
                            "centos",
                            "fedora",
                            "Red Hat Enterprise Linux Server",
                            "redhat",
                            "Mageia",
                        ]:
                            service = "httpd"
                        elif distro.id() in ["debian"]:
                            service = "apache2"
                    elif port_name == "tomcat":
                        if distro.id() in ["debian"]:
                            service = "tomcat8"
                        else:
                            service = "tomcat"
                    else:
                        service = port_name

                    port_number = eval("xmppobject.config.port_%s" % port_name)
                    filename = os.path.join(
                        infostmpdir, "mon_ports_%s_alert.json" % port_name
                    )
                    if port_number in listening_ports:
                        ports_json[port_name] = 1
                        # Remove previous status file if present as error is gone
                        if os.path.isfile(filename):
                            os.remove(filename)
                    else:
                        ports_json[port_name] = 0
                        metriques_json = {}
                        metriques_json["general_status"] = "error"
                        metriques_json["ports"] = {}
                        metriques_json["ports"][port_name] = 0
                        check_and_send_alert(
                            xmppobject,
                            filename,
                            True,
                            metriques_json,
                            port_name,
                            service,
                            "Port %s is down" % port_name,
                        )
                system_json["ports"] = ports_json

            # System resources
            if xmppobject.config.resources_enable:
                resources_json = {}
                resources_json["cpu"] = psutil.cpu_percent()
                resources_json["memory"] = dict(
                    psutil.virtual_memory()._asdict()
                )  # eg {'available': 228483072, 'used': 1699835904, 'cached': 251248640, 'percent': 89.1, 'free': 120410112, 'inactive': 780595200, 'active': 1043791872, 'shared': 16216064, 'total': 2101821440, 'buffers': 30326784}
                resources_json["swap"] = dict(
                    psutil.swap_memory()._asdict()
                )  # eg. {'used': 325361664, 'sout': 1002373120, 'total': 2145382400, 'percent': 15.2, 'sin': 125362176, 'free': 1820020736}
                for filesystem in xmppobject.config.resources_filesystems_list:
                    if filesystem == "root":
                        resources_json["df_"] = dict(
                            psutil.disk_usage("/")._asdict()
                        )  # eg {'used': 12178808832, 'total': 103037329408, 'percent': 12.5, 'free': 85580464128}
                    elif filesystem == "var":
                        resources_json["df_var"] = dict(
                            psutil.disk_usage("/var")._asdict()
                        )
                    elif filesystem == "tmp":
                        resources_json["df_tmp"] = dict(
                            psutil.disk_usage("/tmp")._asdict()
                        )
                # Check if need to send alert
                filename = os.path.join(infostmpdir, "mon_resources_alert.json")
                send_alert = False
                if (
                    resources_json["cpu"] >= xmppobject.config.alerts_cpu_limit
                    or resources_json["memory"]["percent"]
                    >= xmppobject.config.alerts_memory_limit
                    or resources_json["swap"]["percent"]
                    >= xmppobject.config.alerts_swap_limit
                ):
                    send_alert = True
                for filesystem in xmppobject.config.resources_filesystems_list:
                    if filesystem == "root":
                        if (
                            resources_json["df_"]["percent"]
                            >= xmppobject.config.alerts_filesystems_limit
                        ):
                            send_alert = True
                    elif filesystem == "var":
                        if (
                            resources_json["df_var"]["percent"]
                            >= xmppobject.config.alerts_filesystems_limit
                        ):
                            send_alert = True
                    elif filesystem == "tmp":
                        if (
                            resources_json["df_tmp"]["percent"]
                            >= xmppobject.config.alerts_filesystems_limit
                        ):
                            send_alert = True
                if send_alert:
                    metriques_json = {}
                    metriques_json["general_status"] = "error"
                    metriques_json["resources"] = resources_json
                    check_and_send_alert(
                        xmppobject,
                        filename,
                        False,
                        metriques_json,
                        "resources",
                        "",
                        "Resources usage is above the limit",
                    )
                else:
                    # Remove previous status file if present as error is gone
                    if os.path.isfile(filename):
                        os.remove(filename)
                system_json["resources"] = resources_json

            # System ejabberd
            if xmppobject.config.ejabberd_enable:
                ejabberd_json = {}
                send_alert = False
                try:
                    result_connected = subprocess.Popen(
                        ["ejabberdctl", "stats", "onlineusers"],
                        text=True,
                        stdout=subprocess.PIPE,
                    )
                    ejabberd_json["connected_users"] = int(
                        result_connected.stdout.readline()
                    )
                    result_registered = subprocess.Popen(
                        ["ejabberdctl", "stats", "registeredusers"],
                        text=True,
                        stdout=subprocess.PIPE,
                    )
                    ejabberd_json["registered_users"] = int(
                        result_registered.stdout.readline()
                    )
                    for jid in xmppobject.config.offline_count_list:
                        if jid == "rs":
                            result = subprocess.Popen(
                                [
                                    "ejabberdctl",
                                    "get_offline_count",
                                    "rs%s" % xmppobject.config.xmpp_domain,
                                    "%s" % xmppobject.config.xmpp_domain,
                                ],
                                text=True,
                                stdout=subprocess.PIPE,
                            )
                        else:
                            result = subprocess.Popen(
                                [
                                    "ejabberdctl",
                                    "get_offline_count",
                                    "%s" % jid,
                                    "%s" % xmppobject.config.xmpp_domain,
                                ],
                                stdout=subprocess.PIPE,
                            )
                        ejabberd_json["offline_count_%s" % jid] = int(
                            result.stdout.readline()
                        )
                        if (
                            ejabberd_json["offline_count_%s" % jid]
                            >= xmppobject.config.alerts_offline_count_limit
                        ):
                            send_alert = True
                    for jid in xmppobject.config.roster_size_list:
                        result = subprocess.Popen(
                            [
                                "ejabberdctl",
                                "get_roster",
                                "%s" % jid,
                                "%s" % xmppobject.config.xmpp_domain,
                            ],
                            text=True,
                            stdout=subprocess.PIPE,
                        )
                        ejabberd_json["roster_size_%s" % jid] = len(
                            result.stdout.readlines()
                        )
                        if (
                            ejabberd_json["roster_size_%s" % jid]
                            >= xmppobject.config.alerts_roster_size_limit
                        ):
                            send_alert = True
                except Exception as e:
                    # Probably a ejabberdctl error. In any case return an empty json
                    pass
                # Check if need to send alert
                filename = os.path.join(infostmpdir, "mon_ejabberd_alert.json")
                if send_alert:
                    metriques_json = {}
                    metriques_json["general_status"] = "error"
                    metriques_json["ejabberd"] = ejabberd_json
                    check_and_send_alert(
                        xmppobject,
                        filename,
                        False,
                        metriques_json,
                        "ejabberd",
                        "",
                        "Ejabberd offline count or roster size is above the limit",
                    )
                else:
                    # Remove previous status file if present as error is gone
                    if os.path.isfile(filename):
                        os.remove(filename)
                system_json["ejabberd"] = ejabberd_json

            # System syncthing
            if xmppobject.config.syncthing_enable:
                syncthing_json = {}
                try:
                    with open(
                        "/var/lib/syncthing/.config/syncthing/config.xml"
                    ) as xml_file:
                        config_xml = xml_file.read()
                    root = ElementTree.fromstring(config_xml)
                    api_key = root.find("./gui/apikey").text
                    api_headers = {"X-API-Key": api_key}
                    for share_name in xmppobject.config.shares_list:
                        if share_name == "local":
                            result = subprocess.Popen(
                                xmppobject.config.local_share_cmd,
                                shell=True,
                                stdout=subprocess.PIPE,
                            )
                            text = (True,)
                            share = result.stdout.readline()
                        else:
                            share = share_name
                        url = (
                            "http://localhost:8384/rest/db/status?folder=medullamaster_%s"
                            % share
                        )
                        response = requests.get(url, headers=api_headers)
                        if response.status_code == requests.codes.ok:
                            syncthing_json[share] = (
                                response.json()
                            )  # eg. {u'needSymlinks': 0, u'globalSymlinks': 0, u'needBytes': 0, u'stateChanged': u'2021-10-06T21:57:47.773217561+02:00', u'sequence': 15, u'globalDeleted': 5, u'needTotalItems': 0, u'globalTotalItems': 10, u'localDeleted': 5, u'errors': 0, u'globalBytes': 314924, u'invalid': u'', u'needDirectories': 0, u'version': 15, u'localFiles': 4, u'localTotalItems': 10, u'state': u'idle', u'needFiles': 0, u'inSyncBytes': 314924, u'localBytes': 314924, u'globalFiles': 4, u'globalDirectories': 1, u'ignorePatterns': False, u'pullErrors': 0, u'localSymlinks': 0, u'inSyncFiles': 4, u'needDeletes': 0, u'localDirectories': 1}
                            if syncthing_json[share]["state"] == "error":
                                # We'll raise an alert if the share is in error state
                                filename = os.path.join(
                                    infostmpdir, "mon_syncthing_alert.json"
                                )
                                metriques_json = {}
                                metriques_json["general_status"] = "error"
                                metriques_json["syncthing"] = syncthing_json
                                check_and_send_alert(
                                    xmppobject,
                                    filename,
                                    False,
                                    metriques_json,
                                    "syncthing",
                                    "",
                                    "Syncthing share %s is in error state" % share,
                                )
                            else:
                                # Remove previous status file if present as error is gone
                                if os.path.isfile(filename):
                                    os.remove(filename)
                except Exception as e:
                    # Probably a connection error. In any case return an empty json
                    pass
                system_json["syncthing"] = syncthing_json

            # System mysql
            if xmppobject.config.mysql_enable:
                mysql_json = {}
                send_alert = False
                try:
                    cnx = mysql.connector.connect(
                        host=xmppobject.config.medulla_main_db_host,
                        port=xmppobject.config.medulla_main_db_port,
                        user=xmppobject.config.medulla_main_db_user,
                        password=xmppobject.config.medulla_main_db_password,
                        database="xmppmaster",
                    )
                    cursor = cnx.cursor(buffered=True)
                    query = "show status where `variable_name` = 'Uptime';"
                    cursor.execute(query)
                    value = cursor.fetchone()
                    mysql_json["uptime"] = int(value[1])
                    query = "show status where `variable_name` = 'Threads_connected';"
                    cursor.execute(query)
                    value = cursor.fetchone()
                    mysql_json["threads_connected"] = int(value[1])
                    query = (
                        "show status where `variable_name` = 'Max_used_connections';"
                    )
                    cursor.execute(query)
                    value_max_used_connections = cursor.fetchone()
                    query = "show variables where `variable_name` = 'max_connections';"
                    cursor.execute(query)
                    value_max_connections = cursor.fetchone()
                    mysql_json["connections_rate"] = (
                        int(value_max_used_connections[1])
                        / int(value_max_connections[1])
                        * 100
                    )
                    if (
                        mysql_json["connections_rate"]
                        >= xmppobject.config.alerts_mysql_connections_rate_limit
                    ):
                        send_alert = True
                    query = "show status where `variable_name` = 'Aborted_connects';"
                    cursor.execute(query)
                    value_aborted_connects = cursor.fetchone()
                    query = "show status where `variable_name` = 'Connections';"
                    cursor.execute(query)
                    value_connections = cursor.fetchone()
                    mysql_json["aborted_connects_rate"] = (
                        int(value_aborted_connects[1]) / int(value_connections[1]) * 100
                    )
                    if (
                        mysql_json["aborted_connects_rate"]
                        >= xmppobject.config.alerts_mysql_aborted_connects_rate_limit
                    ):
                        send_alert = True
                    query = "show status where variable_name='Connection_errors_max_connections';"
                    cursor.execute(query)
                    value = cursor.fetchone()
                    mysql_json["errors_max_connections"] = int(value[1])
                    query = (
                        "show status where variable_name='Connection_errors_internal';"
                    )
                    cursor.execute(query)
                    value = cursor.fetchone()
                    mysql_json["errors_internal"] = int(value[1])
                    query = (
                        "show status where variable_name='Connection_errors_select';"
                    )
                    cursor.execute(query)
                    value = cursor.fetchone()
                    mysql_json["errors_select"] = int(value[1])
                    query = (
                        "show status where variable_name='Connection_errors_accept';"
                    )
                    cursor.execute(query)
                    value = cursor.fetchone()
                    mysql_json["errors_accept"] = int(value[1])
                    query = "show status where variable_name='subquery_cache_hit';"
                    cursor.execute(query)
                    value_hit = cursor.fetchone()
                    query = "show status where variable_name='subquery_cache_miss';"
                    cursor.execute(query)
                    value_miss = cursor.fetchone()
                    subquery_cache_hit_rate = int(value_hit[1]) / (
                        int(value_hit[1]) + int(value_miss[1])
                    )
                    mysql_json["subquery_cache_hit_rate"] = float(
                        subquery_cache_hit_rate
                    )
                    if (
                        mysql_json["subquery_cache_hit_rate"]
                        < xmppobject.config.alerts_mysql_subquery_cache_hit_rate_limit
                    ):
                        send_alert = True
                    query = "show variables where `variable_name` = 'table_open_cache';"
                    cursor.execute(query)
                    value_table_open_cache = cursor.fetchone()
                    query = "show status where `variable_name` = 'Open_tables';"
                    cursor.execute(query)
                    value_Open_tables = cursor.fetchone()
                    mysql_json["table_cache_usage"] = (
                        int(value_table_open_cache[1]) * 100
                    ) / int(value_Open_tables[1])
                    if (
                        mysql_json["table_cache_usage"]
                        >= xmppobject.config.alerts_mysql_table_cache_usage_limit
                    ):
                        send_alert = True
                    cursor.close()
                    cnx.close()
                except Exception as e:
                    # Probably a connection error. In any case return an empty json
                    pass
                # Check if need to send alert
                filename = os.path.join(infostmpdir, "mon_mysql_alert.json")
                if send_alert:
                    metriques_json = {}
                    metriques_json["general_status"] = "error"
                    metriques_json["ejabberd"] = mysql_json
                    check_and_send_alert(
                        xmppobject,
                        filename,
                        False,
                        metriques_json,
                        "mysql",
                        "",
                        "MySQL usage is not within the limits",
                    )
                else:
                    # Remove previous status file if present as error is gone
                    if os.path.isfile(filename):
                        os.remove(filename)
                system_json["mysql"] = mysql_json

            # System medulla_relay
            if xmppobject.config.medulla_relay_enable:
                medulla_relay_json = {}
                medulla_relay_json["deployments"] = {}
                relayconf = configparser.ConfigParser()
                relayconf.read("/etc/medulla-agent/relayconf.ini")
                if os.path.exists("/etc/medulla-agent/relayconf.ini.local"):
                    relayconf.read("/etc/medulla-agent/relayconf.ini.local")
                if relayconf.has_option("global", "concurrentdeployments"):
                    slots_configured = relayconf.getint(
                        "global", "concurrentdeployments"
                    )
                else:
                    slots_configured = 10
                medulla_relay_json["deployments"]["slots_configured"] = slots_configured
                fifodeploy_path = os.path.join(
                    os.path.dirname(os.path.realpath(__file__)), "..", "fifodeploy"
                )
                deployments_queued = len(
                    [
                        name
                        for name in os.listdir(fifodeploy_path)
                        if os.path.isfile(os.path.join(fifodeploy_path, name))
                    ]
                )
                medulla_relay_json["deployments"][
                    "deployments_queued"
                ] = deployments_queued
                system_json["medulla_relay"] = medulla_relay_json

            # System medulla
            if xmppobject.config.medulla_main_enable:
                medulla_main_json = {}
                try:
                    cnx = mysql.connector.connect(
                        host=xmppobject.config.medulla_main_db_host,
                        port=xmppobject.config.medulla_main_db_port,
                        user=xmppobject.config.medulla_main_db_user,
                        password=xmppobject.config.medulla_main_db_password,
                        database="xmppmaster",
                    )
                    cursor = cnx.cursor(buffered=True)
                    medulla_main_json["deployments"] = {}
                    query = "SELECT id FROM xmppmaster.deploy WHERE state = 'DEPLOYMENT START'"
                    cursor.execute(query)
                    count = cursor.rowcount
                    medulla_main_json["deployments"]["current"] = count
                    medulla_main_json["agents"] = {}
                    query = "SELECT id FROM xmppmaster.machines WHERE agenttype = 'machine' AND enabled = 1"
                    cursor.execute(query)
                    count = cursor.rowcount
                    medulla_main_json["agents"]["online"] = count
                    query = "SELECT id FROM xmppmaster.machines WHERE agenttype = 'machine' AND enabled = 0"
                    cursor.execute(query)
                    count = cursor.rowcount
                    medulla_main_json["agents"]["offline"] = count
                    query = "SELECT id FROM xmppmaster.machines WHERE agenttype = 'machine' AND need_reconf = 1"
                    cursor.execute(query)
                    count = cursor.rowcount
                    medulla_main_json["agents"]["pending_reconf"] = count
                    query = "SELECT id FROM xmppmaster.update_machine"
                    cursor.execute(query)
                    count = cursor.rowcount
                    medulla_main_json["agents"]["pending_update"] = count
                    medulla_main_json["packages"] = {}
                    query = "SELECT id FROM pkgs.packages"
                    cursor.execute(query)
                    count = cursor.rowcount
                    medulla_main_json["packages"]["total"] = count
                    query = "SELECT id FROM pkgs.packages WHERE pkgs_share_id = 1"
                    cursor.execute(query)
                    count = cursor.rowcount
                    medulla_main_json["packages"]["total_global"] = count
                    cursor.close()
                    cnx.close()
                except Exception as e:
                    # Probably a connection error. In any case return an empty json
                    pass
                system_json["medulla_main"] = medulla_main_json

        else:
            # agent machine
            pass

        # Send message
        informations_json = {}
        informations_json["system"] = {}
        informations_json["system"]["status"] = "ready"
        informations_json["system"]["metriques"] = system_json
        send_monitoring_message(xmppobject, "terminalInformations", informations_json)

    except Exception:
        logger.error("\n%s" % (traceback.format_exc()))


def check_and_send_alert(
    xmppobject, filename, strict_check, metriques_json, subject, param0, message
):
    """
    strict_check is a boolean used to define if we check only the presence of the file or the content as well
    """
    alert_json = {}
    alert_json["system"] = {}
    alert_json["system"]["status"] = "error"
    alert_json["system"]["alarms"] = message
    alert_json["system"]["metriques"] = metriques_json
    alert_json["system"]["subject"] = subject
    alert_json["system"]["param0"] = param0
    if strict_check:
        if not os.path.isfile(filename) or file_get_contents(filename) != json.dumps(
            metriques_json
        ):
            send_monitoring_message(xmppobject, "terminalAlert", alert_json)
            file_put_contents(filename, json.dumps(metriques_json))
    else:
        if not os.path.isfile(filename):
            send_monitoring_message(xmppobject, "terminalAlert", alert_json)
            file_put_contents(filename, json.dumps(metriques_json))


def send_monitoring_message(xmppobject, data_type, json_dict):
    """
    data_type can be terminalInformations or terminalAlert
    """
    # Get monitoring agent
    Config = configparser.ConfigParser()
    Config.read("/etc/medulla-agent/relayconf.ini")
    if os.path.exists("/etc/medulla-agent/relayconf.ini.local"):
        Config.read("/etc/medulla-agent/relayconf.ini.local")
    monitoring_agent = "master_mon@medulla"
    if Config.has_section("substitute"):
        if Config.has_option("substitute", "monitoring"):
            monitoring_agent = Config.get("substitute", "monitoring")

    sessionid = getRandomName(5, "mon_medullasystem")
    message_json = {}
    message_json["action"] = "vectormonitoringagent"
    message_json["sessionid"] = sessionid
    message_json["base64"] = False
    message_json["data"] = {}
    message_json["data"]["subaction"] = data_type
    message_json["data"]["date"] = "%s" % datetime.now()
    message_json["data"]["device_service"] = []
    message_json["data"]["device_service"].append(json_dict)
    message_json["data"]["other_data"] = {}
    message_json["ret"] = 0

    try:
        json_msg = json.dumps(message_json, indent=4, cls=DateTimeEncoder)
        logger.debug(
            "Sending monitoring message to %s: %s" % (monitoring_agent, json_msg)
        )
        xmppobject.send_message(
            mto=str(monitoring_agent.strip('"')), mbody=json_msg, mtype="chat"
        )
    except Exception:
        logger.error("The backtrace of this error is \n %s" % traceback.format_exc())


def __read_conf_scheduling_mon_medullasystem(xmppobject):
    """
    Read the plugin configuration
    """
    configfilename = os.path.join(directoryconffile(), "%s.ini" % plugin["NAME"])

    logger.debug("Reading configuration in File %s" % configfilename)

    # default parameters
    xmppobject.config.services_enable = True
    xmppobject.config.ports_enable = True
    xmppobject.config.resources_enable = True
    xmppobject.config.ejabberd_enable = True
    xmppobject.config.syncthing_enable = True
    xmppobject.config.mysql_enable = True
    xmppobject.config.medulla_relay_enable = True
    xmppobject.config.medulla_main_enable = True
    xmppobject.config.services_list = [
        "ejabberd",
        "syncthing",
        "apache",
        "tomcat",
        "ssh",
        "openldap",
        "mysql",
        "mmc-agent",
        "medulla-agent-relay",
        "medulla-package-watching",
        "medulla-inventory-server",
        "medulla-package-server",
        "medulla-master-substitute-inventory",
        "medulla-master-substitute-registration",
        "medulla-master-substitute-logger",
        "medulla-master-substitute-monitoring",
        "medulla-master-substitute-assessor",
        "medulla-master-substitute-reconfigurator",
        "medulla-master-substitute-deployment",
        "medulla-master-substitute-subscription",
    ]
    xmppobject.config.openfiles_check = ["ejabberd", "mysql"]
    xmppobject.config.ports_list = [
        "ejabberd_c2s",
        "ejabberd_s2s",
        "syncthing",
        "syncthing_web",
        "syncthing_discosrv",
        "apache",
        "apache_ssl",
        "tomcat",
        "ssh",
        "mysql",
        "mmc_agent",
        "medulla_inventory_server",
        "medulla_package_server",
    ]
    xmppobject.config.port_ejabberd_c2s = 5222
    xmppobject.config.port_ejabberd_s2s = 5269
    xmppobject.config.port_syncthing = 22000
    xmppobject.config.port_syncthing_web = 8384
    xmppobject.config.port_syncthing_discosrv = 8443
    xmppobject.config.port_apache = 80
    xmppobject.config.port_apache_ssl = 443
    xmppobject.config.port_tomcat = 8081
    xmppobject.config.port_ssh = 22
    xmppobject.config.port_mysql = 3306
    xmppobject.config.port_mmc_agent = 7080
    xmppobject.config.port_medulla_inventory_server = 9999
    xmppobject.config.port_medulla_package_server = 9990
    xmppobject.config.resources_filesystems_list = ["root", "var", "tmp"]
    xmppobject.config.xmpp_domain = "medulla"
    xmppobject.config.offline_count_list = [
        "rs",
        "master",
        "master_reg",
        "master_subs",
        "master_inv",
        "master_asse",
        "master_depl",
        "master_mon",
    ]
    xmppobject.config.roster_size_list = ["master", "master_subs"]
    xmppobject.config.shares_list = [
        "global",
        "local",
        "baseremoteagent",
        "downloads",
        "bootmenus",
    ]
    xmppobject.config.local_share_cmd = "hostname -s | cut -c1-6"
    xmppobject.config.medulla_main_db_host = "localhost"
    xmppobject.config.medulla_main_db_port = 3306
    xmppobject.config.medulla_main_db_user = "mmc"
    xmppobject.config.medulla_main_db_password = "secret"
    xmppobject.config.alerts_cpu_limit = 70
    xmppobject.config.alerts_memory_limit = 70
    xmppobject.config.alerts_swap_limit = 70
    xmppobject.config.alerts_filesystems_limit = 70
    xmppobject.config.alerts_ejabberd_offline_count_limit = 10
    xmppobject.config.alerts_ejabberd_roster_size_limit = 1500
    xmppobject.config.alerts_mysql_connections_rate_limit = 80
    xmppobject.config.alerts_mysql_aborted_connects_rate_limit = 10
    xmppobject.config.alerts_mysql_subquery_cache_hit_rate_limit = 0.2
    xmppobject.config.alerts_mysql_table_cache_usage_limit = 90

    if not os.path.isfile(configfilename):
        logger.warning(
            "plugin %s\nConfiguration file  missing\n"
            "%s" % (plugin["NAME"], configfilename)
        )
        logger.warning("the missing configuration file is created automatically.")
        xmpp_domain = socket.gethostname()
        # The following configuration is for relays and not main medulla
        file_put_contents(
            configfilename,
            "[services]\n"
            "enable = 1\n"
            "services_list = ejabberd, syncthing, apache, tomcat, ssh, mysql, medulla-agent-relay, medulla-package-watching, medulla-package-server\n"
            "openfiles_check = ejabberd, mysql\n"
            "\n"
            "[ports]\n"
            "enable = 1\n"
            "ports_list = ejabberd_c2s, ejabberd_s2s, syncthing, syncthing_web, apache, tomcat, ssh, mysql\n"
            "ejabberd_c2s = 5222\n"
            "ejabberd_s2s = 5269\n"
            "syncthing = 22000\n"
            "syncthing_web = 8384\n"
            "syncthing_discosrv = 8443\n"
            "apache = 80\n"
            "apache_ssl = 443\n"
            "tomcat = 8081\n"
            "ssh = 22\n"
            "mysql = 3306\n"
            "medulla_package_server = 9990\n"
            "\n"
            "[resources]\n"
            "enable = 1\n"
            "filesystems = root, var, tmp\n"
            "\n"
            "[ejabberd]\n"
            "enable = 1\n"
            "xmpp_domain = %s\n"
            "offline_count_list = rs\n"
            "roster_size_list = \n"
            "\n"
            "[syncthing]\n"
            "enable = 1\n"
            "shares_list = global, local, baseremoteagent, downloads, bootmenus\n"
            "local_share_cmd = 'hostname -s | cut -c1-6'\n"
            "\n"
            "[mysql]\n"
            "enable = 0\n"
            "\n"
            "[medulla_relay]\n"
            "enable = 1\n"
            "\n"
            "[medulla_main]\n"
            "enable = 0\n"
            "\n"
            "[alerts]\n"
            "cpu_limit = 70\n"
            "memory_limit = 70\n"
            "swap_limit = 70\n"
            "filesystems_limit = 70\n"
            "ejabberd_offline_count_limit = 10\n"
            "ejabberd_roster_size_limit = 1500\n"
            "mysql_connections_rate_limit = 80\n"
            "mysql_aborted_connects_rate_limit = 10\n"
            "mysql_subquery_cache_hit_rate_limit = 0.2\n"
            "mysql_table_cache_usage_limit = 90\n" % xmpp_domain,
        )

    # Load configuration from file
    Config = configparser.ConfigParser()
    Config.read(configfilename)
    if os.path.exists(configfilename + ".local"):
        Config.read(configfilename + ".local")

    if Config.has_section("services"):
        if Config.has_option("services", "enable"):
            xmppobject.config.services_enable = Config.getboolean("services", "enable")
        if Config.has_option("services", "services_list"):
            services_list = Config.get("services", "services_list")
            xmppobject.config.services_list = [
                str(x.strip())
                for x in re.split(r"[;,:@\(\)\[\]\|\s]\s*", services_list)
                if x.strip() != ""
            ]
        if Config.has_option("services", "openfiles_check"):
            openfiles_check = Config.get("services", "openfiles_check")
            xmppobject.config.openfiles_check = [
                str(x.strip())
                for x in re.split(r"[;,:@\(\)\[\]\|\s]\s*", openfiles_check)
                if x.strip() != ""
            ]
    if Config.has_section("ports"):
        if Config.has_option("ports", "enable"):
            xmppobject.config.ports_enable = Config.getboolean("ports", "enable")
        if Config.has_option("ports", "ports_list"):
            ports_list = Config.get("ports", "ports_list")
            xmppobject.config.ports_list = [
                str(x.strip())
                for x in re.split(r"[;,:@\(\)\[\]\|\s]\s*", ports_list)
                if x.strip() != ""
            ]
        if Config.has_option("ports", "ejabberd_c2s"):
            xmppobject.config.port_ejabberd_c2s = Config.getint("ports", "ejabberd_c2s")
        if Config.has_option("ports", "ejabberd_s2s"):
            xmppobject.config.port_ejabberd_s2s = Config.getint("ports", "ejabberd_s2s")
        if Config.has_option("ports", "syncthing"):
            xmppobject.config.port_syncthing = Config.getint("ports", "syncthing")
        if Config.has_option("ports", "syncthing_web"):
            xmppobject.config.port_syncthing_web = Config.getint(
                "ports", "syncthing_web"
            )
        if Config.has_option("ports", "syncthing_discosrv"):
            xmppobject.config.port_syncthing_discosrv = Config.getint(
                "ports", "syncthing_discosrv"
            )
        if Config.has_option("ports", "apache"):
            xmppobject.config.port_apache = Config.getint("ports", "apache")
        if Config.has_option("ports", "apache_ssl"):
            xmppobject.config.port_apache_ssl = Config.getint("ports", "apache_ssl")
        if Config.has_option("ports", "tomcat"):
            xmppobject.config.port_tomcat = Config.getint("ports", "tomcat")
        if Config.has_option("ports", "ssh"):
            xmppobject.config.port_ssh = Config.getint("ports", "ssh")
        if Config.has_option("ports", "mysql"):
            xmppobject.config.port_mysql = Config.getint("ports", "mysql")
        if Config.has_option("ports", "mmc_agent"):
            xmppobject.config.port_mmc_agent = Config.getint("ports", "mmc_agent")
        if Config.has_option("ports", "medulla_inventory_server"):
            xmppobject.config.port_medulla_inventory_server = Config.getint(
                "ports", "medulla_inventory_server"
            )
        if Config.has_option("ports", "medulla_package_server"):
            xmppobject.config.port_medulla_package_server = Config.getint(
                "ports", "medulla_package_server"
            )
    if Config.has_section("resources"):
        if Config.has_option("resources", "enable"):
            xmppobject.config.resources_enable = Config.getboolean(
                "resources", "enable"
            )
        if Config.has_option("resources", "filesystems"):
            filesystems_list = Config.get("resources", "filesystems")
            xmppobject.config.resources_filesystems_list = [
                str(x.strip())
                for x in re.split(r"[;,:@\(\)\[\]\|\s]\s*", filesystems_list)
                if x.strip() != ""
            ]
    if Config.has_section("ejabberd"):
        if Config.has_option("ejabberd", "enable"):
            xmppobject.config.ejabberd_enable = Config.getboolean("ejabberd", "enable")
        if Config.has_option("ejabberd", "xmpp_domain"):
            xmppobject.config.xmpp_domain = Config.get("ejabberd", "xmpp_domain")
        if Config.has_option("ejabberd", "offline_count_list"):
            offline_count_list = Config.get("ejabberd", "offline_count_list")
            xmppobject.config.offline_count_list = [
                str(x.strip())
                for x in re.split(r"[;,:@\(\)\[\]\|\s]\s*", offline_count_list)
                if x.strip() != ""
            ]
        if Config.has_option("ejabberd", "roster_size_list"):
            roster_size_list = Config.get("ejabberd", "roster_size_list")
            xmppobject.config.roster_size_list = [
                str(x.strip())
                for x in re.split(r"[;,:@\(\)\[\]\|\s]\s*", roster_size_list)
                if x.strip() != ""
            ]
    if Config.has_section("syncthing"):
        if Config.has_option("syncthing", "enable"):
            xmppobject.config.syncthing_enable = Config.getboolean(
                "syncthing", "enable"
            )
        if Config.has_option("syncthing", "shares_list"):
            shares_list = Config.get("syncthing", "shares_list")
            xmppobject.config.shares_list = [
                str(x.strip())
                for x in re.split(r"[;,:@\(\)\[\]\|\s]\s*", shares_list)
                if x.strip() != ""
            ]
        if Config.has_option("syncthing", "local_share_cmd"):
            xmppobject.config.local_share_cmd = Config.get(
                "syncthing", "local_share_cmd"
            )
    if Config.has_section("mysql"):
        if Config.has_option("mysql", "enable"):
            xmppobject.config.mysql_enable = Config.getboolean("mysql", "enable")
    if Config.has_section("medulla_relay"):
        if Config.has_option("medulla_relay", "enable"):
            xmppobject.config.medulla_relay_enable = Config.getboolean(
                "medulla_relay", "enable"
            )
    if Config.has_section("medulla_main"):
        if Config.has_option("medulla_main", "enable"):
            xmppobject.config.medulla_main_enable = Config.getboolean(
                "medulla_main", "enable"
            )
        if Config.has_option("medulla_main", "db_host"):
            xmppobject.config.medulla_main_db_host = Config.get(
                "medulla_main", "db_host"
            )
        if Config.has_option("medulla_main", "db_port"):
            xmppobject.config.medulla_main_db_port = Config.getint(
                "medulla_main", "db_port"
            )
        if Config.has_option("medulla_main", "db_user"):
            xmppobject.config.medulla_main_db_user = Config.get(
                "medulla_main", "db_user"
            )
        if Config.has_option("medulla_main", "db_password"):
            xmppobject.config.medulla_main_db_password = Config.get(
                "medulla_main", "db_password"
            )
    if Config.has_section("alerts"):
        if Config.has_option("alerts", "cpu_limit"):
            xmppobject.config.alerts_cpu_limit = Config.getint("alerts", "cpu_limit")
        if Config.has_option("alerts", "memory_limit"):
            xmppobject.config.alerts_memory_limit = Config.getint(
                "alerts", "memory_limit"
            )
        if Config.has_option("alerts", "swap_limit"):
            xmppobject.config.alerts_swap_limit = Config.getint("alerts", "swap_limit")
        if Config.has_option("alerts", "filesystems_limit"):
            xmppobject.config.alerts_filesystems_limit = Config.getint(
                "alerts", "filesystems_limit"
            )
        if Config.has_option("alerts", "ejabberd_offline_count_limit"):
            xmppobject.config.alerts_ejabberd_offline_count_limit = Config.getint(
                "alerts", "ejabberd_offline_count_limit"
            )
        if Config.has_option("alerts", "ejabberd_roster_size_limit"):
            xmppobject.config.alerts_ejabberd_roster_size_limit = Config.getint(
                "alerts", "ejabberd_roster_size_limit"
            )
        if Config.has_option("alerts", "mysql_connections_rate_limit"):
            xmppobject.config.alerts_mysql_connections_rate_limit = Config.getint(
                "alerts", "mysql_connections_rate_limit"
            )
        if Config.has_option("alerts", "mysql_aborted_connects_rate_limit"):
            xmppobject.config.alerts_mysql_aborted_connects_rate_limit = Config.getint(
                "alerts", "mysql_aborted_connects_rate_limit"
            )
        if Config.has_option("alerts", "mysql_subquery_cache_hit_rate_limit"):
            xmppobject.config.alerts_mysql_subquery_cache_hit_rate_limit = (
                Config.getfloat("alerts", "mysql_subquery_cache_hit_rate_limit")
            )
        if Config.has_option("alerts", "mysql_table_cache_usage_limit"):
            xmppobject.config.alerts_mysql_table_cache_usage_limit = Config.getint(
                "alerts", "mysql_table_cache_usage_limit"
            )
