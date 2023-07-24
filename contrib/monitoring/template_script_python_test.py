#!/usr/bin/python3
# -*- coding: utf-8; -*-
# SPDX-FileCopyrightText: 2022-2023 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-3.0-or-later

import json
import MySQLdb
import traceback
import logging

LOGFILE = "/var/lib/pulse2/script_monitoring/logfilescriptpython.log"
logger = logging.getLogger()


class Mysqlbase:
    def __init__(
        self,
        dbhost,
        dbuser,
        dbpasswd,
        dbname="xmppmaster",
        dbport=3306,
        connect_timeout=30,
    ):
        self.boolconnectionbase = False
        self.dbconnectionMysql = None
        self.Mysql_dbhost = dbhost
        self.Mysql_dbuser = dbuser
        self.Mysql_dbpasswd = dbpasswd
        self.Mysql_dbname = dbname
        self.Mysql_dbport = dbport
        self.Mysql_connect_timeout = connect_timeout

    def connection_Mysql(self):
        if self.boolconnectionbase:
            return self.dbconnectionMysql
        try:
            self.dbconnectionMysql = MySQLdb.connect(
                host=self.Mysql_dbhost,
                user=self.Mysql_dbuser,
                passwd=self.Mysql_dbpasswd,
                db=self.Mysql_dbname,
                port=self.Mysql_dbport,
                connect_timeout=self.Mysql_connect_timeout,
            )
            self.boolconnectionbase = True
            return self.dbconnectionMysql
        except MySQLdb.Error as e:
            self.boolconnectionbase = False
            self.dbconnectionMysql = None
            print(f"We failed to connect to the database and got the error {str(e)}")
            print("\n%s" % (traceback.format_exc()))
            return self.dbconnectionMysql
        except Exception as e:
            self.boolconnectionbase = False
            self.dbconnectionMysql = None
            print("\n%s" % (traceback.format_exc()))
            return self.dbconnectionMysql

    def disconnect_mysql(self):
        if self.boolconnectionbase:
            self.dbconnectionMysql.close()

    def is_connection_Mysql(self):
        return self.boolconnectionbase

    def fetching(self, query):
        results = None
        resultproxy = None
        try:
            if not self.boolconnectionbase:
                self.connection_Mysql()

            if self.boolconnectionbase:
                try:
                    cursor = self.dbconnectionMysql.cursor()
                    print(query)
                    cursor.execute(query)
                    results = cursor.fetchall()
                    columnNames = [column[0] for column in cursor.description]
                    return [dict(zip(columnNames, record)) for record in results]
                except MySQLdb.Error as e:
                    print(f"Error: unable to fecth data {str(e)}")
                    print("\n%s" % (traceback.format_exc()))
                    return results
                finally:
                    cursor.close()
        except Exception as e:
            print(f"Error: unable to connection {str(e)}")
            print("\n%s" % (traceback.format_exc()))
            return results
        return results

    def commit(self, query):
        results = None
        resultproxy = None
        try:
            if not self.boolconnectionbase:
                self.connection_Mysql()

            if self.boolconnectionbase:
                try:
                    cursor = self.dbconnectionMysql.cursor()
                    print(query)
                    results = cursor.execute(query)
                    self.dbconnectionMysql.commit()
                    columnNames = [column[0] for column in cursor.description]
                    return [dict(zip(columnNames, record)) for record in results]
                except MySQLdb.Error as e:
                    self.dbconnectionMysql.rollback()
                    print(f"Error: unable to commit data {str(e)}")
                    print("\n%s" % (traceback.format_exc()))
                    return results
                finally:
                    cursor.close()
        except Exception as e:
            print(f"Error: unable to connect: {str(e)}")
            print("\n%s" % (traceback.format_exc()))
            return results
        return results


def loads_alert():
    # metadata to be added in the python script
    msgfrom = """@@@@@msgfrom@@@@@"""
    binding = """@@@@@binding@@@@@"""
    serialisationpickleevent = (
        """@@@@@event@@@@@"""  # replace """\@\@\@\@\@event@@@@@"""
    )

    eventstruct = json.loads(serialisationpickleevent)
    if "general_status" in eventstruct["mon_devices_doc"]:
        eventstruct["general_status"] = eventstruct["mon_devices_doc"]["general_status"]
    return eventstruct, msgfrom, binding


def main():
    # Personal Code below
    # The print are displayed in the final result file. They are needed for a better comprehension.
    # In the following example code, it shows how to use the base directly

    print("Python Script execution")
    print("We print the comment field of the mon_rules table")
    print(eventstruct["mon_rules_comment"])

    # Exemple use case: We can use every database defined in the plugins_list
    xmppmaster = Mysqlbase(
        eventstruct["conf_submon"]["xmpp_dbhost"],
        eventstruct["conf_submon"]["xmpp_dbuser"],
        eventstruct["conf_submon"]["xmpp_dbpasswd"],
        eventstruct["conf_submon"]["xmpp_dbname"],
        eventstruct["conf_submon"]["xmpp_dbport"],
        eventstruct["conf_submon"]["xmpp_dbpooltimeout"],
    )
    sql = """
            SELECT
            machines.id ,
            machines.jid as jid,
            machines.uuid_serial_machine as uuid_serial_machine,
            machines.platform as platform,
            machines.archi as archi,
            machines.hostname as hostname_machine,
            machines.uuid_inventorymachine,
            machines.ippublic as ippublic,
            machines.ip_xmpp as ip_xmpp,
            machines.macaddress as macaddress,
            machines.subnetxmpp as subnetxmpp,
            machines.agenttype as agenttype,
            machines.groupdeploy as groupdeploy,
            machines.urlguacamole as urlguacamole,
            machines.ad_ou_machine as ad_ou_machine,
            machines.ad_ou_user as ad_ou_user,
            machines.lastuser as lastuser,
            machines.glpi_description as glpi_description,
            machines.glpi_owner_firstname as glpi_owner_firstname,
            machines.glpi_owner_realname as glpi_owner_realname,
            machines.glpi_owner as glpi_owner,
            machines.model as model,
            machines.manufacturer as manufacturer,
            mon_event.id as mon_event_id,
            mon_event.status_event as mon_event_status_event,
            mon_event.type_event as mon_event_type_event,
            mon_event.cmd as mon_event_cmd,
            mon_event.id_rule as mon_event_id_rule ,
            mon_event.machines_id as mon_event_machines_id,
            mon_event.id_device as mon_event_id_device,
            mon_event.parameter_other as mon_event_parameter_other,
            mon_event.ack_user as mon_event_ack_user,
            mon_event.ack_date as mon_event_ack_date,
            mon_rules.id as mon_rules_id ,
            mon_rules.hostname as mon_rules_hostname,
            mon_rules.device_type as mon_rules_device_type,
            mon_rules.binding as mon_rules_binding,
            mon_rules.succes_binding_cmd as mon_rules_succes_binding_cmd,
            mon_rules.no_success_binding_cmd as mon_rules_no_success_binding_cmd,
            mon_rules.error_on_binding as mon_rules_error_on_binding,
            mon_rules.type_event as mon_rules_type_event,
            mon_rules.user as mon_rules_user,
            mon_rules.comment as mon_rules_comment,
            mon_machine.id as mon_machine_id,
            mon_machine.machines_id as mon_machine_machines_id,
            mon_machine.date as mon_machine_date,
            mon_machine.hostname as mon_machine_hostname,
            mon_machine.statusmsg as mon_machine_statusmsg,
            mon_devices.id as mon_devices_id,
            mon_devices.mon_machine_id as mon_devices_mon_machine_id ,
            mon_devices.device_type as mon_devices_device_type,
            mon_devices.serial as mon_devices_serial,
            mon_devices.firmware as mon_devices_firmware,
            mon_devices.status asmon_devices_status,
            mon_devices.alarm_msg as mon_devices_alarm_msg,
            mon_devices.doc as mon_devices_doc,
            machines.hostname as machine_hostname
            FROM
                xmppmaster.mon_event
                    JOIN
                xmppmaster.mon_rules ON xmppmaster.mon_rules.id = xmppmaster.mon_event.id_rule
                    JOIN
                xmppmaster.mon_machine ON xmppmaster.mon_machine.id = xmppmaster.mon_event.machines_id
                    JOIN
                xmppmaster.mon_devices ON xmppmaster.mon_devices.id = xmppmaster.mon_event.id_device
                JOIN
                xmppmaster.machines ON xmppmaster.machines.id = xmppmaster.mon_machine.machines_id
            WHERE
                xmppmaster.mon_event.id = %s;""" % (
        eventstruct["mon_event_id"]
    )
    resultatperso = xmppmaster.fetching(sql)
    print(resultatperso[0])


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.DEBUG,
        format="%(asctime)s %(message)s",
        filename=LOGFILE,
        filemode="a",
    )
    logger.debug("Programm Starting")
    eventstruct, msgfrom, binding = loads_alert()
    main()
