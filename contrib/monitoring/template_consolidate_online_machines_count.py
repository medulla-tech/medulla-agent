#!/usr/bin/python
# -*- coding: utf-8; -*-
#
# (c) 2022 Siveo, http://www.siveo.net/
#
# $Id$
#
# This file is part of Pulse 2, http://pulse2.mandriva.org
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
# MA 02110-1301, USA

import json
import MySQLdb
import traceback
import logging

LOGFILE ="/var/lib/pulse2/script_monitoring/logfilescriptpython.log"
logger = logging.getLogger()

class Mysqlbase():
    def __init__(
            self,
            dbhost,
            dbuser,
            dbpasswd,
            dbname="xmppmaster",
            dbport=3306,
            connect_timeout=30):
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
        else:
            try:
                self.dbconnectionMysql = \
                    MySQLdb.connect(host=self.Mysql_dbhost,
                                    user=self.Mysql_dbuser,
                                    passwd=self.Mysql_dbpasswd,
                                    db=self.Mysql_dbname,
                                    port=self.Mysql_dbport,
                                    connect_timeout=self.Mysql_connect_timeout)
                self.boolconnectionbase = True
                return self.dbconnectionMysql
            except MySQLdb.Error as e:
                self.boolconnectionbase = False
                self.dbconnectionMysql = None
                print(
                    "We failed to connect to the database and got the error %s" %
                    str(e))
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
                    resultproxy = []
                    columnNames = [column[0] for column in cursor.description]
                    for record in results:
                        resultproxy.append(dict(zip(columnNames, record)))
                    return resultproxy
                except MySQLdb.Error as e:
                    print("Error: unable to fecth data %s" % str(e))
                    print("\n%s" % (traceback.format_exc()))
                    return results
                finally:
                    cursor.close()
        except Exception as e:
            print("Error: unable to connection %s" % str(e))
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
                    return cursor.lastrowid
                except MySQLdb.Error as e:
                    self.dbconnectionMysql.rollback()
                    print("Error: unable to commit data %s" % str(e))
                    print("\n%s" % (traceback.format_exc()))
                    return results
                finally:
                    cursor.close()
        except Exception as e:
            print("Error: unable to connect: %s" % str(e))
            print("\n%s" % (traceback.format_exc()))
            return results
        return results


def loads_alert():
    # metadata to be added in the python script
    msgfrom = """@@@@@msgfrom@@@@@"""
    binding = """@@@@@binding@@@@@"""
    serialisationpickleevent = """@@@@@event@@@@@"""  # replace """\@\@\@\@\@event@@@@@"""

    eventstruct = json.loads(serialisationpickleevent)
    if 'general_status' in eventstruct['mon_devices_doc']:
        eventstruct['general_status'] = eventstruct['mon_devices_doc']['general_status']
    return eventstruct, msgfrom, binding


def main():
    # Personal Code below
    # The print are displayed in the final result file. They are needed for a better comprehension.
    # In the following example code, it shows how to use the base directly


    print("Python Script execution")
    print("We print the comment field of the mon_rules table")
    print(eventstruct['mon_rules_comment'])

    # Exemple use case: We can use every database defined in the plugins_list
    xmppmaster = Mysqlbase(eventstruct['conf_submon']['xmpp_dbhost'],
                           eventstruct['conf_submon']['xmpp_dbuser'],
                           eventstruct['conf_submon']['xmpp_dbpasswd'],
                           eventstruct['conf_submon']['xmpp_dbname'],
                           eventstruct['conf_submon']['xmpp_dbport'],
                           eventstruct['conf_submon']['xmpp_dbpooltimeout'])
    sql = """
            SELECT SUM(COALESCE(JSON_EXTRACT( mon_devices.doc, '$.ejabberd.connected_users' ), '')) AS nb_connected_users
            FROM mon_devices
              LEFT JOIN mon_machine ON mon_devices.mon_machine_id = mon_machine.id
            WHERE
              mon_machine.id IN (
                SELECT MAX(mon_machine.id) AS idrefmachine
                FROM mon_devices
                  LEFT JOIN mon_machine ON mon_devices.mon_machine_id = mon_machine.id
                WHERE
                  COALESCE(JSON_EXTRACT(mon_devices.doc, '$.ejabberd.connected_users'), '') != ''
                GROUP BY hostname);"""
    result_ejabberd = xmppmaster.fetching(sql)
    sum_from_monitoring = int(result_ejabberd[0]['nb_connected_users'])
    print('Sum from monitoring: %s' % sum_from_monitoring)
    # Above result contains online machines, relays, substitutes (including master_reconf) and master

    sql = """ SELECT COUNT(*) AS nb_online FROM machines WHERE enabled = 1;"""
    result_online_agents = xmppmaster.fetching(sql)
    sql = """ SELECT COUNT(DISTINCT jidsubtitute) AS nb_substitutes FROM substituteconf;"""
    result_substitutes = xmppmaster.fetching(sql)
    sum_from_db = result_online_agents[0]['nb_online'] + result_substitutes[0]['nb_substitutes'] + 1 + 1 
    print('Sum from db: %s' % sum_from_db)
    # Above result contains substitutes including master and master_reconf as they are present in sum_from_monitoring

    # Define an error margin as 1% of the number of machines
    error_margin = int(sum_from_monitoring * 0.01)
    sum_from_db_low = sum_from_db - error_margin
    sum_from_db_high = sum_from_db + error_margin
    
    # Send a ack message if the sums do not match within the error margin
    if sum_from_monitoring < sum_from_db_low or sum_from_monitoring > sum_from_db_high:
        sql = """ SELECT id, hostname FROM machines WHERE jid = 'rspulse@pulse/mainrelay'; """
        result = xmppmaster.fetching(sql)
        sql = """ INSERT INTO mon_machine (machines_id, hostname) VALUES (%s, '%s');""" % (result[0]['id'], result[0]['hostname'])
        machines_id = xmppmaster.commit(sql)
        sql = """ INSERT INTO mon_devices (mon_machine_id, device_type, status, alarm_msg) VALUES (%s, 'system', 'warning', 'Number of machines connected on ejabberd does not match machines online in databse');""" % (machines_id)
        device_id = xmppmaster.commit(sql)
        sql = """ INSERT INTO mon_event (status_event, type_event, id_rule, machines_id, id_device) VALUES (1, 'log', 1, %s, %s);""" % (machines_id, device_id)
        xmppmaster.commit(sql)

if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG,
                        format='%(asctime)s %(message)s',
                        filename = LOGFILE,
                        filemode = 'a')
    logger.debug("Programm Starting")
    eventstruct, msgfrom, binding = loads_alert()
    main()
