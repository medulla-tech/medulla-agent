# SPDX-FileCopyrightText: 2016-2023 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-3.0-or-later

import MySQLdb
import traceback
import socket
import base64
import json
import logging


class GuacamoleError(Exception):
    pass


plugin = {"VERSION": "2.22", "NAME": "guacamoleconf", "TYPE": "relayserver"}  # fmt: skip
logger = logging.getLogger()


def get_free_tcp_port(objectxmpp):
    """
    Get a free TCP port.

    Parameters:
    - objectxmpp: The XMPP object representing the current agent.

    Returns:
    int: A free TCP port.
    """
    port = -1
    try:
        tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        tcp.bind(("", 0))
        addr, port = tcp.getsockname()
    except Exception as e:
        errorstr = "%s" % traceback.format_exc()
        logger.error("\n%s" % (errorstr))
        errorstr = (
            "Error finding a free port for reverse connection : %s\n"
            "REMOTE traceback on %s\n"
            "%s" % (str(e), objectxmpp.boundjid.bare, errorstr)
        )
    finally:
        tcp.close()
    return port


def insertprotocole(protocole, hostname):
    """
    Generate an SQL query to insert a new protocol entry in the Guacamole database.

    Parameters:
    - protocole (str): The protocol name.
    - hostname (str): The hostname.

    Returns:
    str: SQL query for insertion.
    """
    logger.debug(
        "New connection for machine %s_%s protcol %s"
        % (protocole.upper(), hostname, protocole.lower())
    )
    return """INSERT
                INTO guacamole_connection (connection_name, protocol)
                    VALUES ( '%s_%s', '%s');""" % (
        protocole.upper(),
        hostname,
        protocole.lower(),
    )


def deleteprotocole(protocole, hostname):
    """
    Generate an SQL query to delete an existing protocol entry in the Guacamole database.

    Parameters:
    - protocole (str): The protocol name.
    - hostname (str): The hostname.

    Returns:
    str: SQL query for deletion.
    """
    logger.debug("Deleting old connection for : %s_%s" % (protocole.upper(), hostname))
    return """DELETE FROM `guacamole_connection`
                     WHERE connection_name = '%s_%s';""" % (
        protocole.upper(),
        hostname,
    )


def insertparameter(index, parameter, value):
    """
    Generate an SQL query to insert new parameters in the Guacamole database.

    Parameters:
    - index (int): The connection index.
    - parameter (str): The parameter name.
    - value (str): The parameter value.

    Returns:
    str: SQL query for insertion.
    """
    logger.debug("New parameters in guacamole database: %s = %s" % (parameter, value))
    return """INSERT
                 INTO guacamole_connection_parameter (connection_id,
                                                      parameter_name,
                                                      parameter_value)
                 VALUES (%s, '%s', '%s');""" % (
        index,
        parameter,
        value,
    )


def action(objectxmpp, action, sessionid, data, message, dataerreur):
    """
    Perform Guacamole configuration based on the provided data.

    Parameters:
    - objectxmpp: The XMPP object representing the current agent.
    - action: The action to be performed.
    - sessionid: The session ID associated with the action.
    - data: The data containing information about the Guacamole configuration.
    - message: The XMPP message containing the Guacamole configuration request.
    - dataerreur: Data related to any errors during the Guacamole configuration.

    Returns:
    None
    """
    logger.debug("###################################################")
    logger.debug("call %s from %s" % (plugin, message["from"]))
    logger.debug("###################################################")
    logger.debug(json.dumps(data, indent=4))
    logger.debug("###################################################")
    resultaction = "result%s" % action
    result = {}
    result["action"] = resultaction
    result["ret"] = 0
    result["sessionid"] = sessionid
    result["base64"] = False
    result["data"] = {}
    dataerreur["action"] = resultaction
    dataerreur["data"]["msg"] = "ERROR : %s" % action
    dataerreur["sessionid"] = sessionid
    try:
        try:
            db = MySQLdb.connect(
                host=objectxmpp.config.guacamole_dbhost,
                user=objectxmpp.config.guacamole_dbuser,
                passwd=objectxmpp.config.guacamole_dbpasswd,
                db=objectxmpp.config.guacamole_dbname,
            )
            logger.debug(
                "Connecting with parameters\n"
                "\thost: %s\n"
                "\tuser: %s\n"
                "\tdb: %s\n"
                % (
                    objectxmpp.config.guacamole_dbhost,
                    objectxmpp.config.guacamole_dbuser,
                    objectxmpp.config.guacamole_dbname,
                )
            )
        except Exception as e:
            errorstr = "%s" % traceback.format_exc()
            logger.error("\n%s" % (errorstr))
            dataerreur["data"]["msg"] = (
                "REMOTE MySQL Error: %s on %s\n"
                "traceback\n"
                "%s" % (str(e), objectxmpp.boundjid.bare, errorstr)
            )
            raise GuacamoleError("MySQL connection error")

        cursor = db.cursor()
        result["data"]["uuid"] = data["uuid"]
        result["data"]["machine_id"] = data["machine_id"]
        result["data"]["connection"] = {}

        # Add only detected protocols
        if hasattr(objectxmpp.config, "guacamole_protocols"):
            protos = list(
                set(objectxmpp.config.guacamole_protocols.split())
                & set(data["remoteservice"].keys())
            )
        else:
            protos = data["remoteservice"].keys()

        try:
            # delete connection
            for proto in protos:
                cursor.execute(deleteprotocole(proto, data["hostname"]))
                db.commit()
            # create connection
            for proto in protos:
                result["data"]["connection"][proto.upper()] = -1
                cursor.execute(insertprotocole(proto, data["hostname"]))
                db.commit()
                result["data"]["connection"][proto.upper()] = cursor.lastrowid
        except MySQLdb.Error as e:
            errorstr = "%s" % traceback.format_exc()
            logger.error("\n%s" % (errorstr))
            dataerreur["data"]["msg"] = (
                "REMOTE MySQL Error: %s on %s\n"
                "traceback\n"
                "%s" % (str(e), objectxmpp.boundjid.bare, errorstr)
            )
            raise GuacamoleError("MySQL error deleting existing protocol")
        except Exception as e:
            errorstr = "%s" % traceback.format_exc()
            logger.error("\n%s" % (errorstr))
            dataerreur["data"]["msg"] = (
                "REMOTE Error: %s on %s\n"
                "traceback\n"
                "%s" % (str(e), objectxmpp.boundjid.bare, errorstr)
            )
            raise GuacamoleError("Error deleting existing protocol")
        ###################################
        # configure parameters
        ###################################
        try:
            for proto in protos:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(5.0)
                    sock.connect(
                        (data["machine_ip"], int(data["remoteservice"][proto]))
                    )
                    # Machine is directly reachable. We will not need a
                    # reversessh connection
                    hostname = data["machine_ip"]
                    port = data["remoteservice"][proto]
                except socket.error:
                    # Machine is not reachable. We will need a reversessh
                    # connection
                    hostname = "localhost"
                    port = get_free_tcp_port(objectxmpp)
                finally:
                    try:
                        cursor.execute(
                            insertparameter(
                                result["data"]["connection"][proto.upper()],
                                "hostname",
                                hostname,
                            )
                        )

                        cursor.execute(
                            insertparameter(
                                result["data"]["connection"][proto.upper()],
                                "port",
                                port,
                            )
                        )

                    except Exception as error_connection:
                        logger.error(
                            f"An Error occured while trying to insert the guacamole parameters for the {proto} protocol. With the error {error_connection}"
                        )
                        logger.error(traceback.format_exc())
                    sock.close()

                # Options specific to a protocol
                for option in objectxmpp.config.__dict__.keys():
                    if option.startswith(proto.lower()):
                        if option == "ssh_keyfile":
                            # specific processing for ssh key
                            with open(objectxmpp.config.ssh_keyfile, "r") as keyfile:
                                keydata = keyfile.read()

                            cursor.execute(
                                insertparameter(
                                    result["data"]["connection"][proto.upper()],
                                    "private-key",
                                    keydata,
                                )
                            )

                        else:
                            # Update account for the os
                            if option[4:] == "username":
                                username = "pulseuser"

                                cursor.execute(
                                    insertparameter(
                                        result["data"]["connection"][proto.upper()],
                                        "username",
                                        username,
                                    )
                                )

                            else:
                                cursor.execute(
                                    insertparameter(
                                        result["data"]["connection"][proto.upper()],
                                        option[4:],
                                        getattr(objectxmpp.config, option),
                                    )
                                )
                        if option == "rdp_enable-sftp" or option == "vnc_enable-sftp":
                            logger.error(f"Guacamole option rdp  {rdp_enable-sftp}")
                            logger.error(f"Guacamole option vnc {rdp_enable-sftp}")
                            cursor.execute(
                                insertparameter(
                                    result["data"]["connection"][proto.upper()],
                                    "sftp-hostname",
                                    hostname,
                                )
                            )
                            cursor.execute(
                                insertparameter(
                                    result["data"]["connection"][proto.upper()],
                                    "sftp-port",
                                    "22",
                                )
                            )
                            cursor.execute(
                                insertparameter(
                                    result["data"]["connection"][proto.upper()],
                                    "sftp-username",
                                    username,
                                )
                            )
                            cursor.execute(
                                insertparameter(
                                    result["data"]["connection"][proto.upper()],
                                    "sftp-private-key",
                                    keydata,
                                )
                            )


                    # Commit our queries
                    db.commit()
        except MySQLdb.Error as e:
            errorstr = "%s" % traceback.format_exc()
            logger.error("\n%s" % (errorstr))
            dataerreur["data"]["msg"] = (
                "REMOTE MySQL Error: %s on %s\n"
                "traceback\n"
                "%s" % (str(e), objectxmpp.boundjid.bare, errorstr)
            )
            raise GuacamoleError("MySQL error inserting existing protocol")
        except Exception as e:
            errorstr = "%s" % traceback.format_exc()
            logger.error("\n%s" % (errorstr))
            dataerreur["data"]["msg"] = (
                "REMOTE Error: %s on %s\n"
                "traceback\n"
                "%s" % (str(e), objectxmpp.boundjid.bare, errorstr)
            )
            raise GuacamoleError("Error inserting existing protocol")
    except Exception as e:
        logger.error("Guacamole configuration error %s" % (str(e)))
        objectxmpp.send_message(
            mto=message["from"], mbody=json.dumps(dataerreur), mtype="chat"
        )
    finally:
        db.close()
        # send message result conf guacamol.
        if result["base64"] is True:
            result["data"] = base64.b64encode(json.dumps(result["data"]))
        logger.debug("Sending message %s" % result)
        objectxmpp.send_message(
            mto=message["from"], mbody=json.dumps(result), mtype="chat"
        )
