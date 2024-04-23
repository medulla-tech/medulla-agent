#!/usr/bin/python3
"""
# test ipv4
./master_client_cli.py --allowed_token '4O&vHYKG3Cqq3RCUJu!vnQu+dBGwDkpZ' --message_type test --message_structure xml --debug_level DEBUG
./master_client_cli.py --allowed_token '4O&vHYKG3Cqq3RCUJu!vnQu+dBGwDkpZ' --message_type test --message_structure yaml --debug_level DEBUG
./master_client_cli.py --allowed_token '4O&vHYKG3Cqq3RCUJu!vnQu+dBGwDkpZ' --message_type test --message_structure yaml --debug_level DEBUG
# test ipv6
./master_client_cli.py --allowed_token '4O&vHYKG3Cqq3RCUJu!vnQu+dBGwDkpZ' --message_type test --message_structure xml --debug_level DEBUG --host ::1 --port 57041 --address_format ipv6
./master_client_cli.py --allowed_token '4O&vHYKG3Cqq3RCUJu!vnQu+dBGwDkpZ' --message_type test --message_structure yaml --debug_level DEBUG --host ::1 --port 57041 --address_format ipv6
./master_client_cli.py --allowed_token '4O&vHYKG3Cqq3RCUJu!vnQu+dBGwDkpZ' --message_type test --message_structure yaml --debug_level DEBUG --host ::1 --port 57041 --address_format ipv6

"""
import os
import sys
import socket
import ssl
import gzip
import configparser
import json

# import parent lib
import inspect

currentdir = os.path.dirname(os.path.abspath(inspect.getfile(inspect.currentframe())))
parentdir = os.path.abspath(os.path.join(currentdir, "..", "lib"))
sys.path.insert(0, parentdir)
import argparse
import utils
from utils import convert

sys.path.pop(0)

HOST = "::1"
PORT = 57041
TOKEN_in_BYTES = b"mon_token_securise"


testjson = """{ 'action' : 'testipv',
           'data' : { 'message' : 'Je suis 1 message simple json'}
          }"""

testxml = """<?xml version="1.0" encoding="UTF-8" ?>
<root><action type="str">testipv6</action><sessionid type="str">mysession</sessionid><comment type="str">Deployment</comment><data type="dict"><message type="str">Je suis 1 test ipv6 </message></data><testlist type="list"><item type="int">1</item><item type="int">2</item><item type="int">3</item><item type="str">vert</item><item type="str">rouge</item></testlist><base64 type="bool">false</base64></root>
"""

testyaml = """action: testipv6
comment : Deployment
sessionid: mysession
data:
  message: Je suis 1 test ipv6
  testlist:
    - servera
    - serverb
    - serverc
base64: False
"""


def get_cli_parameter():
    # Création de l'objet ArgumentParser
    parser = argparse.ArgumentParser()
    # Définition des arguments de ligne de commande
    parser.add_argument(
        "--message_type", choices=["iq", "message", "test"], default="message"
    )
    parser.add_argument("--address_format", choices=["ipv6", "ipv4"], default="ipv4")
    parser.add_argument("--test", type=bool, default=False)
    parser.add_argument(
        "--message_structure", choices=["json", "yaml", "xml"], default="json"
    )
    parser.add_argument(
        "--debug_level", choices=["NOTSET", "INFO", "DEBUG"], default="NOTSET"
    )
    parser.add_argument(
        "--config_file",
        default="/etc/medulla-agent-substitute/__server_mmc_master.ini",
    )
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=57040)
    parser.add_argument("--taille_max_message", type=int, default=2097152)
    parser.add_argument("--allowed_token", default="")
    parser.add_argument("--check_hostname", action="store_true", default=False)
    # Analyse des arguments de ligne de commande
    args = parser.parse_args()
    parameters = vars(args)
    if parameters["debug_level"] == "DEBUG":
        print("parameters list")
        for k, v in parameters.items():
            print(f"\t{k} : {v}")
    return parameters


def __main__():
    argument = get_cli_parameter()

    if argument["address_format"] == "ipv6":
        client = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    elif argument["address_format"] == "ipv4":
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    else:
        print("format error")
        sys.exit(-1)

    if argument["message_type"] == "test":
        if argument["message_structure"] == "json":
            test = testjson
        elif argument["message_structure"] == "yaml":
            test = testyaml
        elif argument["message_structure"] == "xml":
            test = testxml

    # Activation de l'option pour réutiliser l'adresse
    client.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    context.check_hostname = argument["check_hostname"]
    context.verify_mode = ssl.CERT_NONE

    # test json
    client.connect((argument["host"], argument["port"]))
    ssock = context.wrap_socket(client, server_hostname=argument["host"])

    try:
        message = argument["allowed_token"] + test
        ssock.sendall(convert.compress_data_to_bytes(message))
        response = convert.decompress_data_to_bytes(ssock.recv(4096))
        print(response.decode())
    finally:
        # Fermeture de la connexion SSL
        # Fermeture du socket principal
        ssock.close()


# Lancement du client
if __name__ == "__main__":
    __main__()
