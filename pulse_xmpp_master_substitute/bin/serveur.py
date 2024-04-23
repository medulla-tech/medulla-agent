#!/usr/bin/python3

import socket
import ssl
import threading

# Configuration du serveur
HOST = "localhost"
PORT = 5822

certfile = "/var/lib/medulla/masterkey/cert.pem"
keyfile = "/var/lib/medulla/masterkey/key.pem"


# Fonction de gestion de la connexion
def handle_connection(conn):
    try:
        # Configuration du contexte SSL
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        context.load_cert_chain(certfile=certfile, keyfile=keyfile)

        # Établissement de la connexion SSL
        ssl_conn = context.wrap_socket(conn, server_side=True)

        # Traitement des données
        data = ssl_conn.recv(1024)
        # Faire quelque chose avec les données reçues...
        response = b"Message recu : " + data
        ssl_conn.sendall(response)
        # Fermeture de la connexion
        ssl_conn.close()
    except ssl.SSLError as e:
        print("Erreur SSL :", e)


# Fonction principale
def main():
    # Création du socket TCP/IP
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    sock.bind((HOST, PORT))
    sock.listen(5)

    print(f"Serveur démarré sur {HOST}:{PORT}")

    while True:
        # Attente d'une connexion entrante
        conn, addr = sock.accept()
        print(f"Nouvelle connexion de {addr[0]}:{addr[1]}")

        # Démarrage d'un thread pour gérer la connexion
        t = threading.Thread(target=handle_connection, args=(conn,))
        t.start()

    # Fermeture du socket principal
    sock.close()


# Lancement du serveur
if __name__ == "__main__":
    main()
