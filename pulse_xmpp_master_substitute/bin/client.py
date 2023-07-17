#!/usr/bin/python3
import socket
import ssl

# Configuration du serveur
SERVER_HOST = 'localhost'
SERVER_PORT = 5822
TOKEN = 'mon_token_securise'

# Fonction principale du client
def main():
    # Création du socket TCP/IP
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((SERVER_HOST, SERVER_PORT))

    # Configuration du contexte SSL
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    # Établissement de la connexion SSL
    ssl_sock = context.wrap_socket(sock, server_hostname=SERVER_HOST)

    try:
        # Envoi du token au serveur
        ssl_sock.sendall(TOKEN.encode())

        # Réception des données du serveur
        data = ssl_sock.recv(1024)
        print("Données reçues du serveur :", data.decode())
    finally:
        # Fermeture de la connexion SSL
        ssl_sock.close()

    # Fermeture du socket principal
    sock.close()

# Lancement du client
if __name__ == '__main__':
    main()
