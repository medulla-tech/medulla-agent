# networkevents.py

## Objectif

Le script surveille les changements d interfaces reseau sous Windows et envoie un message JSON au serveur TCP local de l agent Medulla quand une adresse IP change.

Il sert principalement a notifier un autre processus local qu une ou plusieurs interfaces ont ete ajoutees/supprimees.

Historique :

- ancien mode : ecriture dans un pipe nomme Windows
- mode actuel : client TCP vers le serveur local utilise par kiosk

## Prerequis

### Systeme

- Windows (le script utilise COM, SENS et les API Windows reseau)

### Python

- Python 3
- modules Python requis :
  - `pywin32` (`pythoncom`, `win32api`, `win32com`)
  - modules standard (`ctypes`, `json`, `threading`, `socket`, `struct`, etc.)

### Environnement Medulla

- le module `pulse_xmpp_agent.lib.agentconffile` doit etre disponible
- acces en ecriture pour creer :
  - le log : `.../var/log/networkevents.log`
  - le pidfile : `.../bin/.PID_NETWORKS_ENVENTS`
- acces a la configuration agent :
  - priorite auto sur `C:/Program Files/Medulla/etc/agentconf.ini`
  - lecture de `[kiosk]/am_local_port`

### IPC locale

- le serveur TCP local de l agent doit ecouter sur `127.0.0.1:<port>`
- le port est determine ainsi :
  1. option `--port` si fournie
  2. option `--config-file` si fournie, lecture de `[kiosk]/am_local_port`
  3. resolution automatique de `agentconf.ini`
  4. fallback `8765`

## Comment il fonctionne

1. Au demarrage, il initialise le log et ecrit son PID.
2. Il resout le port TCP local a utiliser.
3. Il lit l etat initial des IP via `GetIpAddrTable()`.
4. Il lance un thread `NetworkManager.run()`.
5. Dans une boucle infinie, il attend un changement d adresse (`NotifyAddrChange`).
6. Il relit la table des IP et compare ancien/nouvel etat.
7. Il construit une structure de diff avec 3 listes :
   - `interface` : IP communes ancien/nouveau
   - `additionalinterface` : IP ajoutees
   - `removedinterface` : IP supprimees
8. Il serialize cette structure avec `json.dumps(...)`.
9. Il ouvre une connexion TCP vers le serveur local et envoie le JSON.
10. Si le serveur n est pas encore disponible, le message est bufferise localement puis renvoye plus tard.

## Forme des messages

Le message envoye au serveur TCP est :

- un texte JSON (pas XML, pas YAML)

Structure JSON envoyee :

```json
{
  "interface": ["ip1", "ip2"],
  "additionalinterface": ["ip_ajoutee"],
  "removedinterface": ["ip_supprimee"]
}
```

Exemple reel possible :

```json
{"interface": ["192.168.1.10"], "additionalinterface": ["10.0.0.5"], "removedinterface": ["192.168.1.20"]}
```

## JSON, XML ou YAML ?

- Format utilise : JSON
- XML : non
- YAML : non

La serialisation est faite explicitement par `json.dumps(datainterface)`.

## Transport TCP utilise

- Hote : `127.0.0.1` par defaut
- Port : `am_local_port` dans `[kiosk]` ou `8765` par defaut
- Envoi : nouvelle connexion TCP a chaque evenement

Pourquoi une nouvelle connexion a chaque fois :

- le client est stateless
- cela simplifie la reprise si le serveur disparait puis reapparait
- l envoi suivant se reconnecte automatiquement

## Robustesse si le serveur TCP est indisponible

Si le serveur local n est pas encore demarre ou temporairement indisponible :

- plusieurs tentatives courtes sont effectuees
- l evenement est place dans un buffer local en memoire
- le buffer est vide automatiquement des que le serveur repond de nouveau

Cela permet de ne pas perdre les premiers evenements au demarrage de l agent.

## Signification des logs

Les changements reseau sont traces avec un statut :

- `[SEND]` : evenement envoye au serveur TCP
- `[NC]` : serveur non connecte ou non disponible, evenement bufferise
- `[NOSEND]` : envoi TCP desactive via `--no-send-kiosk`

En cas de timeout au demarrage, un message de log explicite indique que le serveur TCP local n est probablement pas encore disponible.

## Options principales

- `--host` : hote TCP local, defaut `127.0.0.1`
- `--port` : force le port TCP
- `--config-file` : force le fichier `agentconf.ini`
- `--no-send-kiosk` : desactive l envoi TCP, utile pour debug local
- `--log-level` : niveau de log
- `--log-file` : chemin de log alternatif

## Points d attention

- Le script ne demarre pas le serveur TCP : il suppose que l agent Medulla l a deja lance.
- Les evenements de changement reseau sont emis meme si le serveur local n est pas encore pret.
- Le buffer local est en memoire seulement : il ne survit pas a l arret du processus.
- Le thread tourne en continu, pour un usage service Windows.
- Le pipe nomme `\\.\\pipe\\interfacechang` appartient maintenant au chemin legacy et n est plus le transport actif de `networkevents.py`.

## Fichiers concernes

- Script : `scripts_installer/win/networkevents.py`
- Documentation : `scripts_installer/win/networkevents.md`

## Guide du bêta testeur

Cette section permet de verifier en conditions reelles que :

- `networkevents.py` detecte bien les changements reseau sous Windows
- les evenements sont bien envoyes vers le serveur TCP local de l agent
- le plugin serveur TCP journalise correctement le diff des interfaces

### 1. Creer une interface loopback Windows de test

L objectif est d avoir une interface reseau de laboratoire, sans toucher a l interface physique principale.

Procedure recommandee :

1. Ouvrir `hdwwiz.exe` en administrateur.
2. Choisir `Installer le materiel que je selectionne manuellement dans une liste`.
3. Selectionner `Cartes reseau`.
4. Choisir le constructeur `Microsoft`.
5. Choisir `Microsoft KM-TEST Loopback Adapter` ou `Microsoft Loopback Adapter` selon la version de Windows.
6. Terminer l assistant.
7. Ouvrir `ncpa.cpl`.
8. Renommer l interface creee en `Ethernet 2` si vous voulez reutiliser directement le script PowerShell ci-dessous.

Commande utile pour verifier le nom reel de l interface :

```powershell
Get-NetAdapter | Sort-Object Name | Format-Table Name, InterfaceDescription, Status
```

### 2. Script PowerShell de test cyclique

Ce script ajoute puis retire une IP de test en boucle sur l interface loopback.

Exemple de nom de fichier : `cyclereseu.ps1`

```powershell
# Paramètres
$interfaceName = "Ethernet 2"  # Nom de votre adaptateur KM-TEST Loopback
$testIP = "192.168.200.1"
$testPrefix = 24
$cycleSeconds = 60

# Vérifier que l'interface existe et est active
$adapter = Get-NetAdapter | Where-Object { $_.Name -eq $interfaceName }
if (-not $adapter) {
    Write-Error "Adaptateur '$interfaceName' introuvable."
    exit
}
if ($adapter.Status -ne "Up") {
    Write-Host "Activation de l'interface $interfaceName..."
    Enable-NetAdapter -Name $interfaceName -ErrorAction Stop
}

# Boucle infinie
while ($true) {
    try {
        Write-Host "[$(Get-Date -Format 'HH:mm:ss')] Ajout de l'IP $testIP à $interfaceName..."
        New-NetIPAddress -IPAddress $testIP -PrefixLength $testPrefix -InterfaceAlias $interfaceName -ErrorAction Stop
        Write-Host "IP ajoutée. Attente de $cycleSeconds secondes..."

        Start-Sleep -Seconds $cycleSeconds

        Write-Host "[$(Get-Date -Format 'HH:mm:ss')] Suppression de l'IP $testIP..."
        Remove-NetIPAddress -IPAddress $testIP -InterfaceAlias $interfaceName -Confirm:$false -ErrorAction Stop
        Write-Host "IP supprimée. Attente de $cycleSeconds secondes..."
        Start-Sleep -Seconds $cycleSeconds
    }
    catch {
        Write-Error "Erreur : $_"
        Start-Sleep -Seconds 10
    }
}
```

### 3. Comment lancer le script de test

Dans une console PowerShell ouverte en administrateur :

```powershell
powershell -ExecutionPolicy Bypass -File .\cyclereseu.ps1
```

Ce lancement force l execution du script meme si la politique PowerShell standard est restrictive.

### 4. Ou voir les logs

#### Logs de surveillance reseau

Le script `networkevents.py` ecrit ses traces dans le log reseau local de l agent.

Exemple d emplacement attendu :

- `C:\Program Files\Medulla\var\log\networkevents.log`

Ce log permet de verifier :

- le demarrage du moniteur reseau
- le port TCP cible
- les changements d interfaces detectes
- les cas ou le serveur TCP n est pas encore disponible
- la reprise et la vidange du buffer local

#### Logs cote agent / plugin TCP

Le plugin serveur TCP de l agent ecrit dans les logs habituels de l agent en mode debug.

On doit y voir une ligne de ce type quand l evenement arrive au serveur TCP :

```text
2026-04-29 10:56:43,244 - INFO - (AG_EVENT)changement interface: interface=['127.0.0.1', '192.168.1.28'] additionalinterface=['169.254.254.18'] removedinterface=[]
2026-04-29 10:56:43,248 - DEBUG - (AG_EVENT)Socket Information
2026-04-29 10:56:43,248 - DEBUG - (AG_EVENT)Address Family: 2
2026-04-29 10:56:43,248 - DEBUG - (AG_EVENT)Socket Type: 1
2026-04-29 10:56:43,248 - DEBUG - (AG_EVENT)Protocol: 0
2026-04-29 10:56:43,248 - DEBUG - (AG_EVENT)Listening Address: 127.0.0.1:8765
2026-04-29 10:56:43,248 - DEBUG - (AG_EVENT)Remote Address: 127.0.0.1:64607
```

Signification :

- `changement interface` : le plugin TCP a recu un message de type changement reseau
- `interface=[...]` : IP communes avant/apres
- `additionalinterface=[...]` : IP ajoutees
- `removedinterface=[...]` : IP retirees
- `Listening Address` : socket serveur de l agent
- `Remote Address` : client local qui a envoye l evenement, ici `networkevents.py`

### 5. Exemple de logs de surveillance reseau

Exemple typique cote `networkevents.py` :

```text
2026-04-29 10:17:56,036 - INFO - ***************************
2026-04-29 10:17:56,036 - INFO - networkevents TCP target 127.0.0.1:8765 (source conf: C:\Program Files\Medulla\etc\agentconf.ini)
2026-04-29 10:17:56,050 - INFO - START NETWORKEVENT [PID 11040] 127.0.0.1,192.168.1.28,192.168.200.1
2026-04-29 10:17:56,067 - INFO - start listen network interface
2026-04-29 10:18:36,008 - WARNING - TCP send failed to 127.0.0.1:8765 (timed out). Event buffered (1 pending).
2026-04-29 10:18:36,008 - INFO - [NC] Interface [127.0.0.1,192.168.1.28] chang[+['127.0.0.1', '192.168.1.28']-['']] (event buffered)
2026-04-29 10:19:27,077 - INFO - TCP server available again, flushing 1 buffered event(s)
2026-04-29 10:19:30,089 - INFO - TCP server available again, flushing 1 buffered event(s)
2026-04-29 10:19:33,092 - INFO - TCP server available again, flushing 1 buffered event(s)
2026-04-29 10:19:36,097 - WARNING - TCP send failed to 127.0.0.1:8765 (timed out). Event buffered (2 pending).
2026-04-29 10:19:36,097 - INFO - [NC] Interface [127.0.0.1,169.254.254.18,192.168.1.28] chang[+['169.254.254.18']] (event buffered)
2026-04-29 10:20:27,392 - INFO - TCP server available again, flushing 2 buffered event(s)
2026-04-29 10:20:27,403 - INFO - [SEND] Interface [127.0.0.1,192.168.1.28] chang[-['169.254.254.18']]
2026-04-29 10:20:37,202 - INFO - [SEND] Interface [127.0.0.1,169.254.254.18,192.168.1.28] chang[+['169.254.254.18']]
2026-04-29 10:21:30,702 - INFO - [SEND] Interface [127.0.0.1,192.168.1.28,192.168.200.1] chang[+['192.168.200.1']-['169.254.254.18']]
2026-04-29 10:22:27,733 - INFO - [SEND] Interface [127.0.0.1,192.168.1.28] chang[-['192.168.200.1']]
```

### 6. Explication des lignes de log

- `***************************`
  demarrage du programme de surveillance reseau

- `networkevents TCP target 127.0.0.1:8765`
  le script a determine la cible TCP a utiliser pour l envoi des evenements

- `START NETWORKEVENT [PID ...] ...`
  snapshot initial des IP au moment du demarrage

- `start listen network interface`
  le thread de surveillance est en attente des notifications Windows

- `TCP send failed to 127.0.0.1:8765 (timed out). Event buffered ...`
  le serveur TCP local n etait pas encore disponible ou n a pas repondu a temps
  l evenement n est pas perdu, il est stocke en memoire

- `[NC] Interface ... (event buffered)`
  `NC` signifie non connecte, ou plus precisement serveur TCP indisponible
  le changement reseau a bien ete detecte mais il n a pas encore pu etre remis a l agent

- `TCP server available again, flushing ... buffered event(s)`
  le serveur TCP local repond de nouveau
  le client commence a renvoyer les evenements stockes

- `[SEND] Interface ...`
  le changement reseau a ete envoye avec succes au serveur TCP local

### 7. Interpretation pratique pour un beta test

Si tout fonctionne correctement, vous devez observer :

1. des lignes `[SEND]` dans `networkevents.log`
2. des lignes `changement interface: ...` dans les logs debug de l agent
3. des valeurs coherentes dans `additionalinterface` et `removedinterface`

Si le serveur TCP de l agent n est pas encore pret au moment du test, il est normal de voir d abord :

1. des lignes `TCP send failed ... timed out`
2. des lignes `[NC]`
3. puis plus tard des lignes `TCP server available again, flushing ...`
4. enfin des lignes `[SEND]`

Ce comportement est attendu et valide justement la robustesse du mecanisme de bufferisation TCP.

### 8. Tests avancés : Changement de réseau réel avec reconnexion XMPP

Le test avec interface loopback ci-dessus valide le circuit de detection et d envoi des evenements. Cependant, pour tester **completement** le comportement en conditions reelles, vous devez reproduire des changements de reseau qui modifient la connexion XMPP de l agent.

#### Scenarios recommandes

**Scenario 1 : Basculement filaire ↔ WiFi**

- Agent connecte sur cable reseau (connexion XMPP stable)
- Debrancher le cable physique / desactiver l interface filaire
- Observer :
  - `networkevents.py` detecte la perte de l interface filaire
  - L agent XMPP perd sa connexion ou bascule sur WiFi
  - Logs reseau : `removedinterface=['192.168.X.X']`
  - Logs XMPP : reconnexion automatique sur nouveau reseau
- Rebrancher le cable
- Observer la detection du retour et potentielle reconciliation

**Scenario 2 : Activation / Desactivation VPN**

- Agent connecte sans VPN
- Activer une connexion VPN (Cisco, OpenVPN, Wireguard, etc.)
- Observer :
  - `networkevents.py` detecte les nouvelles interfaces VPN et potentiellement la perte d interfaces precedentes
  - Logs reseau : `additionalinterface=['10.X.X.X']` ou autre range VPN
  - L agent peut basculer sur une route reseau differente
  - Connexion XMPP peut se reinterpreter (meme serveur, route differente)
- Desactiver le VPN
- Observer la detection et le retour aux interfaces initiales

**Scenario 3 : Changement de site / Mobilité**

- Agent en bureau (reseau 192.168.1.0/24)
- Deplacer la machine / fermer le portable et le rouvrir ailleurs
- Connecter sur site different (ex: 192.168.10.0/24, hotel, client, maison)
- Observer :
  - `networkevents.py` detecte le changement complet des interfaces reseau
  - Logs reseau : `removedinterface=['192.168.1.X', ...]` + `additionalinterface=['192.168.10.X', ...]`
  - L agent relance la decouverte de ses parametres (peut avoir un new hostname, new subnet, new gateway, new DNS)
  - Logs XMPP : reconnexion avec potentiellement une nouvelle resolution du serveur Medulla

#### Quoi observer dans les logs

**Dans `networkevents.log` :**

```text
[SEND] Interface [...] chang[+['10.8.0.X']-['192.168.1.X']]  # VPN actif
[SEND] Interface [...] chang[-['10.8.0.X']-[...]]            # VPN desactif
```

**Dans les logs XMPP de l agent :**

- Rechercher les reconnexions : `connecting to server`, `xmpp connection lost`, `reconnecting`
- Verifier que l agent retrouve les bons parametres de server apres changement de reseau
- Verifier que la queue des messages en attente est traitee apres reconnexion

**Resultats attendus :**

- Les changements reseau majeurs (perte/gain d interface) sont detectes promptement
- L agent reconnecte les sessions XMPP apres changement reseau
- Les messages en attente pendant la transition reseau ne sont pas perdus
- L agent retrouve son contexte (enregistrements, synchronisation) apres reconnexion

#### Limitations du test avec loopback

Le test avec interface loopback est **non destructif** et **reproductible** mais il ne reproduit pas :

- La perte reelle d une connexion TCP existante
- La transition d un DNS resolvable vers un autre
- La perte/gain de route reseau par defaut
- La transition entre deux subnets IP reels
- Les delais reseau reels et timeouts pendant la transition

Pour une validation **complete** avant production, **combinez** :

1. le test loopback (validation rapide, cycle rapide)
2. les tests de mobilite / VPN (validation reelle en conditions proches de la production)

