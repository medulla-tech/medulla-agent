# file : pulse_xmpp_master_substitute/lib/glpi_xml_sync/README.md

# glpi_xml_sync

## Scope

Ce dossier contient:

- les ressources de test
- la cartographie des tags XML traites
- le routage vers les modules d'injection

## Ressources de test

- XML de test: `src/python/tests/xml/`
- Exemple de configuration INI: `src/python/tests/config.sample.ini`
- Sorties de test (optionnel): `src/python/tests/output/`
- Script d'export distant: `src/python/tests/export_to_remote.sh`

## Validation locale

Execution de reference:

```bash
python3 src/python/xml_sync.py --config-ini src/python/tests/config.sample.ini
```

Execution avec surcharge CLI:

```bash
python3 src/python/xml_sync.py \
  --config-ini src/python/tests/config.sample.ini \
  --dry-run
```

Export vers une machine distante (exemple Debian 13 GLPI):

```bash
./src/python/tests/export_to_remote.sh --host deb13GLPI --dest ~/glpi_xml_sync_tests
```

Simulation sans copie:

```bash
./src/python/tests/export_to_remote.sh --dry-run
```

## Cartographie des tags XML traites

Cette section decrit les balises XML exploitees par le pipeline glpi_xml_sync,
du parsing vers les modules d'injection.

### 1) Detection des noeuds machine

- Balises recherchees: COMPUTER, MACHINE, HOST
- Fallback structurel: CONTENT contenant HARDWARE ou BIOS
- Module parser: `xml_parser.py`, fonction `_machine_nodes`

### 2) Identifiants globaux inventaire

- DEVICEID
  - chemins: DEVICEID, HARDWARE/DEVICEID, REQUEST/DEVICEID, CONTENT/DEVICEID
  - module parser: `xml_parser.py`, fonction `_global_deviceid`
- VERSIONCLIENT
  - chemins: VERSIONCLIENT, REQUEST/VERSIONCLIENT, QUERY/VERSIONCLIENT
  - module parser: `xml_parser.py`, fonction `_global_versionclient`
- VERSIONPROVIDER
  - chemins: VERSIONPROVIDER, REQUEST/VERSIONPROVIDER, QUERY/VERSIONPROVIDER
  - module parser: `xml_parser.py`, fonction `_global_versionprovider`

### 3) Champs machine core

- OCSID: META/ID, META/DATABASEID, ID, DATABASEID
- NAME: META/NAME, HARDWARE/NAME, NAME, HARDWARE/USERID
- SERIAL: BIOS/SSN, BIOS/SERIAL, SSN, SERIAL
- TAG: META/TAG, ACCOUNTINFO/TAG, TAG
  - variante supportee: ACCOUNTINFO/KEYNAME=TAG + ACCOUNTINFO/KEYVALUE
- Module parser: `xml_parser.py`, fonction `extract_records`
- Module injection: `machine_inject.py`

### 4) Tags software

- Section: SOFTWARES/SOFTWARE
- Fallback: SOFTWARES direct si pas de sous-noeud SOFTWARE
- Champs traites:
  - NAME ou SOFTNAME
  - VERSION
  - PUBLISHER ou EDITOR
  - COMMENTS ou COMMENT
  - INSTALLDATE ou INSTALL_DATE
- Module parser: `xml_parser.py`, fonction `_extract_softwares`
- Module injection: `software_inject.py`

### 5) Tags reseau

- Section: NETWORKS/NETWORK
- Fallback: NETWORKS direct
- Champs traites:
  - MACADDR ou MAC ou MACADDRESS
  - DESCRIPTION ou NAME ou INTERFACE
  - TYPE ou TYPEMIB
  - SPEED
  - IPADDRESS ou IP
  - IPMASK ou MASK
  - IPGATEWAY ou GATEWAY
  - IPSUBNET ou SUBNET
- Module parser: `xml_parser.py`, fonction `_extract_network_interfaces`
- Module injection: `device_inject.py`

### 6) Tags BIOS, CPU, Storage, Sound, Battery

- BIOS (section BIOS)
  - SSN ou MSN
  - BMANUFACTURER, BVERSION, SMODEL, MMODEL
  - Module parser: `xml_parser.py`, fonction `_extract_bios`
  - Module injection: `hardware_inject.py`

- CPU (section CPUS)
  - NAME, MANUFACTURER, FAMILYNAME, CORE, THREAD
  - Module parser: `xml_parser.py`, fonction `_extract_cpus`
  - Module injection: `hardware_inject.py`

- Storage (section STORAGES)
  - NAME, MODEL, MANUFACTURER, SERIALNUMBER, DISKSIZE, TYPE
  - Module parser: `xml_parser.py`, fonction `_extract_storages`
  - Module injection: `hardware_inject.py`

- Sound (section SOUNDS)
  - NAME, MANUFACTURER, DESCRIPTION
  - Module parser: `xml_parser.py`, fonction `_extract_sounds`
  - Module injection: `hardware_inject.py`

- Battery (section BATTERIES)
  - NAME, MANUFACTURER, SERIAL, CHEMISTRY, CAPACITY, REAL_CAPACITY, VOLTAGE
  - Module parser: `xml_parser.py`, fonction `_extract_batteries`
  - Module injection: `hardware_inject.py`

### 7) Tags OS

- Section: OPERATINGSYSTEM
- Champs traites: NAME, VERSION, ARCH, KERNEL_NAME, KERNEL_VERSION, FULL_NAME
- Module parser: `xml_parser.py`, fonction `_extract_operating_systems`
- Module injection: `os_inject.py`

### 8) Sections brutes (raw_sections)

- Toutes les sections de premier niveau sont conservees sauf:
  - DEVICEID
  - VERSIONCLIENT
  - VERSIONPROVIDER
- Une section METADATA est ajoutee avec DEVICEID/VERSIONCLIENT/VERSIONPROVIDER.
- Module parser: `xml_parser.py`, fonction `_extract_raw_sections`

- Sections raw explicitement reinjectees:
  - PRINTERS -> peripheral_inject.py (_sync_printers)
  - USBDEVICES -> peripheral_inject.py (_sync_peripherals)
  - INPUTS -> peripheral_inject.py (_sync_peripherals)

- Toutes les sections raw sont aussi historisees en base plugin:
  - raw_sections_inject.py

### 9) Sections reconnues en mode best-effort XML

Lorsqu'un XML est partiellement corrompu, les blocs suivants sont tentes:

- META
- HARDWARE
- BIOS
- CPUS
- STORAGES
- SOUNDS
- BATTERIES
- OPERATINGSYSTEM
- SOFTWARES
- NETWORKS
- PRINTERS
- USBDEVICES
- INPUTS
- MEMORIES
- CONTROLLERS
- DRIVES
- ENVS
- FIREWALL
- LOCAL_USERS
- LOCAL_GROUPS
- PROCESSES

Module parser: `xml_parser.py`, fonction `_recover_xml_best_effort`.

### 10) Orchestration des modules d'injection

Le pipeline d'injection est orchestre par `sync_service.py`:

1. machine_inject.py
2. os_inject.py
3. device_inject.py
4. peripheral_inject.py
5. hardware_inject.py
6. raw_sections_inject.py
7. software_inject.py
8. networkshare_inject.py
9. runningprocess_inject.py
10. service_inject.py
11. user_inject.py
