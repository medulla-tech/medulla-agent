# SPDX-FileCopyrightText: 2004-2007 Linbox / Free&ALter Soft, http://linbox.com
# SPDX-FileCopyrightText: 2007 Mandriva, http://www.mandriva.com
# SPDX-FileCopyrightText: 2016-2023 Siveo, http://www.siveo.net
# SPDX-FileCopyrightText: 2024-2025 Medulla, http://www.medulla-tech.io
# SPDX-License-Identifier: GPL-3.0-or-later
# file : pulse_xmpp_master_substitute/lib/glpi_xml_sync/xml_parser.py
"""Parsing d'inventaires XML/JSON/YAML et extraction des machines."""

from __future__ import annotations

import argparse
import json
import re
import sys
import xml.etree.ElementTree as ET
from dataclasses import asdict
from pathlib import Path
from typing import Any, Iterable

from .models import (
    BatteryRecord,
    BiosRecord,
    CpuRecord,
    MachineRecord,
    NetworkInterfaceRecord,
    OperatingSystemRecord,
    SoftwareRecord,
    SoundRecord,
    StorageRecord,
)


def _dict_to_element(tag: str, value: Any) -> ET.Element:
    """Convertit une structure Python dictee par JSON/YAML en arbre ElementTree.

    Args:
        tag: Nom de balise racine a utiliser.
        value: Valeur Python a convertir (dict, list, scalaire).

    Returns:
        Element XML construit.
    """
    node = ET.Element((tag or "INVENTORY").strip().upper())

    if isinstance(value, dict):
        for key, child_value in value.items():
            child_tag = (str(key).strip() or "VALUE").upper()
            if isinstance(child_value, list):
                for item in child_value:
                    node.append(_dict_to_element(child_tag, item))
            else:
                node.append(_dict_to_element(child_tag, child_value))
        return node

    if isinstance(value, list):
        for item in value:
            node.append(_dict_to_element("ITEM", item))
        return node

    if value is None:
        node.text = ""
    elif isinstance(value, bool):
        node.text = "true" if value else "false"
    else:
        node.text = str(value)

    return node


def _load_xml(raw: bytes) -> ET.Element:
    """Charge un inventaire XML.

    Args:
        raw: Contenu brut du fichier inventaire.

    Returns:
        Racine XML parsee.
    """
    try:
        return ET.fromstring(raw)
    except ET.ParseError as exc:
        raise ValueError(f"XML invalide: {exc}") from exc


def _extract_xml_text_value(raw_text: str, tag: str) -> str:
    """Extrait une valeur simple <TAG>value</TAG> en mode degradation.

    Args:
        raw_text: Texte XML brut.
        tag: Balise a rechercher.

    Returns:
        Valeur trouvee, ou chaine vide.
    """
    match = re.search(rf"<{tag}>(.*?)</{tag}>", raw_text, flags=re.IGNORECASE | re.DOTALL)
    if not match:
        return ""
    return (match.group(1) or "").strip()


def _recover_xml_best_effort(raw: bytes) -> ET.Element:
    """Reconstruit un inventaire XML partiel en ignorant les sections cassees.

    Args:
        raw: Contenu XML brut potentiellement corrompu.

    Returns:
        Arbre XML partiel recuperable.
    """
    text = raw.decode("utf-8", errors="ignore")
    content = ET.Element("CONTENT")

    # Preserve les metadonnees globales avant de parser les sections detaillees.
    for scalar in ("DEVICEID", "VERSIONCLIENT", "VERSIONPROVIDER"):
        value = _extract_xml_text_value(text, scalar)
        if value:
            node = ET.Element(scalar)
            node.text = value
            content.append(node)

    section_tags = [
        "META",
        "HARDWARE",
        "BIOS",
        "CPUS",
        "STORAGES",
        "SOUNDS",
        "BATTERIES",
        "OPERATINGSYSTEM",
        "SOFTWARES",
        "NETWORKS",
        "PRINTERS",
        "USBDEVICES",
        "INPUTS",
        "MEMORIES",
        "CONTROLLERS",
        "DRIVES",
        "ENVS",
        "FIREWALL",
        "LOCAL_USERS",
        "LOCAL_GROUPS",
        "PROCESSES",
    ]

    for tag in section_tags:
        # Le parsing par blocs limite l'impact d'une section XML corrompue.
        pattern = re.compile(rf"<{tag}(?:\s+[^>]*)?>.*?</{tag}>", re.IGNORECASE | re.DOTALL)
        for block in pattern.findall(text):
            try:
                parsed = ET.fromstring(block)
            except ET.ParseError:
                continue
            content.append(parsed)

    if list(content):
        return content

    raise ValueError("XML invalide et aucune section recuperable en mode best-effort")


def _load_json_best_effort(raw: bytes) -> ET.Element:
    """Tente de charger un JSON partiel en supprimant la fin cassee.

    Args:
        raw: Contenu JSON brut potentiellement tronque.

    Returns:
        Arbre XML interne reconstruit depuis le JSON.
    """
    text = raw.decode("utf-8", errors="ignore")
    decoder = json.JSONDecoder()
    for end in range(len(text), 1, -1):
        candidate = text[:end].rstrip()
        if not candidate:
            continue
        try:
            payload, idx = decoder.raw_decode(candidate)
        except json.JSONDecodeError:
            continue
        if idx <= 0:
            continue
        if isinstance(payload, dict) and len(payload) == 1:
            root_tag, root_value = next(iter(payload.items()))
            return _dict_to_element(str(root_tag), root_value)
        return _dict_to_element("INVENTORY", payload)

    # Fallback pour JSON tronque: nettoyage de fin puis reequilibrage simple.
    candidate = text.strip()
    if candidate:
        candidate = re.sub(r",\s*$", "", candidate)
        candidate = re.sub(r",\s*\"[^\"]*\"\s*:\s*$", "", candidate)
        candidate = re.sub(r"\"[^\"]*\"\s*:\s*$", "", candidate)

        opens_obj = candidate.count("{")
        closes_obj = candidate.count("}")
        opens_arr = candidate.count("[")
        closes_arr = candidate.count("]")

        if closes_arr < opens_arr:
            candidate += "]" * (opens_arr - closes_arr)
        if closes_obj < opens_obj:
            candidate += "}" * (opens_obj - closes_obj)

        try:
            payload = json.loads(candidate)
            if isinstance(payload, dict) and len(payload) == 1:
                root_tag, root_value = next(iter(payload.items()))
                return _dict_to_element(str(root_tag), root_value)
            return _dict_to_element("INVENTORY", payload)
        except json.JSONDecodeError:
            pass

    raise ValueError("JSON invalide et non recuperable en mode best-effort")


def _load_yaml_best_effort(raw: bytes) -> ET.Element:
    """Tente de charger un YAML partiel en supprimant la fin cassee.

    Args:
        raw: Contenu YAML brut potentiellement tronque.

    Returns:
        Arbre XML interne reconstruit depuis le YAML.
    """
    try:
        import yaml  # type: ignore
    except ModuleNotFoundError as exc:
        raise RuntimeError("Support YAML indisponible. Installez 'pyyaml'.") from exc

    text = raw.decode("utf-8", errors="ignore")
    for end in range(len(text), 1, -1):
        candidate = text[:end].rstrip()
        if not candidate:
            continue
        try:
            payload = yaml.safe_load(candidate)
        except Exception:
            continue
        if payload is None:
            continue
        if isinstance(payload, dict) and len(payload) == 1:
            root_tag, root_value = next(iter(payload.items()))
            return _dict_to_element(str(root_tag), root_value)
        return _dict_to_element("INVENTORY", payload)
    raise ValueError("YAML invalide et non recuperable en mode best-effort")


def _load_json(raw: bytes) -> ET.Element:
    """Charge un inventaire JSON en le convertissant vers l'arbre interne.

    Args:
        raw: Contenu JSON brut.

    Returns:
        Arbre XML interne.
    """
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"JSON invalide: {exc}") from exc

    if isinstance(payload, dict) and len(payload) == 1:
        root_tag, root_value = next(iter(payload.items()))
        return _dict_to_element(str(root_tag), root_value)

    return _dict_to_element("INVENTORY", payload)


def _load_yaml(raw: bytes) -> ET.Element:
    """Charge un inventaire YAML en le convertissant vers l'arbre interne.

    Args:
        raw: Contenu YAML brut.

    Returns:
        Arbre XML interne.
    """
    try:
        import yaml  # type: ignore
    except ModuleNotFoundError as exc:
        raise RuntimeError("Support YAML indisponible. Installez 'pyyaml'.") from exc

    try:
        payload = yaml.safe_load(raw.decode("utf-8"))
    except Exception as exc:  # pragma: no cover - depend du parseur YAML installe
        raise ValueError(f"YAML invalide: {exc}") from exc

    if isinstance(payload, dict) and len(payload) == 1:
        root_tag, root_value = next(iter(payload.items()))
        return _dict_to_element(str(root_tag), root_value)

    return _dict_to_element("INVENTORY", payload)


def _load_inventory_from_bytes(
    raw: bytes,
    format_hint: str | None = None,
    best_effort: bool = False,
) -> ET.Element:
    """Charge un inventaire depuis des bytes avec detection/indice de format.

    Args:
        raw: Contenu brut de l'inventaire.
        format_hint: Indice de format optionnel (xml/json/yaml).
        best_effort: Active les strategies de recuperation partielle.

    Returns:
        Arbre XML interne detecte/parse.
    """
    hint = (format_hint or "").strip().lower()
    # Si le hint est fourni, il est prioritaire pour eviter les faux positifs.
    if hint in {"xml", ".xml"}:
        try:
            return _load_xml(raw)
        except ValueError:
            if best_effort:
                return _recover_xml_best_effort(raw)
            raise
    if hint in {"json", ".json"}:
        try:
            return _load_json(raw)
        except ValueError:
            if best_effort:
                return _load_json_best_effort(raw)
            raise
    if hint in {"yaml", "yml", ".yaml", ".yml"}:
        try:
            return _load_yaml(raw)
        except ValueError:
            if best_effort:
                return _load_yaml_best_effort(raw)
            raise

    # Auto-detection ordonnee: XML puis JSON puis YAML.
    for loader in (_load_xml, _load_json, _load_yaml):
        try:
            return loader(raw)
        except (RuntimeError, ValueError):
            continue

    if best_effort:
        for loader in (_recover_xml_best_effort, _load_json_best_effort, _load_yaml_best_effort):
            try:
                return loader(raw)
            except (RuntimeError, ValueError):
                continue

    raise ValueError("Impossible de detecter le format. Precisez format_hint (xml/json/yaml).")


def load_inventory(inventory_path: Path) -> ET.Element:
    """Charge un inventaire XML, JSON ou YAML et retourne l'arbre interne unifie.

    Args:
        inventory_path: Chemin du fichier inventaire.

    Returns:
        Arbre XML interne unifie.
    """
    if not inventory_path.exists() or not inventory_path.is_file():
        raise FileNotFoundError(f"Fichier inventaire introuvable: {inventory_path}")

    raw = inventory_path.read_bytes()
    suffix = inventory_path.suffix.lower()

    if suffix == ".xml":
        return _load_xml(raw)
    if suffix == ".json":
        return _load_json(raw)
    if suffix in {".yml", ".yaml"}:
        return _load_yaml(raw)

    raise ValueError(
        "Format non supporte. Utilisez un fichier .xml, .json, .yml ou .yaml"
    )


def load_inventory_source(
    source: Any,
    format_hint: str | None = None,
    best_effort: bool = False,
) -> ET.Element:
    """Charge un inventaire depuis un fichier, une variable texte/bytes, un dict/list ou un Element.

    Parametres supportes pour source:
    - Path ou chemin (str) vers fichier existant
    - str contenant le contenu brut XML/JSON/YAML
    - bytes contenant le contenu brut XML/JSON/YAML
    - dict/list Python (style JSON/YAML deja deserialise)
    - xml.etree.ElementTree.Element

    Args:
        source: Source inventaire (fichier, texte, bytes, dict/list, Element).
        format_hint: Indice de format optionnel.
        best_effort: Active les strategies de recuperation partielle.

    Returns:
        Arbre XML interne unifie.
    """
    if isinstance(source, ET.Element):
        return source

    if isinstance(source, Path):
        raw = source.read_bytes()
        return _load_inventory_from_bytes(raw, source.suffix, best_effort=best_effort)

    if isinstance(source, dict) or isinstance(source, list):
        return _dict_to_element("INVENTORY", source)

    if isinstance(source, (bytes, bytearray)):
        return _load_inventory_from_bytes(bytes(source), format_hint, best_effort=best_effort)

    if isinstance(source, str):
        candidate = Path(source).expanduser()
        if candidate.exists() and candidate.is_file():
            raw = candidate.read_bytes()
            return _load_inventory_from_bytes(raw, candidate.suffix, best_effort=best_effort)
        return _load_inventory_from_bytes(
            source.encode("utf-8"),
            format_hint,
            best_effort=best_effort,
        )

    raise TypeError("source doit etre Path|str|bytes|dict|list|Element")


def load_xml(xml_path: Path) -> ET.Element:
    """Compatibilite historique: charge un inventaire XML.

    Args:
        xml_path: Chemin vers un inventaire XML.

    Returns:
        Arbre XML parse.
    """
    return load_inventory(xml_path)


def parse_inventory(
    source: Any,
    allow_missing_ocsid: bool,
    format_hint: str | None = None,
    best_effort: bool = False,
) -> list[MachineRecord]:
    """API haut niveau: parse un inventaire depuis un fichier ou une variable.

    Args:
        source: Source inventaire (Path, texte, bytes, dict/list, Element).
        allow_missing_ocsid: Autorise un fallback OCSID sur DEVICEID.
        format_hint: Indice de format optionnel.
        best_effort: Active les strategies de recuperation partielle.

    Returns:
        Liste de machines normalisees.
    """
    root = load_inventory_source(source, format_hint=format_hint, best_effort=best_effort)
    return extract_records(root, allow_missing_ocsid=allow_missing_ocsid)


def _norm(text: str | None) -> str:
    """Nettoie une valeur texte XML.

    Args:
        text: Valeur texte eventuelle.

    Returns:
        Texte nettoye ou chaine vide.
    """
    if text is None:
        return ""
    return text.strip()


def _find_text(node: ET.Element, paths: Iterable[str]) -> str:
    """Retourne le premier texte non vide trouve pour une liste de chemins XPath simples.

    Args:
        node: Noeud XML de recherche.
        paths: Chemins XPath simples testes dans l'ordre.

    Returns:
        Premier texte non vide trouve, ou chaine vide.
    """
    for path in paths:
        found = node.find(path)
        if found is not None and _norm(found.text):
            return _norm(found.text)
    return ""


def _machine_nodes(root: ET.Element) -> list[ET.Element]:
    """Detecte les noeuds representant une machine dans des structures XML variees.

    Args:
        root: Racine XML de l'inventaire.

    Returns:
        Liste des noeuds machine detectes.
    """
    # On essaie d'abord les balises explicites les plus courantes.
    candidates = root.findall(".//COMPUTER")
    if not candidates:
        candidates = root.findall(".//MACHINE")
    if not candidates:
        candidates = root.findall(".//HOST")

    if not candidates:
        has_meta = root.find("META") is not None
        has_hardware = root.find("HARDWARE") is not None
        if has_meta or has_hardware:
            return [root]

    # Fallback tolerant pour structures JSON/YAML converties en pseudo-XML.
    if not candidates:
        detected: list[ET.Element] = []
        seen_ids: set[int] = set()
        for node in root.findall(".//*"):
            has_meta = node.find("META") is not None
            has_hardware = node.find("HARDWARE") is not None
            if has_meta or has_hardware:
                identity = id(node)
                if identity not in seen_ids:
                    detected.append(node)
                    seen_ids.add(identity)
        if detected:
            return detected

    # Format frequent des agents FusionInventory/OCS: REQUEST/CONTENT
    if not candidates:
        for content in root.findall("CONTENT"):
            if content.find("HARDWARE") is not None or content.find("BIOS") is not None:
                candidates.append(content)

    return candidates


def _global_deviceid(root: ET.Element) -> str:
    """Recupere un DEVICEID global dans les formats ou il n'est pas dans CONTENT.

    Args:
        root: Racine XML de l'inventaire.

    Returns:
        DEVICEID global, ou chaine vide.
    """
    deviceid = _find_text(
        root,
        ["DEVICEID", "HARDWARE/DEVICEID", "REQUEST/DEVICEID", "CONTENT/DEVICEID"],
    )
    return deviceid


def _global_versionclient(root: ET.Element) -> str:
    """Recupere VERSIONCLIENT global selon les variantes de XML.

    Args:
        root: Racine XML de l'inventaire.

    Returns:
        VERSIONCLIENT global, ou chaine vide.
    """
    return _find_text(root, ["VERSIONCLIENT", "REQUEST/VERSIONCLIENT", "QUERY/VERSIONCLIENT"])


def _global_versionprovider(root: ET.Element) -> str:
    """Recupere VERSIONPROVIDER global selon les variantes de XML.

    Args:
        root: Racine XML de l'inventaire.

    Returns:
        VERSIONPROVIDER global, ou chaine vide.
    """
    return _find_text(root, ["VERSIONPROVIDER", "REQUEST/VERSIONPROVIDER", "QUERY/VERSIONPROVIDER"])


def _extract_softwares(node: ET.Element) -> list[SoftwareRecord]:
    """Extrait les logiciels d'un noeud machine.

    Args:
        node: Noeud XML representant une machine.

    Returns:
        Liste des logiciels normalises.
    """
    softwares: list[SoftwareRecord] = []

    software_nodes = node.findall("SOFTWARES/SOFTWARE")

    # Certains exports XML exposent SOFTWARES directement sans sous-noeud SOFTWARE.
    if not software_nodes:
        for sw_container in node.findall("SOFTWARES"):
            has_direct_name = sw_container.find("NAME") is not None
            if has_direct_name:
                software_nodes.append(sw_container)
            else:
                for child in list(sw_container):
                    if child.find("NAME") is not None:
                        software_nodes.append(child)

    for sw in software_nodes:
        name = _find_text(sw, ["NAME", "SOFTNAME"])
        if not name:
            continue

        softwares.append(
            SoftwareRecord(
                name=name,
                version=_find_text(sw, ["VERSION"]),
                publisher=_find_text(sw, ["PUBLISHER", "EDITOR"]),
                comments=_find_text(sw, ["COMMENTS", "COMMENT"]),
                install_date=_find_text(sw, ["INSTALLDATE", "INSTALL_DATE"]),
            )
        )

    return softwares


def _extract_network_interfaces(node: ET.Element) -> list[NetworkInterfaceRecord]:
    """Extrait les interfaces reseau d'un noeud machine.

    Args:
        node: Noeud XML representant une machine.

    Returns:
        Liste des interfaces reseau normalisees.
    """
    raw_network_nodes = node.findall("NETWORKS/NETWORK")

    if not raw_network_nodes:
        for net_container in node.findall("NETWORKS"):
            has_direct_mac = net_container.find("MACADDR") is not None
            if has_direct_mac:
                raw_network_nodes.append(net_container)
            else:
                for child in list(net_container):
                    if child.find("MACADDR") is not None or child.find("IPADDRESS") is not None:
                        raw_network_nodes.append(child)

    grouped: dict[str, NetworkInterfaceRecord] = {}
    for net in raw_network_nodes:
        mac = _find_text(net, ["MACADDR", "MAC", "MACADDRESS"]).upper()
        name = _find_text(net, ["DESCRIPTION", "NAME", "INTERFACE"])
        iface_type = _find_text(net, ["TYPE", "TYPEMIB"])
        speed = _find_text(net, ["SPEED"])
        ip = _find_text(net, ["IPADDRESS", "IP"])
        ip_mask = _find_text(net, ["IPMASK", "MASK"])
        ip_gateway = _find_text(net, ["IPGATEWAY", "GATEWAY"])
        ip_subnet = _find_text(net, ["IPSUBNET", "SUBNET"])

        key = mac or name or f"iface-{len(grouped) + 1}"
        if key not in grouped:
            grouped[key] = NetworkInterfaceRecord(
                name=name,
                mac=mac,
                iface_type=iface_type,
                speed=speed,
                ip_mask=ip_mask,
                ip_gateway=ip_gateway,
                ip_subnet=ip_subnet,
                ips=[],
            )

        if ip and ip not in grouped[key].ips:
            grouped[key].ips.append(ip)

        # Comble les champs manquants si un doublon apporte plus d'infos.
        if not grouped[key].name and name:
            grouped[key].name = name
        if not grouped[key].iface_type and iface_type:
            grouped[key].iface_type = iface_type
        if not grouped[key].speed and speed:
            grouped[key].speed = speed
        if not grouped[key].ip_mask and ip_mask:
            grouped[key].ip_mask = ip_mask
        if not grouped[key].ip_gateway and ip_gateway:
            grouped[key].ip_gateway = ip_gateway
        if not grouped[key].ip_subnet and ip_subnet:
            grouped[key].ip_subnet = ip_subnet

    return list(grouped.values())


def _children_to_dict(node: ET.Element) -> dict[str, str]:
    """Convertit les enfants directs en dict (texte brut).

    Args:
        node: Noeud XML parent.

    Returns:
        Dictionnaire cle=tag, valeur=texte normalise.
    """
    data: dict[str, str] = {}
    for child in list(node):
        key = (child.tag or "").strip().upper()
        if not key:
            continue
        data[key] = _norm(child.text)
    return data


def _to_int(value: str) -> int:
    """Convertit en entier, 0 si invalide.

    Args:
        value: Valeur texte candidate.

    Returns:
        Entier converti, ou 0 en cas d'echec.
    """
    try:
        return int((value or "").strip())
    except (TypeError, ValueError):
        return 0


def _extract_bios(node: ET.Element) -> list[BiosRecord]:
    """Extrait les informations BIOS du noeud XML.

    Args:
        node: Noeud XML representant une machine.

    Returns:
        Liste des BIOS normalises.
    """
    items: list[BiosRecord] = []
    for bios in node.findall("BIOS"):
        raw = _children_to_dict(bios)
        items.append(
            BiosRecord(
                ssn=raw.get("SSN", "") or raw.get("MSN", ""),
                bmanufacturer=raw.get("BMANUFACTURER", ""),
                bversion=raw.get("BVERSION", ""),
                smodel=raw.get("SMODEL", ""),
                mmodel=raw.get("MMODEL", ""),
                raw=raw,
            )
        )
    return items


def _extract_cpus(node: ET.Element) -> list[CpuRecord]:
    """Extrait les informations processeurs du noeud XML.

    Args:
        node: Noeud XML representant une machine.

    Returns:
        Liste des CPU normalises.
    """
    items: list[CpuRecord] = []
    for cpu in node.findall("CPUS"):
        raw = _children_to_dict(cpu)
        items.append(
            CpuRecord(
                name=raw.get("NAME", ""),
                manufacturer=raw.get("MANUFACTURER", ""),
                familyname=raw.get("FAMILYNAME", ""),
                core=_to_int(raw.get("CORE", "0")),
                thread=_to_int(raw.get("THREAD", "0")),
                raw=raw,
            )
        )
    return items


def _extract_storages(node: ET.Element) -> list[StorageRecord]:
    """Extrait les informations de stockage du noeud XML.

    Args:
        node: Noeud XML representant une machine.

    Returns:
        Liste des stockages normalises.
    """
    items: list[StorageRecord] = []
    for storage in node.findall("STORAGES"):
        raw = _children_to_dict(storage)
        items.append(
            StorageRecord(
                name=raw.get("NAME", ""),
                model=raw.get("MODEL", ""),
                manufacturer=raw.get("MANUFACTURER", ""),
                serialnumber=raw.get("SERIALNUMBER", ""),
                diskgb=_to_int(raw.get("DISKSIZE", "0")),
                storage_type=raw.get("TYPE", ""),
                raw=raw,
            )
        )
    return items


def _extract_sounds(node: ET.Element) -> list[SoundRecord]:
    """Extrait les informations de cartes son du noeud XML.

    Args:
        node: Noeud XML representant une machine.

    Returns:
        Liste des cartes son normalisees.
    """
    items: list[SoundRecord] = []
    for sound in node.findall("SOUNDS"):
        raw = _children_to_dict(sound)
        items.append(
            SoundRecord(
                name=raw.get("NAME", ""),
                manufacturer=raw.get("MANUFACTURER", ""),
                description=raw.get("DESCRIPTION", ""),
                raw=raw,
            )
        )
    return items


def _extract_batteries(node: ET.Element) -> list[BatteryRecord]:
    """Extrait les informations de batteries du noeud XML.

    Args:
        node: Noeud XML representant une machine.

    Returns:
        Liste des batteries normalisees.
    """
    items: list[BatteryRecord] = []
    for battery in node.findall("BATTERIES"):
        raw = _children_to_dict(battery)
        items.append(
            BatteryRecord(
                name=raw.get("NAME", ""),
                manufacturer=raw.get("MANUFACTURER", ""),
                serial=raw.get("SERIAL", ""),
                chemistry=raw.get("CHEMISTRY", ""),
                capacity=_to_int(raw.get("CAPACITY", "0")),
                real_capacity=_to_int(raw.get("REAL_CAPACITY", "0")),
                voltage=_to_int(raw.get("VOLTAGE", "0")),
                raw=raw,
            )
        )
    return items


def _extract_operating_systems(node: ET.Element) -> list[OperatingSystemRecord]:
    """Extrait les informations OS.

    Args:
        node: Noeud XML representant une machine.

    Returns:
        Liste des OS normalises.
    """
    items: list[OperatingSystemRecord] = []
    for osnode in node.findall("OPERATINGSYSTEM"):
        raw = _children_to_dict(osnode)
        items.append(
            OperatingSystemRecord(
                name=raw.get("NAME", ""),
                version=raw.get("VERSION", ""),
                architecture=raw.get("ARCH", ""),
                kernel_name=raw.get("KERNEL_NAME", ""),
                kernel_version=raw.get("KERNEL_VERSION", ""),
                full_name=raw.get("FULL_NAME", ""),
                raw=raw,
            )
        )
    return items


def _extract_raw_sections(
    node: ET.Element,
    deviceid: str,
    versionclient: str,
    versionprovider: str,
) -> dict[str, list[dict[str, str]]]:
    """Extrait generiquement les sections XML de premier niveau pour ne rien perdre.

    Args:
        node: Noeud XML representant une machine.
        deviceid: DEVICEID resolu pour la machine.
        versionclient: VERSIONCLIENT resolu pour la machine.
        versionprovider: VERSIONPROVIDER resolu pour la machine.

    Returns:
        Dictionnaire des sections brutes indexees par nom de section.
    """
    ignored_tags = {"DEVICEID", "VERSIONCLIENT", "VERSIONPROVIDER"}
    result: dict[str, list[dict[str, str]]] = {}

    for child in list(node):
        section = (child.tag or "").strip().upper()
        if not section or section in ignored_tags:
            continue

        result.setdefault(section, []).append(_children_to_dict(child))

    metadata = {
        "DEVICEID": deviceid,
        "VERSIONCLIENT": versionclient,
        "VERSIONPROVIDER": versionprovider,
    }
    if any(metadata.values()):
        result["METADATA"] = [metadata]

    return result


def _extract_inventory_tag(node: ET.Element) -> str:
    """Extrait le tag inventaire depuis les variantes XML supportees.

    Args:
        node: Noeud XML representant une machine.

    Returns:
        Valeur de tag, ou chaine vide si absente.
    """
    tag = _find_text(node, ["META/TAG", "ACCOUNTINFO/TAG", "TAG"])
    if tag:
        return tag

    # Support des payloads de type:
    # <ACCOUNTINFO><KEYNAME>TAG</KEYNAME><KEYVALUE>123456</KEYVALUE></ACCOUNTINFO>
    for accountinfo in node.findall("ACCOUNTINFO"):
        keyname = _find_text(accountinfo, ["KEYNAME"]).upper()
        if keyname != "TAG":
            continue
        keyvalue = _find_text(accountinfo, ["KEYVALUE"])
        if keyvalue:
            return keyvalue

    return ""


def extract_records(root: ET.Element, allow_missing_ocsid: bool) -> list[MachineRecord]:
    """Extrait les postes du XML dans un format normalise.

    Args:
        root: Racine XML de l'inventaire.
        allow_missing_ocsid: Autorise le fallback OCSID sur DEVICEID.

    Returns:
        Liste des machines normalisees.
    """
    records: list[MachineRecord] = []
    global_deviceid = _global_deviceid(root)
    global_versionclient = _global_versionclient(root)
    global_versionprovider = _global_versionprovider(root)

    for node in _machine_nodes(root):
        ocsid = _find_text(node, ["META/ID", "META/DATABASEID", "ID", "DATABASEID"])
        deviceid = _find_text(node, ["META/DEVICEID", "HARDWARE/DEVICEID", "DEVICEID"]) or global_deviceid
        versionclient = _find_text(node, ["META/VERSIONCLIENT", "VERSIONCLIENT"]) or global_versionclient
        versionprovider = _find_text(node, ["META/VERSIONPROVIDER", "VERSIONPROVIDER"]) or global_versionprovider
        name = _find_text(node, ["META/NAME", "HARDWARE/NAME", "NAME", "HARDWARE/USERID"])
        serial = _find_text(node, ["BIOS/SSN", "BIOS/SERIAL", "SSN", "SERIAL"])
        tag = _extract_inventory_tag(node)

        if not ocsid and allow_missing_ocsid:
            ocsid = deviceid

        if not ocsid:
            continue

        if not name:
            name = f"ocs-{ocsid}"

        records.append(
            MachineRecord(
                ocsid=ocsid,
                name=name,
                deviceid=deviceid,
                versionclient=versionclient,
                versionprovider=versionprovider,
                serial=serial,
                tag=tag,
                softwares=_extract_softwares(node),
                network_interfaces=_extract_network_interfaces(node),
                bios=_extract_bios(node),
                cpus=_extract_cpus(node),
                storages=_extract_storages(node),
                sounds=_extract_sounds(node),
                batteries=_extract_batteries(node),
                operating_systems=_extract_operating_systems(node),
                raw_sections=_extract_raw_sections(
                    node,
                    deviceid=deviceid,
                    versionclient=versionclient,
                    versionprovider=versionprovider,
                ),
            )
        )
    return records


def _parse_args() -> argparse.Namespace:
    """Arguments du mode programme autonome.

    Args:
        Aucun.

    Returns:
        Namespace argparse avec options du parseur autonome.
    """
    parser = argparse.ArgumentParser(
        description="Parse un inventaire XML/JSON/YAML et affiche la structure normalisee"
    )
    parser.add_argument("inventory_path", help="Chemin d'un inventaire XML, JSON ou YAML")
    parser.add_argument(
        "--allow-missing-ocsid",
        action=argparse.BooleanOptionalAction,
        default=False,
        help="Autorise DEVICEID comme fallback si OCSID absent",
    )
    parser.add_argument(
        "--best-effort",
        action=argparse.BooleanOptionalAction,
        default=False,
        help="Ignore les parties mal formees quand une recuperation partielle est possible",
    )
    return parser.parse_args()


def main() -> int:
    """Point d'entree CLI du parseur autonome.

    Args:
        Aucun.

    Returns:
        Code de sortie processus (0/2/3).
    """
    args = _parse_args()
    inventory_path = Path(args.inventory_path).expanduser().resolve()

    try:
        records = parse_inventory(
            inventory_path,
            allow_missing_ocsid=args.allow_missing_ocsid,
            best_effort=args.best_effort,
        )
    except (FileNotFoundError, RuntimeError, ValueError) as exc:
        print(f"ERREUR: {exc}", file=sys.stderr)
        return 2

    print(
        json.dumps(
            {
                "status": "ok" if records else "empty",
                "inventory_path": str(inventory_path),
                "machines_detected": len(records),
                "sample": asdict(records[0]) if records else None,
            },
            ensure_ascii=True,
        )
    )
    return 0 if records else 3


if __name__ == "__main__":
    raise SystemExit(main())
