# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2024-2026 Medulla / Natsu, http://www.medulla-tech.io
# SPDX-License-Identifier: GPL-3.0-or-later


def xml_fix(xml):
    """
    Corrections propres aux inventaires des machines Apple.

    Type de chassis manquant:
        GLPI Agent ne remonte pas REQUEST/CONTENT/HARDWARE/CHASSIS_TYPE sous
        macOS. Sans lui, GLPI ne donne aucun type a l'ordinateur, et Medulla
        ne retrouve pas la machine dans GLPI a l'enregistrement de l'agent
        (machine "non inventoriee"). On l'ajoute donc: "Laptop" pour un
        MacBook ou un Mac avec batterie, "Virtual Machine" pour un modele
        "VirtualMac...", "Desktop" sinon.
        Les machines virtuelles reconnues par GLPI Agent ne sont pas
        modifiees: leur type vient de VMSYSTEM.
    """

    import xml.etree.cElementTree as ET

    root = ET.fromstring(xml)

    manufacturer = root.findtext("./CONTENT/BIOS/SMANUFACTURER") or ""
    hardware = root.find("./CONTENT/HARDWARE")
    if not manufacturer.strip().lower().startswith("apple") or hardware is None:
        return xml

    # Type de chassis manquant
    vmsystem = (hardware.findtext("VMSYSTEM") or "").strip().lower()
    chassis = hardware.find("CHASSIS_TYPE")
    if vmsystem in ("", "physical") and (chassis is None or not (chassis.text or "").strip()):
        model = (root.findtext("./CONTENT/BIOS/SMODEL") or "").strip().lower()
        has_battery = root.find("./CONTENT/BATTERIES") is not None
        if chassis is None:
            chassis = ET.SubElement(hardware, "CHASSIS_TYPE")
        if model.startswith("virtualmac"):
            # VM macOS que GLPI Agent declare "Physical"
            chassis.text = "Virtual Machine"
        elif model.startswith("macbook") or has_battery:
            chassis.text = "Laptop"
        else:
            chassis.text = "Desktop"

    return ET.tostring(root, encoding="unicode")
