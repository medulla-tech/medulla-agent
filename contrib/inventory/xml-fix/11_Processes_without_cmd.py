# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2024-2026 Medulla / Natsu, http://www.medulla-tech.io
# SPDX-License-Identifier: GPL-3.0-or-later


def xml_fix(xml):
    """
    Supprime les entrees REQUEST/CONTENT/PROCESSES sans CMD (ou sans PID / USER).
    GLPI 10 refuse sinon tout l'inventaire (HTTP 400 "Required property missing: cmd").
    """
    import xml.etree.ElementTree as ET

    if isinstance(xml, bytes):
        xml = xml.decode("utf-8")
    root = ET.fromstring(xml)
    content = root.find("./CONTENT")
    if content is None:
        return xml
    retires = 0
    for proc in list(content.findall("PROCESSES")):
        for champ in ("CMD", "PID", "USER"):
            noeud = proc.find(champ)
            if noeud is None or not (noeud.text or "").strip():
                content.remove(proc)
                retires += 1
                break
    if not retires:
        return xml
    return ET.tostring(root, encoding="unicode")
