# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2024-2026 Medulla / Natsu, http://www.medulla-tech.io 
# SPDX-License-Identifier: GPL-3.0-or-later


def xml_fix(xml):
    """
    Recherche REQUEST/CONTENT/CPUS/THREAD
    et convertit la valeur en entier.
    """

    import xml.etree.cElementTree as ET

    root = ET.fromstring(xml)

    node = root.find("./CONTENT/CPUS/THREAD")

    if node is not None and node.text:
        try:
            value = float(node.text.strip())
            node.text = str(int(value))
        except ValueError:
            pass

    return ET.tostring(root, encoding="unicode")
