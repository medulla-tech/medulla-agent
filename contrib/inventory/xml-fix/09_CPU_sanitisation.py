# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2024-2026 Medulla / Natsu, http://www.medulla-tech.io
# SPDX-License-Identifier: GPL-3.0-or-later


def xml_fix(xml):
    """
    Recherche:
        - REQUEST/CONTENT/CPUS/THREAD,
        - REQUEST/CONTENT/CPUS/STEPPING.
    et convertit la valeur en entier.
    """

    import xml.etree.cElementTree as ET

    root = ET.fromstring(xml)

    # Sanitize THREAD value (must be INT value)
    node = root.find("./CONTENT/CPUS/THREAD")

    if node is not None and node.text:
        try:
            value = float(node.text.strip())
            node.text = str(int(value))
        except ValueError:
            pass

    # Sanitize STEPPING value (must be INT value)
    node = root.find("./CONTENT/CPUS/STEPPING")

    if node is not None and node.text:
        try:
            value = int(node.text.strip())
            node.text = str(value)
        except ValueError:
            node.text = "0"
            pass

    return ET.tostring(root, encoding="unicode")
