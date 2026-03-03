# -*- coding: utf-8 -*-
# SPDX-FileCopyrightText: 2024 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-3.0-or-later

# Fix for ARM64 CPUs where STEPPING is not a valid integer.
# GLPI expects an integer for stepping, but ARM64 processors
# may report a string like "Revision" or an empty value.

import re


def xml_fix(xml):
    def fix_stepping(match):
        value = match.group(1).strip()
        if value == "" or not value.isdigit():
            return "<STEPPING>0</STEPPING>"
        return match.group(0)

    xml = re.sub(r'<STEPPING>(.*?)</STEPPING>', fix_stepping, xml)
    xml = re.sub(r'<STEPPING/>', '<STEPPING>0</STEPPING>', xml)
    return xml
