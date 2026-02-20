#!/usr/bin/env python3
# -*- coding: utf-8; -*-
# SPDX-FileCopyrightText: 2016-2023 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-3.0-or-later
# file pulse_xmpp_agent/lib/uuid_deterministic.py
import socket
import uuid
import subprocess
import re
import platform

class DeterministicUUID:
    @staticmethod
    def get_mac_address():
        """Récupère l'adresse MAC de la première interface réseau active."""
        system = platform.system()
        try:
            if system == "Linux":
                result = subprocess.check_output(["ip", "link", "show"]).decode("utf-8")
                macs = re.findall(r"link/ether (\w\w:\w\w:\w\w:\w\w:\w\w:\w\w)", result)
                return macs[0] if macs else "00:00:00:00:00:00"
            elif system == "Darwin":  # macOS
                result = subprocess.check_output(["networksetup", "-listallhardwareports"]).decode("utf-8")
                macs = re.findall(r"Ethernet Address: (\w\w:\w\w:\w\w:\w\w:\w\w:\w\w)", result)
                return macs[0] if macs else "00:00:00:00:00:00"
            elif system == "Windows":
                result = subprocess.check_output(["getmac", "/V", "/FO", "CSV"]).decode("utf-8")
                macs = re.findall(r"(\w\w-\w\w-\w\w-\w\w-\w\w-\w\w)", result)
                return macs[0].replace("-", ":") if macs else "00:00:00:00:00:00"
            else:
                return "00:00:00:00:00:00"
        except Exception:
            return "00:00:00:00:00:00"

    @staticmethod
    def get_bios_uuid():
        system = platform.system()
        try:
            if system == "Windows":
                # Utilisation de PowerShell pour récupérer l'UUID via CIM
                result = subprocess.check_output(
                    ["powershell", "-command",
                    "Get-CimInstance -ClassName Win32_ComputerSystemProduct | Select-Object -ExpandProperty UUID"],
                    stderr=subprocess.DEVNULL
                ).decode("utf-8").strip()
                return result if result else "default-bios-uuid"
            elif system == "Linux":
                return subprocess.check_output(
                    ["/usr/sbin/dmidecode", "-t", "system", "-s", "uuid"],
                    stderr=subprocess.DEVNULL
                ).decode("utf-8").strip()
            elif system == "Darwin":
                result = subprocess.check_output(
                    ["system_profiler", "SPHardwareDataType"],
                    stderr=subprocess.DEVNULL
                ).decode("utf-8")
                match = re.search(r"Hardware UUID: ([\w-]+)", result)
                return match.group(1) if match else "default-bios-uuid"
            else:
                return "default-bios-uuid"
        except Exception:
            return "default-bios-uuid"

    @staticmethod
    def get_deterministic_uuid():
        """Génère un UUID déterministe basé sur le BIOS UUID, l'adresse MAC et le nom d'hôte."""
        hostname = socket.gethostname()
        bios_uuid = DeterministicUUID.get_bios_uuid()
        mac_address = DeterministicUUID.get_mac_address()

        # Chaîne unique combinant les 3 éléments
        unique_string = f"{bios_uuid}-{mac_address}-{hostname}"

        # Hachage SHA-1 pour générer l'UUID
        namespace = uuid.UUID("12345678-1234-5678-1234-567812345678")
        return str(uuid.uuid5(namespace, unique_string))

# Exemple d'utilisation
if __name__ == "__main__":
    print(DeterministicUUID.get_deterministic_uuid())
