#!/usr/bin/python3
# -*- coding: utf-8; -*-
# SPDX-FileCopyrightText: 2016-2023 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-3.0-or-later

import netifaces
import subprocess

import platform
import logging
import re
import socket
import psutil
import os
import sys

# from distutils.util import strtobool
from lib.utils import simplecommand, powerschellscript1ps1
from . import utils

import traceback

if sys.platform.startswith("win"):
    import wmi

logger = logging.getLogger()


class networkagentinfo:
    def __init__(self, sessionid, action="resultgetinfo", param=[]):
        self.sessionid = sessionid
        self.action = action
        self.messagejson = {}
        self.networkobjet(self.sessionid, self.action)
        for d in self.messagejson["listipinfo"]:
            d["macnotshortened"] = d["macaddress"]
            d["macaddress"] = self.reduction_mac(d["macaddress"])
        if len(param) != 0 and len(self.messagejson["listipinfo"]) != 0:
            dd = []
            param1 = list(map(self.reduction_mac, param))
            for d in self.messagejson["listipinfo"]:
                e = [s for s in param1 if d["macaddress"] == s]
                if e:
                    dd.append(d)
            self.messagejson["listipinfo"] = dd

    def reduction_mac(self, mac):
        mac = mac.lower()
        mac = mac.replace(":", "")
        mac = mac.replace("-", "")
        mac = mac.replace(" ", "")
        return mac

    def getuser(self):
        return list({users[0] for users in psutil.users()})

    def networkobjet(self, sessionid, action):
        self.messagejson = {
            "action": action,
            "sessionid": sessionid,
            "listdns": [],
            "listipinfo": [],
            "dhcp": "False",
            "dnshostname": "",
            "msg": platform.system(),
        }
        try:
            self.messagejson["users"] = self.getuser()
        except BaseException:
            self.messagejson["users"] = ["system"]

        if sys.platform.startswith("linux"):
            p = subprocess.Popen(
                "ps aux | grep dhclient | grep -v leases | grep -v grep | awk '{print $NF}'",
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
            )
            if sys.version_info[0] == 3:
                result = [x.decode("utf-8") for x in p.stdout.readlines()]
            else:
                result = p.stdout.readlines()
            self.messagejson["dhcp"] = "True" if len(result) > 0 else "False"
            self.messagejson["listdns"] = self.listdnslinux()
            self.messagejson["listipinfo"] = self.getLocalIipAddress()
            self.messagejson["dnshostname"] = platform.node()
            return self.messagejson

        elif sys.platform.startswith("win"):
            """revoit objet reseau windows"""
            # interface active only
            # pythoncom.CoInitialize()
            # try:
            # wmi_obj = wmi.WMI()
            # wmi_sql = "select * from Win32_NetworkAdapterConfiguration where IPEnabled=TRUE"
            # wmi_out = wmi_obj.query(wmi_sql)
            # finally:
            # pythoncom.CoUninitialize()
            # for dev in wmi_out:
            # objnet = {}
            # objnet['macaddress'] = dev.MACAddress
            # objnet['ipaddress'] = dev.IPAddress[0]
            # try:
            # objnet['gateway'] = dev.DefaultIPGateway[0]
            # except BaseException:
            # objnet['gateway'] = ""
            # objnet['mask'] = dev.IPSubnet[0]
            # objnet['dhcp'] = dev.DHCPEnabled
            # objnet['dhcpserver'] = dev.DHCPServer
            # self.messagejson['listipinfo'].append(objnet)
            # try:
            # self.messagejson['listdns'].append(
            # dev.DNSServerSearchOrder[0])
            # except BaseException:
            # pass
            # self.messagejson['dnshostname'] = dev.DNSHostName
            # self.messagejson['msg'] = platform.system()
            # all interface
            wmi_obj = wmi.WMI()
            wmi_sql = "select * from Win32_NetworkAdapterConfiguration"
            wmi_out = wmi_obj.query(wmi_sql)
            for dev in wmi_out:
                if dev.MACAddress is None:
                    continue
                objnet = {"macaddress": dev.MACAddress, "Description": dev.Description}
                try:
                    objnet["ipaddress"] = dev.IPAddress[0]
                except BaseException:
                    objnet["ipaddress"] = None
                try:
                    objnet["gateway"] = dev.DefaultIPGateway[0]
                except BaseException:
                    objnet["gateway"] = ""
                try:
                    objnet["mask"] = dev.IPSubnet[0]
                except BaseException:
                    objnet["mask"] = None
                try:
                    objnet["dhcp"] = dev.DHCPEnabled
                except BaseException:
                    objnet["dhcp"] = None
                try:
                    objnet["dhcpserver"] = dev.DHCPServer
                except BaseException:
                    objnet["dhcpserver"] = None
                self.messagejson["listipinfo"].append(objnet)
                try:
                    self.messagejson["listdns"].append(dev.DNSServerSearchOrder[0])
                except BaseException:
                    pass
                try:
                    self.messagejson["dnshostname"] = dev.DNSHostName
                except BaseException:
                    pass
            return self.messagejson
        elif sys.platform.startswith("darwin"):
            return self.MacOsNetworkInfo()
        else:
            self.messagejson["msg"] = f"system {sys.platform} : not managed yet"
            return self.messagejson

    def isIPValid(self, ipaddress):
        """
        This function tests the provided IP Address to see
        if it is a valid IP or not.
        Only IPv4 is supported.

        @param ipaddress: The ip address to test

        @rtype: Boolean. True if the ip adress is valid, False otherwise
        """
        try:
            socket.inet_aton(ipaddress)
            return True
        except socket.error:
            return False

    def IpDhcp(self):
        """
        This function provide the IP of the dhcp server used on the machine.
        """
        obj1 = {}
        system = ""
        ipdhcp = ""
        ipadress = ""
        p = subprocess.Popen(
            "cat /proc/1/comm",
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )
        result = p.stdout.readlines()
        if sys.version_info[0] == 3:
            system = result[0].decode("utf-8").rstrip("\n")
        else:
            system = result[0].rstrip("\n")

        """ Returns the list of ip gateways for linux interfaces """

        if system == "init":
            p = subprocess.Popen(
                "cat /var/log/syslog | grep -e DHCPACK | tail -n10 | awk '{print $(NF-2)\"@\" $NF}'",
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
            )
            arrayresult = p.stdout.readlines()
            if sys.version_info[0] == 3:
                result = [x.decode("utf-8").rstrip("\n") for x in arrayresult]
            else:
                result = [x.rstrip("\n") for x in arrayresult]
            for item in result:
                # result[i] = result[i].rstrip('\n')
                d = item.split("@")
                obj1[d[0]] = d[1]
        elif system == "systemd":
            p = subprocess.Popen(
                'journalctl | grep "dhclient\\["',
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
            )
            arrayresult = p.stdout.readlines()
            if sys.version_info[0] == 3:
                result = [x.decode("utf-8").rstrip("\n") for x in arrayresult]
            else:
                result = [x.rstrip("\n") for x in arrayresult]
            for i in result:
                # i = i.rstrip('\n')
                colonne = i.split(" ")
                if "DHCPACK" in i:
                    ipdhcp = ""
                    ipadress = ""
                    ipdhcp = colonne[-1:][0]
                elif "bound to" in i:
                    for z in colonne:
                        if self.isIPValid(z):
                            ipadress = z
                            if ipdhcp != "":
                                obj1[ipadress] = ipdhcp
                            break
                    ipdhcp = ""
                    ipadress = ""
                else:
                    continue
        return obj1

    @staticmethod
    def get_mac_address(ip):
        """
        Récupère l'adresse MAC associée à une adresse IPv4 en utilisant la commande 'ip' sous Linux.
        Args:
            ip (str): Adresse IPv4 pour laquelle vous souhaitez obtenir l'adresse MAC.
        Returns:
            str or None: L'adresse MAC associée à l'adresse IPv4, ou None si l'adresse MAC n'est pas trouvée.
        """
        try:
            # Vérifie le système d'exploitation
            current_os = platform.system().lower()
            if current_os == 'linux':
                # Utilise la commande 'ip' pour obtenir le nom de l'interface
                name_command = f"ip addr | grep 'inet {ip}' | awk '{{print($NF)}}'"
                interface_name = (
                    subprocess.check_output(name_command, shell=True, text=True).strip()
                )
                # Utilise la commande 'ip' pour obtenir l'adresse MAC de l'interface
                mac_command = f"ip link show dev {interface_name} | grep link/ether | awk '{{print($2)}}'"
                mac_address = subprocess.check_output(mac_command, shell=True, text=True).strip()
                return mac_address
            else:
                # Autres systèmes d'exploitation (non Linux), vous pouvez ajouter ici une autre logique si nécessaire
                return None
        except Exception:
            return None

    @staticmethod
    def get_mac_address_with_netifaces(ip):
        """
        Récupère l'adresse MAC associée à une adresse IPv4 en utilisant la bibliothèque netifaces.
        Args:
            ip (str): Adresse IPv4 pour laquelle vous souhaitez obtenir l'adresse MAC.
        Returns:
            str or None: L'adresse MAC associée à l'adresse IPv4, ou None si l'adresse MAC n'est pas trouvée.
        """
        try:
            mac_address = ni.ifaddresses(ip)[ni.AF_LINK][0]['addr']
            return mac_address
        except KeyError:
            return None

    def MacAddressToIp(self, ip):
        """
        Récupère l'adresse MAC associée à une adresse IPv4 en utilisant d'abord la fonction get_mac_address_with_netifaces,
        puis en utilisant la fonction get_mac_address si la première échoue sous Linux.
        Args:
            ip (str): Adresse IPv4 pour laquelle vous souhaitez obtenir l'adresse MAC.
        Returns:
            str or None: L'adresse MAC associée à l'adresse IPv4, ou None si l'adresse MAC n'est pas trouvée.
        """
        mac = NetworkAgentInfo.get_mac_address_with_netifaces(ip)

        if mac is not None:
            return mac
        # Si la première fonction échoue et que le système est Linux, utilisez la fonction get_mac_address
        current_os = platform.system().lower()
        if current_os == 'linux':
            return NetworkAgentInfo.get_mac_address(ip)
        return None

    def MacOsNetworkInfo(self):
        self.messagejson["dnshostname"] = platform.node()
        self.messagejson["listipinfo"] = []
        self.messagejson["dhcp"] = "False"

        for i in netifaces.interfaces():
            # addrs = netifaces.ifaddresses(i)
            try:
                # if_mac = addrs[netifaces.AF_LINK][0]['addr']
                # if_ip = addrs[netifaces.AF_INET][0]['addr']
                p = subprocess.Popen(
                    f"ipconfig getpacket {i}",
                    shell=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                )
                result = p.stdout.readlines()
                code_result = p.wait()
                if code_result == 0:
                    partinfo = {
                        "dhcpserver": "",
                        "dhcp": "False",
                        "macaddress": netifaces.ifaddresses(i)[netifaces.AF_LINK][0][
                            "addr"
                        ],
                    }
                    for line in result:
                        line = line.rstrip("\n")
                        colonne = line.split("=")
                        if len(colonne) != 2:
                            colonne = line.split(":")
                        if colonne[0].strip().startswith("yiaddr"):
                            partinfo["ipaddress"] = colonne[1].strip()
                        elif colonne[0].strip().startswith("subnet_mask"):
                            partinfo["mask"] = colonne[1].strip()
                        elif colonne[0].strip().startswith("router"):
                            partinfo["gateway"] = colonne[1].strip(" {}")
                        elif colonne[0].strip().startswith("server_identifier"):
                            partinfo["dhcpserver"] = colonne[1].strip()
                            partinfo["dhcp"] = "True"
                            self.messagejson["dhcp"] = "True"
                        elif colonne[0].strip().startswith("domain_name_server"):
                            self.messagejson["listdns"] = (
                                colonne[1].strip(" {}").split(",")
                            )
                            self.messagejson["listdns"] = [
                                x.strip() for x in self.messagejson["listdns"]
                            ]
                        else:
                            continue
                    try:
                        if partinfo["ipaddress"] != "":
                            self.messagejson["listipinfo"].append(partinfo)
                    except BaseException:
                        pass
            except (
                BaseException
            ):  # IndexError, KeyError: #ignore ifaces that dont have MAC or IP
                pass
        return self.messagejson

    def getLocalIipAddress(self):
        dhcpserver = self.IpDhcp()
        ip_addresses = []
        defaultgateway = {}
        try:
            gws = netifaces.gateways()
            intergw = gws["default"][netifaces.AF_INET]
            defaultgateway[intergw[1]] = intergw[0]
        except Exception:
            pass
        interfaces = netifaces.interfaces()
        for i in interfaces:
            if i == "lo":
                continue
            if iface := netifaces.ifaddresses(i).get(netifaces.AF_INET):
                for j in iface:
                    if (
                        j["addr"] != "127.0.0.1"
                        and self.MacAdressToIp(j["addr"]) is not None
                    ):
                        obj = {"ipaddress": j["addr"], "mask": j["netmask"]}
                        try:
                            obj["broadcast"] = j["broadcast"]
                        except BaseException:
                            obj["broadcast"] = "0.0.0.0"
                        try:
                            obj["gateway"] = defaultgateway.get(str(i), "0.0.0.0")
                        except Exception:
                            obj["gateway"] = "0.0.0.0"

                        obj["macaddress"] = self.MacAdressToIp(j["addr"])
                        try:
                            if dhcpserver[j["addr"]] is not None:
                                obj["dhcp"] = "True"
                                obj["dhcpserver"] = dhcpserver[j["addr"]]
                            else:
                                obj["dhcp"] = "False"
                                obj["dhcpserver"] = "0.0.0.0"
                        except BaseException:
                            obj["dhcp"] = "False"
                            obj["dhcpserver"] = "0.0.0.0"
                        ip_addresses.append(obj)
        return ip_addresses

    def listdnslinux(self):
        dns = []
        p = subprocess.Popen(
            "cat /etc/resolv.conf | grep nameserver | awk '{print $2}'",
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
        )
        result = p.stdout.readlines()
        return (
            [x.decode("utf-8").strip() for x in result]
            if sys.version_info[0] == 3
            else [x.strip() for x in result]
        )


def powershellfqdnwindowscommand():
    """
    search fqdn for machine windows from activedirectory
    """
    try:
        output = subprocess.check_output(
            [
                "powershell.exe",
                """([adsisearcher]"(&(objectClass=computer)(name=$env:computername))").findone().path""",
            ],
            shell=True,
        )
        output = output.decode("cp850")
        lou = [x.replace("OU=", "") for x in output.split(",") if "OU=" in x]
        outou = [y for y in lou if not re.findall("[éèêëÉÈÊËàâäÀÂÄôöÔÖùÙ\\(\\)]", y)]
        if not outou:
            return ""
        outou.reverse()
        return "@@".join(outou)
    except subprocess.CalledProcessError as e:
        logger.error(f"subproces powershellfqdnwindowscommand.output = {e.output}")
    return ""


def powershellfqdnwindowscommandbyuser(user):
    try:
        output = subprocess.check_output(
            [
                "powershell.exe",
                f"""([adsisearcher]"(&(objectClass=user)(samaccountname={user}))").findone().path""",
            ],
            shell=True,
        )
        output = output.decode("cp850")
        lou = [x.replace("OU=", "") for x in output.split(",") if "OU=" in x]
        outou = [y for y in lou if not re.findall("[éèêëÉÈÊËàâäÀÂÄôöÔÖùÙ\\(\\)]", y)]
        if not outou:
            return ""
        outou.reverse()
        return "@@".join(outou)
    except subprocess.CalledProcessError as e:
        logger.error(
            f"subproces powershellfqdnwindowscommandbyuser.output = {e.output}"
        )
    return ""


def powershellgetlastuser():
    if sys.platform.startswith("win"):
        script = os.path.abspath(
            os.path.join(
                os.path.dirname(os.path.realpath(__file__)),
                "..",
                "script",
                "getlastuser.ps1",
            )
        )
        result = powerschellscript1ps1(script)
        try:
            if result["code"] == 0:
                ret = []
                line = [
                    x.replace(os.linesep, "")
                    for x in result["result"]
                    if x.strip().replace(os.linesep, "") != ""
                ]
                namelist = []
                if len(line) > 2:
                    for t in line[2:]:
                        if res := t.split("\\")[1]:
                            if final := res.split(" ")[:-1]:
                                namelist.append(" ".join(final))
                return ",".join(namelist)
        except IndexError:
            logger.warning("detection last name")
            logger.error("\n%s" % (traceback.format_exc()))
            return "system"
    return "system"


def isMachineInDomain():
    """
    returns if the machine is part of an AD domain or not
    """
    try:
        output = subprocess.check_output(
            ["powershell.exe", """(gwmi win32_computersystem).partofdomain"""],
            shell=True,
        )
        return output.strip() == "true"
    except subprocess.CalledProcessError as e:
        logger.error(f"subproces isMachineInDomain.output = {e.output}")
    return False


def organizationbymachine():
    """
    AD information for machine
    search fqdn for machine windows from activedirectory
    """
    fqdnwindows = ""
    if sys.platform.startswith("linux") or sys.platform.startswith("darwin"):
        return ""
    elif sys.platform.startswith("win"):
        if indomain := isMachineInDomain():
            return powershellfqdnwindowscommand()
        else:
            return ""
    else:
        return ""


def organizationbyuser(user):
    """
    AD information for user
    search fqdn for machine windows from activedirectory
    """
    fqdnwindows = ""
    if sys.platform.startswith("linux") or sys.platform.startswith("darwin"):
        return ""
    elif sys.platform.startswith("win"):
        if indomain := isMachineInDomain():
            return powershellfqdnwindowscommandbyuser(user)
        else:
            return ""
    else:
        return ""


def interfacename(mac):
    return next(
        (
            interface
            for interface in netifaces.interfaces()
            if isInterfaceToMacadress(interface, mac)
        ),
        "",
    )


def lit_networkconf():
    pass


def isInterfaceToMacadress(interface, mac):
    addrs = netifaces.ifaddresses(interface)
    try:
        if_mac = addrs[netifaces.AF_LINK][0]["addr"]
    except (
        BaseException
    ):  # IndexError, KeyError: #ignore ifaces that dont have MAC or IP
        return False
    return if_mac == mac


def isInterfaceToIpadress(interface, ip):
    addrs = netifaces.ifaddresses(interface)
    try:
        if_ip = addrs[netifaces.AF_INET][0]["addr"]
    except (
        BaseException
    ):  # IndexError, KeyError: #ignore ifaces that dont have MAC or IP
        return False
    return if_ip == ip


def rewriteInterfaceTypeRedhad(configfile, data, interface):
    tab = []
    with open(configfile, "rb") as inputFile:
        filecontent = inputFile.read()
    tab = filecontent.split("\n")
    ll = [
        x
        for x in tab
        if not x.strip().startswith("IPADDR")
        and not x.strip().startswith("NETMASK")
        and not x.strip().startswith("NETWORK")
        and not x.strip().startswith("GATEWAY")
        and not x.strip().startswith("BROADCAST")
        and not x.strip().startswith("BOOTPROTO")
    ]
    try:
        if data["dhcp"]:
            ll.insert(1, "BOOTPROTO=dhcp")
        else:
            ll.insert(1, "BOOTPROTO=static")
            ll.append(f'IPADDR={data["ipaddress"]}')
            ll.append(f'NETMASK={data["mask"]}')
            ll.append(f'GATEWAY={data["gateway"]}')
        strr = "\n".join(ll)
        with open(configfile, "wb") as inputFile:
            inputFile.write(strr)
    except BaseException:
        return False
    return True


def rewriteInterfaceTypeDebian(data, interface):
    tab = []
    z = []
    try:
        with open("/etc/network/interfaces", "rb") as inputFile:
            filecontent = inputFile.read()
        with open("/etc/network/interfacesold", "wb") as inputFile:
            inputFile.write(filecontent)
        b = filecontent.split("\n")
        ll = [
            x.strip()
            for x in b
            if not x.startswith("auto")
            and "auto" not in x
            and not x.startswith("#")
            and x != ""
        ]
        string = "\n".join(ll)
        ll = [x.strip() for x in string.split("iface") if x != ""]
        z.extend(t for t in ll if t.split(" ")[0] != interface)
        if data["dhcp"] is True:
            tab.extend(("\nauto %s\n" % interface, "iface %s inet dhcp\n" % interface))
        else:
            tab.extend(
                (
                    "auto %s\n" % interface,
                    "iface %s inet static\n" % interface,
                    "\taddress %s\n" % data["ipaddress"],
                    "\tnetmask %s\n" % data["mask"],
                    "\tgateway %s\n" % data["gateway"],
                )
            )
        val1 = "".join(tab)
        for t in z:
            val = "\nauto %s\niface " % t.split(" ")[0]
            val = "%s %s\n" % (val, t)
        with open("/etc/network/interfaces", "wb") as inputFile:
            inputFile.write("%s\n%s" % (val, val1))
        return True
    except BaseException:
        return False


def typelinuxfamily():
    debiandist = [
        "astra",
        "canaima",
        "collax",
        "cumulus",
        "damn",
        "debian",
        "doudoulinux",
        "euronode",
        "finnix",
        "grml",
        "kanotix",
        "knoppix",
        "linex",
        "linspire",
        "advanced",
        "lmde",
        "mepis",
        "ocera",
        "ordissimo",
        "parsix",
        "pureos",
        "rays",
        "aptosid",
        "ubuntu",
        "univention",
        "xandros",
    ]
    val = platform.platform().lower()
    return next(("debian" for t in debiandist if t in val), "redhat")


def getsystemressource():
    p = subprocess.Popen(
        "cat /proc/1/comm", shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT
    )
    result = p.stdout.readlines()
    return result[0].rstrip("\n")


def getWindowsNameInterfaceForMacadress(macadress):
    obj = utils.simplecommand("wmic NIC get MACAddress,NetConnectionID")
    for lig in obj["result"]:
        l = lig.lower()
        mac = macadress.lower()
        if l.startswith(mac):
            element = lig.split(" ")
            element[0] = ""
            fin = [x for x in element if x.strip() != ""]
            return " ".join(fin)


def getUserName():
    """
    This function allow to obtain the name of the connected users
    """
    if sys.platform.startswith("linux"):
        connected_users = simplecommand("who | cut -d" "  -f1 | sort | uniq")

    return connected_users
