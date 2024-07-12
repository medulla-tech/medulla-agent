#!/usr/bin/python3
# -*- coding: utf-8; -*-
# SPDX-FileCopyrightText: 2016-2023 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-3.0-or-later

import netifaces
import subprocess
import sys
import platform
import logging
import re
import socket
import psutil
import os
from distutils.util import strtobool
from lib.utils import simplecommand, powerschellscriptps1
from . import utils

if sys.platform.startswith("win"):
    import wmi
    import pythoncom


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
                if len(e) != 0:
                    dd.append(d)
            self.messagejson["listipinfo"] = dd

    def reduction_mac(self, mac):
        mac = mac.lower()
        mac = mac.replace(":", "")
        mac = mac.replace("-", "")
        mac = mac.replace(" ", "")
        return mac

    def getuser(self):
        userlist = list({users[0] for users in psutil.users()})
        return userlist

    def networkobjet(self, sessionid, action):
        """
        Collecte des informations sur la configuration réseau de l'ordinateur.

        Args:
            sessionid (str): Identifiant de session pour l'action en cours.
            action (str): Action à entreprendre.

        Returns:
            dict: Un dictionnaire contenant des informations sur la configuration réseau.
                Les clés comprennent :
                - "action": Action spécifiée en argument.
                - "sessionid": Identifiant de session spécifié en argument.
                - "listdns": Liste des serveurs DNS configurés.
                - "listipinfo": Liste des informations sur les adresses IP et les interfaces réseau.
                - "dhcp": Indique si DHCP est activé (True/False).
                - 'dhcpinfo' est présent seulement si dhcp est True
                - "dnshostname": Nom de l'hôte DNS.
                - "msg": Système d'exploitation en cours d'exécution.

        Note:
            Cette fonction collecte des informations sur la configuration réseau de l'ordinateur
            en fonction du système d'exploitation en cours d'exécution.
            - Sur Linux, elle vérifie la configuration DHCP et collecte les informations des interfaces réseau.
            - Sur Windows, elle collecte les informations des interfaces réseau, y compris les adresses IP, les passerelles, etc.
            - Sur macOS, elle appelle la fonction MacOsNetworkInfo pour collecter des informations spécifiques.
            - Pour d'autres systèmes d'exploitation, un message indiquant qu'ils ne sont pas encore gérés est renvoyé.
        """
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
                "ip addr show | grep dynamic",
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
            )
            result = [x.decode("utf-8").strip() for x in p.stdout.readlines()]
            self.messagejson["dhcp"] = "True" if len(result) > 0 else "False"
            if self.messagejson["dhcp"]:
                pattern = (
                    r"inet (\S+)\/(\d+) metric (\d+) brd (\S+) scope global (\S+) (\S+)"
                )
                self.messagejson["dhcpinfo"] = []
                for info_line in result:
                    match = re.match(pattern, info_line)
                    if match:
                        # Créez un dictionnaire avec les informations extraites
                        info_dict = {
                            "ip_address": match.group(1),
                            "subnet_mask": match.group(2),
                            "metric": match.group(3),
                            "broadcast_address": match.group(4),
                            "scope": match.group(5),
                            "interface": match.group(6),
                        }
                        self.messagejson["dhcpinfo"].append(info_dict)

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
            pythoncom.CoInitialize()
            try:
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
            finally:
                # Assurez-vous de libérer les ressources après utilisation
                pythoncom.CoUninitialize()
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
        system = result[0].rstrip("\n")
        """ Returns the list of ip gateways for linux interfaces """

        if system == "init":
            p = subprocess.Popen(
                "cat /var/log/syslog | grep -e DHCPACK | tail -n10 | awk '{print $(NF-2)\"@\" $NF}'",
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
            )
            result = p.stdout.readlines()

            for i in range(len(result)):
                result[i] = result[i].rstrip("\n")
                d = result[i].split("@")
                obj1[d[0]] = d[1]
        elif system == "systemd":
            p = subprocess.Popen(
                'journalctl | grep "dhclient\\["',
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
            )
            result = p.stdout.readlines()
            for i in result:
                i = i.rstrip("\n")
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

    def MacAdressToIp(self, ip):
        "Returns a list of MACs for interfaces that have given IP, returns None if not found"
        for i in netifaces.interfaces():
            addrs = netifaces.ifaddresses(i)
            try:
                if_mac = addrs[netifaces.AF_LINK][0]["addr"]
                if_ip = addrs[netifaces.AF_INET][0]["addr"]
            except (
                BaseException
            ):  # IndexError, KeyError: #ignore ifaces that dont have MAC or IP
                if_mac = if_ip = None
            if if_ip == ip:
                return if_mac
        return None

    def MacOsNetworkInfo(self):
        self.messagejson["dnshostname"] = platform.node()
        self.messagejson["listipinfo"] = []
        self.messagejson["dhcp"] = "False"

        for i in netifaces.interfaces():
            try:
                p = subprocess.Popen(
                    "ipconfig getpacket %s" % i,
                    shell=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                )
                result = p.stdout.readlines()
                code_result = p.wait()
                if code_result == 0:
                    partinfo = {}
                    partinfo["dhcpserver"] = ""
                    partinfo["dhcp"] = "False"
                    partinfo["macaddress"] = netifaces.ifaddresses(i)[
                        netifaces.AF_LINK
                    ][0]["addr"]
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
            iface = netifaces.ifaddresses(i).get(netifaces.AF_INET)
            if iface:
                for j in iface:
                    if (
                        j["addr"] != "127.0.0.1"
                        and self.MacAdressToIp(j["addr"]) is not None
                    ):
                        obj = {}
                        obj["ipaddress"] = j["addr"]
                        obj["mask"] = j["netmask"]
                        try:
                            obj["broadcast"] = j["broadcast"]
                        except BaseException:
                            obj["broadcast"] = "0.0.0.0"
                        try:
                            if str(i) in defaultgateway:
                                obj["gateway"] = defaultgateway[str(i)]
                            else:
                                obj["gateway"] = "0.0.0.0"
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
        for i in result:
            dns.append(i.rstrip("\n"))
        return dns


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
        outou = []
        lou = [x.replace("OU=", "") for x in output.split(",") if "OU=" in x]
        for y in lou:
            if not re.findall("[éèêëÉÈÊËàâäÀÂÄôöÔÖùÙ\\(\\)]", y):
                outou.append(y)
        if len(outou) != 0:
            outou.reverse()
            result = "@@".join(outou)
            return result
        else:
            return ""
    except subprocess.CalledProcessError as e:
        logging.getLogger().error(
            "subproces powershellfqdnwindowscommand.output = " + e.output
        )
    return ""


def powershellfqdnwindowscommandbyuser(user):
    try:
        output = subprocess.check_output(
            [
                "powershell.exe",
                """([adsisearcher]"(&(objectClass=user)(samaccountname=%s))").findone().path"""
                % user,
            ],
            shell=True,
        )
        output = output.decode("cp850")
        outou = []
        lou = [x.replace("OU=", "") for x in output.split(",") if "OU=" in x]
        for y in lou:
            if not re.findall("[éèêëÉÈÊËàâäÀÂÄôöÔÖùÙ\\(\\)]", y):
                outou.append(y)
        if len(outou) != 0:
            outou.reverse()
            result = "@@".join(outou)
            return result
        else:
            return ""
    except subprocess.CalledProcessError as e:
        logging.getLogger().error(
            "subproces powershellfqdnwindowscommandbyuser.output = " + e.output
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
        result = powerschellscriptps1(script)
        if result["code"] == 0:
            ret = []
            line = [
                x.replace("\n", "")
                for x in result["result"].split("\r\n")
                if x.replace("\n", "") != ""
            ]
            if len(line) == 3:
                descriptor = [x for x in line[0].split(" ") if x != ""]
                informationuser = [x for x in line[2].split(" ") if x != ""]
                if descriptor[0].startswith("Last"):
                    ret = informationuser[1].split("\\")
                if descriptor[1].startswith("Last"):
                    ret = informationuser[0].split("\\")
                return ret[1]
    return ""


def isMachineInDomain():
    """
    returns if the machine is part of an AD domain or not
    """
    try:
        output = subprocess.check_output(
            ["powershell.exe", """(gwmi win32_computersystem).partofdomain"""],
            shell=True,
        )
        return bool(strtobool(output.strip()))
    except subprocess.CalledProcessError as e:
        logging.getLogger().error("subproces isMachineInDomain.output = " + e.output)
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
        indomain = isMachineInDomain()
        if indomain:
            fqdnwindows = powershellfqdnwindowscommand()
            return fqdnwindows
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
        indomain = isMachineInDomain()
        if indomain:
            fqdnwindows = powershellfqdnwindowscommandbyuser(user)
            return fqdnwindows
        else:
            return ""
    else:
        return ""


def interfacename(mac):
    for interface in netifaces.interfaces():
        if isInterfaceToMacadress(interface, mac):
            return interface
    return ""


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
    if if_mac == mac:
        return True
    return False


def isInterfaceToIpadress(interface, ip):
    addrs = netifaces.ifaddresses(interface)
    try:
        if_ip = addrs[netifaces.AF_INET][0]["addr"]
    except (
        BaseException
    ):  # IndexError, KeyError: #ignore ifaces that dont have MAC or IP
        return False
    if if_ip == ip:
        return True
    return False


def rewriteInterfaceTypeRedhad(configfile, data, interface):
    tab = []
    inputFile = open(configfile, "rb")
    filecontent = inputFile.read()
    inputFile.close()
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
            ll.append("IPADDR=%s" % data["ipaddress"])
            ll.append("NETMASK=%s" % data["mask"])
            ll.append("GATEWAY=%s" % data["gateway"])
        strr = "\n".join(ll)
        inputFile = open(configfile, "wb")
        inputFile.write(strr)
        inputFile.close()
    except BaseException:
        return False
    return True


def rewriteInterfaceTypeDebian(data, interface):
    tab = []
    z = []
    try:
        inputFile = open("/etc/network/interfaces", "rb")
        filecontent = inputFile.read()
        inputFile.close()
        inputFile = open("/etc/network/interfacesold", "wb")
        inputFile.write(filecontent)
        inputFile.close()
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
        for t in ll:
            if t.split(" ")[0] != interface:
                z.append(t)
        if data["dhcp"] is True:
            tab.append("\nauto %s\n" % interface)
            tab.append("iface %s inet dhcp\n" % interface)
        else:
            tab.append("auto %s\n" % interface)
            tab.append("iface %s inet static\n" % interface)
            tab.append("\taddress %s\n" % data["ipaddress"])
            tab.append("\tnetmask %s\n" % data["mask"])
            tab.append("\tgateway %s\n" % data["gateway"])
        val1 = "".join(tab)
        for t in z:
            val = "\nauto %s\niface " % t.split(" ")[0]
            val = "%s %s\n" % (val, t)
        inputFile = open("/etc/network/interfaces", "wb")
        inputFile.write("%s\n%s" % (val, val1))
        inputFile.close()
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
    for t in debiandist:
        if t in val:
            return "debian"
    return "redhat"


def getsystemressource():
    p = subprocess.Popen(
        "cat /proc/1/comm", shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT
    )
    result = p.stdout.readlines()
    system = result[0].rstrip("\n")
    return system


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
