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
from ipaddress import ip_address
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
        self.messagejson = {}
        self.messagejson["action"] = action
        self.messagejson["sessionid"] = sessionid
        self.messagejson["listdns"] = []
        self.messagejson["listipinfo"] = []
        self.messagejson["dhcp"] = "False"
        self.messagejson["dnshostname"] = ""
        self.messagejson["msg"] = platform.system()
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
            result = p.stdout.readlines()
            if len(result) > 0:
                self.messagejson["dhcp"] = "True"
            else:
                self.messagejson["dhcp"] = "False"
            self.messagejson["listdns"] = self.listdnslinux()
            self.messagejson["listipinfo"] = self.getLocalIipAddress()
            self.messagejson["dnshostname"] = platform.node()
            return self.messagejson

        elif sys.platform.startswith("win"):
            """revoit objet reseau windows"""
            pythoncom.CoInitialize()
            try:
                wmi_obj = wmi.WMI()
                wmi_sql = "select * from Win32_NetworkAdapterConfiguration where IPEnabled=TRUE"
                wmi_out = wmi_obj.query(wmi_sql)
            finally:
                pythoncom.CoUninitialize()
            for dev in wmi_out:
                objnet = {}
                objnet["macaddress"] = dev.MACAddress
                objnet["ipaddress"] = dev.IPAddress[0]
                try:
                    objnet["gateway"] = dev.DefaultIPGateway[0]
                except BaseException:
                    objnet["gateway"] = ""
                objnet["mask"] = dev.IPSubnet[0]
                objnet["dhcp"] = dev.DHCPEnabled
                objnet["dhcpserver"] = dev.DHCPServer
                self.messagejson["listipinfo"].append(objnet)
                try:
                    self.messagejson["listdns"].append(dev.DNSServerSearchOrder[0])
                except BaseException:
                    pass
                self.messagejson["dnshostname"] = dev.DNSHostName
            self.messagejson["msg"] = platform.system()
            return self.messagejson

        elif sys.platform.startswith("darwin"):
            return self.MacOsNetworkInfo()
        else:
            self.messagejson["msg"] = "system %s : not managed yet" % sys.platform
            return self.messagejson

    def IpDhcp(self):
        """
        This function retrieves the DHCP server IP addresses used on the machine.
        It parses system logs (/var/log/syslog and journal logs) to extract DHCP-related information.
        Returns a dictionary where keys are IP addresses and values are corresponding DHCP server IP addresses.
        """
        obj1 = {}
        system = ""
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

        if system == "init":
            p = subprocess.Popen(
                "grep -e DHCPACK /var/log/syslog | tail -n10 | awk '{print $(NF-2)\"@\" $NF}'",
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
            )
            arrayresult = p.stdout.readlines()
            result = [x.decode("utf-8").rstrip("\n") for x in arrayresult]
            for item in result:
                d = item.split("@")
                try:
                    ip = ipaddress.ip_address(d[0])
                    dhcp_ip = ipaddress.ip_address(d[1])
                    obj1[str(ip)] = str(dhcp_ip)
                except ValueError:
                    pass
        elif system == "systemd":
            p = subprocess.Popen(
                "journalctl -t dhclient --no-pager | grep -E 'DHCPACK|bound to'",
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
            )
            arrayresult = p.stdout.readlines()
            result = [x.decode("utf-8").rstrip("\n") for x in arrayresult]
            for line in result:
                match = re.search(
                    r"DHCPACK.*?(\d+\.\d+\.\d+\.\d+|\w{0,4}:\w{0,4}:\w{0,4}:\w{0,4}:\w{0,4}:\w{0,4})",
                    line,
                )
                if match:
                    ipdhcp = match.group(1)
                elif "bound to" in line:
                    match_ip = re.search(
                        r"bound to (\d+\.\d+\.\d+\.\d+|\w{0,4}:\w{0,4}:\w{0,4}:\w{0,4}:\w{0,4}:\w{0,4})",
                        line,
                    )
                    if match_ip:
                        ipadress = match_ip.group(1)
                        try:
                            ip = ipaddress.ip_address(ipadress)
                            dhcp_ip = ipaddress.ip_address(ipdhcp)
                            obj1[str(ip)] = str(dhcp_ip)
                        except ValueError:
                            pass

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
