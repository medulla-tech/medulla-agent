#!/usr/bin/env python
# -*- coding: utf-8; -*-
#
# (c) 2016 siveo, http://www.siveo.net
#
# This file is part of Pulse 2, http://www.siveo.net
#
# Pulse 2 is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# Pulse 2 is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with Pulse 2; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
# MA 02110-1301, USA.

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
import utils

if sys.platform.startswith('win'):
    import wmi
    import pythoncom


logger = logging.getLogger()

class networkagentinfo:
    def __init__(self, sessionid, action='resultgetinfo', param=[]):
        self.sessionid = sessionid
        self.action = action
        self.messagejson = {}
        self.networkobjet(self.sessionid, self.action)
        for d in self.messagejson['listipinfo']:
            d['macnotshortened'] = d['macaddress']
            d['macaddress'] = self.reduction_mac(d['macaddress'])
        if len(param) != 0 and len(self.messagejson['listipinfo']) != 0:
            dd = []
            param1 = map(self.reduction_mac, param)
            for d in self.messagejson['listipinfo']:
                e = [s for s in param1 if d['macaddress'] == s]
                if e:
                    dd.append(d)
            self.messagejson['listipinfo'] = dd

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
            'action': action,
            'sessionid': sessionid,
            'listdns': [],
            'listipinfo': [],
            'dhcp': 'False',
            'dnshostname': '',
            'msg': platform.system(),
        }
        try:
            self.messagejson['users'] = self.getuser()
        except BaseException:
            self.messagejson['users'] = ["system"]

        if sys.platform.startswith('linux'):
            p = subprocess.Popen("ps aux | grep dhclient | grep -v leases | grep -v grep | awk '{print $NF}'",
                                 shell=True,
                                 stdout=subprocess.PIPE,
                                 stderr=subprocess.STDOUT)
            result = p.stdout.readlines()
            self.messagejson['dhcp'] = 'True' if len(result) > 0 else 'False'
            self.messagejson['listdns'] = self.listdnslinux()
            self.messagejson['listipinfo'] = self.getLocalIipAddress()
            self.messagejson['dnshostname'] = platform.node()
            return self.messagejson

        elif sys.platform.startswith('win'):
            """ revoit objet reseau windows """
            #self.messagejson['msg'] = platform.system()
            # all interface
            pythoncom.CoInitialize()
            try:
                wmi_obj = wmi.WMI()
                wmi_sql = "select * from Win32_NetworkAdapterConfiguration"
                wmi_out = wmi_obj.query(wmi_sql)
            finally:
                pythoncom.CoUninitialize()
            for dev in wmi_out:
                if dev.MACAddress is None:
                    continue
                objnet = {'macaddress': dev.MACAddress, 'Description': dev.Description}
                try:
                    objnet['ipaddress'] = dev.IPAddress[0]
                except BaseException:
                    objnet['ipaddress'] = None
                try:
                    objnet['gateway'] = dev.DefaultIPGateway[0]
                except BaseException:
                    objnet['gateway'] = ""
                try:
                    objnet['mask'] = dev.IPSubnet[0]
                except BaseException:
                    objnet['mask'] = None
                try:
                    objnet['dhcp'] = dev.DHCPEnabled
                except BaseException:
                    objnet['dhcp'] = None
                try:
                    objnet['dhcpserver'] = dev.DHCPServer
                except BaseException:
                    objnet['dhcpserver'] = None
                self.messagejson['listipinfo'].append(objnet)
                try:
                    self.messagejson['listdns'].append(dev.DNSServerSearchOrder[0])
                except BaseException:
                    pass
                try:
                    self.messagejson['dnshostname'] = dev.DNSHostName
                except BaseException:
                    pass
            return self.messagejson
        elif sys.platform.startswith('darwin'):
            return self.MacOsNetworkInfo()
        else:
            self.messagejson['msg'] = f"system {sys.platform} : not managed yet"
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
        p = subprocess.Popen('cat /proc/1/comm',
                             shell=True,
                             stdout=subprocess.PIPE,
                             stderr=subprocess.STDOUT)
        result = p.stdout.readlines()
        system = result[0].rstrip('\n')
        """ Returns the list of ip gateways for linux interfaces """

        if system == "init":
            p = subprocess.Popen('cat /var/log/syslog | grep -e DHCPACK | tail -n10 | awk \'{print $(NF-2)"@" $NF}\'',
                                 shell=True,
                                 stdout=subprocess.PIPE,
                                 stderr=subprocess.STDOUT)
            result = p.stdout.readlines()

            for i in range(len(result)):
                result[i] = result[i].rstrip('\n')
                d = result[i].split("@")
                obj1[d[0]] = d[1]
        elif system == "systemd":
            p = subprocess.Popen('journalctl | grep "dhclient\["',
                                 shell=True,
                                 stdout=subprocess.PIPE,
                                 stderr=subprocess.STDOUT)
            result = p.stdout.readlines()
            for i in result:
                i = i.rstrip('\n')
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
        'Returns a list of MACs for interfaces that have given IP, returns None if not found'
        for i in netifaces.interfaces():
            addrs = netifaces.ifaddresses(i)
            try:
                if_mac = addrs[netifaces.AF_LINK][0]['addr']
                if_ip = addrs[netifaces.AF_INET][0]['addr']
            except BaseException:  # IndexError, KeyError: #ignore ifaces that dont have MAC or IP
                if_mac = if_ip = None
            if if_ip == ip:
                return if_mac
        return None

    def MacOsNetworkInfo(self):
        self.messagejson["dnshostname"] = platform.node()
        self.messagejson["listipinfo"] = []
        self.messagejson["dhcp"] = 'False'

        for i in netifaces.interfaces():
            #addrs = netifaces.ifaddresses(i)
            try:
                #if_mac = addrs[netifaces.AF_LINK][0]['addr']
                #if_ip = addrs[netifaces.AF_INET][0]['addr']
                p = subprocess.Popen(
                    f'ipconfig getpacket {i}',
                    shell=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                )
                result = p.stdout.readlines()
                code_result = p.wait()
                if code_result == 0:
                    partinfo = {
                        "dhcpserver": '',
                        "dhcp": 'False',
                        "macaddress": netifaces.ifaddresses(i)[netifaces.AF_LINK][
                            0
                        ]['addr'],
                    }
                    for line in result:
                        line = line.rstrip('\n')
                        colonne = line.split("=")
                        if len(colonne) != 2:
                            colonne = line.split(":")
                        if colonne[0].strip().startswith('yiaddr'):
                            partinfo["ipaddress"] = colonne[1].strip()
                        elif colonne[0].strip().startswith('subnet_mask'):
                            partinfo["mask"] = colonne[1].strip()
                        elif colonne[0].strip().startswith('router'):
                            partinfo["gateway"] = colonne[1].strip(" {}")
                        elif colonne[0].strip().startswith('server_identifier'):
                            partinfo["dhcpserver"] = colonne[1].strip()
                            partinfo["dhcp"] = 'True'
                            self.messagejson["dhcp"] = 'True'
                        elif colonne[0].strip().startswith('domain_name_server'):
                            self.messagejson["listdns"] = colonne[1].strip(
                                " {}").split(",")
                            self.messagejson["listdns"] = [
                                x.strip() for x in self.messagejson["listdns"]]
                        else:
                            continue
                    try:
                        if partinfo["ipaddress"] != '':
                            self.messagejson["listipinfo"].append(partinfo)
                    except BaseException:
                        pass
            except BaseException:  # IndexError, KeyError: #ignore ifaces that dont have MAC or IP
                pass
        return self.messagejson

    def getLocalIipAddress(self):
        dhcpserver = self.IpDhcp()
        ip_addresses = []
        defaultgateway = {}
        try:
            gws = netifaces.gateways()
            intergw = gws['default'][netifaces.AF_INET]
            defaultgateway[intergw[1]] = intergw[0]
        except Exception:
            pass
        interfaces = netifaces.interfaces()
        for i in interfaces:
            if i == 'lo':
                continue
            if iface := netifaces.ifaddresses(i).get(netifaces.AF_INET):
                for j in iface:
                    if j['addr'] != '127.0.0.1' and self.MacAdressToIp(
                            j['addr']) != None:
                        obj = {'ipaddress': j['addr'], 'mask': j['netmask']}
                        try:
                            obj['broadcast'] = j['broadcast']
                        except BaseException:
                            obj['broadcast'] = "0.0.0.0"
                        try:
                            obj['gateway'] = defaultgateway.get(str(i), "0.0.0.0")
                        except Exception:
                            obj['gateway'] = "0.0.0.0"

                        obj['macaddress'] = self.MacAdressToIp(j['addr'])
                        try:
                            if dhcpserver[j['addr']] != None:
                                obj['dhcp'] = 'True'
                                obj['dhcpserver'] = dhcpserver[j['addr']]
                            else:
                                obj['dhcp'] = 'False'
                                obj['dhcpserver'] = "0.0.0.0"
                        except BaseException:
                            obj['dhcp'] = 'False'
                            obj['dhcpserver'] = "0.0.0.0"
                        ip_addresses.append(obj)
        return ip_addresses

    def listdnslinux(self):
        p = subprocess.Popen("cat /etc/resolv.conf | grep nameserver | awk '{print $2}'",
                             shell=True,
                             stdout=subprocess.PIPE,
                             stderr=subprocess.STDOUT)
        result = p.stdout.readlines()
        return [i.rstrip('\n') for i in result]

def powershellfqdnwindowscommand():
    """
        search fqdn for machine windows from activedirectory
    """
    try:
        output = subprocess.check_output(["powershell.exe", """([adsisearcher]"(&(objectClass=computer)(name=$env:computername))").findone().path"""],
                                         shell=True)
        output = output.decode('cp850')
        outou = []
        lou = [x.replace("OU=", "") for x in output.split(",") if "OU=" in x]
        for y in lou:
            if not re.findall('[éèêëÉÈÊËàâäÀÂÄôöÔÖùÙ\(\)]', y):
                outou.append(y)
        if len(outou) != 0:
            outou.reverse()
            result = "@@".join(outou)
            return result
        else:
            return ""
    except subprocess.CalledProcessError, e:
        logger.error("subproces powershellfqdnwindowscommand.output = " + e.output)
    return ""

def powershellfqdnwindowscommandbyuser(user):
    try:
        output = subprocess.check_output(["powershell.exe", """([adsisearcher]"(&(objectClass=user)(samaccountname=%s))").findone().path"""%user], shell=True)
        output = output.decode('cp850')
        outou = []
        lou = [x.replace("OU=", "") for x in output.split(",") if "OU=" in x]
        for y in lou:
            if not re.findall('[éèêëÉÈÊËàâäÀÂÄôöÔÖùÙ\(\)]', y):
                outou.append(y)
        if len(outou) != 0:
            outou.reverse()
            result = "@@".join(outou)
            return result
        else:
            return ""
    except subprocess.CalledProcessError, e:
        logger.error("subproces powershellfqdnwindowscommandbyuser.output = " + e.output)
    return ""

def powershellgetlastuser():
    if sys.platform.startswith('win'):
        script = os.path.abspath(os.path.join(os.path.dirname(os.path.realpath(__file__)), "script", "getlastuser.ps1"))
        result = powerschellscriptps1(script)
        try:
            if result['code'] == 0:
                ret = []
                line = [x.replace("\n", '') for x in result['result'].split("\r\n") if x.replace("\n", '') != ""]
                if len(line) == 3:
                    descriptor = [x for x in line[0].split(' ') if x != ""]
                    informationuser = [x for x in line[2].split(' ') if x != ""]
                    if  descriptor[0].startswith('Last'):
                        ret = informationuser[1].split('\\')
                    if  descriptor[1].startswith('Last'):
                        ret = informationuser[0].split('\\')
                    return ret[1]
        except IndexError:
            logger.warning("detection last name")
            return "system"
    return "system"


def isMachineInDomain():
    """
        returns if the machine is part of an AD domain or not
    """
    try:
        output = subprocess.check_output(["powershell.exe", """(gwmi win32_computersystem).partofdomain"""],
                                         shell=True)
        return bool(strtobool(output.strip()))
    except subprocess.CalledProcessError, e:
        logger.error("subproces isMachineInDomain.output = " + e.output)
    return False


def organizationbymachine():
    """
        AD information for machine
        search fqdn for machine windows from activedirectory
    """
    fqdnwindows = ""
    if sys.platform.startswith('linux') or sys.platform.startswith('darwin'):
        return ""
    elif sys.platform.startswith('win'):
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
    if sys.platform.startswith('linux') or sys.platform.startswith('darwin'):
        return ""
    elif sys.platform.startswith('win'):
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
        if_mac = addrs[netifaces.AF_LINK][0]['addr']
    except BaseException:  # IndexError, KeyError: #ignore ifaces that dont have MAC or IP
        return False
    return if_mac == mac


def isInterfaceToIpadress(interface, ip):
    addrs = netifaces.ifaddresses(interface)
    try:
        if_ip = addrs[netifaces.AF_INET][0]['addr']
    except BaseException:  # IndexError, KeyError: #ignore ifaces that dont have MAC or IP
        return False
    return if_ip == ip

def rewriteInterfaceTypeRedhad(configfile, data, interface):
    tab = []
    with open(configfile, 'rb') as inputFile:
        filecontent = inputFile.read()
    tab = filecontent.split("\n")
    ll = [x for x in tab if
          not x.strip().startswith('IPADDR')
          and not x.strip().startswith('NETMASK')
          and not x.strip().startswith('NETWORK')
          and not x.strip().startswith('GATEWAY')
          and not x.strip().startswith('BROADCAST')
          and not x.strip().startswith('BOOTPROTO')]
    try:
        if data['dhcp']:
            ll.insert(1, "BOOTPROTO=dhcp")
        else:
            ll.insert(1, 'BOOTPROTO=static')
            ll.append(f"IPADDR={data['ipaddress']}")
            ll.append(f"NETMASK={data['mask']}")
            ll.append(f"GATEWAY={data['gateway']}")
        strr = "\n".join(ll)
        with open(configfile, 'wb') as inputFile:
            inputFile.write(strr)
    except BaseException:
        return False
    return True


def rewriteInterfaceTypeDebian(data, interface):
    tab = []
    z = []
    try:
        with open("/etc/network/interfaces", 'rb') as inputFile:
            filecontent = inputFile.read()
        with open("/etc/network/interfacesold", 'wb') as inputFile:
            inputFile.write(filecontent)
        b = filecontent.split("\n")
        ll = [x.strip() for x in b if not x.startswith('auto') and
              'auto' not in x and not x.startswith('#') and x != '']
        string = "\n".join(ll)
        ll = [x.strip() for x in string.split('iface') if x != '']
        z.extend(t for t in ll if t.split(" ")[0] != interface)
        if data['dhcp'] is True:
            tab.extend(("\nauto %s\n" % interface, "iface %s inet dhcp\n" % interface))
        else:
            tab.extend(
                (
                    "auto %s\n" % interface,
                    "iface %s inet static\n" % interface,
                    "\taddress %s\n" % data['ipaddress'],
                    "\tnetmask %s\n" % data['mask'],
                    "\tgateway %s\n" % data['gateway'],
                )
            )
        val1 = "".join(tab)
        for t in z:
            val = "\nauto %s\niface " % t.split(" ")[0]
            val = "%s %s\n" % (val, t)
        with open("/etc/network/interfaces", 'wb') as inputFile:
            inputFile.write("%s\n%s" % (val, val1))
        return True
    except BaseException:
        return False


def typelinuxfamily():
    debiandist = [
        'astra',
        'canaima',
        'collax',
        'cumulus',
        'damn',
        'debian',
        'doudoulinux',
        'euronode',
        'finnix',
        'grml',
        'kanotix',
        'knoppix',
        'linex',
        'linspire',
        'advanced',
        'lmde',
        'mepis',
        'ocera',
        'ordissimo',
        'parsix',
        'pureos',
        'rays',
        'aptosid',
        'ubuntu',
        'univention',
        'xandros']
    val = platform.platform().lower()
    return next(('debian' for t in debiandist if t in val), 'redhat')


def getsystemressource():
    p = subprocess.Popen('cat /proc/1/comm',
                         shell=True,
                         stdout=subprocess.PIPE,
                         stderr=subprocess.STDOUT)
    result = p.stdout.readlines()
    return result[0].rstrip('\n')


def getWindowsNameInterfaceForMacadress(macadress):
    obj = utils.simplecommand("wmic NIC get MACAddress,NetConnectionID")
    for lig in obj['result']:
        l = lig.lower()
        mac = macadress.lower()
        if l.startswith(mac):
            element = lig.split(' ')
            element[0] = ''
            fin = [x for x in element if x.strip() != ""]
            return " ".join(fin)


def getUserName():
    """
    This function allow to obtain the name of the connected users
    """
    if sys.platform.startswith('linux'):
        connected_users = simplecommand("who | cut -d" "  -f1 | sort | uniq")

    return connected_users
