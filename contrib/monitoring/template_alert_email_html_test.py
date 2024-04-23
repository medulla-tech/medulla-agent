#!/usr/bin/python
# -*- coding: utf-8; -*-
# SPDX-FileCopyrightText: 2022-2023 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-3.0-or-later

import json
import smtplib
import logging
from email.mime.multipart import MIMEMultipart
import email.mime.application
from email.mime.text import MIMEText
from email.utils import formatdate
import os.path
import traceback

LOGFILE = "/var/lib/medulla/script_monitoring/logfilescriptemail.log"
logger = logging.getLogger()

# jsonstructparametre={"subject" : "Event report",
# "email_account" : "systemdev@siveo.net"
# "email_password" : "P@ssw0rd$",
# "email_server" : "smtp-fr.securemail.pro",
# "email_serverport" : 465  ,
# "email_servertype" : "SMTP_SSL",
# "email_mimetype" : "html,text"}

import sys

if sys.version_info >= (3, 0, 0):
    basestring = (str, bytes)


def _template_html_event(dictresult):
    templateevent = """<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8" />
<title></title>
<style type="text/css">
table {
border:3px solid #6495ed;
border-collapse:collapse;
width:90%;
margin:auto;
}
thead, tfoot {
background-color:#D0E3FA;
background-image:url(sky.jpg);
border:1px solid #6495ed;
}
tbody {
background-color:#FFFFFF;
border:1px solid #6495ed;
}
th {
font-family:monospace;
border:1px dotted #6495ed;
padding:5px;
background-color:#EFF6FF;
width:25%;
}
td {
font-family:sans-serif;
font-size:80%;
border:1px solid #6495ed;
padding:5px;
text-align:left;
}
caption {
font-family:sans-serif;
}

</style>
</head>
<body>
<div>


  <p>PULSE MONITORING</p>
  <img src=" data:image/png;base64,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" alt="medulla logo" />
</div>
<h1>ALERT @mon_devices_device_type@ : @general_status@ </h1>
<h2>Machine @mon_machine_hostname@ [@jid@ ]</h2>

<!-- DEVICE INFORMATION -->
<!-- mon_devices_mon_machine_id = @mon_devices_mon_machine_id@ -->
<!-- mon_devices_doc = @mon_devices_doc@ -->
<!-- mon_devices_status = @mon_devices_status@ -->
<!-- mon_devices_device_type = @mon_devices_device_type@ -->
<!-- mon_devices_firmware = @mon_devices_firmware@ -->
<!-- mon_devices_alarm_msg = @mon_devices_alarm_msg@ -->
<!-- mon_devices_serial = @mon_devices_serial@ -->
<!-- mon_devices_id = @mon_devices_id@ -->"""

    if dictresult["mon_devices_device_type"] == "device":
        templateevent += """
<table>
  <!-- <caption>Device information</caption> -->
   <thead>
        <tr>
            <th colspan="5">DEVICE</th>
        </tr>
    </thead>
  <tbody>
    <tr>
      <th scope="col">status</th>
      <th scope="col">firmware</th>
      <th scope="col">serial</th>
      <th scope="col">alarm_msg</th>
      <th scope="col">retour</th>
    </tr>
    <tr>
      <td>@mon_devices_status@</td>
      <td>@mon_devices_firmware@</td>
      <td>@mon_devices_serial@</td>
      <td>@mon_devices_alarm_msg@</td>
      <td><code>@mon_devices_doc@</code></td>
    </tr>
  </tbody>
</table>"""
    elif dictresult["mon_devices_device_type"] == "system":
        codemetrique = json.dumps(dictresult["mon_devices_doc"], indent=4)
        templateevent += (
            """
<table>
  <!-- <caption>System information</caption> -->
   <thead>
        <tr>
            <th colspan="1">SYSTEM METRIQUE</th>
        </tr>
    </thead>
  <tbody>
    <tr>
      <th scope="col">@mon_devices_device_type@</th>
    </tr>
    <tr>
      <td><code>%s</code></td>
    </tr>
  </tbody>
</table>"""
            % codemetrique
        )

    templateevent += """
<!-- MACHINES INFORMATION -->
<!-- mon_machine_hostname = @mon_machine_hostname@
mon_machine_statusmsg =@mon_machine_statusmsg@
mon_machine_date = @mon_machine_date@
mon_machine_id = @mon_machine_id@
mon_machine_machines_id = @mon_machine_machines_id@ -->
"""
    if dictresult["agenttype"] == "relayserver":
        Tmach = f'RELAY SERVER ({dictresult["platform"]})'
    else:
        Tmach = f'MACHINE ({dictresult["platform"]})'
    templateevent += """
<table>
  <!-- <caption>Device information</caption> -->
   <thead>
        <tr>
            <th colspan="7">%s</th>
        </tr>
    </thead>
  <tbody>
    <tr>
      <th scope="col">host</th>
      <th scope="col">archi</th>
      <th scope="col">date</th>
      <th scope="col">model</th>
      <th scope="col">serial</th>
      <th scope="col">devices firmware</th>
      <th scope="col">manufacturer</th>
    </tr>
    <tr>
      <td>@mon_machine_hostname@</td>
      <td>@archi@</td>
      <td>@mon_machine_date@</td>
      <td>@model@</td>
      <td>@uuid_serial_machine@</td>
      <td>@mon_devices_firmware@</td>
      <td scope="col">@manufacturer@</td>

    </tr>
  </tbody>
</table>""" % (
        Tmach
    )

    templateevent += """
<!-- network INFORMATION -->
<!-- ippublic = @ippublic@
subnetxmpp =@subnetxmpp@
ip_xmpp = @ip_xmpp@
macaddress = @macaddress@
groupdeploy = @groupdeploy@ -->
"""

    templateevent += """
<table>
  <!-- <caption>Network information</caption> -->
   <thead>
        <tr>
            <th colspan="6">NETWORK</th>
        </tr>
    </thead>
  <tbody>
    <tr>
      <th scope="col">ippublic</th>
      <th scope="col">ip_xmpp</th>
      <th scope="col">subnetxmpp</th>
      <th scope="col">ip_xmpp</th>
      <th scope="col">macaddress</th>
      <th scope="col">groupdeploy</th>
    </tr>
    <tr>
      <th scope="col">@ippublic@</th>
      <th scope="col">@ip_xmpp@</th>
      <th scope="col">@subnetxmpp@</th>
      <th scope="col">@ip_xmpp@</th>
      <th scope="col">@macaddress@</th>
      <th scope="col">@groupdeploy@</th>

    </tr>
  </tbody>
</table>"""

    templateevent += """
<!-- GLPI INFORMATION -->
<!-- uuid_inventorymachine = @uuid_inventorymachine@
glpi_description =@glpi_description@
glpi_owner_firstname = @glpi_owner_firstname@
glpi_owner_realname = @glpi_owner_realname@
glpi_owner = @glpi_owner@ -->
<table>
  <!-- <caption>Device information</caption> -->
   <thead>
        <tr>
            <th colspan="5">GLPI INFORMATIONS</th>
        </tr>
    </thead>
  <tbody>
    <tr>
      <th scope="col">id</th>
      <th scope="col">description</th>
      <th scope="col">owner_firstname</th>
      <th scope="col">owner_realname</th>
      <th scope="col">owner</th>
    </tr>
    <tr>
      <td>@uuid_inventorymachine@</td>
      <td>@glpi_description@</td>
      <td>@glpi_owner_firstname@</td>
      <td>@glpi_owner_realname@</td>
      <td>@glpi_owner@</td>
    </tr>
  </tbody>
</table>"""

    if dictresult["ad_ou_machine"] or dictresult["ad_ou_user"]:
        templateevent += """
        <!-- AD INFORMATION -->
        <!-- ad_ou_machine = @ad_ou_machine@
        ad_ou_user =@ad_ou_user@ -->
        <table>
        <!-- <caption>ACTIVE DIRECTORY INFORMATIONS</caption> -->
        <thead>
                <tr>
                    <th colspan="2">ACTIVE DIRECTORY INFORMATIONS</th>
                </tr>
            </thead>
        <tbody>
            <tr>
            <th scope="col">OU USER</th>
            <th scope="col">OU MACHINE</th>
            </tr>
            <tr>
            <td>@ad_ou_user@</td>
            <td>@ad_ou_machine@</td>
            </tr>
        </tbody>
        </table>"""

    templateevent += """
<!-- EVENT INFORMATION -->
<!-- mon_event_type_event = @mon_event_type_event@
mon_event_id = @mon_event_id@
mon_event_cmd = @mon_event_cmd@
mon_event_status_event = @mon_event_status_event@
mon_event_machines_id = @mon_event_machines_id@
mon_event_id_device = @mon_event_id_device@
mon_event_id_rule = @mon_event_id_rule@
mon_event_ack_date = @mon_event_ack_date@
mon_event_parameter_other = @mon_event_parameter_other@
mon_event_ack_user = @mon_event_ack_user@ -->

<!-- RULES INFORMATION -->
<!-- mon_rules_user = @mon_rules_user@
mon_rules_error_on_binding = @mon_rules_error_on_binding@
mon_rules_id = @mon_rules_id@
mon_rules_hostname = @mon_rules_hostname@
mon_rules_succes_binding_cmd = @mon_rules_succes_binding_cmd@
mon_rules_comment = @mon_rules_comment@
mon_rules_binding = @mon_rules_binding@
mon_rules_type_event = @mon_rules_type_event@
mon_rules_device_type = @mon_rules_device_type@
mon_rules_no_success_binding_cmd = @mon_rules_no_success_binding_cmd@ -->

<table>
  <!-- <caption>Device information</caption> -->
   <thead>
        <tr>
            <th colspan="6">RULES</th>
        </tr>
    </thead>
  <tbody>
    <tr>
      <th scope="col">HOSTNAME/ALL</th>
      <th scope="col">Type</th>
      <th scope="col">param user rule</th>
      <th scope="col">comments</th>
      <th scope="col">BINDING</th>
      <th scope="col">cmd</th>
    </tr>
    <tr>
     <td>@mon_rules_hostname@</td>
      <td>@mon_rules_type_event@</td>
      <td>@mon_rules_user@</td>
      <td>@mon_rules_comment@</td>
      <td><code>@mon_rules_binding@</code></td>
      <td><code>@mon_event_cmd@</code></td>
    </tr>
  </tbody>
</table>

</body>
</html>"""
    for t in dictresult:
        search = f"@{t}@"
        templateevent = templateevent.replace(search, str(dictresult[t]))
    return templateevent


def loads_alert():
    """
    Metadata to be added in the python script
    """
    msgfrom = """@@@@@msgfrom@@@@@"""
    binding = """@@@@@binding@@@@@"""

    serialisationpickleevent = """@@@@@event@@@@@"""

    eventstruct = json.loads(serialisationpickleevent)
    if "general_status" in eventstruct["mon_devices_doc"]:
        eventstruct["general_status"] = eventstruct["mon_devices_doc"]["general_status"]

    # ---------------------------------------------
    # eventstruct est la structure des informations de l'alerte.
    # ----------------------------------------------------
    return eventstruct, msgfrom.strip(), binding.strip()


class message_email_smtp_ssl:
    def __init__(self, serverhost, porthost, compte_email, email_password):
        self.serverhost = serverhost
        self.porthost = porthost
        self.compte_email = compte_email
        self.email_password = email_password
        self.fromaddr = f"Alert <{compte_email}>"
        self.subject_email = "Event report"
        self.namefile = None

    def destinaire(self, list_to_addrs_array):
        if isinstance(list_to_addrs_array, basestring):
            self.to_addrs_array = list_to_addrs_array.split(",")
        else:
            self.to_addrs_array = list_to_addrs_array

    def subject(self, subject_email="Event report"):
        self.subject_email = subject_email

    def document_attache(self, namefile=None):
        self.namefile = namefile

    def message_text(self, minetype_plain_text=None):
        self.msg_plain_text = minetype_plain_text

    def message_html(self, minetype_html_text=None):
        self.msg_html_text = minetype_html_text

    def connectsend(self):
        if self.msg_plain_text:
            try:
                self.server = (
                    smtplib.SMTP_SSL()
                )  # We use the SMTP_SSL() function instead of SMTP()
                print(self.serverhost)
                print(self.porthost)
                connect_to_server = self.server.connect(self.serverhost, self.porthost)
                print(connect_to_server)

                hello_from_server = self.server.ehlo()
                print(hello_from_server)
                self.server.login(self.compte_email, self.email_password)
                return True
            except BaseException:
                print("\n%s" % (traceback.format_exc()))
                return False
        else:
            print("Message undefined")
        return False

    def send_mail(self):
        if not self.connectsend():
            return
        msg = MIMEMultipart("alternative")
        msg["From"] = self.fromaddr
        msg["To"] = ",".join(self.to_addrs_array)
        msg["Subject"] = self.subject_email
        msg["Date"] = formatdate(localtime=True)
        # Record the MIME types of both parts - text/plain and text/html.
        if self.msg_plain_text:
            part1 = MIMEText(self.msg_plain_text, "plain")
            msg.attach(part1)
        if self.msg_html_text:
            part2 = MIMEText(self.msg_html_text, "html")
            msg.attach(part2)
        if self.namefile:
            if os.path.isfile(self.namefile):
                suffixe = self.namefile.split(".")
                suffixe = suffixe[-1] if len(suffixe) > 1 else "dat"
                with open(self.namefile, "rb") as fp:
                    att = email.mime.application.MIMEApplication(
                        fp.read(), _subtype=suffixe
                    )
                att.add_header(
                    "Content-Disposition",
                    "attachment",
                    filename=os.path.basename(self.namefile),
                )
                msg.attach(att)
        try:
            self.server.sendmail(self.fromaddr, self.to_addrs_array, msg.as_string())
        except smtplib.SMTPException as e:
            print(e)
        self.server.quit()


class message_email_smtp_ssl_tls:
    def __init__(self, serverhost, porthost, compte_email, email_password):
        self.serverhost = serverhost
        self.porthost = porthost
        self.compte_email = compte_email
        self.email_password = email_password
        self.fromaddr = f"Alert <{compte_email}>"
        self.subject_email = "Event report"
        self.namefile = None

    def destinaire(self, list_to_addrs_array):
        self.to_addrs_array = list_to_addrs_array

    def subject(self, subject_email="Event report"):
        self.subject_email = subject_email

    def document_attache(self, namefile=None):
        self.namefile = namefile

    def message_text(self, minetype_plain_text=None):
        self.msg_plain_text = minetype_plain_text

    def message_html(self, minetype_html_text=None):
        self.msg_html_text = minetype_html_text

    def connectsend(self):
        if self.msg_plain_text:
            try:
                self.server = smtplib.SMTP()  # With TLS, we use SMTP()
                print(self.serverhost)
                print(self.porthost)
                connect_to_server = self.server.connect(self.serverhost, self.porthost)
                print(connect_to_server)
                logger.debug(f"connect_to_server {connect_to_server}")

                hello_from_server = self.server.ehlo()
                print(hello_from_server)

                self.server.starttls()
                self.server.login(self.compte_email, self.email_password)
                return True
            except BaseException:
                print("\n%s" % (traceback.format_exc()))
                return False
        else:
            print("Message undefined")
        return False

    def send_mail(self):
        if not self.connectsend():
            return
        msg = MIMEMultipart("alternative")
        msg["From"] = self.fromaddr
        msg["To"] = ",".join(self.to_addrs_array)
        msg["Subject"] = self.subject_email
        msg["Date"] = formatdate(localtime=True)
        # Record the MIME types of both parts - text/plain and text/html.
        if self.msg_plain_text:
            part1 = MIMEText(self.msg_plain_text, "plain")
            msg.attach(part1)
        if self.msg_html_text:
            part2 = MIMEText(self.msg_html_text, "html")
            msg.attach(part2)
        if self.namefile:
            if os.path.isfile(self.namefile):
                suffixe = self.namefile.split(".")
                suffixe = suffixe[-1] if len(suffixe) > 1 else "dat"
                with open(self.namefile, "rb") as fp:
                    att = email.mime.application.MIMEApplication(
                        fp.read(), _subtype=suffixe
                    )
                att.add_header(
                    "Content-Disposition",
                    "attachment",
                    filename=os.path.basename(self.namefile),
                )
                msg.attach(att)
        try:
            self.server.sendmail(self.fromaddr, self.to_addrs_array, msg.as_string())
        except smtplib.SMTPException as e:
            print(e)
        self.server.quit()


def main():
    doc = _template_html_event(eventstruct)
    if eventstruct["mon_rules_comment"]["email_servertype"]:
        emailobj = message_email_smtp_ssl(
            eventstruct["mon_rules_comment"]["email_server"],
            eventstruct["mon_rules_comment"]["email_serverport"],
            eventstruct["mon_rules_comment"]["email_account"],
            eventstruct["mon_rules_comment"]["email_password"],
        )
        emailobj.subject(subject_email=eventstruct["mon_rules_comment"]["subject"])
        emailobj.destinaire([eventstruct["mon_rules_user"]])
        emailobj.message_text(minetype_plain_text="ne pas repondre")
        emailobj.message_html(minetype_html_text=doc)
        emailobj.send_mail()


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.DEBUG,
        format="%(asctime)s %(message)s",
        filename=LOGFILE,
        filemode="a",
    )
    logger.debug("Program Starting")
    eventstruct, msgfrom, binding = loads_alert()
    print(json.dumps(eventstruct, indent=4))

    main()
