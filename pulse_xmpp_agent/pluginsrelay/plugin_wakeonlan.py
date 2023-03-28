# SPDX-FileCopyrightText: 2016-2023 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-2.0-or-later

from lib import utils
from wakeonlan import wol

plugin={"VERSION": "2.0", "NAME" :"wakeonlan","TYPE":"relayserver"}
@utils.pluginprocess
def action( objectxmpp, action, sessionid, data, message, dataerreur,result):
    print data
    if hasattr(objectxmpp.config, 'wol_port'):
        wol_port = int(objectxmpp.config.wol_port)
    else:
        wol_port = 9

    try:
        wol.send_magic_packet(data['macaddress'], port=wol_port)
        result['data']['start'] = "ok"
    except:
        dataerreur['data']['msg'] = "ERROR : plugin wakeonlan"
        dataerreur['ret'] = 255
        raise
