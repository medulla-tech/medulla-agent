#!/usr/bin/env python3
# -*- coding: utf-8; -*-
# SPDX-FileCopyrightText: 2016-2023 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-3.0-or-later

from slixmpp import ClientXMPP, WebSocketXMPP


def client_base(conf):
    """Return the slixmpp class the XMPP client must inherit from."""
    if getattr(conf, "enable_websocket", False) and getattr(conf, "websocket_url", ""):
        return WebSocketXMPP
    return ClientXMPP


def init_client(client, jid, password, conf):
    """Run the __init__ of the class returned by client_base()."""
    if client_base(conf) is WebSocketXMPP:
        WebSocketXMPP.__init__(client, jid, password, conf.websocket_url)
    else:
        ClientXMPP.__init__(client, jid, password)


def connect_client(client, host, port):
    """Connect over WebSocket for a WebSocketXMPP client, otherwise over TCP."""
    if isinstance(client, WebSocketXMPP):
        client.connect(url=client._ws_url)
    else:
        client.connect(host=host, port=port)
