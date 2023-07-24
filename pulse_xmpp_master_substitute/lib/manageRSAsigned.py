# -*- coding: utf-8; -*-
# SPDX-FileCopyrightText: 2016-2023 Siveo <support@siveo.net>
# SPDX-License-Identifier: GPL-3.0-or-later


from Cryptodome.PublicKey import RSA
from Cryptodome.Signature import pss
from Cryptodome.Hash import SHA256
import os
import base64

import logging
import traceback

logger = logging.getLogger()


class MsgsignedRSA:
    """
        Class use for verify from message xmpp.
        The message structure pulse xmpp has a session id.
        Session id is signed with the private key of the sender of the message.
        The receiver of the message can verify the origin of the message by comparing\
        the signature of the sessionid with the sessionid.

        Examples sender signed  data:
            master = MsgsignedRSA("master")
            sig = master.signedmsg(data)

            receiver verify data:
            client = MsgsignedRSA("client")
            key_public_server_String_base = "KGlDcnlwdG8uUHVibGljS.....NTE5OTFMCnNiLg=="
            object_key_public_server = client.Base64_To_ObjKeyRSA(key_public_server_String_base)
            client.verifymsg(object_key_public_server,data, sig)
    """

    def __init__(self, type):
        """
        :param type: Uses this parameter to give a name to the key
        :type b: string
        :return: Function init has no return
        """
        self.type = type
        self.filekeypublic = os.path.join(
            self.Setdirectorytempinfo(), "%s-public-RSA.key" % self.type
        )
        self.fileallkey = os.path.join(
            self.Setdirectorytempinfo(), "%s-all-RSA.key" % self.type
        )
        # format PEM
        self.filekeyprivate = os.path.join(
            self.Setdirectorytempinfo(), "%s-private-RSA.key" % self.type
        )
        self.dirtempinfo = self.Setdirectorytempinfo()
        self.allkey = None
        self.publickey = None
        self.privatekey = None
        self.bpublickey = None
        self.bprivatekey = None
        self.init_key()

    def tobytes(self, s, encoding="latin-1"):
        if s is None:
            return None
        if isinstance(s, bytes):
            return s
        elif isinstance(s, bytearray):
            return bytes(s)
        elif isinstance(s, str):
            return s.encode(encoding)
        elif isinstance(s, memoryview):
            return s.tobytes()
        else:
            return bytes([s])

    def tostr(self, bs):
        if bs is None:
            return None
        if isinstance(bs, str):
            return bs
        return bs.decode("latin-1")

    def byte_string(self, s):
        return isinstance(s, bytes)

    def init_key(self):
        """
        Function that loads the keys if it exists or creates\
        them in the case where it does not exist.
        """
        if os.path.exists(self.filekeypublic) and os.path.exists(self.filekeyprivate):
            # on charge les keys
            self.bprivatekey = RSA.import_key(open(self.filekeyprivate).read())
            self.bpublickey = RSA.import_key(open(self.filekeypublic).read())
            self.bprivatekey = self.bprivatekey.export_key()
            self.bpublickey = self.bpublickey.export_key()
            self._init_key()
        else:
            self.generateRSAclefagentOpenssh()

    def _init_keypub(self):
        self.publickey = self.tostr(base64.b64encode(self.bpublickey))

    def _init_keypriv(self):
        self.privatekey = self.tostr(base64.b64encode(self.bprivatekey))

    def _init_key(self):
        self._init_keypub()
        self._init_keypriv()

    def get_key_public(self):
        return self.publickey

    def get_key_private(self):
        return self.privatekey

    def get_key_public_bytes(self):
        return self.bpublickey

    def get_key_private_byte(self):
        return self.bprivatekey

    def get_key_public_base64_bytes(self):
        return base64.b64encode(self.bpublickey)

    def get_key_private_base64_byte(self):
        return base64.b64encode(self.bprivatekey)

    def get_name_key(self):
        return ["%s-public-RSA.key" % self.type, "%s-private-RSA.key" % self.type]

    def generateRSAclefagentOpenssh(self):
        """
        Function generate clef RSA to file
        sauve key in string
        """
        self.allkey = RSA.generate(2048)
        self.bpublickey = self.allkey.export_key("OpenSSH")
        self.bprivatekey = self.allkey.export_key("PEM")

        # write fichier public et private
        with open(self.filekeypublic, "wb") as file:
            file.write(self.bpublickey)
        with open(self.filekeyprivate, "wb") as file:
            file.write(self.bprivatekey)
        self.bpublickey = self.bpublickey
        self.bprivatekey = self.bprivatekey
        self._init_key()
        return self.allkey

    def loadkeypublic(self, filekeypublic=None):
        """
        Function load from file the public key to object RSA key
        """
        if filekeypublic is not None:
            filekeypublic = self.tostr(filekeypublic)
            if os.path.exists(filekeypublic):
                out = RSA.import_key(open(filekeypublic).read())
                return out.export_key()
            else:
                logger.error("loadkeypublic verify path public key %s" % filekeypublic)
                return None
        else:
            filekeypublic = self.filekeypublic
            if os.path.exists(filekeypublic):
                self.bpublickey = RSA.import_key(open(filekeypublic).read())
                self.bpublickey = self.bpublickey.export_key()
                self._init_keypub()
                return self.bpublickey
            return None

    def loadkeyprivate(self, filekeyprivate=None):
        """
        Function load from file the public key to object RSA key
        """
        if filekeyprivate is not None:
            filekeyprivate = self.tostr(filekeyprivate)
            if os.path.exists(filekeyprivate):
                out = RSA.import_key(open(filekeyprivate).read())
                return out.export_key()
            else:
                logger.error(
                    "loadkeypublic verify path private key %s" % filekeyprivate
                )
                return None
        else:
            filekeyprivate = self.filekeyprivate
            if os.path.exists(filekeyprivate):
                self.bprivatekey = RSA.import_key(open(filekeyprivate).read())
                self.bprivatekey = self.bprivatekey.export_key()
                self._init_keypriv()
                return self.bprivatekey
            return None

    def loadkeypublicbytes(self, filekeypublic=None):
        """
        Function load from file the public key to object RSA key
        """
        return self.tobytes(self.loadkeypublic(filekeypublic=filekeypublic))

    def loadkeyprivatebytes(self, filekeyprivate=None):
        """
        Function load from file the private key to object RSA key
        """
        return self.tobytes(self.loadkeyprivate(filekeyprivate=filekeyprivate))

    def loadkeypublictobase64byte(self, filekeypublic=None):
        """
        Function load from file the public keys RSA as a base64 string
        """
        if filekeypublic is None:
            return None

        bkespub = self.loadkeypublicbytes(self, filekeypublic=filekeypublic)

        if bkespub is None:
            return None

        return base64.b64encode(bkespub)

    def loadkeypublictobase64(self, filekeypublic=None):
        """
        Function load from file the public keys RSA as a base64 string
        """
        return self.tostr(self.loadkeypublictobase64byte(filekeypublic=filekeypublic))

    def loadkeyprivatetobase64byte(self, filekeyprivate=None):
        """
        Function load from file the private keys RSA as a base64 string
        """
        if filekeypublic is None:
            return None

        bkespriv = self.loadkeyprivatebytes(self, filekeyprivate=filekeyprivate)

        if bkespriv is None:
            return None

        return base64.b64encode(bkespriv)

    def loadkeyprivatetobase64(self, filekeyprivate=None):
        """
        Function load from file the private keys RSA as a base64 string
        """
        return self.tostr(
            self.loadkeyprivatetobase64byte(filekeyprivate=filekeyprivate)
        )

    def Setdirectorytempinfo(self):
        """
        create directory
        """
        dirtempinfo = os.path.join(
            os.path.dirname(os.path.realpath(__file__)), "..", "INFOSTMP"
        )
        if not os.path.exists(dirtempinfo):
            os.makedirs(dirtempinfo, mode=0o700)
        return dirtempinfo

    def signedmsg(self, message, file_private_key=None):
        """
        Function signed message with key private.
        """
        if file_private_key is not None:
            file_private_key = self.tostr(file_private_key)
        else:
            file_private_key = self.filekeyprivate
        if not os.path.exists(file_private_key):
            logger.error("signed msg impossible read private key %s" % file_private_key)
            return False
        message = self.tobytes(message)
        key = RSA.import_key(open(file_private_key).read())
        b_h = SHA256.new(message)
        signature = pss.new(key).sign(b_h)
        return self.tostr(base64.b64encode(signature))

    def verifymsg(self, message, b64_signed_message, file_public_key=None):
        """
        Function verify message with footprint
        """
        if file_public_key is not None:
            file_public_key = self.tostr(file_public_key)
        else:
            file_public_key = self.filekeypublic
        if not os.path.exists(file_public_key):
            logger.error("verifymsg impossible read public key %s" % file_public_key)
            return False
        message = self.tobytes(message)
        b_signed_message = base64.b64decode(self.tobytes(b64_signed_message))
        key = RSA.import_key(open(file_public_key).read())
        b_h = SHA256.new(message)
        verifier = pss.new(key)
        try:
            verifier.verify(b_h, b_signed_message)
            return True
        except (ValueError, TypeError):
            pass
        return False

    def isPublicKey(self, name):
        """
        function check if  key name file exist
        :param name: Uses this parameter to give a name to the key
        :type name : string
        :return boolean exist or not exist
        """
        filepublickey = os.path.join(
            self.Setdirectorytempinfo(), "%s-public-RSA.key" % name
        )
        if os.path.exists(filepublickey):
            return True
        else:
            return False


def installpublickey(name_or_filepublickey, keybase64, typekey="public"):
    return install_key(name_or_filepublickey, keybase64, typekey)


def installprivatekey(name_or_filepublickey, keybase64, typekey="private"):
    return install_key(name_or_filepublickey, keybase64, typekey)


def install_key(name_or_filepublickey, keybase64, typekey):
    """
    function install key from str base64 key to file name
    remarque: install only if key name missing
        if key exist in file then not use parameter keybase64

    :param name_or_filepublickey: Uses this parameter to give a name to the key
                                    or the complet path of the key public
    :param keybase64: Uses this parameter to give a key
    :type keybase64 : string or bytes in base64 key

    :return: Function return objetkey load from file ou use keybase64 parameter
    """

    def tostr(bs):
        if bs is None:
            return None
        if isinstance(bs, str):
            return bs
        return bs.decode("latin-1")

    def tobytes(s, encoding="latin-1"):
        if s is None:
            return None
        if isinstance(s, bytes):
            return s
        elif isinstance(s, bytearray):
            return bytes(s)
        elif isinstance(s, str):
            return s.encode(encoding)
        elif isinstance(s, memoryview):
            return s.tobytes()
        else:
            return bytes([s])

    try:
        if not keybase64:
            logger.error("[install_key] verifymsg keybase64  =(%s)" % keybase64)
        keybase64 = install_key.tobytes(keybase64)

        name_or_filepublickey = install_key.tostr(name_or_filepublickey)
        if name_or_filepublickey:
            dirname = os.path.dirname(name_or_filepublickey)
            if dirname:
                if not os.path.exists(dirname):
                    os.makedirs(dirname, mode=0o700)
                filepublickey = name_or_filepublickey
            else:
                # name key
                filepublickey = os.path.join(
                    os.path.dirname(os.path.realpath(__file__)),
                    "..",
                    "INFOSTMP",
                    "%s-%s-RSA.key" % (name_or_filepublickey, typekey),
                )
        else:
            logger.error(
                "[install_key %s ] verifymsg name or path key %s"
                % (typekey, name_or_filepublickey)
            )
            return False
        try:
            with open(filepublickey, "wb") as file:
                file.write(base64.b64decode(keybase64))
            return True
        except Exception:
            logger.error("install_key")
            logger.error("\n%s" % (traceback.format_exc()))
    except Exception:
        logger.error("install_key")
        logger.error("\n%s" % (traceback.format_exc()))
    return False
