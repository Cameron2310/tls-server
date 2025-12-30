from collections import namedtuple
from os import urandom

from constants import TLS_VERSION
from . import utils

ServerHello = namedtuple("ServerHello", ["message", "private_key"])


def create_server_hello_extensions(keys: utils.KeyPair):
    supported_versions = utils.create_extension(0x2b, [0x03, 0x04])

    len_key = (len(keys.public_key.public_bytes_raw())).to_bytes(2, "big")
    public_key_raw = keys.public_key.public_bytes_raw()

    key_bytes = utils.create_extension(0x33, 0x1d.to_bytes(2, "big") + len_key + public_key_raw)
    
    return supported_versions + key_bytes 


def create_server_hello(session_id) -> ServerHello:
    handshake_record = [0x16]
    keys = utils.generate_key_pair()

    server_random = [int(i) for i in urandom(32)]

    cipher_suite = [0x13, 0x01]
    compression_method = [0x00]

    extensions = create_server_hello_extensions(keys)
    handshake = TLS_VERSION + server_random + [0x20] + [int(i) for i in session_id] + cipher_suite + compression_method + [int(i) for i in (len(extensions)).to_bytes(2, "big")] + extensions 

    handshake_data = [int(i) for i in (len(handshake) + 4).to_bytes(2, "big")]
    len_handshake = [int(i) for i in (len(handshake)).to_bytes(2, "big")]

    return ServerHello(handshake_record + TLS_VERSION + handshake_data + [0x02, 0x00] + len_handshake + handshake, keys.private_key)
