from collections import namedtuple
from . import utils

ClientHello = namedtuple("ClientHello", ["random", "session_id", "public_key"])


def parse_client_message(client_message: bytes):
    client_message = client_message.hex()
    end_of_msg = 68

    index_client_version = client_message.find("0303")
    client_random = client_message[index_client_version + 4: index_client_version + end_of_msg]

    idx_client_random = client_message.find(client_random)
    start_idx_session_id = idx_client_random + 64
    session_id = client_message[start_idx_session_id + 2: start_idx_session_id + end_of_msg - 2]

    start_idx_key_share = client_message.rfind("0020")
    client_key = client_message[start_idx_key_share + 4: start_idx_key_share + end_of_msg]

    encoded_key = bytes.fromhex(client_key)
    encoded_session_id = bytes.fromhex(session_id)
    encoded_client_random = bytes.fromhex(client_random)

    client_key = utils.generate_public_key(encoded_key)
    return ClientHello(encoded_client_random, encoded_session_id, client_key)
   
