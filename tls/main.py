import logging
import socket

from constants import APPLICATION_DATA_RECORD_TYPE, TLS_VERSION
from . import client, server, utils

logger = logging.getLogger("tls_server")


class TlsSession:
    def __init__(self, client_sock: socket.socket):
        self.client_sock = client_sock
        self.app_keys = None
        self.handshake_keys = None
        
        self.app_record_count = 0
        self.handshake_record_count = 0


    def wrap_handshake_msg(self, data: bytes):
        record_type = bytes([APPLICATION_DATA_RECORD_TYPE])
        protocol_version = bytes(TLS_VERSION)
        len_data_in_bytes = (len(data) + 17).to_bytes(2, "big")
        final_byte = bytes([0x16])

        additional = record_type + protocol_version + len_data_in_bytes
        encrypted_data = utils.encrypt(self.handshake_keys.shs_key, utils.xor_iv(self.handshake_keys.shs_iv, self.handshake_record_count), data + final_byte, additional)
        
        record = additional + encrypted_data
        self.handshake_record_count += 1

        return record
   

    def wrap_app_msg(self, data: bytes):
        record_type = bytes([APPLICATION_DATA_RECORD_TYPE])
        protocol_version = bytes(TLS_VERSION)

        try:
            len_data_in_bytes = (len(data) + 17).to_bytes(2, "big")
        except OverflowError as e:
            logger.exception(f"Too much data to send over HTTPS...\n{e}")

        final_byte = bytes([APPLICATION_DATA_RECORD_TYPE])
        additional = record_type + protocol_version + len_data_in_bytes
        encrypted_data = utils.encrypt(self.app_keys.server_app_key, utils.xor_iv(self.app_keys.server_app_iv, self.app_record_count), data + final_byte, additional)
        
        record = additional + encrypted_data
        self.app_record_count += 1

        return record

    
    def unwrap_handshake_msg(self, encrypted_msg: bytes):
        additional, ciphertext = encrypted_msg[:5], encrypted_msg[5:]

        return utils.decrypt(self.handshake_keys.chs_key, self.handshake_keys.chs_iv, ciphertext, additional)


    def unwrap_app_msg(self, encrypted_msg: bytes):
        additional, ciphertext = encrypted_msg[:5], encrypted_msg[5:]

        return utils.decrypt(self.app_keys.client_app_key, self.app_keys.client_app_iv, ciphertext, additional)

   
    def handle_https_request(self, request: bytes):
        running_msgs = request[5:]

        client_hello = client.parse_client_message(request)
        server_hello = server.create_server_hello(client_hello.session_id)
        
        server_hello_msg = bytes(server_hello.message)
        self.client_sock.send(server_hello_msg)

        running_msgs += server_hello_msg[5:]

        self.handshake_keys = utils.make_handshake_keys(client_hello.public_key, server_hello.private_key, request[5:], server_hello_msg[5:])

        change_cipher_spec = [0x14]
        change_cipher_spec.extend(TLS_VERSION)
        change_cipher_spec.extend([0x00, 0x01, 0x01])
        change_cipher_spec = bytes(change_cipher_spec)
        
        s_extensions = bytes([0x08, 0x00, 0x00, 0x02, 0x00, 0x00])
        s_encrypted_extensions = self.wrap_handshake_msg(s_extensions)

        running_msgs += s_extensions
       
        cert = utils.get_server_cert()
        cert_message_type = bytes([0x0b])
        cert_payload_len = (len(cert) + 9).to_bytes(3, "big")
        cert_handshake_header = cert_message_type + cert_payload_len

        request_context = bytes([0x00])
        certificates_len = (len(cert) + 5).to_bytes(3, "big")  # len of all certs
        cert_len = len(cert).to_bytes(3, "big")
        cert_extensions = bytes([0x00, 0x00])

        cert_data = cert_handshake_header + request_context + certificates_len + cert_len + cert + cert_extensions
        s_cert_wrapped = self.wrap_handshake_msg(cert_data)

        running_msgs += cert_data

        # NOTE: Cert verify
        hashed_msgs = utils.hash_messages(running_msgs)
        msgs = bytes([0x20] * 64) + b"TLS 1.3, server CertificateVerify" + b"\0"

        signed_data = utils.sign_hash(utils.hash_messages(msgs + hashed_msgs))

        algorithm_val = bytes([0x08, 0x04])
        len_signature = len(signed_data).to_bytes(2, "big")

        cert_verify_msg_type = bytes([0x0f])
        cert_verify_payload_len = (len(signed_data) + len(algorithm_val) + len(len_signature)).to_bytes(3, "big")
        cert_verify_header = cert_verify_msg_type + cert_verify_payload_len

        cert_verify_data = cert_verify_header + algorithm_val + len_signature + signed_data
        s_cert_verify = self.wrap_handshake_msg(cert_verify_data)

        running_msgs += cert_verify_data

        # NOTE: Server Handshake Finished
        verify_hash = utils.verify_data(self.handshake_keys.shs, running_msgs)
        hs_done_msg_type = bytes([0x14])
        hs_final_header = hs_done_msg_type + (len(verify_hash)).to_bytes(3, "big")

        verify_data = hs_final_header + verify_hash
        s_hs_final_msg = self.wrap_handshake_msg(verify_data)

        running_msgs += verify_data

        self.app_keys = utils.make_server_app_keys(self.handshake_keys.handshake_secret, running_msgs)

        self.client_sock.sendall(change_cipher_spec + s_encrypted_extensions + s_cert_wrapped + s_cert_verify + s_hs_final_msg)
        self.client_sock.recv(80)

        next_client_return = self.client_sock.recv(1024)
        next_decipher = self.unwrap_app_msg(next_client_return)

        return next_decipher


