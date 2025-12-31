import logging
import socket
import threading
from constants import TLS_RECORD
import tls.main
from routing import handle_path
from http_message import Request

FORMAT = '%(name)s: %(asctime)s - (%(levelname)s) %(message)s'
logging.basicConfig(format=FORMAT)

logger = logging.getLogger("tls_server")
logger.setLevel(logging.INFO)


def handle_request(client_sock: socket.socket, request_id: int):
    try:
        batch_size = 2048
        data = client_sock.recv(batch_size)
        is_https = data.hex(sep=" ").startswith(TLS_RECORD)

        if is_https:
            logger.info("https request being handled...")
            tls_session = tls.main.TlsSession(client_sock)
            data = tls_session.handle_https_request(data)

        request = Request(data)
        content_length = request.find_header("Content-Length")

        if content_length:
            content_length = int(content_length) - batch_size
       
        else:
            content_length = 0

        if content_length > batch_size:
            byte_list = [request.body]

            while content_length > 0:
                content_length -= batch_size
                byte_list.append(client_sock.recv(batch_size))
            
            request.body = b"".join(byte_list)

        response = handle_path(request)
        logger.info(f"responding to request {request_id}")

        if is_https:
            logger.info("\n sending https response...")
            client_sock.sendall(tls_session.wrap_app_msg(response))

        else:
            client_sock.sendall(response)

    finally:
        client_sock.close()


def start_server(port: int, max_connections: int):
    request_count = -1

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_sock:
        server_sock.bind(("localhost", port))
        server_sock.listen(max_connections)
        logger.info(f"spinning up server on port {port}...")

        while True:
            client_sock, _ = server_sock.accept()
            request_count += 1

            try:
                t = threading.Thread(target=handle_request, args=((client_sock, request_count)))
                t.daemon = True
                t.start()
                
            except Exception as e:
                logger.critical(f"Exception received\n{e}")
                logger.critical("Shutting down...")
                break


if __name__ == "__main__":
    start_server(8000, 5)
