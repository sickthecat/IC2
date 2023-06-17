import socket
import threading
from cryptography.fernet import Fernet
import base64
import hashlib
import hmac
import ssl
from queue import Queue

class ChatServer:
    def __init__(self, host, port, password):
        self.host = host
        self.port = port
        self.clients = []
        self.key = Fernet.generate_key()
        self.fernet = Fernet(self.key)
        self.mac_key = hashlib.sha256(self.key).digest()
        self.password = password
        self.broadcast_queue = Queue()  # Add the broadcast_queue attribute

    def start(self):
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        context.load_cert_chain(certfile="fullchain.pem", keyfile="privkey.pem")

        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0) as sock:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                with context.wrap_socket(sock, server_side=True) as ssock:
                    ssock.bind((self.host, self.port))
                    ssock.listen(5)
                    print("Server started on {}:{}".format(self.host, self.port))

                    # Start a separate thread for message broadcasting
                    broadcast_thread = threading.Thread(target=self.broadcast_messages)
                    broadcast_thread.start()

                    while True:
                        client_socket, addr = ssock.accept()
                        if not self.verify_client_auth(client_socket):
                            print("Client authentication failed for address:", addr)
                            client_socket.close()
                            continue

                        self.clients.append(client_socket)

                        client_thread = threading.Thread(target=self.handle_client, args=(client_socket,))
                        client_thread.start()
        except socket.error as e:
            print("Error starting the server:", e)

    def verify_client_auth(self, client_socket):
        try:
            client_socket.sendall(b"Password:")
            password_attempt = client_socket.recv(1024).decode().strip()
            if password_attempt != self.password:
                client_socket.sendall(b"Authentication failed. Closing connection.")
                return False
            else:
                client_socket.sendall(b"Authentication successful. Connection established.")
                return True
        except socket.error as e:
            print("Error verifying client authentication:", e)
            return False

    def handle_client(self, client_socket):
        try:
            encrypted_key = self.key
            client_socket.send(base64.urlsafe_b64encode(encrypted_key))
        except socket.error as e:
            print("Error sending encryption key to client:", e)
            self.remove_client(client_socket)
            return

        while True:
            try:
                encrypted_msg = client_socket.recv(1024)
                if not encrypted_msg:
                    self.remove_client(client_socket)
                    break

                decrypted_msg = self.fernet.decrypt(encrypted_msg).decode()
                if not self.verify_message(decrypted_msg):
                    print("Message verification failed, potential tampering detected.")
                    self.remove_client(client_socket)
                    break

                print("Received message:", decrypted_msg)

                # Add the received message to the broadcast queue
                self.broadcast_queue.put((client_socket, decrypted_msg))
            except (socket.error, Fernet.InvalidToken) as e:
                print("Error handling client message:", e)
                self.remove_client(client_socket)
                break

    def broadcast_messages(self):
        while True:
            if not self.broadcast_queue.empty():
                sender_socket, message = self.broadcast_queue.get()

                encrypted_reply = self.fernet.encrypt(message.encode())
                self.broadcast(sender_socket, encrypted_reply)

    def broadcast(self, sender_socket, msg):
        for client_socket in self.clients:
            if client_socket != sender_socket:
                try:
                    client_socket.send(msg)
                except socket.error as e:
                    print("Error broadcasting message to a client:", e)
                    self.remove_client(client_socket)

    def remove_client(self, client_socket):
        if client_socket in self.clients:
            self.clients.remove(client_socket)
            client_socket.close()

    def verify_message(self, message):
        message_parts = message.split(":")
        if len(message_parts) != 2:
            return False

        received_message = message_parts[0]
        received_mac = base64.urlsafe_b64decode(message_parts[1])
        calculated_mac = hmac.new(self.mac_key, received_message.encode(), hashlib.sha256).digest()

        return hmac.compare_digest(calculated_mac, received_mac)


if __name__ == "__main__":
    password = "vision"  # Replace with your desired password
    server = ChatServer('afflicted.sh', 8003, password)
    server.start()

