import threading
import socket
import base64
from cryptography.fernet import Fernet
import hashlib
import hmac
import ssl


class ChatClient:
    def __init__(self, host, port, password):
        self.host = host
        self.port = port
        self.key = None
        self.fernet = None
        self.mac_key = None
        self.password = password.encode()

    def connect(self):
        try:
            context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            client_socket = context.wrap_socket(socket.socket(socket.AF_INET, socket.SOCK_STREAM))
            client_socket.connect((self.host, self.port))
            print("Connected to {}:{}".format(self.host, self.port))
        except socket.error as e:
            print("Error connecting to the server:", e)
            return

        try:
            password_prompt = client_socket.recv(1024).decode().strip()
            if password_prompt != "Password:":
                print("Unexpected server response. Closing connection.")
                client_socket.close()
                return

            client_socket.sendall(self.password)
            auth_response = client_socket.recv(1024).decode().strip()
            if auth_response != "Authentication successful. Connection established.":
                print("Authentication failed. Closing connection.")
                client_socket.close()
                return
        except socket.error as e:
            print("Error during authentication:", e)
            client_socket.close()
            return

        try:
            encrypted_key = base64.urlsafe_b64decode(client_socket.recv(1024))
            self.key = encrypted_key
            self.fernet = Fernet(self.key)
            self.mac_key = hashlib.sha256(self.key).digest()
        except socket.error as e:
            print("Error receiving encryption key from server:", e)
            client_socket.close()
            return

        receive_thread = threading.Thread(target=self.receive_messages, args=(client_socket,))
        receive_thread.start()

        while True:
            message = input("Enter a message: ")
            if message.lower() == "exit":
                break

            self.send_message(client_socket, message)

        client_socket.close()

    def receive_messages(self, client_socket):
        while True:
            try:
                encrypted_msg = client_socket.recv(1024)
                if not encrypted_msg:
                    print("Disconnected from the server.")
                    break

                decrypted_msg = self.fernet.decrypt(encrypted_msg).decode()
                if not self.verify_message(decrypted_msg):
                    print("Message verification failed, potential tampering detected.")
                    break

                print("Received message:", decrypted_msg)
            except (socket.error, Fernet.InvalidToken) as e:
                print("Error receiving message:", e)
                break

    def send_message(self, client_socket, message):
        try:
            mac = hmac.new(self.mac_key, message.encode(), hashlib.sha256).digest()
            message_with_mac = "{}:{}".format(message, base64.urlsafe_b64encode(mac).decode())

            encrypted_msg = self.fernet.encrypt(message_with_mac.encode())
            client_socket.sendall(encrypted_msg)
        except socket.error as e:
            print("Error sending message to server:", e)

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
    client = ChatClient('afflicted.sh', 8003, password)
    client.connect()
