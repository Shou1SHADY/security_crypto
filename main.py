import socket
import json
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
import base64

# Function to encrypt a message with another client's public key
def encrypt_message_with_public_key(message, public_key):
    public_key = RSA.import_key(public_key)
    cipher = PKCS1_OAEP.new(public_key)
    encrypted_message = cipher.encrypt(message.encode())
    return base64.b64encode(encrypted_message).decode()

# Function to request public key of another client
def request_public_key(client_name):
    request_data = {
        "action": "get_public_key",
        "username": client_name
    }
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
        client.connect(('localhost', 12345))
        client.send(json.dumps(request_data).encode())
        response = client.recv(1024).decode()
        response_data = json.loads(response)
        if response_data["response"] == "Public key found":
            return response_data["public_key"]
        else:
            print("Public key not found for the specified client.")
            return None

# Function to request public key of another client and send an encrypted message
def request_public_key_and_send_message(client_name):
    message = input("Enter the message you want to encrypt and send: ")
    public_key = request_public_key(client_name)
    if public_key:
        encrypted_message = encrypt_message_with_public_key(message, public_key)
        print("Encrypted message:", encrypted_message)
        send_encrypted_message_to_server(client_name, encrypted_message)
    else:
        print("Failed to send encrypted message.")

# Function to send the encrypted message to the server for storage
def send_encrypted_message_to_server(client_name, encrypted_message):
    request_data = {
        "action": "store_encrypted_message",
        "client_name": client_name,
        "encrypted_message": encrypted_message
    }
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
        client.connect(('localhost', 12345))
        client.send(json.dumps(request_data).encode())
        response = client.recv(1024).decode()
        print("Server response:", response)

# Function for client registration
def register(username, password):
    public_key, private_key = generate_key_pair()
    hashed_password = hash_password(password)
    request_data = {
        "action": "register",
        "username": username,
        "password": password,
        "hashed_password": hashed_password,
        "public_key": public_key.decode()
    }
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
        client.connect(('localhost', 12345))
        client.send(json.dumps(request_data).encode())
        response = client.recv(1024).decode()
        print(response)

# Function for client login
def login(username, password):
    request_data = {
        "action": "login",
        "username": username,
        "password": password
    }
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
        client.connect(('localhost', 12345))
        client.send(json.dumps(request_data).encode())
        response = client.recv(1024).decode()
        print(response)

# Function to generate RSA key pair
def generate_key_pair():
    key = RSA.generate(2048)
    return key.publickey().export_key(), key.export_key()

# Main function for client operations
def main():
    while True:
        print("1. Register")
        print("2. Login")
        print("3. Request Public Key of Another Client and Send Encrypted Message")
        choice = input("Enter your choice (1/2/3): ")
        if choice == '1':
            username = input("Enter username: ")
            password = input("Enter password: ")
            register(username, password)
        elif choice == '2':
            username = input("Enter username: ")
            password = input("Enter password: ")
            login(username, password)
        elif choice == '3':
            client_name = input("Enter the name of the client whose public key you want to request: ")
            request_public_key_and_send_message(client_name)
        else:
            print("Invalid choice. Please enter 1, 2, or 3.")

if __name__ == "__main__":
    main()
