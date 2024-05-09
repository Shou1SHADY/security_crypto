import socket
import json
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
import threading
import json

def get_public_key_for_username(username, credentials_file):
    try:
        with open(credentials_file, 'r') as file:
            credentials = json.load(file)
            for cred in credentials:
                if cred['username'] == username:
                    client_public_key_bytes = cred.get('client_key', None)
                    if client_public_key_bytes:
                        return serialization.load_pem_public_key(client_public_key_bytes.encode(), backend=default_backend())
                    else:
                        print("Public key not found for the username:", username)
                        return None
            else:
                print("Username not found:", username)
                return None
    except (FileNotFoundError, json.JSONDecodeError) as e:
        print("Error reading credentials file:", e)
        return None

def handle_client(client_socket, private_key,serialized_public_key,credentials_file):
    # Send the public key to the client
    client_socket.sendall(serialized_public_key)

    # Receive encrypted data from the client

    encrypted_data = client_socket.recv(4096)

    # Decrypt the data using the private key
    decrypted_data = private_key.decrypt(
        encrypted_data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    # Receive the server's public key
    client_key = client_socket.recv(4096)

    client_public_key = serialization.load_pem_public_key(client_key, backend=default_backend())    # Deserialize the client's public key

    print(client_key)
    # Split the decrypted data into username, password, and hashed password
    username, password, hashed_password = decrypted_data.decode().split('|')
    print("Received username:", username)
    print("Received password:", password)
    print("Received hashed password:", hashed_password)

    # Check if hashed password already exists in the file
    try:
        with open(credentials_file, 'r') as file:
            credentials = json.load(file)
            for cred in credentials:
                if cred['hashed_password'] == hashed_password and cred['username'] == username:
                    print("Password already exists")
                    # Notify the client that login was successful
                    client_socket.sendall(b"Login successful")
                    break
                else:
                    # Store received credentials in JSON file
                    new_credentials = {'username': username, 'password': password, 'hashed_password': hashed_password,"client_key":client_public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo).decode()}
                    credentials.append(new_credentials)
                    with open(credentials_file, 'w') as file:
                        json.dump(credentials, file)
    except (FileNotFoundError, json.JSONDecodeError):
        # If file doesn't exist or is empty, create new file and store credentials
        new_credentials = {'username': username, 'password': password, 'hashed_password': hashed_password,"client_key": client_public_key.public_bytes(encoding=serialization.Encoding.PEM, format=serialization.PublicFormat.SubjectPublicKeyInfo).decode()}
        with open(credentials_file, 'w') as file:
            json.dump([new_credentials], file)


    partner_encrypted_data = client_socket.recv(4096)

    # Decrypt the data using the private key
    partner_decrypted_data = private_key.decrypt(
        partner_encrypted_data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    partner = partner_decrypted_data.decode()
            # Search for the client's public key using the username
    client_public_key_for_username = get_public_key_for_username(partner, credentials_file)
    if client_public_key_for_username:
        print("Public key found for the username:", partner)
        # encrypted_partner_public_key = client_public_key.encrypt(
        #     client_public_key_for_username.encode(),
        #     padding.OAEP(
        #         mgf=padding.MGF1(algorithm=hashes.SHA256()),
        #         algorithm=hashes.SHA256(),
        #         label=None
        #     )
        # )
        # client_socket.sendall(encrypted_partner_public_key)
    else:
        print("Public key not found for the username:", partner)


    # Close the client socket
    client_socket.close()

def generate_keys():
    # Generate RSA key pair
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    # Get public key
    public_key = private_key.public_key()
    return private_key, public_key

def main():
    # Server details
    SERVER_IP = '127.0.0.1'
    SERVER_PORT = 22345

    # Create a socket object
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Bind the socket to the address
    server_socket.bind((SERVER_IP, SERVER_PORT))

    # Listen for incoming connections
    server_socket.listen(3)
    print("Server listening on port", SERVER_PORT)

    # JSON file to store user credentials
    credentials_file = "credentials.json"

    try:
        private_key, public_key = generate_keys()
        # Serialize the public key
        serialized_public_key = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        while True:

            # Accept a client connection
            client_socket, client_address = server_socket.accept()
            print("Connection established with", client_address)
            client_thread = threading.Thread(target=handle_client, args=(client_socket, private_key,serialized_public_key,credentials_file))
            client_thread.start()


    except KeyboardInterrupt:
        print("Server shutting down...")
    finally:
        # Close the server socket
        server_socket.close()

if __name__ == "__main__":
    main()
