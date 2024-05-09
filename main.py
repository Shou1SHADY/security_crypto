import socket
import hashlib
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import rsa


def hash_password(password):
    # Using SHA-256 hashing algorithm
    hashed_password = hashlib.sha256(password.encode()).hexdigest()
    return hashed_password


def encrypt_data(data, public_key):
    # Encrypt data using RSA public key
    encrypted_data = public_key.encrypt(
        data.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted_data

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
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    private_key, public_key = generate_keys()
    # Serialize the public key
    clientKey = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    try:
        # Connect to the server
        client_socket.connect((SERVER_IP, SERVER_PORT))

        # Receive the server's public key
        serialized_public_key = client_socket.recv(4096)
        server_public_key = serialization.load_pem_public_key(serialized_public_key, backend=default_backend())    # Deserialize the client's public key


        # Get username and password from the client
        username = input("Enter username: ")
        password = input("Enter password: ")

        # Hash the password
        hashed_password = hash_password(password)


        data_to_send = f"{username}|{password}|{hashed_password}"

        # Encrypt the data using RSA public key
        encrypted_data = encrypt_data(data_to_send, server_public_key)

        # Send encrypted data to the server as a single message
        client_socket.sendall(encrypted_data)
        client_socket.sendall(clientKey)

        print("Data sent successfully.")

        # Receive response from the server

        response = client_socket.recv(1024)
        if response == b"Login successful":
            print("Login successful! You are now logged in.")
            # Perform actions for a successful login
        else:
            print("Register new user.")

        partner = input("Enter partner username: ")
        partner_data = encrypt_data(partner, server_public_key)
        client_socket.sendall(partner_data)

    #     partner_public_key = client_socket.recv(4096)
    #
    # # Decrypt the data using the private key
    #     partner_public_decrypted_data = private_key.decrypt(
    #     partner_public_key,
    #     padding.OAEP(
    #         mgf=padding.MGF1(algorithm=hashes.SHA256()),
    #         algorithm=hashes.SHA256(),
    #         label=None
    #         )
    #     )
    #     print(partner_public_decrypted_data)
    except Exception as e:
        print("Error:", e)
    finally:
        # Close the socket
        client_socket.close()


if __name__ == "__main__":
    main()
