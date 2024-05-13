import socket
import json
import hashlib
import os

# Function to load or create a JSON file to store client data
def load_or_create_data():
    if os.path.exists("client_data.json"):
        if os.stat("client_data.json").st_size == 0:
            return {}
        with open("client_data.json", "r") as f:
            return json.load(f)
    else:
        with open("client_data.json", "w") as f:
            json.dump({}, f)
        return {}

# Function to register a new client
def register_client(username, password, hashed_password, public_key):
    client_data = load_or_create_data()
    client_data[username] = {
        "hashed_password": hashed_password,
        "public_key": public_key,
        "messages": []  # Initialize an empty list to store messages
    }
    with open("client_data.json", "w") as f:
        json.dump(client_data, f)

# Function to authenticate a client
def authenticate_client(username, password):
    client_data = load_or_create_data()
    if username in client_data:
        stored_hashed_password = client_data[username]["hashed_password"]
        hashed_password = hashlib.sha256(password.encode()).hexdigest()
        if hashed_password == stored_hashed_password:
            return True
    return False

# Function to handle client requests
def handle_client(conn, addr):
    print(f"Connected to {addr}")
    while True:
        data = conn.recv(1024).decode()
        if not data:
            break
        request = json.loads(data)
        if request["action"] == "register":
            register_client(request["username"], request["password"], request["hashed_password"], request["public_key"])
            conn.send(json.dumps({"response": "Registered successfully"}).encode())
        elif request["action"] == "login":
            if authenticate_client(request["username"], request["password"]):
                conn.send(json.dumps({"response": "Successfully logged in"}).encode())
            else:
                conn.send(json.dumps({"response": "Login failed"}).encode())
        elif request["action"] == "get_public_key":
            requested_username = request["username"]
            public_key = get_public_key(requested_username)
            if public_key:
                conn.send(json.dumps({"response": "Public key found", "public_key": public_key}).encode())
            else:
                conn.send(json.dumps({"response": "Public key not found"}).encode())
        elif request["action"] == "store_encrypted_message":
            client_name = request["client_name"]
            encrypted_message = request["encrypted_message"]
            store_encrypted_message(client_name, encrypted_message)
            conn.send(json.dumps({"response": "Encrypted message stored successfully"}).encode())
    conn.close()

# Function to get public key of a client
def get_public_key(username):
    client_data = load_or_create_data()
    if username in client_data:
        return client_data[username]["public_key"]
    return None

# Function to store an encrypted message for a client
def store_encrypted_message(client_name, encrypted_message):
    client_data = load_or_create_data()
    if client_name in client_data:
        # Check if the 'messages' key exists for the client, if not, initialize it with an empty list
        if 'messages' not in client_data[client_name]:
            client_data[client_name]["messages"] = []
        client_data[client_name]["messages"].append(encrypted_message)
        with open("client_data.json", "w") as f:
            json.dump(client_data, f)

# Main function to start the server
def main():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(('localhost', 12345))
    server.listen(5)
    print("Server started. Waiting for connections...")

    while True:
        conn, addr = server.accept()
        handle_client(conn, addr)

if __name__ == "__main__":
    main()
