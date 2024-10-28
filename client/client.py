# Client should be able to send and retrieve files.
# It should ask the server where to send it and then it should send those files to the host
# When retrieving files clients should ask the server for that specific file.
# Files will be encrypted through the fastes encryption algorithm (XChaCha20?) which proves to be
# enough for years (maybe add an option to extra security, changing the algorithm for something slower?)
# The key to descrypt those files will be sent to the server. Any time a new client connects with its
# credentials. It will be sent the key to the files.

import socket
import sys
import os

from cryptography.hazmat.primitives.asymmetric.ec import ECDH

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from port import port
from base64 import b64encode
from Crypto.Cipher import ChaCha20
from Crypto.Random import get_random_bytes
from Crypto.Hash import HMAC, SHA256, SHAKE256
from Crypto.PublicKey import ECC
from Crypto.Protocol.DH import key_agreement

def kdf(x):
    return SHAKE256.new(x).read(32)
def send_secure_message(socket, key, message):
    nonce = get_random_bytes(12)
    cipher = ChaCha20.new(key=key, nonce=nonce)
    cyphered_message = cipher.encrypt(message.encode('utf-8'))
    socket.sendall(nonce)
    socket.sendall(cyphered_message)
    return 1

def receive_secure_message(socket, key):
    nonce = socket.recv(12)
    encrypted_message = (socket.recv(1024))
    cipher = ChaCha20.new(key=key, nonce=nonce)
    decrypted_message = cipher.decrypt(encrypted_message)
    return decrypted_message.decode('utf-8')


def client_setup():
    private_key = ECC.generate(curve='P-256')
    public_key = private_key.public_key()
    public_key_for_server = public_key.export_key(format='PEM')
    # Crear un socket
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Dirección IP y puerto del servidor al que queremos conectarnos
    server_address = ('127.0.0.1', port())  # Cambia IP y puerto si es necesario

    # Conectar con el servidor
    client_socket.connect(server_address)

    server_public_key = ECC.import_key(client_socket.recv(1024).decode('utf-8'))
    client_socket.sendall(public_key_for_server.encode('utf-8'))
    key = key_agreement(static_pub=server_public_key, static_priv=private_key, kdf=kdf)
    print(key)
    print(receive_secure_message(client_socket, key))
    client_socket.sendall(f"Buenos dias servidor, al habla el cliente!".encode('utf-8'))
    data = client_socket.recv(1024)
    if data.decode('utf-8') != "Buenos dias cliente, hace un dia soleado. Estamos gestionando la maniobra para asignare un puerto abierto al que dockear.":
        pass # Crear rutina para manejar esto TODO
    #print("Aca toy")
    data = client_socket.recv(1024)
    data = data.decode('utf-8')

    port_id = int(data)  # Unpack as a big-endian unsigned int
    print(f"Puerto recibido con el número {port_id}, esperando señal para establecer conexion.")

    server_address = (server_address[0], port_id)
    new_client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    new_client_socket.connect(server_address)
    data = new_client_socket.recv(1024)
    if data.decode('utf-8') != ("Buenos dias cliente, conexión con el nuevo servidor establecida, confirme al puerto principal."):
        pass # Crear rutina para gestionar esto TODO

    client_socket.sendall("Conexion con el nuevo servidor establecida. Les deseamos un buen dia.".encode('utf-8'))
    new_client_socket.sendall("Confirmado con el puerto principal. Quedamos a la espera de comandos.".encode('utf-8'))

    return new_client_socket

def encrypt_file(key, filename):
    path = "./crypto/client"
    encrypted_file = []
    if filename in os.listdir(path):
        file_path = os.path.join(path, filename)
        if os.path.isfile(file_path):
            nonce = get_random_bytes(12)
            cipher = ChaCha20.new(key=key, nonce=nonce)

            with open(file_path, 'rb') as f:
                plaintext = f.read()

            cyphered_file_contents = cipher.encrypt(plaintext)
            hmac = HMAC.new(key, cyphered_file_contents, SHA256)
            hmac_digest = hmac.digest()

            encrypted_file.append({
                'filename': filename,
                'key': b64encode(key).decode('utf-8'),
                'nonce': b64encode(nonce).decode('utf-8'),
                'hmac': b64encode(hmac_digest).decode('utf-8'),
            })

            return {'cyphered_contents': cyphered_file_contents,
            'file_data': encrypted_file}

def check_hmac(encrypted_file, cyphered_contents, hmac):
    hmac_stored = HMAC.new(encrypted_file['key'], cyphered_contents, SHA256)
    hmac_digest = hmac_stored.digest()
    if hmac.compare_digest(hmac_digest, hmac):
        return 1
    else:
        return 0

def send_file_to_server(file_data, client_socket):
    file_data = "here should be the string? showing the file data" # TODO SERGIO help
    client_socket.sendall(file_data.encode('utf-8'))


def client_identification(client_socket):
    valid = False
    while not valid:
        # Nombre de usuario
        data = client_socket.recv(1024).decode('utf-8')
        print(data)
        username = input()
        print(username)
        client_socket.sendall(username.encode('utf-8'))

        # Contraseña
        data = client_socket.recv(1024).decode('utf-8')
        print(data, end="")
        password = input()
        client_socket.sendall(password.encode('utf-8'))

        if client_socket.recv(1024).decode('utf-8') == "Identificación completada con éxito.":
            valid = True
    client_socket.sendall("Roger that".encode('utf-8'))



def main():

    client_socket = client_setup()
    client_identification(client_socket)

    # Saludo de bienvenida.
    print(client_socket.recv(1024).decode('utf-8'))

    exit = False
    while not exit:

        command = input("[ User ]: ")
        client_socket.sendall(command.encode('utf-8'))
        data = client_socket.recv(1024).decode('utf-8')

        if command == "exit":
            exit = True
        elif command[:6] == "upload":
            host_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            ip, port = data[1:-1].split(",")
            print(f"{ip.strip()},{port},{str(int(port))}")
            host_address = (ip.strip()[1:-1], int(port))
            host_socket.connect(host_address)

            file_path = command[6:].strip()
            with open(file_path, "rb") as file:
                # Read and send the file in chunks
                while True:
                    datab = file.read(1024)  # Buffer size
                    if not datab:
                        break
                    host_socket.sendall(datab)
            host_socket.close()
            print("[ Server ]: " + client_socket.recv(1024).decode('utf-8'))
            client_socket.sendall(input("[ User ]: ").encode('utf-8'))
        elif command[:8] == "download":
            host_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            print(f"DATA{data}")
            ip, port = data[1:-1].split(",")
            print(f"{ip.strip()},{str(int(port))}")
            host_address = (ip.strip()[1:-1], int(port))
            host_socket.connect(host_address)
            file_name = command[8:].strip()
            with open(file_name, "wb") as file:
                # Recibe y escribe el archivo
                while True:
                    datab = host_socket.recv(1024)  # Buffer size
                    if not datab:
                        break
                    file.write(datab)
            host_socket.close()
            client_socket.sendall("OK".encode('utf-8'))
            data = client_socket.recv(1024).decode('utf-8')
        elif data == "Download accepted, prepare to receive jump coordinates!":
            pass
        print("[ Server ]: " + data)


    client_socket.close()

if __name__ == "__main__":
    main()
