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


from Crypto.Cipher import ChaCha20
from Crypto.Random import get_random_bytes
from Crypto.Hash import HMAC, SHA256, SHAKE256
from Crypto.PublicKey import ECC
from Crypto.Protocol.DH import key_agreement
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from port import port

def kdf(x):
    return SHAKE256.new(x).read(32)


def send_secure_message(socket, key, message):
    nonce = get_random_bytes(12)
    cipher = ChaCha20.new(key=key, nonce=nonce)
    cyphered_message = cipher.encrypt(message)
    socket.sendall(nonce)
    socket.sendall(cyphered_message)
    return 1


def receive_secure_message(socket, key):
    nonce = socket.recv(12)
    encrypted_message = (socket.recv(1024))
    cipher = ChaCha20.new(key=key, nonce=nonce)
    decrypted_message = cipher.decrypt(encrypted_message)
    return decrypted_message


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
    print("Clave simetrica: ", key)
    port_id = int(receive_secure_message(client_socket, key))
    print(f"Puerto recibido con el número {port_id}, esperando señal para establecer conexion.")

    server_address = (server_address[0], port_id)
    new_client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    new_client_socket.connect(server_address)

    return new_client_socket, key

def encrypt_file(key, filename):
    path = "./"
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

            file_data = {
                'filename': filename,
                'key': key.hex(),
                'nonce': nonce.hex(),
                'hmac': hmac_digest.hex(),
            }

            return {'cyphered_contents': cyphered_file_contents,
            'file_data': file_data}

def check_hmac(cyphered_contents, hmac_value, key):
    hmac_value = bytes.fromhex(hmac_value)
    hmac_stored = HMAC.new(key, cyphered_contents, SHA256)
    hmac_digest = hmac_stored.digest()
    if HMAC.compare_digest(hmac_digest, hmac_value):
        return 1
    else:
        return 0

def client_identification(client_socket, key):
    valid = False
    while not valid:
        # Nombre de usuario
        data = receive_secure_message(client_socket, key).decode('utf-8')
        print("[ Server ]: " + data)
        username = input()
        print(username)
        send_secure_message(client_socket, key, username.encode('utf-8'))

        # Contraseña
        data = receive_secure_message(client_socket, key).decode('utf-8')
        print("[ Server ]: " + data, end="")
        password = input()
        send_secure_message(client_socket, key, password.encode('utf-8'))
        data = receive_secure_message(client_socket, key).decode('utf-8')
        print("[ Server ]:" + data)
        if data == "Identificación completada con éxito." or data == "No existe el usuario indicado.\nAcabamos de crear una cuenta asociada a su usuario.":
            valid = True
    return


def main():

    client_socket, key = client_setup()
    client_identification(client_socket, key)
    send_secure_message(client_socket, key, "Why none listens to me?".encode('utf-8'))
    # Saludo de bienvenida.
    print("Clave simetrica", key)
    print(receive_secure_message(client_socket, key).decode('utf-8'))

    exit = False
    while not exit:
        data = None
        command = input("[ User ]: ")
        send_secure_message(client_socket, key, command.encode('utf-8'))
        data = receive_secure_message(client_socket, key).decode('utf-8')

        if command == "exit":
            exit = True
        elif command[:6] == "upload":
            host_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            ip, port = data[1:-1].split(",")
            host_address = (ip.strip()[1:-1], int(port))
            host_socket.connect(host_address)

            file_path = command[6:].strip()
            encrypted_file = encrypt_file(key, file_path)
            cyphered_contents = encrypted_file['cyphered_contents']
            file_data = encrypted_file['file_data']
            i = 0
            while i+1024 < len(cyphered_contents):
                datab = cyphered_contents[i:i+1024]
                host_socket.sendall(datab)
                i+=1024
            if i + 1024 >= len(cyphered_contents):
                datab = cyphered_contents[i:]
                host_socket.sendall(datab)

            with open(file_path, "rb") as file:
                # Read and send the file in chunks
                while True:
                    datab = file.read(1024)  # Buffer size
                    if not datab:
                        break
                    host_socket.sendall(datab)
            host_socket.close()
            print("[ Server ]: " + receive_secure_message(client_socket, key).decode('utf-8'))
            new_data = input("[ User ]: ")
            new_data =new_data+','+file_data["hmac"]+','+file_data["nonce"]
            send_secure_message(client_socket, key, new_data.encode('utf-8'))


        elif command[:8] == "download":
            host_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            ip, port, file_key, HMAC, nonce = data.split(",")
            host_socket.connect((ip, int(port)))
            file_name = command[8:].strip()
            with open(file_name, "wb") as file:
                # Recibe y escribe el archivo
                while True:
                    datab = host_socket.recv(1024)  # Buffer size
                    if not datab:
                        break
                    file.write(datab)
            host_socket.close()
            with open(file_name, 'rb') as file:  # Open the file in binary mode
                content = file.read()
            #if check_hmac(content, HMAC, bytes.fromhex(file_key)):
            #    print("[ User ]: HMAC MATCHES, FILE HAS NOT BEEN ALTERED")
            cypher = ChaCha20.new(key=bytes.fromhex(file_key), nonce=bytes.fromhex(nonce))
            decyphered_contents = cypher.decrypt(content)
            with open("descifrado.jpeg", "wb") as file:
                file.write(decyphered_contents)
            data = "Dowload process finished"

        print("[ Server ]: " + data)

    client_socket.close()


if __name__ == "__main__":
    main()
