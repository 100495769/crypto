# Server will act as a reference guide to where files are located.
# It will provide a client an adequate host (maybe not implement this yet as it is out of scope)
# It should also store the information of the user, login credentials and a random index to each file
# of the user. The index will be used to ask the hosts to retrieve a file, making the hosts unable to
# check which file they are storing
import signal
import time
import socket
import sys
import os

from Crypto.PublicKey import ECC
from Crypto.Cipher import ChaCha20
from Crypto.Random import get_random_bytes
from Crypto.Protocol.DH import key_agreement
from Crypto.Hash import SHAKE256
from port import port
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))


def get_port(ports_pool) -> int:
    # This function returns an available port from the ports_pool
    counter = 4
    n_ports = len(ports_pool)

    # Check for all the ports in the pool until one is available
    while n_ports > counter:

        port = ports_pool[counter]
        finder_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        result = finder_socket.connect_ex(('localhost', port))
        if result != 0:
            del ports_pool[counter]
            return port
        counter += 1

    # If no available port return -1
    return -1


def kdf(x):
    return SHAKE256.new(x).read(32)


# Crear un socket
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
ports_pool = list(range(port() + 1, port() + 499))
# Enlazar el socket a una dirección y puerto
server_socket.bind(('127.0.0.1', port()))


def signal_handler(sig, frame):
    pass


signal.signal(signal.SIGUSR1, signal_handler)


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


while True:
    # Establecimiento de clave asimetrica para esta sesion
    private_key = ECC.generate(curve='P-256')
    public_key = private_key.public_key()
    public_key_for_client = public_key.export_key(format='PEM')

    # Escuchar por conexiones entrantes.
    server_socket.listen()
    client_socket, client_address = server_socket.accept()

    print(f"Conexión establecida con {client_address}")

    client_socket.sendall(public_key_for_client.encode('utf-8'))
    client_public_key = ECC.import_key(client_socket.recv(1024).decode('utf-8'))
    key = key_agreement(static_pub=client_public_key, static_priv=private_key, kdf=kdf)
    print(key)
    port = str(get_port(ports_pool))

    while port == "-1":
        # Espera a que se libere un puerto.
        time.sleep(0.5)
        port = str(get_port(ports_pool))

    #Crear nuevo proceso para el cliente.
    pid = os.fork()
    if pid == 0:
        os.execl("/usr/bin/python3","python3", os.path.join(os.getcwd(), "server_client.py"), port, str(client_address[0]), str(client_address[1]), key.hex())

    # Espera a la señal de que el servidor se ha establecido correctamente. SIGUSR1
    signal.pause()
    # Comunicar el puerto al cliente.
    print(port)
    send_secure_message(client_socket, key, port.encode('utf-8'))

    # Cerrar conexion y logearlo.
    client_socket.close()
    with open("server_log.txt", 'a') as log:
        os.write(log.fileno(), str(time.time()).encode() + b": Connection Successful with " + (str(client_address[0]) + ":" + str(client_address[1]) + "\n").encode())