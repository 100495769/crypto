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
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
import datetime
from cryptography import x509
from cryptography.x509 import load_pem_x509_certificate
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes


sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from port import port

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

running = True
def signal_handler(sig, frame):
    global running
    if(sig == signal.SIGINT) and running == True:
        running = False
    elif sig == signal.SIGINT:
        os.kill(os.getpid(), signal.SIGTERM)



def main(private_key_password):
    while running:
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
        print("Clave simetrica en server.py: ", key)
        port = str(get_port(ports_pool))

        while port == "-1":
            # Espera a que se libere un puerto.
            time.sleep(0.5)
            port = str(get_port(ports_pool))

        #Crear nuevo proceso para el cliente.
        pid = os.fork()
        if pid == 0:
            os.execl("/usr/bin/python3","python3", os.path.join(os.getcwd(), "server_client.py"), port, str(client_address[0]), str(client_address[1]), key.hex(), private_key_password)

        # Espera a la señal de que el servidor se ha establecido correctamente. SIGUSR1
        signal.pause()
        # Comunicar el puerto al cliente.
        print(port)
        send_secure_message(client_socket, key, port.encode('utf-8'))

        # Cerrar conexion y logearlo.
        client_socket.close()
        with open("server_log.txt", 'a') as log:
            os.write(log.fileno(), str(time.time()).encode() + b": Connection Successful with " + (str(client_address[0]) + ":" + str(client_address[1]) + "\n").encode())

def create_certificate():
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    # Generamos una clave lo suficientemente larga para que sea segura. 512bits es muy superior a lo recomendado
    # Hacemos esto para asegurarnos el no tener que cambiar la contraseña en un futuro.
    clave = os.urandom(64)
    # La clave para cifrar la private key del certificado la damos en hexadecimal
    print("La contraseña es:\n", clave.hex(),
          "\nSe ha creado tambien un fichero 'clave.txt', que contiene la clave.\nPorfavor memorice la contraseña y elimine este archivo de manera definitiva e irreversible, de inmediato .\n No nos hacemos cargo de la seguridad de esta contraseña si no se cumple con lo mencionado.")

    with open("clave.txt", "w") as file:
        file.write(clave.hex())

    with open("encrypted_private_key.pem", "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.BestAvailableEncryption(clave),
        ))


    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "ES"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Madrid"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Leganes"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Nube de Tormenta"),
        x509.NameAttribute(NameOID.COMMON_NAME, "root"),
    ])
    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.now(datetime.timezone.utc)
    ).not_valid_after(
        # El certificado sera valido por 10 años.
        datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=3650)
    ).sign(key, hashes.SHA256())

    with open("certificate.pem", "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

def sign_challenge(private_key, challenge):
    signature = private_key.sign(
        challenge,
        padding.PKCS1v15(),  # Algoritmo de relleno (padding)
        hashes.SHA256()  # Algoritmo de hash
    )
    return signature

def verify_signature(certificate, challenge, signature):
    public_key = certificate.public_key()

    try:
        # Verificar la firma
        public_key.verify(
            signature,
            challenge,
            padding.PKCS1v15(),  # El mismo padding utilizado al firmar
            hashes.SHA256()  # El mismo algoritmo de hash utilizado al firmar
        )
        return 0
    except:
        return -1


def generate_challenge():
    challenge = os.urandom(32)  # 32 bytes de datos aleatorios
    return challenge

def check_certificate():
    #
    try:
        with open("encrypted_private_key.pem", "rb") as key:
            encrypted_private_key = key.read()
        private_key_password = input("Clave del certificado: ")
        private_key = serialization.load_pem_private_key(
            encrypted_private_key,
            password=bytes.fromhex(private_key_password)
        )
        try:
            with open("certificate.pem", "rb") as cert:
                cert_data= cert.read()
                certificate = load_pem_x509_certificate(cert_data)


            # Hacemos una prueba para ver que el certificado corresponde con la clave privada.
            challenge = generate_challenge()
            signature = sign_challenge(private_key, challenge)
            if verify_signature(certificate, challenge, signature) == 0:
                print("Certificado correcto.")
                return private_key_password

        except:
            print("Certificado no encontrado. Recuerde almacenar el certificado como: 'certificate.pem', y la clave privada como: 'encrypted_private_key.pem'.")
            return -1
        with open("private_key.pem", "wb") as key_file:
            key_file.write(private_key)


    except:
        if input("Clave privada no es correcta o no encontrada:\n'y' para crear un certificado nuevo\n'n' para salir\n").lower() == "y":
            # Creamos nuevo certificado:
            create_certificate()
            return -1
        else:
            print("Recuerde almacenar el certificado como: 'certificate.pem', y la clave privada como: 'encrypted_private_key.pem'.")
            return -1


if __name__ == '__main__':
    signal.signal(signal.SIGINT, signal_handler) #Usaremos SIGSTOP para parar el main()
    private_key_password = check_certificate()
    if private_key_password != -1:
        main(private_key_password)