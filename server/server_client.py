import socket
import signal
import sys
import os
import json

import datetime
from Crypto.Cipher import ChaCha20
from Crypto.Random import get_random_bytes
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509 import load_pem_x509_certificate, NameOID, load_pem_x509_csr
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import padding

from fileStorage import UserFile, UsersInfo
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from port import port

def send_secure_message(socket, key, message):
    nonce = get_random_bytes(12)
    cipher = ChaCha20.new(key=key, nonce=nonce)
    cyphered_message = cipher.encrypt(message)
    socket.sendall(nonce)
    socket.sendall(cyphered_message)
    return 1

def receive_secure_message(socket, key):
    nonce = socket.recv(12)
    encrypted_message = (socket.recv(16384))
    cipher = ChaCha20.new(key=key, nonce=nonce)
    decrypted_message = cipher.decrypt(encrypted_message)
    return decrypted_message




def server_client_setup():
    key = sys.argv[4]
    key = bytes.fromhex(key)
    print("Clave simetrica en server_client.py: ", key)
    port_id = int(sys.argv[1])
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('127.0.0.1', port_id))
    server_socket.listen()

    os.kill(os.getppid(), signal.SIGUSR1)
    client_socket, client_address = server_socket.accept()
    private_key_cert_password = sys.argv[5]
    return client_socket, key, private_key_cert_password

def verify_signature(certificate, challenge, signature):
    public_key = certificate.public_key()
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    print("Clave pública en formato PEM:")
    print(pem.decode('utf-8'))
    print("Challenge: \n",challenge)
    print("Signature: \n",signature)
    try:
        # Verificar la firma
        public_key.verify(
            signature,
            challenge,
            padding.PKCS1v15(),  # El mismo padding utilizado al firmar
            hashes.SHA256()  # El mismo algoritmo de hash utilizado al firmar
        )
        print("Firma okay")
        return 0
        with open("certificate.pem", "rb") as f:
            root_cert = load_pem_x509_certificate(f.read())
        root_p_key = root_cert.public_key()

        try:
            #Ahora intentamos comprobar si fue emitido por este CA
            root_p_key.verify(
                certificate.signature,
                certificate.tbs_certificate_bytes,  # Datos firmados
                padding.PKCS1v15(),  # Tipo de padding usado durante la firma
                certificate.signature_hash_algorithm,
            )
            print("Certificate verified")
            return 0
        except:
            print("Certificate not verified")
            return -1
    except Exception as e:
        print(f"Firma not verified {e}")
        return -1

def server_client_identification(client_socket, key, private_cert_key) -> UserFile:
    valid = False
    while not valid:
        users_info = UsersInfo()
        message = "Bienvenido esperamos su nombre de identificación y su código de acceso. \nNombre de identificación: ".encode('utf-8')
        #1.
        send_secure_message(client_socket, key, message)
        #2.
        username = receive_secure_message(client_socket, key).decode('utf-8')
        print("Nombre de usuario logeandose: " + username)
        if not users_info.check_existance(username):
            #Si no existe el usuario. Esperamos a saber si le intentamos registrar.
            #3.
            send_secure_message(client_socket, key, "user_not_registered".encode('utf-8'))
            #4.
            if not receive_secure_message(client_socket, key).decode('utf-8') == username:
                return -1
            else:
                #5.
                send_secure_message(client_socket, key,"registering".encode('utf-8'))
                #Receive the certificate request.
                with open(f"{username}_csr.pem", "wb") as file:
                    file.write(receive_secure_message(client_socket, key))
                # Cargar el certificado desde el archivo
                with open(f"{username}_csr.pem", "rb") as f:
                    csr_data = f.read()
                    csr = load_pem_x509_csr(csr_data)
                # Cargar el Root CA
                with open("certificate.pem", "rb") as f:
                    cert_data = f.read()
                    cert = load_pem_x509_certificate(cert_data)
                # Cargamos la clave privada del certificado
                with open("encrypted_private_key.pem", "rb") as f:
                    encrypted_private_key = f.read()
                print("Acatoy")
                # Contraseña para descifrar
                password = bytes.fromhex(private_cert_key)

                # Deserializar la clave privada
                private_key = serialization.load_pem_private_key(
                    encrypted_private_key,
                    password=password,
                )


                # Extraer el Common Name (CN) del Subject del certificado
                subject_name = csr.subject
                common_name = None
                for attribute in subject_name:
                    if attribute.oid == NameOID.COMMON_NAME:
                        common_name = attribute.value
                        break

                if common_name != username:
                    # Si el certificado a firmar no coincide con el usuario que queriamos registrar. Terminamos el proceso
                    print("Nombre de usuario incorrecto.")
                    return -1

                else:
                    # Crear el certificado a partir del CSR
                    certificado = x509.CertificateBuilder().subject_name(
                        csr.subject  # Usamos el sujeto del CSR
                    ).issuer_name(
                        # El emisor del certificado es el Root CA
                        cert.subject
                    ).public_key(
                        csr.public_key()  # La clave pública del CSR
                    ).serial_number(
                        x509.random_serial_number()  # Número de serie único
                    ).not_valid_before(
                        datetime.datetime.utcnow()
                    ).not_valid_after(
                        # El certificado será válido por diez años
                        datetime.datetime.utcnow() + datetime.timedelta(days=3650)
                    ).add_extension(
                        x509.SubjectKeyIdentifier.from_public_key(csr.public_key()),
                        critical=False,
                    ).add_extension(
                        x509.KeyUsage(
                            digital_signature=True,
                            content_commitment=False,
                            key_encipherment=False,
                            data_encipherment=False,
                            key_agreement=False,
                            key_cert_sign=False,
                            crl_sign=False,
                            encipher_only=False,
                            decipher_only=False,
                        ),
                        critical=True,
                    ).add_extension(
                        x509.BasicConstraints(ca=False, path_length=None),
                        critical=True,
                    ).sign(private_key, hashes.SHA256()) #Firmamos con clave privada de root
                    with open(f"{username}_certificado.pem", "wb") as file:
                        file.write(certificado.public_bytes(serialization.Encoding.PEM))
                    with open(f"{username}_certificado.pem", "rb") as file:
                        send_secure_message(client_socket, key, file.read())
                    print("OKAY")

                    # Eliminamos los certificados del usuario, aunque no sea comprometedor esto.
                    #os.remove(f"{username}_certificado.pem")
                    #os.remove(f"{username}_csr.pem", "wb")

                    users_info.write_new(username)
                    valid = True
        else:
            send_secure_message(client_socket, key, "user_registered".encode('utf-8'))
            certificado_bytes = receive_secure_message(client_socket, key)
            #with open(f"{username}_certificado.pem", "wb") as file:
            #   file.write(certificado_bytes)
            certificado = load_pem_x509_certificate(certificado_bytes)
            challenge = os.urandom(32)
            send_secure_message(client_socket, key, challenge)
            signed = receive_secure_message(client_socket, key)
            if verify_signature(certificado, challenge, signed) == 0:
                send_secure_message(client_socket, key, "oka".encode('utf-8'))
                return UserFile(username)
            else:
                send_secure_message(client_socket, key, "invalid".encode('utf-8'))
                return -1

def find_free_host(file):
    return ('localhost', port() + 500)
# TODO search for a host that has space in a file



def host_establish_connection(host_address):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.connect(host_address)
    new_port = server_socket.recv(1024).decode('utf-8')
    new_host = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    new_host.connect((host_address[0], int(new_port)))
    return new_host, new_port




def command_manager(client_socket, user_file, data, key):

    if data == "ls":
        contents = user_file.list_contents()
        message = json.dumps(contents, indent=4).encode('utf-8')
        send_secure_message(client_socket, key, message)
    elif data[:2] == "cd":
        message = "cd".encode('utf-8')
        send_secure_message(client_socket, key, message)
        dirname = data[3:]
        user_file.change_directory(dirname)
    elif data == "help":
        message = "Los comandos disponibles son: help, exit, cd, ls, rm (not implementado todavia), upload, download, pwd, mkdir, rmdir.".encode('utf-8')
        send_secure_message(client_socket, key, message)
    elif data == "exit":
        message = "exit".encode('utf-8')
        send_secure_message(client_socket, key, message)
    elif data[:3] == "pwd":
        message = f"{user_file.show_current_path()}".encode('utf-8')
        send_secure_message(client_socket, key, message)
    elif data[:5] == "mkdir":
        user_file.make_new_dir(data[6:].strip())
        message = "mkdir".encode('utf-8')
        send_secure_message(client_socket, key, message)
    elif data[:5] == "rmdir":
        # Take into account that the dir has files. Soo those files have to be deleted first TODO
        message = "rmdir".encode('utf-8')
        send_secure_message(client_socket, key, message)
        dirname = data[6:]
        user_file.remove_directory(dirname)
    elif data[:2] == "rm":
        # Bad remove not well done TODO
        message = "rm".encode('utf-8')
        send_secure_message(client_socket, key, message)
        filename = data[3:]
        user_file.delete_file(filename)
    elif data[:6] == "upload":

        host_address = find_free_host(data[7:])
        host_socket, host_new_port = host_establish_connection(find_free_host(data[7:]))
        host_socket.sendall("upload".encode('utf-8'))
        file_id = host_socket.recv(1024).decode('utf-8')
        host_client_address = str((host_address[0], int(host_new_port) + 1))
        host_client_Address = f"{host_client_address}".encode('utf-8')
        send_secure_message(client_socket, key, host_client_Address)
        host_socket.close()

        data2 = "In which directory do you want to write?"
        send_secure_message(client_socket, key, data2.encode('utf-8'))
        location, hmac, nonce = receive_secure_message(client_socket, key).decode('utf-8').split(',')

        if location == "home":
            user_file.write_new(data[7:].strip(), host_address, file_id, key, hmac, nonce)
        else:
            user_file.save_to_dir(location, data[7:].strip(), host_address, file_id, key, hmac, nonce)

        host_socket.close()
    elif data[:8] == "download":
        # TODO SACAR CLAVE CRYPTO AQUI
        host_address, file_id, file_key, HMAC, nonce = user_file.for_sergio(data[8:].strip())
        host_address = (host_address[0], int(host_address[1]))
        host_socket, host_new_port = host_establish_connection(host_address)
        host_socket.sendall(f"download {file_id}".encode('utf-8'))
        client_data =  str(host_address[0])+','+str(int(host_new_port)+1) + ',' + file_key + ',' + HMAC + ',' + nonce
        send_secure_message(client_socket, key, client_data.encode('utf-8'))
        host_socket.close()

    else:
        message = f"Invalid command {data}".encode('utf-8')
        send_secure_message(client_socket, key, message)


def main():

    client_socket, key, private_key_cert_password = server_client_setup()
    user_file = server_client_identification(client_socket, key, private_key_cert_password)
    if type(user_file) == int and user_file == -1:
        #Si no se ha podido registrar o no ha iniciado sesion.
        return -1
    data = (f"Buenos dias {user_file.username}.\nLos comandos disponibles son: help, exit, cd, ls, rm (not implementado todavia), upload, download, pwd, mkdir, rmdir.\n "
            f"Quedamos a la espera de mas ordenes.")
    receive_secure_message(client_socket,key).decode('utf-8')
    send_secure_message(client_socket, key, data.encode('utf-8'))

    while True:
        # Loop principal SIA
        data = receive_secure_message(client_socket, key).decode('utf-8')
        command_manager(client_socket, user_file, data, key)

if __name__ == '__main__':
    main()