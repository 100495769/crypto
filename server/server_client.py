import socket
import signal
import sys
import os
import json


from Crypto.Cipher import ChaCha20
from Crypto.Random import get_random_bytes
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
    encrypted_message = (socket.recv(1024))
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
    return client_socket, key


def server_client_identification(client_socket, key) -> UserFile:
    valid = False
    while not valid:

        message = "Bienvenido esperamos su nombre de identificación y su código de acceso. \nNombre de identificación: ".encode('utf-8')
        send_secure_message(client_socket, key, message)
        username = receive_secure_message(client_socket, key).decode('utf-8')
        print("Nombre de usuario logeandose: " + username)
        send_secure_message(client_socket, key,"Código de acceso: ".encode('utf-8'))
        password = receive_secure_message(client_socket, key).decode('utf-8')
        print("Contraseña de usuario logeandose: " + password)
        users_info = UsersInfo()
        if not users_info.check_existance(username):
            users_info.write_new(username, password)
            message = "No existe el usuario indicado.\nAcabamos de crear una cuenta asociada a su usuario.".encode('utf-8')
            valid = True
        else:
            stored_pass = users_info.data[username]["password"]
            if stored_pass == password:
                message = "Identificación completada con éxito.".encode('utf-8')
                valid = True
            else:
                message = "Contraseña incorrecta. Reiniciando proceso de identificación.\n".encode('utf-8')

        send_secure_message(client_socket, key, message)
    user_file = UserFile(username)
    return user_file

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

    client_socket, key = server_client_setup()
    user_file = server_client_identification(client_socket, key)
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