import socket
import signal
import sys
import os
import json
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from port import port
from fileStorage import UserFile, UsersInfo

def server_client_setup():
    port_id = int(sys.argv[1])
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('127.0.0.1', port_id))
    server_socket.listen()


    os.kill(os.getppid(), signal.SIGUSR1)
    client_socket, client_address = server_socket.accept()
    #print(os.getpid(), "Conexión recibida")
    if str(client_address[0]) != sys.argv[2] or str(client_address[1]) != sys.argv[3]:
        pass
        # Crear rutina para gestionar cliente erroneo. TODO
        # Quizas habria que quitar esto
    client_socket.sendall(f"Buenos dias cliente, conexión con el nuevo servidor establecida, confirme al puerto principal.".encode('utf-8'))

    data = client_socket.recv(1024)
    if data.decode('utf-8') != "Confirmado con el puerto principal. Quedamos a la espera de comandos.":
        pass  # Crear rutina para manejar esto TODO
    return client_socket


# changed the output type to the userfile to get the data in the userfile after autentification
def server_client_identification(client_socket) -> UserFile:
    valid = False
    while not valid:
        client_socket.sendall("Bienvenido esperamos su nombre de identificación y su código de acceso. \nNombre de identificación: ".encode('utf-8'))
        username = client_socket.recv(1024).decode('utf-8')
        print(username)
        client_socket.sendall("Código de acceso: ".encode('utf-8'))
        password = client_socket.recv(1024).decode('utf-8')
        print(password)
        users_info = UsersInfo()
        if not users_info.check_existance(username):
            print("You were not registered.")
            users_info.write_new(username, password)
            print("You have been registered and logged in.")
            valid = True
            """confirmation = input("Do you want to register? yes/no")
            if confirmation == "yes":
                users_info.write_new(username, password)
                valid = True
            elif confirmation == "no":
                print("Goodbye!")
                return -1
            else:
                print("Incorrect answer")"""
        else:
            stored_pass = users_info.data[username]["password"]
            if stored_pass == password:
                print("User exists.")
                valid = True
            else:
                print("Wrong password.")

    client_socket.sendall(f"Identificación completada con éxito.".encode('utf-8'))
    client_socket.recv(1024)
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








#function to manage all of the commands
def command_manager(client_socket, user_file, data):
    if data == "ls":
        contents = user_file.list_contents()
        client_socket.sendall(json.dumps(contents, indent=4).encode('utf-8'))
    elif data[:2] == "cd":
        client_socket.sendall("cd".encode('utf-8'))
        dirname = data[3:]
        user_file.change_directory(dirname)
    elif data == "help":
        client_socket.sendall("help".encode('utf-8'))
    elif data == "exit":
        client_socket.sendall("exit".encode('utf-8'))
        client_socket.close()
    # lets ignore it i beg u
    #elif data[:2] == "mv":
        #client_socket.sendall("mv".encode('utf-8'))
    elif data[:3] == "pwd":
        client_socket.sendall(f"{user_file.show_current_path()}".encode('utf-8'))
    elif data[:5] == "mkdir":
        user_file.make_new_dir(data[6:].strip())
        client_socket.sendall("mkdir".encode('utf-8'))
    elif data[:5] == "rmdir":
        # Take into account that the dir has files. Soo those files have to be deleted first TODO
        client_socket.sendall("rmdir".encode('utf-8'))
        dirname = data[6:]
        user_file.remove_directory(dirname)
    elif data[:2] == "rm":
        client_socket.sendall("rm".encode('utf-8'))
        filename = data[3:]
        user_file.delete_file(filename)
    elif data[:6] == "upload":

        host_address = find_free_host(data[7:])
        host_socket, host_new_port = host_establish_connection(find_free_host(data[7:]))
        host_socket.sendall("upload".encode('utf-8'))
        file_id = host_socket.recv(1024).decode('utf-8')
        host_client_address = str((host_address[0], int(host_new_port) + 1))
        client_socket.sendall(f"{host_client_address}".encode('utf-8'))
        host_socket.close()

        client_socket.sendall("In which directory do you want to write?".encode('utf-8'))
        location = client_socket.recv(1024).decode('utf-8')
        if location == "home":
            user_file.write_new(data[7:].strip(), host_address, file_id)
        else:
            user_file.save_to_dir(location, data[7:].strip(), host_address, file_id)

        host_socket.close()
    elif data[:8] == "download":
        # TODO SACAR CLAVE CRYPTO AQUI
        host_address, file_id = user_file.for_sergio(data[8:].strip())
        host_address = (host_address[0], int(host_address[1]))
        host_socket, host_new_port = host_establish_connection(host_address)
        host_socket.sendall(f"download {file_id}".encode('utf-8'))
        host_client_address = str((host_address[0], int(host_new_port) + 1))
        client_socket.sendall(f"{host_client_address}".encode('utf-8'))
        host_socket.close()
        data = client_socket.recv(1024).decode('utf-8')
        if data != "OK":
            pass # TODO implementar rutina para manejar esto


        client_socket.sendall("Download was successful.".encode('utf-8'))

    else:
        client_socket.sendall(f"Invalid command {data}".encode('utf-8'))


def main():

    client_socket = server_client_setup()
    user_file = server_client_identification(client_socket)

    client_socket.sendall(f"Buenos dias {user_file.username}.\nLos comandos disponibles son: help, exit, cd, ls, rm, mv, upload, download, pwd, mkdir, rmdir.\n "
                          f"Quedamos a la espera de mas ordenes.".encode('utf-8'))

    while True:
        # Loop principal SIA
        data = client_socket.recv(1024).decode('utf-8')
        command_manager(client_socket, user_file, data)

if __name__ == '__main__':
    main()