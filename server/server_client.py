import socket
import sys
import os
import signal
from port import port



def server_client_setup():
    port_id = int(sys.argv[1])
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('127.0.0.1', port_id))

    os.kill(os.getppid(), signal.SIGUSR1)

    server_socket.listen()
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



def server_client_identification(client_socket) -> list:
    valid = False
    while not valid:
        client_socket.sendall("Bienvenido esperamos su nombre de identificación y su código de acceso. \nNombre de identificación: ".encode('utf-8'))
        username = client_socket.recv(1024).decode('utf-8')
        print(username)
        client_socket.sendall("Código de acceso: ".encode('utf-8'))
        password = client_socket.recv(1024).decode('utf-8')
        print(password)

        #Check password and client blah blah blah make valid true if it is there.
        valid = True
    client_socket.sendall(f"Identificación completada con éxito.".encode('utf-8'))
    client_socket.recv(1024)


    return username

def find_free_host(file):
    return ('localhost', port() + 500)
# TODO search for a host that has space in a file

def find_file_host(file_name):
    return ('localhost', port()+ 500)






def host_establish_connection(host_address):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    print("1.1")
    server_socket.connect(host_address)
    print("1.2")
    new_port = server_socket.recv(1024).decode('utf-8')
    print("2.1")
    new_host = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    print("2.2")
    new_host.connect((host_address[0], int(new_port)))
    print("2.3")
    return new_host, new_port










def main():

    client_socket = server_client_setup()
    username = server_client_identification(client_socket)

    client_socket.sendall(f"Buenos dias {username}.\nLos comandos disponibles son: help, exit, cd, ls, rm, mv, upload, download, pwd, mkdir, rmdir.\n "
                          f"Quedamos a la espera de mas ordenes.".encode('utf-8'))

    while True:
        # Loop principal
        data = client_socket.recv(1024).decode('utf-8')
        if data == "ls":
            client_socket.sendall("Sia, Sergimichi".encode('utf-8'))
        elif data == "cd":
            client_socket.sendall("cd".encode('utf-8'))
        elif data == "help":
            client_socket.sendall("help".encode('utf-8'))
        elif data == "exit":
            client_socket.sendall("exit".encode('utf-8'))
            client_socket.close()
        elif data[:2] == "mv":
            client_socket.sendall("mv".encode('utf-8'))
        elif data == "pwd":
            client_socket.sendall("pwd".encode('utf-8'))
        elif data[:5] == "mkdir":
            client_socket.sendall("mkdir".encode('utf-8'))
        elif data[:5] == "rmdir":
            # Take into account that the dir has files. Soo those files have to be deleted first TODO
            client_socket.sendall("rmdir".encode('utf-8'))


        elif data[:2] == "rm":
            client_socket.sendall("rm".encode('utf-8'))





        elif data[:6] == "upload":
            host_address = find_file_host(data[7:])
            print("1")
            host_socket, host_new_port = host_establish_connection(find_free_host(data[7:]))
            print("2")
            host_socket.sendall("upload".encode('utf-8'))
            file_id = host_socket.recv(1024).decode('utf-8')
            host_client_address = str((host_address[0], int(host_new_port) + 1))
            client_socket.sendall(f"{host_client_address}".encode('utf-8'))
            host_socket.close()




        elif data[:8] == "download":
            host_socket = host_establish_connection(find_file_host(data[9:]))
            client_socket.sendall("download".encode('utf-8'))

        else:
            client_socket.sendall(f"Invalid command {data}".encode('utf-8'))


if __name__ == '__main__':
    main()