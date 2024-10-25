import socket
import sys
import os
import signal



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

def host_establish_connection(host_address):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    server_socket.connect(host_address)
    new_port = server_socket.recv(1024).decode('utf-8')
    new_host = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    new_host.connect((host_address[0], int(new_port)))
    return new_host










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
            client_socket.sendall("rmdir".encode('utf-8'))


        elif data[:2] == "rm":
            client_socket.sendall("rm".encode('utf-8'))
        elif data[:6] == "upload":
            client_socket.sendall("upload".encode('utf-8'))
        elif data[:8] == "download":
            client_socket.sendall("download".encode('utf-8'))

        else:
            client_socket.sendall(f"Invalid command {data}".encode('utf-8'))


if __name__ == '__main__':
    main()