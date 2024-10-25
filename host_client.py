import socket
import sys
import os
import signal

def host_server_setup():
    port_id = int(sys.argv[1])
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('127.0.0.1', port_id))

    os.kill(os.getppid(), signal.SIGUSR1)

    server_socket.listen()
    client_socket, client_address = server_socket.accept()

    if str(client_address[0]) != sys.argv[2] or str(client_address[1]) != sys.argv[3]:
        pass
        # Crear rutina para gestionar cliente erroneo. TODO
        # Quizas habria que quitar esto
    return client_socket

def main():
    client_socket = host_server_setup()

    while True:

if __name__ == '__main__':
    main()