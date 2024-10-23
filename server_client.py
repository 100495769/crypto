import socket
import sys
import os
import signal
def main():
    print(sys.argv)
    port_id = int(sys.argv[1])
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('127.0.0.1', port_id))

    os.kill(os.getppid(), signal.SIGUSR1)

    server_socket.listen()
    client_socket, client_address = server_socket.accept()
    print(os.getpid(),"Conexión recibida")
    if str(client_address[0]) != sys.argv[2] or str(client_address[1]) != sys.argv[3]:
        pass
        # Crear rutina para gestionar cliente erroneo. TODO
        # Quizas habria que quitar esto
    client_socket.sendall(f"Buenos dias cliente, conexión con el nuevo servidor establecida."
                          f" Esperamos que confirme al puerto principal para completar la transferencia.".encode('utf-8'))

    data = client_socket.recv(1024)
    if data.decode('utf-8') != "Confirmado con el puerto principal. Quedamos a la espera de comandos.":
        pass # Crear rutina para manejar esto TODO

    client_socket.sendall("Los comandos disponibles son: help, exit, cd, ls, rm, mv, upload, download, pwd, mkdir, rmdir.".encode('utf-8'))


    while True:
        # Loop principal
        data = client_socket.recv(1024).decode('utf-8')
        if data == "ls":
            client_socket.sendall("Sia, Sergimichi".encode('utf-8'))
if __name__ == '__main__':
    main()