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
    client_socket.sendall(f"Buenos dias cliente, conexión con el nuevo servidor establecida, confirme al puerto principal.".encode('utf-8'))

    data = client_socket.recv(1024)
    if data.decode('utf-8') != "Confirmado con el puerto principal. Quedamos a la espera de comandos.":
        pass # Crear rutina para manejar esto TODO

    client_socket.sendall("Los comandos disponibles son: help, exit, cd, ls, rm, mv, upload, download, pwd, mkdir, rmdir.".encode('utf-8'))


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
        elif data[:1] == "rm":
            client_socket.sendall("rm".encode('utf-8'))
        elif data[:1] == "mv":
            client_socket.sendall("mv".encode('utf-8'))
        elif data[:5] == "upload":
            client_socket.sendall("upload".encode('utf-8'))
        elif data[:7] == "download":
            client_socket.sendall("download".encode('utf-8'))
        elif data == "pwd":
            client_socket.sendall("pwd".encode('utf-8'))
        elif data[:4] == "mkdir":
            client_socket.sendall("mkdir".encode('utf-8'))
        elif data[:4] == "rmdir":
            client_socket.sendall("rmdir".encode('utf-8'))
        else:
            pass
if __name__ == '__main__':
    main()