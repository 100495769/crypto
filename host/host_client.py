import socket
import sys
import os
import signal

def host_server_setup():
    port_id = int(sys.argv[1])
    host_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    host_socket.bind(('127.0.0.1', port_id))

    os.kill(os.getppid(), signal.SIGUSR1)

    host_socket.listen()
    server_socket, server_address = host_socket.accept()

    if str(server_address[0]) != sys.argv[2] or str(server_address[1]) != sys.argv[3]:
        pass
        # Crear rutina para gestionar cliente erroneo. TODO
        # Quizas habria que quitar esto
    return server_socket


def download_setup(file_id, file):
    pass




def new_id():
    try:
        with open("id_storage.txt", "r+") as f:
            id = f.read()
            f.seek(0)
            f.write(str((int(id) + 1)))
            f.truncate()
        return id
    except:
        pass  # Crear rutina para gestionar errores aqui, MUY IMPORTANTE ESTE TIPO DE ERROR
        # No queremos sobre escribir en un id porque se pierde la informacion. TODO

def upload_setup():
    file_id = new_id()
    host_client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    host_client_socket.bind(('127.0.0.1', int(sys.argv[1]) + 1))
    host_client_socket.listen()
    return file_id, host_client_socket


def main():
    server_socket = host_server_setup()
    command = server_socket.recv(1024).decode('utf-8')

    if command[:2] == "rm":
        pass
    elif command[:6] == "upload":
        file_id, host_client_socket = upload_setup()
        print("Upload hecho")
        server_socket.sendall(file_id.encode('utf-8'))
        client_socket, client_address = host_client_socket.accept()
        print("Conexion con cliente completada")
        with open(file_id, 'wb') as f:
            while True:
                data = client_socket.recv(1024)  # Buffer size
                if not data:
                    break
                f.write(data)
        print("Gatito Escribido")
        client_socket.close()
        server_socket.close()
    elif command[:8] == "download":
        download_setup(command[8:].strip())

if __name__ == '__main__':
    main()