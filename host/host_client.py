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

    return server_socket


def new_id():
    try:
        with open("id_storage.txt", "r+") as f:
            id = f.read()
            f.seek(0)
            f.write(str((int(id) + 1)))
            f.truncate()
        return id
    except:
        pass



def client_setup():
    host_client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    host_client_socket.bind(('127.0.0.1', int(sys.argv[1]) + 1))
    host_client_socket.listen()
    return host_client_socket


def main():
    server_socket = host_server_setup()
    command = server_socket.recv(1024).decode('utf-8')

    if command[:2] == "rm":
        pass
    elif command[:6] == "upload":
        host_client_socket = client_setup()
        file_id = new_id()
        server_socket.sendall(file_id.encode('utf-8'))
        client_socket, client_address = host_client_socket.accept()
        with open(file_id, 'wb') as f:
            while True:
                data = client_socket.recv(1024)  # Buffer size
                if not data:
                    break
                f.write(data)
        print("Archivo escrito")
        client_socket.close()
        server_socket.close()
    elif command[:8] == "download":
        host_client_socket = client_setup()
        file_id = command[8:].strip()
        client_socket, client_address = host_client_socket.accept()
        with open(file_id, 'rb') as file:
            while True:
                data = file.read(1024)
                if not data:
                    break
                client_socket.sendall(data)
        print("Archivo mandado")
        client_socket.close()


if __name__ == '__main__':
    main()