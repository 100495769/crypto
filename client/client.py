# Client should be able to send and retrieve files.
# It should ask the server where to send it and then it should send those files to the host
# When retrieving files clients should ask the server for that specific file.
# Files will be encrypted through the fastes encryption algorithm (XChaCha20?) which proves to be
# enough for years (maybe add an option to extra security, changing the algorithm for something slower?)
# The key to descrypt those files will be sent to the server. Any time a new client connects with its
# credentials. It will be sent the key to the files.

import socket
from port import port


def client_setup():
    # Crear un socket
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Dirección IP y puerto del servidor al que queremos conectarnos
    server_address = ('127.0.0.1', port())  # Cambia IP y puerto si es necesario

    # Conectar con el servidor
    client_socket.connect(server_address)
    client_socket.sendall(f"Buenos dias servidor, al habla el cliente!".encode('utf-8'))
    data = client_socket.recv(1024)
    if data.decode('utf-8') != "Buenos dias cliente, hace un dia soleado. Estamos gestionando la maniobra para asignare un puerto abierto al que dockear.":
        pass # Crear rutina para manejar esto TODO
    #print("Aca toy")
    data = client_socket.recv(1024)
    data = data.decode('utf-8')

    port_id = int(data)  # Unpack as a big-endian unsigned int
   #print(f"Puerto recibido con el número {port_id}, esperando señal para establecer conexion.")

    server_address = (server_address[0], port_id)
    new_client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    new_client_socket.connect(server_address)
    data = new_client_socket.recv(1024)
    if data.decode('utf-8') != ("Buenos dias cliente, conexión con el nuevo servidor establecida, confirme al puerto principal."):
        pass # Crear rutina para gestionar esto TODO

    client_socket.sendall("Conexion con el nuevo servidor establecida. Les deseamos un buen dia.".encode('utf-8'))
    new_client_socket.sendall("Confirmado con el puerto principal. Quedamos a la espera de comandos.".encode('utf-8'))

    return new_client_socket

def client_identification(client_socket):
    valid = False
    while not valid:
        # Nombre de usuario
        data = client_socket.recv(1024).decode('utf-8')
        print(data)
        username = input()
        print(username)
        client_socket.sendall(username.encode('utf-8'))

        # Contraseña
        data = client_socket.recv(1024).decode('utf-8')
        print(data, end="")
        password = input()
        client_socket.sendall(password.encode('utf-8'))

        if client_socket.recv(1024).decode('utf-8') == "Identificación completada con éxito.":
            valid = True
    client_socket.sendall("Roger that".encode('utf-8'))



def main():

    client_socket = client_setup()
    client_identification(client_socket)

    # Saludo de bienvenida.
    print(client_socket.recv(1024).decode('utf-8'))

    exit = False
    while not exit:

        command = input("[ User ]: ")
        client_socket.sendall(command.encode('utf-8'))
        data = client_socket.recv(1024).decode('utf-8')

        if command == "exit":
            exit = True
        if command[:6] == "upload":
            host_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            ip, port = data[1:-1].split(",")
            print(f"{ip.strip()},{port},{str(int(port))}")
            host_address = (ip.strip()[1:-1], int(port))
            host_socket.connect(host_address)

            file_path = command[6:].strip()
            with open(file_path, "rb") as file:
                # Read and send the file in chunks
                while True:
                    datab = file.read(1024)  # Buffer size
                    if not datab:
                        break
                    host_socket.sendall(datab)
            host_socket.close()

        elif data == "Download accepted, prepare to receive jump coordinates!":
            pass
        print("[ Server ]: " + data)


    client_socket.close()

if __name__ == "__main__":
    main()
