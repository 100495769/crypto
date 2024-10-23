# Client should be able to send and retrieve files.
# It should ask the server where to send it and then it should send those files to the host
# When retrieving files clients should ask the server for that specific file.
# Files will be encrypted through the fastes encryption algorithm (XChaCha20?) which proves to be
# enough for years (maybe add an option to extra security, changing the algorithm for something slower?)
# The key to descrypt those files will be sent to the server. Any time a new client connects with its
# credentials. It will be sent the key to the files.

import socket
from port import port
# Crear un socket
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Dirección IP y puerto del servidor al que queremos conectarnos
server_address = ('127.0.0.1', port())  # Cambia IP y puerto si es necesario

# Conectar con el servidor
client_socket.connect(server_address)
client_socket.sendall(f"Buenos dias servidor, al habla el cliente!".encode('utf-8'))
data = client_socket.recv(1024)
if data.decode('utf-8') == "Buenos dias cliente, hace un dia soleado. Estamos gestionando la maniobra para asignare un puerto abierto al que dockear.":
    print("Aca toy")
    data = client_socket.recv(1024)
    data = data.decode('utf-8')
    print(data)
    port_id = int(data)  # Unpack as a big-endian unsigned int
    print(f"Puerto recibido con el número {port_id}, esperando señal para establecer conexion.")
    client_socket.recv(1024)

    server_address = (server_address[0], port_id)
    new_client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    new_client_socket.connect(server_address)
    data = new_client_socket.recv(1024)
    if data.decode('utf-8') == ("Buenos dias cliente, conexión con el nuevo servidor establecida. Esperamos que confirme"
                                "al puerto principal para completar la transferencia."):
        client_socket.sendall("Conexion con el nuevo servidor establecida. Les deseamos un buen dia.".encode('utf-8'))
        client_socket.close()
    new_client_socket.sendall("Confirmado con el puerto principal. Quedamos a la espera de comandos.".encode('utf-8'))

    data = new_client_socket.recv(1024)
    print(data.decode('utf-8'))
    while True:
        command = input("\n")
        new_client_socket.sendall(command.encode('utf-8'))
        if command == "ls":
            data = new_client_socket.recv(1024).decode('utf-8')
            print(data)


    new_client_socket.close()
