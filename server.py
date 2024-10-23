# Server will act as a reference guide to where files are located.
# It will provide a client an adequate host (maybe not implement this yet as it is out of scope)
# It should also store the information of the user, login credentials and a random index to each file
# of the user. The index will be used to ask the hosts to retrieve a file, making the hosts unable to
# check which file they are storing
import signal
import sys
import time
import socket
import struct
import os
from port import port

def get_port(ports_pool) -> int:
    # This function returns an available port from the ports_pool
    counter = 0
    n_ports = len(ports_pool)

    # Check for all the ports in the pool until one is available
    while n_ports > counter:

        port = ports_pool[counter]
        finder_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        result = finder_socket.connect_ex(('localhost', port))
        if result != 0:
            return port
        counter += 1

    # If no available port return -1
    return -1

# Crear un socket
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
ports_pool = list(range(49153, 65535))
# Enlazar el socket a una dirección y puerto
server_socket.bind(('127.0.0.1', port()))

while True:
    # Escuchar por conexiones entrantes
    server_socket.listen()
    client_socket, client_address = server_socket.accept()
    print(f"Conexión establecida con {client_address}")
    data = client_socket.recv(1024)
    if data.decode('utf-8') == "Buenos dias servidor, al habla el cliente!":
        print("Valores del cliente estables... ¡Estableciendo conexión segura!")
        client_socket.sendall(f"Buenos dias cliente, hace un dia soleado. Estamos gestionando la maniobra para asignare un puerto abierto al que dockear.".encode('utf-8'))
        port = str(get_port(ports_pool))
        while port == "-1":
            # Espera a que se libere un puerto.
            time.sleep(0.5)
            port = str(get_port(ports_pool))

        #Crear nuevo proceso para el cliente.
        client_socket.sendall(f"{port}".encode('utf-8'))
        print(port)
        pid = os.fork()
        if pid == 0:
            print("Una de puerto:"+ port)
            os.execl("/usr/bin/python3","python3", os.path.join(os.getcwd(), "server_client.py"), port, str(client_address[0]), str(client_address[1]))
        print(port)
        signal.pause()

        print('Thats one small step for (a) pipe, one giant leap for portkind.')
        client_socket.sendall(f"Why noone listens to me".encode('utf-8'))
        data = client_socket.recv(1024)
        if data.decode('utf-8') != ("Conexion con el nuevo servidor establecida. Les deseamos un buen dia."):
            # Crear rutina para manejar estas situaciones TODO
            pass
        else:
            client_socket.close()
