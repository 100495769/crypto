# Server will act as a reference guide to where files are located.
# It will provide a client an adequate host (maybe not implement this yet as it is out of scope)
# It should also store the information of the user, login credentials and a random index to each file
# of the user. The index will be used to ask the hosts to retrieve a file, making the hosts unable to
# check which file they are storing



# Arreglar la funcion de asignacion de puertos, no funciona.
# Terminar TODOs
# Manera limpia de terminarlo sighandler para sigstop?
# Eso es all UwU hasta que se apliquen cripto cosas.


import signal

import time
import socket
import os
from port import port

def get_port(ports_pool) -> int:
    # This function returns an available port from the ports_pool
    counter = 4
    n_ports = len(ports_pool)

    # Check for all the ports in the pool until one is available
    while n_ports > counter:

        port = ports_pool[counter]
        finder_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        result = finder_socket.connect_ex(('localhost', port))
        if result != 0:
            del ports_pool[counter]
            return port
        counter += 1

    # If no available port return -1
    return -1

# Crear un socket
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
ports_pool = list(range(port() + 1, port() + 499))
# Enlazar el socket a una dirección y puerto
server_socket.bind(('127.0.0.1', port()))
def signal_handler(sig, frame):
    pass
signal.signal(signal.SIGUSR1, signal_handler)


while True:
    # Escuchar por conexiones entrantes.
    server_socket.listen()
    client_socket, client_address = server_socket.accept()
    #print(f"Conexión establecida con {client_address}")

    data = client_socket.recv(1024)
    if data.decode('utf-8') != "Buenos dias servidor, al habla el cliente!":
        pass #Crear rutina para gestionar esto. TODO
    #print("Valores del cliente estables... ¡Estableciendo conexión segura!")


    # Crear un proceso server_client y comunicar el puerto en el momento adecuado al cliente.
    client_socket.sendall(f"Buenos dias cliente, hace un dia soleado. Estamos gestionando la maniobra para asignare un puerto abierto al que dockear.".encode('utf-8'))
    port = str(get_port(ports_pool))

    while port == "-1":
        # Espera a que se libere un puerto.
        time.sleep(0.5)
        port = str(get_port(ports_pool))

    #Crear nuevo proceso para el cliente.
    pid = os.fork()
    if pid == 0:
        os.execl("/usr/bin/python3","python3", os.path.join(os.getcwd(), "server_client.py"), port, str(client_address[0]), str(client_address[1]))

    # Espera a la señal de que el servidor se ha establecido correctamente. SIGUSR1
    signal.pause()
    # Comunicar el puerto al cliente.
    client_socket.sendall(f"{port}".encode('utf-8'))

    #print('Thats one small step for (a) port, one giant leap for portkind.')
    # Espera a que el cliente confirme la conexion correcta.

    data = client_socket.recv(1024) # Añadir un timeout por si el cliente corta la conexión antes. TODO
    if data.decode('utf-8') != ("Conexion con el nuevo servidor establecida. Les deseamos un buen dia."):
        # Crear rutina para manejar estas situaciones TODO
        pass
    else:
        # Cerrar conexion y logearlo.
        client_socket.close()
        with open("server_log.txt", 'a') as log:
            os.write(log.fileno(), str(time.time()).encode() + b": Connection Successful with " + (str(client_address[0]) + ":" + str(client_address[1]) + "\n").encode())