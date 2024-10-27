# Hosts will receive a file and an index and will store it.
import signal
import socket
import time
import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
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
            del ports_pool[counter]
            del ports_pool[counter+1] #=> why
            return port
        counter += 1

    # If no available port return -1
    return -1

def signal_handler(sig, frame):
    pass

def main():
    # No me preguntes por qué lo tengo que importar aquí.
    from port import port




    signal.signal(signal.SIGUSR1, signal_handler)
    host_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    host_socket.bind(('localhost', port() + 500))
    ports_pool = list(range(port() + 501, port() + 1000))

    while True:
        host_socket.listen()
        print('Waiting for a connection...')
        server_socket, server_address = host_socket.accept()
        print("Conexionado")

        port = str(get_port(ports_pool))

        while port == "-1":
            # Espera a que se libere un puerto.
            time.sleep(0.5)
            port = str(get_port(ports_pool))
        # Crear nuevo proceso para el cliente.
        pid = os.fork()
        if pid == 0:
            os.execl("/usr/bin/python3", "python3", os.path.join(os.getcwd(), "host_client.py"), port,
                     str(server_address[0]), str(server_address[1]))

        # Espera a la señal de que el servidor se ha establecido correctamente. SIGUSR1
        signal.pause()
        # Comunicar el puerto al cliente.
        print("Enviado nuevo puerto")
        server_socket.sendall(f"{port}".encode('utf-8'))
        print("Enviacion correcta")
        server_socket.close()

if __name__ == '__main__':
    main()