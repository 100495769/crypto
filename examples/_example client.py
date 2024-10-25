# Client should be able to send and retrieve files.
# It should ask the server where to send it and then it should send those files to the host
# When retrieving files clients should ask the server for that specific file.
# Files will be encrypted through the fastes encryption algorithm (XChaCha20?) which proves to be
# enough for years (maybe add an option to extra security, changing the algorithm for something slower?)
# The key to descrypt those files will be sent to the server. Any time a new client connects with its
# credentials. It will be sent the key to the files.

import socket
import struct
# Crear un socket
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Dirección IP y puerto del servidor al que queremos conectarnos
server_address = ('127.0.0.1', 60000)  # Cambia IP y puerto si es necesario

# Conectar con el servidor
client_socket.connect(server_address)
client_socket.sendall(f"Buenos dias servidor, al habla el cliente!".encode('utf-8'))
data = client_socket.recv(1024)
if data.decode('utf-8') == "Buenos dias cliente, hace un dia soleado. Estamos listos para recibir archivos.":

    file_path = "../gatito.jpeg"
    client_socket.sendall(file_path.encode('utf-8'))

    with open(file_path, 'rb') as f:
        # Read and send the file in chunks
        while True:
            data = f.read(1024)  # Buffer size
            if not data:
                break
            client_socket.sendall(data)

    print("File sent successfully.")
client_socket.close()
