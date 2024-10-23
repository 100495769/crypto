# Server will act as a reference guide to where files are located.
# It will provide a client an adequate host (maybe not implement this yet as it is out of scope)
# It should also store the information of the user, login credentials and a random index to each file
# of the user. The index will be used to ask the hosts to retrieve a file, making the hosts unable to
# check which file they are storing

import socket

# Crear un socket
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Enlazar el socket a una dirección y puerto
server_socket.bind(('127.0.0.1', 60000))

# Escuchar por conexiones entrantes
server_socket.listen()

print("Esperando conexiones...")

client_socket, client_address = server_socket.accept()
print(f"Conexión establecida con {client_address}")
data = client_socket.recv(1024)
if data.decode('utf-8') == "Buenos dias servidor, al habla el cliente!":
    print("Valores del cliente estables... ¡Estableciendo conexión segura!")
    client_socket.sendall(f"Buenos dias cliente, hace un dia soleado. Estamos listos para recibir archivos.".encode('utf-8'))

file_name = client_socket.recv(1024).decode('utf-8')
file_path = "server/" + file_name
print("Recibiendo "+file_name+". Procediendo a su procesado.")
with open(file_path, 'wb') as f:
    counter = 0
    while True:
        data = client_socket.recv(1024)  # Buffer size
        if not data:
            break
        counter += 1024
        print("Se han recibido:",counter,"bytes. Procediendo a su escritura.")
        f.write(data)
# Recibir datos del cliente
print("Se ha completado el proceso. Archivo recibido y almacenado de manera correcta.")