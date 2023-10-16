from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from socket import *
from Certificate import Certificate
from cryptography.fernet import Fernet
from Manage_Userbase import Userbase
from ServerManager import ServerManager
PADDING = padding.OAEP(
    mgf=padding.MGF1(algorithm=hashes.SHA256()),
    algorithm=hashes.SHA256(),
    label=None
)
userbase = Userbase()

# CREA SERVER SOCKET
port = 12000
server_ip = "localhost"

server_socket = socket(AF_INET, SOCK_STREAM)
server_socket.bind((server_ip, port))
client_ip = None

# INICIA COMUNICACIÓN CON EL CLIENTE, CREA CONNECTION SOCKET
while True:
    print("Esperando conexión\n")
    server_socket.listen(1)
    if client_ip is not None:
        print(f"Conexión finalizada con {client_ip[0]}")
    connection_socket, client_ip = server_socket.accept()
    print(f"Conexión iniciada con {client_ip[0]}\n")
    # CREA CLAVE PÚBLICA Y CERTIFICADO
    # actualmente crea un certificado en cada instancia, en el futuro comprobará si dispone de uno válido
    cert = Certificate()

    # ENVÍA SU CERTIFICADO
    with open("database/certificate.pem", "rb") as f:
        certificate_pem_data = f.read()

    connection_socket.send(certificate_pem_data)

    # RECIBE CLAVE SIMÉTRICA ENCRIPTADA CON CLAVE PÚBLICA
    encrypted_symmetric_key = connection_socket.recv(2048)

    # DESENCRIPTA CLAVE SIMÉTRICA CON CLAVE PRIVADA
    with open("database/private_key.pem", "rb") as f:
        private_key_pem_data = f.read()

    private_key = serialization.load_pem_private_key(data=private_key_pem_data, password=None)
    symmetric_key = private_key.decrypt(encrypted_symmetric_key, PADDING)
    fernet = Fernet(symmetric_key)
    server_manager = ServerManager(tcp_socket=connection_socket, fernet=fernet)

    # RECIBE ESTADO DE CUENTA DEL CLIENTE
    new = server_manager.receive()
    if new == -1:
        continue
    new_bool = {'y': False, 'n': True}
    new = new_bool.get(new)

    # RECIBE USUARIO
    username = server_manager.receive()
    if username == -1:
        continue

    # COMPRUEBA SU USUARIO ESTÁ EN BASE DE DATOS
    if new:
        if userbase.user_with_username(username) is not None:
            answer = "ERROR"
            server_manager.send(answer)
            connection_socket.close()
            continue

        answer = "NOERR"
        new_user = {"username": username, "password": None}
        server_manager.send(answer)

        # RECIBE CONTRASEÑA
        password = server_manager.receive()
        if password == -1:
            continue
        new_user["password"] = password
        userbase.add_user(new_user)

    else:
        test = userbase.user_with_username(username)
        if userbase.user_with_username(username) is None:
            answer = "ERROR"
            server_manager.send(answer)
            connection_socket.close()
            continue

        # RECIBE CONTRASEÑA
        password = server_manager.receive()
        if password == -1:
            continue

        # VALIDA SI LA CONTRASEÑA ES CORRECTA
        userbase.user_password_match(username, password)
