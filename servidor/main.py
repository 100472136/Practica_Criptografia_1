from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from socket import *
from Certificate import Certificate
from cryptography.fernet import Fernet
from Manage_Userbase import Userbase
from ServerManager import ServerManager
from cryptography import x509

PASSPHRASE = b'\x94sO\xc1\xd4\x13\x0e\x11\x98\xee\x9a\x95W\xf6\xb5\x16'
PADDING = padding.OAEP(
    mgf=padding.MGF1(algorithm=hashes.SHA256()),
    algorithm=hashes.SHA256(),
    label=None
)

HMAC_PADDING = padding.PSS(
    mgf=padding.MGF1(hashes.SHA256()),
    salt_length=padding.PSS.MAX_LENGTH
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
    if client_ip is not None:
        print(f"Conexión finalizada con {client_ip[0]}\n\n")
    print("Esperando conexión")
    server_socket.listen(1)
    connection_socket, client_ip = server_socket.accept()
    print(f"\n\nConexión iniciada con {client_ip[0]}")

    # COMPRUEBA SI TIENE UN CERTIFICADO CORRECT0
    with open("database/certificate.pem", "rb") as f:
        certificate_pem_data = f.read()

    try:
        x509.load_pem_x509_certificate(certificate_pem_data)
    except ValueError:
        cert = Certificate(PASSPHRASE)  # SI NO TIENE UN CERTIFICADO CORRECTO, CREA OTRO
        with open("database/certificate.pem", "rb") as f:
            certificate_pem_data = f.read()

    print("Enviando certificado...")
    connection_socket.send(certificate_pem_data)

    # RECIBE CLAVE SIMÉTRICA ENCRIPTADA CON CLAVE PÚBLICA
    print("Recibiendo clave simétrica...")
    encrypted_symmetric_key = connection_socket.recv(2048)

    # DESENCRIPTA CLAVE SIMÉTRICA CON CLAVE PRIVADA
    with open("database/private_key.pem", "rb") as f:
        private_key_pem_data = f.read()

    private_key = serialization.load_pem_private_key(data=private_key_pem_data, password=PASSPHRASE)
    symmetric_key = private_key.decrypt(encrypted_symmetric_key, PADDING)
    fernet = Fernet(symmetric_key)
    server_manager = ServerManager(tcp_socket=connection_socket, fernet=fernet, private_key=private_key)

    # RECIBE ESTADO DE CUENTA DEL CLIENTE
    new = server_manager.receive()
    if new == -1:
        continue
    new_bool = {'y': False, 'n': True}
    new = new_bool.get(new)
    if new:
        print("Cliente solicita registro de nuevo usuario.")
    else:
        print("Cliente solicita iniciar sesión")

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
            print(f"Error: solicitando crear cuenta con nombre de usuario {username}:ya existente")
            continue

        print(f"Iniciando registro de cuenta con nombre de usuario {username}")
        server_manager.send("NOERR")

        # RECIBE CONTRASEÑA
        password = server_manager.receive()
        if password == -1:
            continue
        userbase.add_user(username, password)
        server_manager.send("NOERR")
        print(f"Registro de cuenta con nombre de usuario {username} completada satisfactoriamente")

    else:
        test = userbase.user_with_username(username)
        if userbase.user_with_username(username) is None:
            answer = "ERROR"
            server_manager.send(answer)
            connection_socket.close()
            print(f"Error: cliente solicitando iniciar sesión con nombre de usuario {username}: no existente")
            continue

        server_manager.send("NOERR")
        print(f"Iniciando inicio de sesión para usuario {username}")

        # RECIBE CONTRASEÑA
        password = server_manager.receive()
        if password == -1:
            continue

        # VALIDA SI LA CONTRASEÑA ES CORRECTA
        if userbase.user_password_match(username, password):
            server_manager.send("NOERR")
            print(f"Inicio de sesión para usuario {username} completo satisfactoriamente.")
        else:
            server_manager.send("ERROR")
            print(f"Error en el inicio de sesión del usuario {username}: contraseña incorrecta.")
