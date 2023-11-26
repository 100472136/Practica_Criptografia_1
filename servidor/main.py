from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from socket import *
from Certificate import Certificate
from cryptography.fernet import Fernet
from Manage_Userbase import Userbase
from ServerManager import ServerManager
from cryptography import x509
from Enterprise_Keys_Manager import EnterpriseKeysManager

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


def main():
    userbase = Userbase()
    register_input = 'r'
    login_input = 'i'
    trainer_account_input = 'e'

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
        if new == register_input:
            if register(userbase, server_manager) < 0:
                print("Error en el registro de cuenta.")
                connection_socket.close()
                continue
        elif new == login_input:
            if login(userbase, server_manager) < 0:
                print("Error en el inicio de sesión de cuenta.")
                connection_socket.close()
                continue
            print("CREATING ACCCOUNT")
        elif new == trainer_account_input:
            if create_trainer_account(userbase, server_manager) < 0:
                print("Error en la creación de cuenta de entrenador")
                continue
        else:
            print("Error, mensaje de cliente incorrecto.")
            server_manager.send("ERROR")
            continue


def register(userbase: Userbase, server_manager: ServerManager) -> int:
    # recibe usuario del cliente
    username = server_manager.receive()
    if username == -1:
        return -3

    # comprueba si el usuario está en la base de datos
    if userbase.user_with_username(username) is not None:
        server_manager.send("ERROR")
        return -1

    server_manager.send("NOERR")

    # recibe contraseña del cliente
    password = server_manager.receive()
    if password == -1:
        return -2
    userbase.add_user(username, password)
    server_manager.send("NOERR")
    return 0


def login(userbase: Userbase, server_manager: ServerManager) -> int:
    # recibe usuario del cliente
    username = server_manager.receive()
    if username == -1:
        return -3

    # comprueba si el usuario está en la base de datos
    if userbase.user_with_username(username) is None:
        server_manager.send("ERROR")
        return -1

    server_manager.send("NOERR")

    # RECIBE CONTRASEÑA
    password = server_manager.receive()
    if password == -1:
        return -2

    # comprueba si la contraseña le corresponde al nombre de usuario
    if userbase.user_password_match(username, password):
        server_manager.send("NOERR")
        return -2
    server_manager.send("ERROR")
    return 0


def create_trainer_account(userbase: Userbase, server_manager: ServerManager) -> int:
    # recibe clave de empresa del cliente
    enterprise_key = server_manager.receive()
    key_manager = EnterpriseKeysManager()
    if key_manager.find_key(enterprise_key) < 0:
        server_manager.send("ERROR")
        return -1
    server_manager.send("NOERR")
    username = server_manager.receive()
    if userbase.user_with_username(username):
        server_manager.send("ERROR")
        return -2
    server_manager.send("NOERR")
    password = server_manager.receive()
    userbase.add_user(username, password)
    server_manager.send("NOERR")
    print("CUENTA CREADA SIN PROBLEMAS")
    return 0


main()
