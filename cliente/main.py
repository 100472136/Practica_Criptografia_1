from User import User
from cryptography.fernet import Fernet
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature
from getpass import getpass as pwd_input
from socket import *
from ServerManager import ServerManager
import secrets
import string

REGISTER = 'r'
LOGIN = 'i'
TRAINER_ACCOUNT = 'e'

# contraseña generada aleatoriamente para cifrado de archivos
PASSPHRASE = b'E{\xac|?\xd7\xce`\x1b\xd8\xfb\x1cK\xfed\xeb'

# padding para encriptado simétrico
PADDING = padding.OAEP(
    mgf=padding.MGF1(algorithm=hashes.SHA256()),
    algorithm=hashes.SHA256(),
    label=None
)


def main():
    #  iniciar comunicación a través de socket
    server_name = "localhost"
    port = 12000
    client_socket = socket(AF_INET, SOCK_STREAM)
    try:
        client_socket.connect((server_name, port))
    except ConnectionRefusedError:
        raise ConnectionRefusedError("Error: server not active\n")

    # recibir certificado del servidor
    t_cert_pem_data = client_socket.recv(2048)

    t_cert = x509.load_pem_x509_certificate(t_cert_pem_data)

    # verificar que la firma del certificado es válida
    with open("../CA_low/database/ca_cert.pem", "rb") as f:
        ca_cert_pem_data = f.read()
    ca_cert = x509.load_pem_x509_certificate(ca_cert_pem_data)
    try:
        ca_cert.public_key().verify(
            signature=t_cert.signature,
            data=t_cert.tbs_certificate_bytes,
            padding=padding.PKCS1v15(),
            algorithm=t_cert.signature_hash_algorithm
        )
    except BrokenPipeError:
        client_socket.close()
        print("Error: cliente ha finalizado conexión")
    except InvalidSignature:
        print("La firma del certificado es incorrecta")


    # generar clave secreta
    symmetric_key = Fernet.generate_key()
    fernet = Fernet(symmetric_key)
    # server_manager se usará para comunicarse con el servidor
    server_manager = ServerManager(client_socket, fernet, PASSPHRASE, t_cert)

    #  encriptar clave simétrica con clave pública del servidor y enviarla al servidor
    encrypted_symmetric_key = t_cert.public_key().encrypt(
        symmetric_key,
        PADDING
    )

    server_manager.send(encrypted_symmetric_key, encrypted=True)

    interaction_type = input("Bienvenido al sistema de conexión con entrenadores personales!\n"
                             "Qué desea hacer? (Introduzca la tecla correcta):\n"
                             "\tIniciar sesión (I)\n\tRegistrarse (R)\n"
                             "\tRegistrar una cuenta de entrenador (E)\n").lower()
    while interaction_type != LOGIN and interaction_type != REGISTER and interaction_type != TRAINER_ACCOUNT:
        print("Por favor, introduzca I si quiere iniciar sesión, R si quiere registrarse o E si quiere "
              "registrar una cuenta de entrenador.\n")
        interaction_type = input("Bienvenido al sistema de conexión con entrenadores personales!\n"
                                 "Iniciar sesión (I)\nRegistrarse (R)\n"
                                 "Registrar una cuenta de entrenador (E)\n").lower()

    server_manager.send(interaction_type)
    if interaction_type == REGISTER:
        user = create_account(server_manager)
    elif interaction_type == LOGIN:
        user = login(server_manager)
    else:
        create_trainer_account(server_manager)
        return

    print(f"Bienvenido, {user.username}")


def create_account(server_manager: ServerManager) -> User:
    username = input("Introduzca un nombre de usuario:\t")

    # envía nombre de usuario al servidor
    server_manager.send(username)

    server_error = server_manager.receive()
    if server_error is None:
        raise EnvironmentError("Error en el servidor, finalizando conexión.")
    elif server_error:
        raise ValueError("Error: cuenta con ese nombre de usuario ya existe.")

    password = pwd_input("Cree una contraseña, debe de tener mínimo 7 caracteres:\t")
    while len(password) < 7:
        password = pwd_input("Error, contraseña debe de tener mínimo 7 caracteres.\n"
                             "Cree una contraseña, debe de tener mínimo 7 caracteres:\t")

    server_manager.send(password)
    if server_manager.receive() is None:
        raise EnvironmentError("Error en el servidor, finalizando conexión.")

    return User(username, password, interaction_type=REGISTER)


def login(server_manager: ServerManager) -> User:
    username = input("Introduzca su nombre de usuario:\t")
    server_manager.send(username)
    server_error = server_manager.receive()
    if server_error is None:
        raise EnvironmentError("Error en el servidor, finalizando conexión.")
    if server_error:
        raise ValueError("Cuenta con ese nombre de usuario no existe.")
    password = pwd_input("Introduzca su contraseña:\t")
    server_manager.send(password)
    server_error = server_manager.receive()
    if server_error is None:
        raise EnvironmentError("Error en el servidor, finalizando conexión.")
    if server_error:
        raise ValueError("Contraseña incorrecta.")
    return User(username, password, interaction_type=LOGIN)


def create_trainer_account(server_manager: ServerManager):
    enterprise_key = pwd_input("Por favor, introduzca la clave de empresa correspondiente:\t")
    server_manager.send(enterprise_key)
    server_error = server_manager.receive()
    if server_error is None:
        raise EnvironmentError("Error en el servidor, finalizando conexión.")
    if server_error:
        raise ValueError("Clave de empresa incorrecta")
    print("Clave de empresa correcta, se generará una cuenta de entrenador.")
    username = input("Introduzca un nombre de usuario para el entrenador:\t")
    server_manager.send(username)
    server_error = server_manager.receive()
    if server_error is None:
        raise EnvironmentError("Error en el servidor, finalizando conexión.")
    elif server_error:
        raise ValueError("Cuenta con ese nombre de usuario ya existe.\n")
    password = ''.join(secrets.choice(string.ascii_letters + string.digits + string.punctuation) for i in range(8))
    server_manager.send(password)
    if server_manager.receive() is None:
        raise EnvironmentError("Error en el servidor, finalizando conexión.")

    print("Cuenta creada, por favor, envíe estos datos al entrenador personal:\n"
          f"\tNombre de usuario: {username}\n"
          f"\tContraseña: {password}")


main()
