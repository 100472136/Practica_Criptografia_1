from User import User
from cryptography.fernet import Fernet
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
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


def listen_for_commands(message, command_list:list[str]) -> str:
    for element in command_list:
        element.lower()
    command_given = input(message).lower()
    while command_given not in command_list:
        print("Por favor, introduzca un comando correcto.")
        command_given = input(message).lower()
    return command_given


def create_account(server_manager: ServerManager) -> User:
    username = input("Introduzca un nombre de usuario:\t")

    # envía nombre de usuario al servidor
    server_manager.send(username)

    server_error = server_manager.receive_answer()
    if server_error is None:
        raise EnvironmentError("Error en el servidor, finalizando conexión.")
    elif server_error:
        raise ValueError("Error: cuenta con ese nombre de usuario ya existe.")

    password = pwd_input("Cree una contraseña, debe de tener mínimo 7 caracteres:\t")
    while len(password) < 7:
        password = pwd_input("Error, contraseña debe de tener mínimo 7 caracteres.\n"
                             "Cree una contraseña, debe de tener mínimo 7 caracteres:\t")

    server_manager.send(password)
    account_type = server_manager.receive()
    if account_type == "Trainer":
        return User(username, password, account_type)
    elif account_type == "Client":
        return User(username, password, account_type)
    else:
        raise EnvironmentError("Error en el servidor, finalizando conexión")


def login(server_manager: ServerManager) -> User:
    username = input("Introduzca su nombre de usuario:\t")
    server_manager.send(username)
    server_error = server_manager.receive_answer()
    if server_error is None:
        raise EnvironmentError("Error en el servidor, finalizando conexión.")
    if server_error:
        raise ValueError("Cuenta con ese nombre de usuario no existe.")
    password = pwd_input("Introduzca su contraseña:\t")
    server_manager.send(password)
    account_type = server_manager.receive()
    if account_type == "Trainer":
        return User(username, password, account_type)
    elif account_type == "Client":
        return User(username, password, account_type)
    else:
        raise ValueError("Contraseña incorrecta")


def create_trainer_account(server_manager: ServerManager):
    enterprise_key = pwd_input("Por favor, introduzca la clave de empresa correspondiente:\t")
    server_manager.send(enterprise_key)
    server_error = server_manager.receive_answer()
    if server_error is None:
        raise EnvironmentError("Error en el servidor, finalizando conexión.")
    if server_error:
        raise ValueError("Clave de empresa incorrecta")
    print("Clave de empresa correcta, se generará una cuenta de entrenador.")
    username = input("Introduzca un nombre de usuario para el entrenador:\t")
    server_manager.send(username)
    server_error = server_manager.receive_answer()
    if server_error is None:
        raise EnvironmentError("Error en el servidor, finalizando conexión.")
    elif server_error:
        raise ValueError("Cuenta con ese nombre de usuario ya existe.\n")
    password = ''.join(secrets.choice(string.ascii_letters + string.digits + string.punctuation) for i in range(8))
    server_manager.send(password)
    if server_manager.receive_answer() is None:
        raise EnvironmentError("Error en el servidor, finalizando conexión.")

    print("Cuenta creada, por favor, envíe estos datos al entrenador personal:\n"
          f"\tNombre de usuario: {username}\n"
          f"\tContraseña: {password}")


def trainer_functionality(server_manager: ServerManager, user: User):
    request_number = int(server_manager.receive())
    requests_exist = request_number > 0
    if requests_exist:
        print(f"Tienes {request_number} solicitudes de clientes.")
    exit_input = False
    while not exit_input:
        command = listen_for_commands("Qué desea hacer?\n"
                                      "\tAtender solicitudes - A\n"
                                      "\tSalir - S\n",
                                      ['A', 'S'])
        if command == 'A':
            if not requests_exist:
                continue
            server_manager.send(command)
            for i in range(1,request_number):
                username_to_add = server_manager.receive()
                request_command = listen_for_commands(f"Solicitud de {username_to_add}. Desea aceptarla? (y/n):",
                                                      ['y', 'n'])
                server_manager.send(request_command)
                server_error = server_manager.receive_answer()
                if server_error is None or not server_error:
                    print("Error en el servidor, no se ha podido procesar la solicitud. Por favor, vuelva a intentarlo.")
                    break
        elif command == 'S':
            server_manager.send(command)
            exit_input = True


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

    # TO DO: verificar certificado

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
    interaction_type = listen_for_commands("Bienvenido al sistema de conexión con entrenadores personales!\n"
                                           "Qué desea hacer? (Introduzca la tecla correcta):\n"
                                           "\tIniciar sesión (I)\n\tRegistrarse (R)\n"
                                           "\tRegistrar una cuenta de entrenador (E)\n",
                                           [LOGIN, REGISTER, TRAINER_ACCOUNT])

    server_manager.send(interaction_type)
    if interaction_type == REGISTER:
        user = create_account(server_manager)
    elif interaction_type == LOGIN:
        user = login(server_manager)
    else:
        create_trainer_account(server_manager)
        return

    print(f"Bienvenido, {user.username}!")

    if user.account_type == "Client":
        trainer_functionality(server_manager, user)
    else:
        return


main()
