from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from socket import *
from Certificate import Certificate
from cryptography.fernet import Fernet
from Manage_Userbase import *
from ServerManager import ServerManager
from cryptography import x509
from Enterprise_Keys_Manager import init_keys_file, find_key
from User import User
from User_Files_Manager import UserFiles

PASSPHRASE = b'\x94sO\xc1\xd4\x13\x0e\x11\x98\xee\x9a\x95W\xf6\xb5\x16'
PADDING = padding.OAEP(
    mgf=padding.MGF1(algorithm=hashes.SHA256()),
    algorithm=hashes.SHA256(),
    label=None
)


def send_routine(trainer_files: UserFiles, routine_name: str, server_manager: ServerManager) -> int:
    routine = trainer_files.get_routine(routine_name)
    if routine is None:
        server_manager.send("FIN")
        return -1
    server_manager.send(routine["name"])
    for exercise in routine.get("exercises"):
        #  send exercise name
        server_manager.send(exercise[0])
        #  send rep number
        server_manager.send(exercise[1])
        #  send target muscle
        server_manager.send(exercise[2])
    server_manager.send("FIN")
    return 0


def send_comments(user_files: UserFiles, server_manager: ServerManager):
    comments = user_files.get_comments()
    for comment in comments:
        server_manager.send(comment["trainer"])
        server_manager.send(comment["comment"])
    server_manager.send("FIN")


def register(server_manager: ServerManager) -> User | None:
    # recibe usuario del cliente
    username = server_manager.receive()
    if username == -1:
        return

    # comprueba si el usuario está en la base de datos
    if user_with_username(username) is not None:
        server_manager.send("ERROR")
        return

    server_manager.send("NOERR")

    # recibe contraseña del cliente
    password = server_manager.receive()
    if password == -1:
        return
    add_user(username, password, "Client")
    return User(username, password, type="Client")


def login(server_manager: ServerManager) -> User | None:
    # recibe usuario del cliente
    username = server_manager.receive()
    if username == -1:
        return

    # comprueba si el usuario está en la base de datos
    if user_with_username(username) is None:
        server_manager.send("ERROR")
        return

    server_manager.send("NOERR")

    # RECIBE CONTRASEÑA
    password = server_manager.receive()
    if password == -1:
        return

    # comprueba si la contraseña le corresponde al nombre de usuario
    if not user_password_match(username, password):
        server_manager.send("ERROR")
        return
    user_type = get_user_type(username)
    server_manager.send(user_type)
    return User(username, password, type=user_type)


def create_trainer_account(server_manager: ServerManager) -> int:
    # recibe clave de empresa del cliente
    enterprise_key = server_manager.receive()
    init_keys_file()
    if find_key(enterprise_key) < 0:
        server_manager.send("ERROR")
        return -1
    server_manager.send("NOERR")
    username = server_manager.receive()
    if user_with_username(username):
        server_manager.send("ERROR")
        return -2
    server_manager.send("NOERR")
    password = server_manager.receive()
    add_user(username, password, account_type="Trainer")
    server_manager.send("NOERR")
    return 0


def trainer_functionality(server_manager: ServerManager, trainer: str) -> int:
    routine = None
    while True:
        command = server_manager.receive()
        if routine is None:
            if command == '3':  # entrenador quiere salir
                print("Trainer client exit")
                return 0
            elif command == '1':  # entrenador quiere modificar las rutinas de un cliente
                user = server_manager.receive()
                if not user_with_username(user) or get_user_type(user) == "Trainer":
                    server_manager.send("ERROR")
                    continue
                trainer_files = UserFiles(user)
                server_manager.send("NOERR")
                command = server_manager.receive()
                if command == '1':  # entrenador quiere añadir una nueva rutina
                    routine_name = server_manager.receive()
                    routine = trainer_files.get_routine(routine_name)
                    if routine is not None:
                        server_manager.send("ERR")
                        send_routine(trainer_files, routine_name, server_manager)
                    else:
                        routine = {"name": routine_name, "exercises": []}
                        trainer_files.add_routine(routine_name)
                        server_manager.send("NOERR")
                elif command == '2':  # entrenador quiere seleccionar una rutina existente
                    routine_name = server_manager.receive()
                    routine = trainer_files.get_routine(routine_name)
                    if routine is None:
                        server_manager.send("ERR")
                        routine = {"name": routine_name, "exercises": []}
                        trainer_files.add_routine(routine_name)
                    else:
                        server_manager.send("NOERR")
                        send_routine(trainer_files, routine_name, server_manager)
                elif command == '3':  # entrenador quiere eliminar una rutina
                    routine_name = server_manager.receive()
                    error_code = trainer_files.delete_routine(routine_name)
                    if error_code < 0:
                        server_manager.send("ERR")
                        print(f"Deleting routine cancelled with error code {error_code}")
                        continue
                    server_manager.send("NOERR")
                else:
                    continue
            elif command == '2':  # entrenador quiere añadir un comentario
                user = server_manager.receive()
                if not user_with_username(user) or get_user_type(user) == "Trainer":
                    server_manager.send("ERROR")
                    continue
                server_manager.send("NOERR")
                comment = server_manager.receive()
                trainer_files = UserFiles(user)
                trainer_files.add_comment(trainer, comment)

        else:
            if command == "1":  # trainer wants to add an exercise
                print("Trainer wants to add an exercise")
                exercise_name = server_manager.receive()
                rep_number = server_manager.receive()
                target_muscle = server_manager.receive()
                print(f"Ejercicio recibido de entrenador, se va a añadir a rutina {routine_name}")
                error_code = trainer_files.add_set_to_routine(routine_name, exercise_name, target_muscle, rep_number)
                if error_code < 0:
                    server_manager.send("ERROR")
                    print(f"Exiting with error {error_code}")
                    return -1
                else:
                    server_manager.send("NOERR")
            elif command == "2":  # trainer wants to exit
                routine = None
                continue


def client_functionality(server_manager: ServerManager, client: str):
    client_files = UserFiles(client)
    while True:
        command = server_manager.receive()
        if command == '1':  # usuario quiere ver sus rutinas
            routines = client_files.get_routines()
            if len(routines) == 0:
                server_manager.send("FIN")
            for routine in routines:
                send_routine(client_files, routine["name"], server_manager)
        elif command == '2':  # usuario quiere ver sus comentarios
            send_comments(client_files, server_manager)
        elif command == '3':
            return


def main():
    init_userbase()
    register_char = 'r'
    login_char = 'i'
    trainer_account_char = 'e'

    # CREA SERVER SOCKET
    ports = [12000, 12001, 12002]
    server_ip = "localhost"

    server_socket = socket(AF_INET, SOCK_STREAM)
    try:
        server_socket.bind((server_ip, ports[0]))
        print(f"Servidor iniciado en puerto {ports[0]}")
    except OSError:
        try:
            server_socket.bind((server_ip, ports[1]))
            print(f"Servidor iniciado en puerto {ports[1]}")
        except OSError:
            server_socket.bind((server_ip, ports[2]))
            print(f"Servidor iniciado en puerto {ports[2]}")
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
        symmetric_key = private_key.decrypt(
            encrypted_symmetric_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None))
        fernet = Fernet(symmetric_key)
        server_manager = ServerManager(tcp_socket=connection_socket, fernet=fernet, private_key=private_key)

        # recibe tipo de interacción del cliente
        interaction_type = server_manager.receive()
        if interaction_type == -1:
            continue
        if interaction_type == register_char:
            user = register(server_manager)
            if user is None:
                print("Error en el registro de cuenta.")
                connection_socket.close()
                continue
        elif interaction_type == login_char:
            user = login(server_manager)
            if user is None:
                print("Error en el inicio de sesión de cuenta.")
                connection_socket.close()
                continue
        elif interaction_type == trainer_account_char:
            if create_trainer_account(server_manager) < 0:
                print("Error en la creación de cuenta de entrenador")
            continue
        else:
            print("Error, mensaje de cliente incorrecto.")
            server_manager.send("ERROR")
            continue
        if user.type == "Trainer":
            trainer_functionality(server_manager, user.username)
        elif user.type == "Client":
            client_functionality(server_manager, user.username)


main()
