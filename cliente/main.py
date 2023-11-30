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
import time

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


def input_exercise() -> tuple[str, str, str]:
    exercise_name = input("Introduzca el nombre del ejercicio: ")
    rep_number = None
    while rep_number is None:
        rep_number = input("Introduzca el número de repeticiones del set: ")
        try:
            int(rep_number)
        except ValueError:
            print("Número no válido")
            rep_number = None
    target_muscle = input("Introduzca el músculo principal del ejercicio: ")
    return exercise_name, rep_number, target_muscle


def receive_routine(server_manager: ServerManager) -> dict | None:
    routine_name = server_manager.receive()
    if routine_name == "FIN":  # routine doesn't exist
        return None
    routine = {"name": routine_name, "exercises": []}
    while True:
        exercise_name = server_manager.receive()
        if exercise_name == "FIN":  # end of routine
            return routine
        rep_number = server_manager.receive()
        target_muscles = server_manager.receive()
        routine["exercises"].append([exercise_name, rep_number, target_muscles])


def receive_comments(server_manager: ServerManager) -> list:
    comments = []
    while True:
        comment_name = server_manager.receive()
        if comment_name == "FIN":
            return comments
        comment_message = server_manager.receive()
        comments.append({"name": comment_name, "message": comment_message})


def print_comments(comments: list):
    for comment in comments:
        print(f"Comentario de {comment['name']}: {comment['message']}")


def print_routine(routine: dict):
    routine_name = routine.get("name")
    print(f"Rutina {routine_name}")
    exercises = routine.get("exercises")
    for exercise in exercises:
        print(f"\t{exercise[2]}: {exercise[1]} repeticiones de {exercise[0]}.")
    return


def listen_for_commands(message, input_command_list: list[str]) -> str:
    command_list = []
    for element in input_command_list:
        command_list.append(element.lower())
    command_given = input(message).lower()
    while command_given not in command_list:
        print(f"{command_given} no es un comando correcto.")
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
    return User(username, password, account_type="Client")


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
    routine = None
    while True:
        if routine is None:
            command = listen_for_commands("Qué desea hacer?\n"
                                          "\tModificar rutinas de un cliente - 1\n"
                                          "\tAñadir un comentario a un cliente - 2\n"
                                          "\tSalir - 3\n",
                                          ['1', '2', '3'])
            server_manager.send(command)
            if command == '1':
                client_to_add = input("Introduzca el nombre del cliente al que quiere añadir ejercicios: ")
                server_manager.send(client_to_add)
                server_error = server_manager.receive_answer()
                if server_error is None or server_error:
                    print("Usuario no válido (es un entrenador o un usuario no existente")
                    continue
                if routine is None:
                    command = listen_for_commands("Qué desea hacer?\n"
                                                  "\tCrear nueva rutina - 1\n"
                                                  "\tSeleccionar una rutina existente - 2\n"
                                                  "\tEliminar una rutina - 3\n",
                                                  ['1', '2', '3'])
                    server_manager.send(command)
                    if command == '1':  # crear una nueva rutina
                        routine_to_add = input("Indique el nombre de la rutina: ")
                        server_manager.send(routine_to_add)
                        server_error = server_manager.receive_answer()
                        if server_error is None or server_error:
                            print("Rutina ya existe")
                            routine = receive_routine(server_manager)
                            print_routine(routine)
                        else:
                            print("Perfecto, rutina creada")
                            routine = {"name": routine_to_add, "exercises": []}
                    elif command == '2':  # modificar rutina existente
                        routine_to_add = input("Indique el nombre de la rutina: ")
                        server_manager.send(routine_to_add)
                        server_error = server_manager.receive_answer()
                        if server_error is None or server_error:
                            print("Rutina no existe")
                            routine = {"name": routine_to_add, "exercises": []}
                        else:
                            routine = receive_routine(server_manager)
                            print_routine(routine)
                    elif command == '3':  # eliminar rutina
                        routine_to_delete = input("Indique el nombre de la rutina a eliminar: ")
                        server_manager.send(routine_to_delete)
                        server_error = server_manager.receive_answer()
                        if server_error is None or server_error:
                            print("Rutina no existe")
                        else:
                            print("Perfecto, rutina eliminada")
            elif command == '2':  # enviar un comentario
                client = input("Introduzca el nombre del usuario al que desea dejar un comentario: ")
                server_manager.send(client)
                server_error = server_manager.receive_answer()
                if server_error is None or server_error:
                    print("Usuario no válido")
                    continue
                comment = input("Introduzca el comentario: ")
                server_manager.send(comment)
                print(f"Perfecto, comentario añadido a {client}")
            elif command == '3':  # salir
                print("Hasta luego!")
                return

        else:
            command = listen_for_commands("Opciones de rutina:\n"
                                          "\tAñadir un ejercicio - 1\n"
                                          "\tSalir - 2\n",
                                          ['1', '2'])
            if command == '1':  # añadir un ejercicio
                server_manager.send(command)
                exercise_name, rep_number, target_muscle = input_exercise()
                print(f"Sending exercise {exercise_name}, with {rep_number} reps and targeting {target_muscle}")
                server_manager.send(exercise_name)
                server_manager.send(rep_number)
                server_manager.send(target_muscle)
                server_error = server_manager.receive_answer()
                if server_error is None or server_error:
                    raise EnvironmentError("Error en el servidor")
                print("Ejercicio añadido!")
            elif command == '2':  # salir
                server_manager.send(command)
                routine = None
                continue


def client_functionality(server_manager: ServerManager, client: User):
    print(f"Bienvenido, {client.username}!")
    while True:
        command = listen_for_commands("Qué desea hacer?\n"
                                      "\tVer rutinas - 1\n"
                                      "\tVer comentarios - 2\n"
                                      "\tSalir - 3\n",
                                      ['1', '2', '3'])
        server_manager.send(command)
        if command == '3':  # salir
            print("Hasta luego!")
            break
        elif command == '1':  # ver rutinas
            current_routine = {}
            while current_routine is not None:
                current_routine = receive_routine(server_manager)
                if current_routine is None:
                    print("Aún no dispone de rutinas, por favor espere a que un entrenador le añada una rutina "
                          "a su perfil")
                else:
                    print_routine(current_routine)
                    current_routine = None
                    continue
        elif command == '2':  # ver comentarios
            comments = receive_comments(server_manager)
            if len(comments) == 0:
                print("Ningún entrenador le ha dejado un comentario")
            else:
                print_comments(comments)
                time.sleep(2)
        elif command == '3':
            print("Hasta luego!")
            return


def main():
    #  iniciar comunicación a través de socket
    server_name = "localhost"
    #  lista de posibles puertos
    ports = [12000, 12001, 12002]

    # Flag to indicate if connection is successful
    connected = False

    for port in ports:
        try:
            client_socket = socket(AF_INET, SOCK_STREAM)
            client_socket.connect((server_name, port))
            connected = True
            break  # exit the loop if connection successful
        except ConnectionRefusedError:
            continue

    if not connected:
        raise ConnectionRefusedError("No se pudo conectar a ninguno de los puertos")

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

    if user.account_type == "Trainer":
        trainer_functionality(server_manager, user)
    else:
        client_functionality(server_manager, user)


main()
