from User import User
from cryptography.fernet import Fernet
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from getpass import getpass as pwd_input
from socket import *
from ServerManager import ServerManager

PADDING = padding.OAEP(
    mgf=padding.MGF1(algorithm=hashes.SHA256()),
    algorithm=hashes.SHA256(),
    label=None
)

#  INICIAR COMUNICACIÓN
server_name = "localhost"
port = 12000
client_socket = socket(AF_INET, SOCK_STREAM)
try:
    client_socket.connect((server_name, port))
except ConnectionRefusedError:
    raise ConnectionRefusedError("Error: server not active\n")

# RECIBIR CERTIFICADO DEL SERVIDOR
t_cert_pem_data = client_socket.recv(2048)

t_cert = x509.load_pem_x509_certificate(t_cert_pem_data)

# VERIFICAR CERTIFICADO

# GENERAR CLAVE SIMÉTRICA
symmetric_key = Fernet.generate_key()
fernet = Fernet(symmetric_key)
server_manager = ServerManager(client_socket, fernet)
# server_manager se usará para comunicarse con el servidor empleando la clave simétrica

#   ENCRIPTAR  CLAVE SIMÉTRICA CON CLAVE PÚBLICA DEL SERVIDOR
encrypted_symmetric_key = t_cert.public_key().encrypt(
    symmetric_key,
    PADDING
)

# ENVIAR CLAVE SIMÉTRICA ENCRIPTADA AL SERVIDOR
server_manager.send(encrypted_symmetric_key, encrypted=True)

# PIDE INPUT DE USUARIO(LOGIN)
new = input("Bienvenido al sistema de conexión con entrenadores personales!\nTiene cuenta? (y/n):\t").lower()
while new != 'y' and new != 'n':
    new = input("La respuesta debe de ser 'y' (sí) o 'n' (no): Tiene cuenta creada? (y/n):\t").lower()

if new == 'n':
    username = input("Introduzca un nombre de usuario:\t")
    password = pwd_input("Cree una contraseña, debe de tener mínimo 7 caracteres:\t")
    while len(password) < 7:
        password = pwd_input("Error, contraseña debe de tener mínimo 7 caracteres.\nCree una contraseña, debe de tener "
                             "mínimo 7 caracteres:\t")
else:
    username = input("Introduzca su nombre de usuario:\t")
    password = pwd_input("Introduzca su contraseña:\t")
user = User(new=new, username=username, password=password)

# ENVÍA ESTADO DE CUENTA AL SERVIDOR
server_manager.send(message=user.new)

# ENVÍA USUARIO AL SERVIDOR
server_manager.send(user.username)

# RECIBE RESPUESTA DEL SERVIDOR
answer = server_manager.receive()
answer_to_bool = {"ERROR": True, "NOERR": False}
error = answer_to_bool.get(answer)
if error is None:
    raise EnvironmentError("Error en el servidor, finalizando conexión.")
if error:
    if new == 'n':
        raise ValueError("Cuenta con ese nombre de usuario ya existe.")
    else:
        raise ValueError("Cuenta con ese nombre de usuario no existe.")

# ENVÍA CONTRASEÑA AL SERVIDOR
server_manager.send(user.password)
error = answer_to_bool.get(server_manager.receive())
if not error:
    print(f"Bienvenido, {user.username}")
else:
    if new == 'y':
        print("Contraseña incorrecta.")
    else:
        print("Ha habido un error, por favor, vuelva a intentarlo")
