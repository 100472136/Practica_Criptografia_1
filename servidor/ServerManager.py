from socket import *
from cryptography.fernet import InvalidToken
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization


class ServerManager:
    def __init__(self, tcp_socket: socket, fernet: Fernet, private_key: rsa.RSAPrivateKey):
        self.__socket = tcp_socket
        self.__fernet = fernet
        self.__padding = padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                                     salt_length=padding.PSS.MAX_LENGTH)
        self.__private_key = private_key
        self.__client_public_key = self.read_client_public_key()

    @staticmethod
    def read_client_public_key():
        with open("database/client_public_key.pem", "rb") as f:
            client_public_key_pem = f.read()

        return serialization.load_pem_public_key(client_public_key_pem)

    def send(self, message: bytes | str, encrypted=False):
        try:
            if isinstance(message, str):
                message = message.encode()
            if not encrypted:
                signature = self.__private_key.sign(message, padding=self.__padding, algorithm=hashes.SHA256())
                message = self.__fernet.encrypt(message) + signature
            self.__socket.send(message)
        except BrokenPipeError:
            self.__socket.close()
            print("Error: cliente ha finalizado conexión.\n")

    def receive(self):
        try:
            answer = self.__socket.recv(4096)
            signature = answer[slice(answer.find(b"==") + 2, len(answer))]  # == indica el final del
            #  mensaje cifrado
            answer = self.__fernet.decrypt(answer)
            #  comprueba si el mensaje corresponde a la firma
            self.__client_public_key.verify(
                signature=signature,
                data=answer,
                padding=self.__padding,
                algorithm=hashes.SHA256()
            )
            return answer.decode()
        except BrokenPipeError:
            self.__socket.close()
            print("Error: cliente ha finalizado conexión")
        except InvalidToken:    # error al verificar integridad del mensaje con la MAC
            self.__socket.close()
            print("Error: Mensaje corrupto.")
