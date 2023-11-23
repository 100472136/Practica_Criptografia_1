from socket import *
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography import x509


class ServerManager:
    def __init__(self, tcp_socket: socket, fernet: Fernet, passphrase: bytes,
                 server_certificate: x509.Certificate):
        self.__socket = tcp_socket
        self.__fernet = fernet
        self.__padding = padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                                     salt_length=padding.PSS.MAX_LENGTH)
        self.__asymmetric_key = self.read_asymmetric_key(passphrase)
        self.__server_public_key = server_certificate.public_key()

    @staticmethod
    def read_asymmetric_key(passphrase):
        with open("pemfiles/private_key.pem", "rb") as f:
            private_key_pem_data = f.read()
        return serialization.load_pem_private_key(data=private_key_pem_data, password=passphrase)

    def send(self, message: bytes | str, encrypted=False):
        try:
            if isinstance(message, str):
                message = message.encode()
            if not encrypted:
                signature = self.__asymmetric_key.sign(message, padding=self.__padding, algorithm=hashes.SHA256())
                message = self.__fernet.encrypt(message) + signature
            self.__socket.send(message)
        except BrokenPipeError:
            raise BrokenPipeError("Error: servidor ha finalizado conexión.\n")

    def receive(self):
        try:
            answer = self.__socket.recv(4096)
            signature = answer[slice(answer.find(b"==") + 2, len(answer))]  # == indica el final del
            #  mensaje cifrado
            answer = self.__fernet.decrypt(answer)
            #  comprueba si el mensaje corresponde a la firma
            self.__server_public_key.verify(
                signature=signature,
                data=answer,
                padding=self.__padding,
                algorithm=hashes.SHA256()
            )
            return answer.decode()
        except BrokenPipeError:
            raise BrokenPipeError("Error: servidor ha finalizado conexión.\n")
