import socket
from socket import *

import cryptography.fernet
from cryptography.fernet import Fernet


class ServerManager:
    def __init__(self, tcp_socket: socket, fernet: Fernet):
        self.__socket = tcp_socket
        self.__fernet = fernet

    def send(self, message: bytes | str, encrypted=False):
        try:
            if isinstance(message, str):
                message = message.encode()
            if not encrypted:
                message = self.__fernet.encrypt(message)
            self.__socket.send(message)
        except BrokenPipeError:
            raise BrokenPipeError("Error: servidor ha finalizado conexión.\n")

    def receive(self):
        try:
            answer = self.__socket.recv(4096)
            answer = self.__fernet.decrypt(answer)
            return answer.decode()
        except BrokenPipeError:
            self.__socket.close()
            print("Error: cliente ha finalizado conexión")
        except cryptography.fernet.InvalidToken:    # error al verificar integridad del mensaje con la MAC
            self.__socket.close()
            print("Error: Mensaje corrupto.")
