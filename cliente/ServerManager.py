from socket import *
from cryptography.fernet import Fernet


def send_to_server(tcp_socket: socket, message: bytes | str):
    try:
        if isinstance(message, str):
            message = message.encode()
        tcp_socket.send(message)
    except BrokenPipeError:
        raise BrokenPipeError("Error: servidor ha finalizado conexión.\n")


def receive_from_server(tcp_socket: socket, fernet: Fernet):
    try:
        answer = tcp_socket.recv(4096)
        return fernet.decrypt(answer).decode()
    except BrokenPipeError:
        raise BrokenPipeError("Error: servidor ha finalizado conexión.\n")
