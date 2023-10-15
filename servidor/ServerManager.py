from socket import *
from cryptography.fernet import Fernet


def receive_and_decode(tcp_socket: socket, fernet: Fernet):
    try:
        answer = tcp_socket.recv(4096)
        return fernet.decrypt(answer).decode()
    except BrokenPipeError:
        raise BrokenPipeError("Error: cliente ha finalizado conexión.\n")
