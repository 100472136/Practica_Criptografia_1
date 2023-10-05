from cryptography.fernet import Fernet


class Login:
    def __init__(self, symmetric_key: Fernet):
        self.__user = input(b"Introduzca nombre de usuario:")
        self.__password = input(b"Introduzca contraseña:")
        self.__f = Fernet(symmetric_key)

    def encrypt_login(self):
        return [self.__f.encrypt(self.__user), self.__password]