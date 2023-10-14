from cryptography.fernet import Fernet


class Login:
    def __init__(self, symmetric_key: bytes):
        self.__user = input("Introduzca nombre de usuario:")
        self.__password = input("Introduzca contraseña:")
        self.__f = Fernet(key=symmetric_key)

    def encrypt_login(self):
        return [self.__f.encrypt(self.__user.encode('utf-8')), self.__password]