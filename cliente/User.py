from cryptography.fernet import Fernet


class User:
    def __init__(self, username: str, password: str, new: str):
        self.username = username
        self.password = password
        self.new = new

