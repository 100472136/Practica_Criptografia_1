from cryptography.fernet import Fernet


class UserInfo:
    def __init__(self, symmetric_key: bytes, username: str, password: str, new: str):
        self.f = Fernet(key=symmetric_key)
        self.username = self.f.encrypt(username.encode())
        self.password = self.f.encrypt(password.encode())
        self.new = self.f.encrypt(new.encode())

