import json
import os
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.exceptions import InvalidKey
PATH = "database/userbase.json"


def init_userbase():
    try:
        with open(PATH, "r") as file:
            json.load(file)
    except json.decoder.JSONDecodeError:
        base_userbase = {"users": []}
        with open(PATH, "w") as file:
            json.dump(base_userbase, file, indent=4)


def encrypt_password(password):
    if not isinstance(password, bytes):
        password = password.encode()
    salt = os.urandom(16)
    kdf = Scrypt(
        salt=salt,
        length=32,
        n=2**14,
        r=8,
        p=1
    )
    return salt, kdf.derive(password)


def user_with_username(username: str):
    with open(PATH, "r") as file:
        data_list = json.load(file)
    for user in data_list["users"]:
        if user.get("username") == username:
            return user
    return None


def get_user_type(username:str):
    user = user_with_username(username)
    if user is None:
        raise ValueError("Usuario no existente")
    return user.get("type")


def add_user(username: str, password: str, account_type: str):
    if user_with_username(username) is not None:
        raise ValueError("Intentando añadir usuario ya existente.")
    with open(PATH, "r") as file:
        data_list = json.load(file)
    salt, password_key = encrypt_password(password)
    data_list["users"].append({"username": username, "type": account_type, "password_key": password_key.decode('latin-1'),
                               "salt": salt.decode('latin-1')})
    with open(PATH, "w") as file:
        json.dump(data_list, file, indent=4)


def remove_user(username: str):
    if user_with_username(username) is None:
        raise ValueError("Intentando eliminar usuario no existente")
    with open(PATH, "r") as file:
        data_list = json.load(file)
    for i in range(0, len(data_list["users"])):
        if data_list["users"][i].get("username") == username:
            del data_list["users"][i]
            break
    with open(PATH, "w") as file:
        json.dump(data_list, file, indent=4)


def user_password_match(username: str, password: str):
    user = user_with_username(username)
    if user is None:
        raise ValueError("Intentando comprobar contraseña de usuario no existente.")
    salt = user["salt"].encode('latin-1')
    password_key = user["password_key"].encode('latin-1')
    kdf = Scrypt(
        salt=salt,
        length=32,
        n=2**14,
        r=8,
        p=1
    )
    try:
        kdf.verify(password.encode(), password_key)
    except InvalidKey:
        return False
    remove_user(username)
    add_user(username, password, user.get("type"))
    return True
