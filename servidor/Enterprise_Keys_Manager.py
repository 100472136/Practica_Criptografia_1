import json
import os
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.exceptions import InvalidKey

PATH = "database/enterprise_keys.json"


def init_keys_file():
    try:
        with open(PATH, 'r') as file:
            json.load(file)
    except json.decoder.JSONDecodeError:
        with open(PATH, 'w') as file:
            json.dump({"keys": []}, file, indent=4)
        add_key("1234567")
        add_key("test_key!")
        print("This part is reached properly")


def derive_key(key: str) -> [bytes, bytes]:
    key = key.encode("latin-1")
    salt = os.urandom(16)
    kdf = Scrypt(
        salt=salt,
        length=32,
        n=2**14,
        r=8,
        p=1
    )
    return salt, kdf.derive(key)


def add_key(key: str) -> int:
    """
    Adds key to keys file
    :param key:
    :return: -1 if key is already in file, 0 otherwise
    :rtype: int
    """
    if find_key(key) != -2:
        print("KEY FOUND ERROR")
        return -1
    salt, key = derive_key(key)
    with open(PATH, 'r') as file:
        data_list: dict = json.load(file)
    data_list["keys"].append({"salt": salt.decode('latin-1'), "key": key.decode('latin-1')})
    with open(PATH, 'w') as file:
        json.dump(data_list, file, indent=4)
    return 0


def find_key(key: str) -> int:
    """
    Finds key in key manager file.

    :param key: Key to find.

    :return: Returns the key index if found.
    :rtype: int

    :return: Returns -1 if the data list is empty.
    :rtype: int

    :return: Returns -2 if the key is not found.
    :rtype: int
    """
    with open(PATH, 'r') as file:
        data_list = json.load(file)
    if len(data_list) == 0:
        return -1
    for i in range(0, len(data_list["keys"])-1):
        current_key = data_list["keys"][i]
        salt = current_key.get("salt").encode("latin-1")
        derived_key = current_key.get("key").encode("latin-1")
        kdf = Scrypt(
            salt=salt,
            length=32,
            n=2 ** 14,
            r=8,
            p=1
        )
        try:
            kdf.verify(key.encode(), derived_key)
            return i
        except InvalidKey:
            continue
    return -2


def delete_key(key: str) -> int:
    key_index = find_key(key)
    if key_index < 0:
        return -1
    with open(PATH, "rw") as file:
        data_list: dict = json.load(file)
        del data_list["keys"][key_index]
        json.dump(data_list, file, indent=4)
    return 0
