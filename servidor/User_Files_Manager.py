from User import User
import os
import json
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

SALT = b'\xe3\xb9xCHL~\xd2i\xd8\xe6\x8ei\xa2\x1f\x1c'


class UserFiles:
    def __init__(self, user: User, trainer: User):
        if trainer.type != "Trainer" or user.type != "User":
            raise TypeError("Usuario dado debe de ser un entrenador.")
        self.__trainer = trainer
        self.__user = user
        self.__generate_fernet()
        self.__path = f"servidor/database/user_files/{trainer.username}/{self.__user.username}"
        self.__exercises = {}
        if not os.path.exists(self.__path):
            self.__write({"routines": {}, "comments": {}})

    def __generate_fernet(self):
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=SALT,
            iterations=480000
        )
        self.__fernet = Fernet(key=kdf.derive(self.__user.password.encode()))

    def __write(self, json_content: dict) -> int:
        print("Writing...")
        ciphertext = self.__fernet.encrypt(json.dumps(json_content, indent=4).encode("latin-1"))
        with open(self.__path, "w") as file:
            if file.write(ciphertext.decode("latin-1")) < 0:
                return -1
        return 0

    def __read(self) -> dict:
        with open(self.__path, "r") as file:
            cleartext = file.read()
        return json.loads(self.__fernet.decrypt(cleartext.encode("latin-1")))

    def add_routine(self, routine_name: str) -> int:
        data_list = self.__read()
        if routine_name in data_list.get("routines"):
            return -1
        data_list.get("routines")[routine_name] = {}
        self.__write(data_list)

    def add_custom_exercise(self, exercise_name: str, targeted_muscles: list):
        if exercise_name in self.__exercises:
            return -1
        self.__exercises[exercise_name] = targeted_muscles

    def add_set_to_routine(self, routine_name: str, exercise_name: str, rep_number: int):
        data_list = self.__read()
        if routine_name not in data_list.get("routines"):
            return -1
        if exercise_name not in self.__exercises:
            return -2
        data_list.get("routines")[routine_name][exercise_name] = rep_number
        self.__write(data_list)


class TrainerFiles:
    def __init__(self, trainer: User):
        if trainer.type != "Trainer":
            raise TypeError("Usuario dado debe de ser un entrenador.")
        self.__trainer = trainer
        self.__generate_fernet()
        self.__path = f"database/user_files/{trainer.username}/trainer_info.txt"
        if not os.path.exists(self.__path):
            self.__write({"requests": [], "users": [], "custom_exercises": {}})

    def __generate_fernet(self,):
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=SALT,
            iterations=480000
        )
        self.__fernet = Fernet(key=kdf.derive(self.__trainer.password.encode()))

    def __write(self, json_content: dict) -> int:
        print("Writing...")
        ciphertext = self.__fernet.encrypt(json.dumps(json_content, indent=4).encode("latin-1"))
        with open(self.__path, "w") as file:
            if file.write(ciphertext.decode("latin-1")) < 0:
                return -1
        return 0

    def __read(self) -> dict:
        with open(self.__path, "r") as file:
            cleartext = file.read()
        return json.loads(self.__fernet.decrypt(cleartext.encode("latin-1")))

    def get_requests(self) -> list:
        data_list = self.__read()
        return data_list.get("requests")
