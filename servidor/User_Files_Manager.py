import base64
import os
import json
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

SALT = b'\xd9zo\xdb\xdb\x1a\xdd\xb5\xb9\xd7\x11\xca\xd4\xc8\x02\x02'
KEY = b'AByFwoVOv7gkvaSsRtVVK3j6kHUF659COOtNoviqoyU='


class UserFiles:
    def __init__(self, user: str):
        self.__user = user
        self.__path = f"database/user_files/{self.__user}.txt"
        self.__generate_fernet()
        if not os.path.exists(self.__path):
            self.__write({"routines": [], "comments": []})

    def __generate_fernet(self):
        self.__fernet = Fernet(key=KEY)

    def __write(self, json_content: dict) -> int:
        ciphertext = self.__fernet.encrypt(json.dumps(json_content, indent=4).encode("latin-1"))
        with open(self.__path, "w") as file:
            if file.write(ciphertext.decode("latin-1")) < 0:
                return -1
        return 0

    def __read(self) -> dict:
        with open(self.__path, "r") as file:
            cleartext = file.read()
        return json.loads(self.__fernet.decrypt(cleartext.encode("latin-1")))

    @staticmethod
    def routine_in_data_list(data_list: dict, routine_name: str) -> bool:
        routines = data_list["routines"]
        for routine in routines:
            if routine.get("name") == routine_name:
                return True
        return False

    def add_routine(self, routine_name: str) -> int:
        data_list = self.__read()
        if self.routine_in_data_list(data_list, routine_name):
            return -1
        data_list["routines"].append({"name": routine_name, "exercises": []})
        print(data_list["routines"])
        self.__write(data_list)

    def add_set_to_routine(self, routine_name: str, exercise_name: str, target_muscle: str, rep_number: int):
        data_list = self.__read()
        if not self.routine_in_data_list(data_list, routine_name):
            return -1
        routines = data_list["routines"]
        for routine in routines:
            print(f"Checking if {routine_name} exists")
            # Check if the current routine matches the specified routine name
            if routine["name"] == routine_name:
                # If found, add the new exercise to the routine
                routine["exercises"].append([exercise_name, rep_number, target_muscle])
                # Save the updated data list
                self.__write(data_list)
                print(f"Exercise {exercise_name} added to routine {routine_name}")
                return 0
        return -2

    def get_routines(self) -> list:
        data_list = self.__read()
        return data_list.get("routines")

    def get_routine(self, routine_name: str) -> dict | None:
        data_list = self.__read()
        if not self.routine_in_data_list(data_list, routine_name):
            return
        for routine in data_list.get("routines"):
            if routine.get("name") == routine_name:
                return routine
        return

    def delete_routine(self, routine_name:str) -> int:
        data_list = self.__read()
        if not self.routine_in_data_list(data_list, routine_name):
            return -1
        routines = data_list["routines"]
        for routine in routines:
            if routine["name"] == routine_name:
                # delete routine
                routines.remove(routine)
                self.__write(data_list)
                return 0
        return -2

    def get_comments(self):
        """
        Returns comments list and deletes comments
        """
        data_list = self.__read()
        comment_list = data_list["comments"]
        data_list["comments"] = []
        self.__write(data_list)
        return comment_list

    def add_comment(self, trainer_username: str, comment: str):
        data_list = self.__read()
        data_list["comments"].append({"trainer": trainer_username, "comment": comment})
        self.__write(data_list)
