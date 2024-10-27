import os
import json

class UserFile:

    def __init__(self, username, storage_location='user_files'):
        self.username = username
        self.storage_location = storage_location

        self.file_path = os.path.join(self.storage_location, f'{self.username}.json')

        if not os.path.exists(self.storage_location):
            os.makedirs(self.storage_location)

        if os.path.exists(self.file_path):
            with open(self.file_path, 'r') as f:
                self.data = json.load(f)
        else:
            self.data = {"home": {}}
            self.save()

    def save(self):
        with open(self.file_path, 'w') as f:
            json.dump(self.data, f, indent=4)


    def write_new(self, filename, host_address, file_id):
        if filename not in self.data["home"]:
            self.data["home"][filename] = {
                "host_address": host_address,
                "file_id": file_id
            }
            self.save()
        else:
            print(f"File with a name {filename} already exists")

    def make_new_dir(self, dirname):
        if dirname not in self.data["home"]:
            self.data["home"][dirname] = {}
            self.save()
        else:
            print(f"Directory {dirname} already exists")
        self.save()

    def save_to_dir(self, dirname, filename, host_address, file_id):
        if dirname in self.data["home"]:
            if filename not in self.data["home"][dirname]:
                self.data["home"][dirname][filename] = {
                    "host_address": host_address,
                    "file_id": file_id
                }
                self.save()
            else:
                print(f"File with the name {filename} already exists in {dirname}.")
        else:
            print(f"Directory {dirname} does not exist.")

    def list_contents(self):
        return self.data


class UsersInfo:

    def __init__(self, username, storage_location='server'):
        self.username = username
        self.storage_location = storage_location

        self.file_path = os.path.join(self.storage_location, 'usernames.json')

        if not os.path.exists(self.storage_location):
            os.makedirs(self.storage_location)

        if os.path.exists(self.file_path):
            with open(self.file_path, 'r') as f:
                self.data = json.load(f)
        else:
            self.data = {}
            self.save()

    def save(self):
        with open(self.file_path, 'w') as f:
            json.dump(self.data, f, indent=4)

    def write_new(self, username, password):
        if username not in self.data:
            self.data[username] = {
                "password": password
            }
            self.save()
        else:
            print(f"Username {username} already exists")

    def list_contents(self):
        return list(self.data.keys())
