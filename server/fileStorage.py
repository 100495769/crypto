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


    def write_new(self, filename, file_id, host_address):
        if filename not in self.data["home"]:
            self.data["home"][filename] = {
                "host_address": host_address,
                "file_id": file_id
            }
        else:
            print(f"FIle with a name {filename} already exists")
        self.save()

    def list_contents(self):
        return self.data