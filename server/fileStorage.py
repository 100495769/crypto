import os
import json

class UserFile:
    """This class describes the structure of the json storage of information for each user.
    Each json is stored on the server in a file user_files"""
    def __init__(self, username, storage_location='user_files'):
        self.username = username
        self.storage_location = storage_location
        self.current_dir = ["home"]

        self.file_path = os.path.join(self.storage_location, f'{self.username}.json')

        if not os.path.exists(self.storage_location):
            os.makedirs(self.storage_location)

        if os.path.exists(self.file_path):
            with open(self.file_path, 'r') as f:
                self.data = json.load(f)
        else:
            self.data = {"home": {}}
            self.save()

    # saving data to json
    def save(self):
        with open(self.file_path, 'w') as f:
            json.dump(self.data, f, indent=4)

    # writing new user file to json
    def write_new(self, filename, host_address, file_id):
        current_dir = self.get_current_directory()
        if filename not in current_dir:
            current_dir[filename] = {
                "host_address": host_address,
                "file_id": file_id
            }
            self.save()
        else:
            print(f"File with a name {filename} already exists")

    # creating of a new directory
    def make_new_dir(self, dirname):
        current_dir = self.get_current_directory()
        if dirname not in current_dir:
            current_dir[dirname] = {}
            self.save()
        else:
            print(f"Directory {dirname} already exists")
        self.save()

    # saving to the directory
    def save_to_dir(self, dirname, filename, host_address, file_id):
        current_dir = self.get_current_directory()
        if dirname in current_dir:
            if filename not in current_dir[dirname]:
                current_dir[dirname][filename] = {
                    "host_address": host_address,
                    "file_id": file_id
                }
                self.save()
            else:
                print(f"File with the name {filename} already exists in {dirname}.")
        else:
            print(f"Directory {dirname} does not exist.")

    # removing the directory
    def remove_directory(self, dirname):
        current_dir = self.get_current_directory()
        if dirname in current_dir:
            current_dir.pop(dirname);
            self.save()
        else:
            print(f"Directory {dirname} does not exist")

    # changing the directory
    def change_directory(self, dirname):
        current_dir = self.get_current_directory()
        if dirname == "../" or dirname == "..":
            if len(self.current_dir) > 1:
                self.current_dir.pop()
            else:
                print(f"You are at the root directory")
        if dirname in current_dir:
            self.current_dir.append(dirname)
        else:
            print(f"Directory {dirname} does not exist")

    # in order to work with cd in future -> getting current directory
    def get_current_directory(self):
        current = self.data["home"]
        for dirname in self.current_dir[1:]:
            current = current.get(dirname, {})
        return current

    # display all contents
    def list_contents(self):
        current_dir = self.get_current_directory()
        return current_dir

    # showing pwd
    def show_current_path(self):
        result = ""
        for dirname in self.current_dir:
            result += "/" + dirname
        return result

    # deleting file from directory
    def delete_file(self, filename):
        current_dir = self.get_current_directory()
        if filename == current_dir[-1]:
            print(f"You are trying to delete a directory.")
        elif filename in current_dir:
            current_dir.pop(filename)
            self.save()
        else:
            print(f"File {filename} does not exist")

    # silly method for sergio
    def for_sergio(self, filename):
        current_dir = self.get_current_directory()
        if filename in current_dir:
            file_data = current_dir[filename]
            return tuple(file_data["host_address"]), file_data["file_id"]
        return None, None


class UsersInfo:
    """This class describes the single json file for the storage of all the usernames and
    passwords associated to them. It is stored exactly in the root of the server"""
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

    # saving info to json
    def save(self):
        with open(self.file_path, 'w') as f:
            json.dump(self.data, f, indent=4)

    # writing new user data to the file
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
