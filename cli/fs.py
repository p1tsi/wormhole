import os.path
from InquirerPy import inquirer

from cli.utils import *
from cli.base import BaseModule


class FileSystem(BaseModule):

    def __init__(self, wh):
        super().__init__(wh, "fs/")

    def _run(self):
        folder_path = ""

        subcmd = inquirer.fuzzy(
            message="Choose subcommand:",
            choices=["ls"]
        ).execute()

        where = inquirer.fuzzy(
            message="Choose where:",
            choices=["bundle", "home", "tmp"]
        ).execute()

        ls_command = self.command + subcmd
        file_list, err = self.wh.execute_method(ls_command, where, folder_path)
        
        while file_list:
            files = dict()
            for f in file_list.get("items"):
                files[f.get("name")] = True if f.get("type") == "directory" else False

            subfile = inquirer.fuzzy(
                message="Choose subdir:",
                choices=files.keys()
            ).execute()

            if files.get(subfile):
                folder_path = os.path.join(folder_path, subfile)
                file_list, err = self.wh.execute_method(ls_command, where, f"/{folder_path}")
            else:
                download_command = self.command + "download"
                path = next(filter(lambda x: x.get("name") == subfile, file_list.get("items"))).get('path')
                data, err = self.wh.execute_method(download_command, path)
