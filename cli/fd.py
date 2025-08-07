from InquirerPy import inquirer

from cli.utils import *
from cli.base import BaseModule


class FileDescriptor(BaseModule):

    def __init__(self, wh):
        super().__init__(wh, "fileDescriptors/")

    def _run(self):

        choice = inquirer.fuzzy(
            message="Choose which type of file descriptors:",
            choices=["vnode", "socket"]
        ).execute()

        self.command += "getFds"
        data, err = self.wh.execute_method(self.command, 0 if choice == "vnode" else 1)

        item_count = len(data)
        for i, (k, v) in enumerate(data.items()):
            print(f"{i+1}/{item_count}\tFD: {k}")
            print()
            print_dict(v, indent=1)
            print()
