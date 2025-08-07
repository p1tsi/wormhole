from InquirerPy import inquirer

from cli.utils import *
from cli.base import BaseModule

class UserDefaults:

    @staticmethod
    def print_data(data, err):
        print()
        print_dict(data)


class BundleInfo:
    
    @staticmethod
    def print_data(data, err):
        print()
        print(f"Name: {data.get('name')}")
        print(f"Bundle id: {data.get('id')}")
        print(f"Version: {data.get('semVer')}")
        print(f"Bundle Dir: {data.get('bundle')}")
        print(f"Binary: {data.get('binary')}")
        print(f"MinOS: {data.get('minOS')}")
        print(f"Home: {data.get('home')}")
        print(f"Temp Dir: {data.get('tmp')}")

        print()
        print("Info.plist")
        print("----------")
        print()
        print_dict(data.get('json'), indent=0)            


class Info(BaseModule):

    SUBCOMMANDS = {
        #"icon",
        "info": BundleInfo,
        "userDefaults": UserDefaults,
    }

    def __init__(self, wh):
        super().__init__(wh, Info.__name__.lower()+"/")

    def _run(self):

        choice = inquirer.fuzzy(
            message="Available subcommands:",
            choices=self.SUBCOMMANDS
        ).execute()

        self.command += choice
        data, err = self.wh.execute_method(self.command)

        self.SUBCOMMANDS.get(choice).print_data(data, err)
