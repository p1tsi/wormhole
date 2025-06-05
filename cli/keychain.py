from cli.utils import *
from cli.base import BaseModule


class Keychain(BaseModule):

    def __init__(self, wh):
        super().__init__(wh, Keychain.__name__.lower()+"/")

    def run(self):
        self.command += "list"
        data, err = self.wh.execute_method(self.command, False) # The false is about auth with FaceID/TouchID
        
        item_count = len(data)
        for i, item in enumerate(data):
            print(f"Item: {i+1}/{item_count}")
            print()
            print_dict(item, indent=1)
            print()
