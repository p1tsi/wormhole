from InquirerPy import inquirer

from cli.utils import *
from cli.base import BaseModule
from cli.classdump import Classdump


class Heap(BaseModule):
    
    def __init__(self, wh):
        super().__init__(wh, Heap.__name__.lower()+"/")

    def run(self):

        class_list, err = Classdump(self.wh).search()

        clazz = inquirer.fuzzy(
            message="Filter classes:",
            choices=class_list,
            max_height="80%"
        ).execute()

        self.command += "inspect"

        data, err = self.wh.execute_method(self.command, clazz)
        
        print(data)

