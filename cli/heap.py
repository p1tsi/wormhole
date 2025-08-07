from InquirerPy import inquirer

from cli.utils import *
from cli.base import BaseModule
from cli.classdump import Classdump


class HeapObject:

    def __init__(self, classname:str, json_obj: dict):
        self.classname = classname
        self.description = json_obj.get('description')
        self.ptr = json_obj.get('ptr')
        self.isa = json_obj.get('isa')
        self.ivars = json_obj.get('ivars')

    def __repr__(self):
        print(f"\t{self.classname}")


class Heap(BaseModule):
    
    def __init__(self, wh):
        super().__init__(wh, Heap.__name__.lower()+"/")

    def _run(self):

        class_list, err = Classdump(self.wh).search()

        clazz = inquirer.fuzzy(
            message="Filter classes:",
            choices=class_list,
            max_height="80%"
        ).execute()

        self.command += "inspect"

        data, err = self.wh.execute_method(self.command, clazz)
        
        print()
        for item in data:
            print(f"{item.get('isa')} @ {item.get('ptr')} ({item.get('description')})")
            print()
            for ivar in item.get("ivars"):
                value = ivar.get('value').replace('\n', ' ')
                print(f"\t{ivar.get('name')} @ {item.get('ptr')} = {value}")
            
            print()


