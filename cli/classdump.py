from InquirerPy import inquirer

from cli.utils import *
from cli.base import BaseModule

    

class Classdump(BaseModule):

    def __init__(self, wh):
        super().__init__(wh, Classdump.__name__.lower()+"/")

    def search(self):
        search_command = self.command + "search"

        scope = inquirer.fuzzy(
            message="Choose scope:",
            choices=["__main__", "__app__", "__global__"]
        ).execute()

        return self.wh.execute_method(search_command, scope)        

    def filter_classes(self, class_list):
        clazz = inquirer.fuzzy(
            message="Filter classes:",
            choices=class_list,
            max_height="80%"
        ).execute()

        inspect_command = self.command + "inspect"
        return self.wh.execute_method(inspect_command, clazz)

    def _run(self):

        class_list, err = self.search()
        class_info, err = self.filter_classes(class_list)
        
        print()
        print(f"Module: {class_info.get('module')}")
        print(f"Super Classes: {class_info.get('prototypeChain')}")
        print()

        del class_info["module"]
        del class_info["prototypeChain"]

        choice_list = list(class_info.keys())
        choice_list.append("exit")
        while True:
            element = inquirer.fuzzy(
                message="What would you like to inspect?",
                choices=choice_list,
                max_height="80%"
            ).execute()

            if element == "exit":
                break
            elif element == "ivars" or element == "protocols":
                print()
                print_dict(class_info.get(element), indent=1)
                print()
            else:
                print()
                print_list(class_info.get(element), indent=1)
                print()
