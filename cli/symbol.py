from InquirerPy import inquirer

from cli.utils import *
from cli.base import BaseModule


class Symbol(BaseModule):

    def __init__(self, wh):
        super().__init__(wh, Symbol.__name__.lower()+"/")

    def _run(self):
        get_modules = self.command + "modules"
        data, err = self.wh.execute_method(get_modules, False) # The false is about auth with FaceID/TouchID
        
        libraries = list(
            map(lambda f: f.get('name'), filter(lambda f: "/System/Library/" not in f.get('path') and "/usr/" not in f.get('path'), data)))
        choosen_lib = inquirer.fuzzy(
            message="What would you like to inspect?",
            choices=libraries,
            max_height="80%"
        ).execute()

        print(choosen_lib)

        repeat = True
        while repeat:
            choosen_element = inquirer.fuzzy(
                message="What would you like to inspect?",
                choices=["importedModules", "exported", "symbols", "classes", "exit"],
                max_height="80%"
            ).execute()

            if choosen_element == "exit":
                repeat = False
            elif choosen_element == "classes":
                # TODO: classdump/list (path)
                pass
            else:
                subcommand = self.command + choosen_element
                data, err = self.wh.execute_method(subcommand, choosen_lib)

                if choosen_element == "importedModules":
                    print_list(data, indent=1)
                else:
                    item_list = data.get('list')
                    print(item_list)
                    names = list(map(lambda x: x.get("name"), item_list))
                    choosen_item = inquirer.fuzzy(
                        message="What would you like to inspect?",
                        choices=names,
                        max_height="80%"
                    ).execute()

                    print(choosen_item)

                    result = next((item for item in item_list if item.get('name') == choosen_item), None)
                    print(result)
                    asm_data, err = self.wh.execute_method("disasm", result.get('address'))
                    
                    for instruction in asm_data.get('instructions'):
                        print(f"\t{instruction.get('string')}")
