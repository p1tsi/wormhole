from InquirerPy import inquirer

from cli.base import BaseModule


class Hook(BaseModule):

    def __init__(self, wh):
        super().__init__(wh, Hook.__name__.lower())
        self.is_hooking = False

    def _run(self):

        choice = inquirer.fuzzy(
            message="Filter classes:",
            choices=["start", "stop"],
        ).execute()

        if choice == "stop":
            # Check out obj lifetime... 
            #if self.is_hooking:
            self.wh.unhook()
            #else:
            #    print()
            #    print("No hook set at the moment...")
        else:

            hooking_modules, custom_hooking_modules = [], []
            connectors = ["file"]

            hooking_modules = inquirer.checkbox(
                message="Select standard modules:",
                choices=self.wh.standard_modules(),
                instruction="(Use space to select, enter to confirm)"
            ).execute()

            available_custom_modules = self.wh.custom_modules()
            if available_custom_modules:
                custom_hooking_modules = inquirer.checkbox(
                    message="Select custom modules:",
                    choices=available_custom_modules,
                    instruction="(Use space to select, enter to confirm)"
                ).execute()
            
            self.is_hooking = self.wh.operations(hooking_modules, custom_hooking_modules, connectors)
