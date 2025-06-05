import threading

from InquirerPy import inquirer

class Hook:

    def __init__(self, wh):
        self.wh = wh
        self.is_hooking = False

    def run(self):

        choice = inquirer.fuzzy(
            message="Filter classes:",
            choices=["start", "stop"],
        ).execute()

        if choice == "stop":
            if self.is_hooking:
                self.wh.unhook()
            else:
                print()
                print("No hook set at the moment...")
        else:

            hooking_modules, custom_hooking_modules = [], []
            connectors = ["file"]

            hooking_modules = inquirer.checkbox(
                message="Select standard modules:",
                choices=self.wh.standard_modules(),
                instruction="(Use space to select, enter to confirm)"
            ).execute()

            custom_hooking_modules = inquirer.checkbox(
                message="Select custom modules:",
                choices=self.wh.custom_modules(),
                instruction="(Use space to select, enter to confirm)"
            ).execute()
            
            self.is_hooking = self.wh.operations(hooking_modules, custom_hooking_modules, connectors)
