from InquirerPy import inquirer

from cli.base import BaseModule


class Url(BaseModule):

    def __init__(self, wh):
        super().__init__(wh, Url.__name__.lower()+"/")

    def _run(self):
        choice = inquirer.fuzzy(
            message="Available subcommands:",
            choices=["list", "open"]
        ).execute()

        if choice == "list":
            self.command += choice
            data, err = self.wh.execute_method(self.command)

            if data:
                print()
                for item in data.get('urls'):
                    print(f"Name: {item.get('name')}")
                    print(f"Role: {item.get('role')}")
                    print("Schemas:")
                    for schema in item.get('schemes'):
                        print(f"\t{schema}")
            else:
                print("No deep link found.")
        else:
            url_to_open = input("> ")
            self.command += choice
            data, err = self.wh.execute_method(self.command, url_to_open)

            print(data)
