from cli.base import BaseModule


class Dumpipa(BaseModule):

    def __init__(self, wh):
        super().__init__(wh, Dumpipa.__name__.lower())

    def _run(self):
        data, err = self.wh.execute_method(self.command)
        if err:
            print(f"Error dumping ipa: {err}")
        else:
            print(data)