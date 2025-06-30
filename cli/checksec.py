from cli.base import BaseModule
from cli.utils import *


class Checksec(BaseModule):

    def __init__(self, wh):
        super().__init__(wh, Checksec.__name__.lower())

    def _run(self):
        data, err = self.wh.execute_method(self.command)
        Checksec.print_data(data, err)


    @staticmethod
    def print_data(data, err):
        
        print()
        print("Pie:", "✅" if data.get("pie") else "❌")
        print("Canary:", "✅" if data.get("canary") else "❌")
        print("ARC:", "✅" if data.get("arc") else "❌")
        print("Encrypted:", "✅" if data.get("encrypted") else "❌")                

        print()
        print("Entitlements:")
        print("-------------")
        print()

        print_dict(data.get('entitlements'), indent=1)
        