from cli.base import BaseModule


class Certpinning(BaseModule):
    
    def __init__(self, wh):
        super().__init__(wh, Certpinning.__name__.lower())

    def run(self):
        data, _ = self.wh.execute_method(self.command)
        if data:
            print("Certificate pinning bypassed: ✅")
        else:
            print("Error trying bypass certificate pinning")