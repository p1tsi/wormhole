class BaseModule:

    def __init__(self, wh, command):
        self.wh = wh
        self.command = command
    
    def run(self):
        raise NotImplementedError()